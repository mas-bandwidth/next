// Feasibility spike for the relay consolidation plan (step 1, the risky half):
// prove we can run the ACTUAL compiled relay_xdp.o through BPF_PROG_RUN in CI,
// populate its maps, feed it a frame, and read back the verdict + output bytes.
// If this works, a conformance corpus can be fired three ways -- reference relay,
// a future extracted userspace core, and the real BPF object -- for the strongest
// possible wire-compat guarantee. Two crypto-free cases here; the full corpus is
// a follow-up. Requires the relay_module kfunc to be insmodded (the object won't
// load otherwise -- see the CI XDP job).

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// XDP action codes (uapi/linux/bpf.h)
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3

static int put_u32be(unsigned char *p, unsigned int v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; return 4; }
static int put_u16be(unsigned char *p, unsigned int v) { p[0]=v>>8; p[1]=v; return 2; }

// build ETH(14)+IP(20)+UDP(8)+payload into out, return total length
static int build_frame(unsigned char *out, unsigned int saddr, unsigned int daddr,
                       unsigned short sport, unsigned short dport,
                       const unsigned char *payload, int payload_len) {
    int o = 0;
    // ethernet: dst mac, src mac, ethertype IPv4
    memset(out + o, 0x11, 6); o += 6;
    memset(out + o, 0x22, 6); o += 6;
    o += put_u16be(out + o, 0x0800);
    // ipv4
    int ip_start = o;
    out[o++] = 0x45;            // version 4, ihl 5
    out[o++] = 0x00;            // tos
    o += put_u16be(out + o, 20 + 8 + payload_len); // total length
    o += put_u16be(out + o, 0); // id
    o += put_u16be(out + o, 0); // flags/frag
    out[o++] = 64;              // ttl
    out[o++] = 17;              // protocol UDP
    o += put_u16be(out + o, 0); // checksum (ignored by test_run)
    o += put_u32be(out + o, saddr);
    o += put_u32be(out + o, daddr);
    (void)ip_start;
    // udp
    o += put_u16be(out + o, sport);
    o += put_u16be(out + o, dport);
    o += put_u16be(out + o, 8 + payload_len);
    o += put_u16be(out + o, 0); // checksum
    // payload
    if (payload_len > 0) { memcpy(out + o, payload, payload_len); o += payload_len; }
    return o;
}

static int print_all(enum libbpf_print_level level, const char *fmt, va_list args) {
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv) {
    const char *obj_path = argc > 1 ? argv[1] : "relay_xdp.o";

    libbpf_set_print(print_all);

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "FAIL: open %s\n", obj_path); return 1; }

    // the program section is SEC("relay_xdp"), a nonstandard name libbpf cannot infer
    // a program type from (bpftool works because it is told 'type xdp' explicitly)
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "relay_xdp_filter");
    if (!prog) { fprintf(stderr, "FAIL: find prog relay_xdp_filter\n"); return 1; }
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

    if (bpf_object__load(obj)) { fprintf(stderr, "FAIL: load (kfunc module insmodded?)\n"); return 1; }

    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    if (!config_map) { fprintf(stderr, "FAIL: find config_map\n"); return 1; }
    int config_fd = bpf_map__fd(config_map);

    // populate config_map[0]: relay_public_address = 127.0.0.1, relay_port = 40000.
    // poke by offset against the map's real value size so we don't depend on struct
    // layout: dedicated(u32)@0, relay_public_address(u32 be)@4, relay_port(u16 be)@12.
    size_t vsize = bpf_map__value_size(config_map);
    unsigned char *config = calloc(1, vsize);
    put_u32be(config + 4, 0x7f000001);          // relay_public_address, stored big endian
    // relay_port is compared against udp->dest which is network byte order; store htons(40000)
    unsigned short port_be = htons(40000);
    memcpy(config + 12, &port_be, 2);
    // relay_public_address in the program is compared to ip->daddr (network order). ip->daddr
    // we build as 0x7f000001 via put_u32be (big endian bytes) -> matches config bytes above.
    int zero = 0;
    if (bpf_map_update_elem(config_fd, &zero, config, BPF_ANY)) { fprintf(stderr, "FAIL: config update\n"); return 1; }
    free(config);

    unsigned char frame[2048];
    unsigned char out[2048];
    int rc = 0;

    // case 1: wrong dest port -> program falls through to XDP_PASS (dedicated=0)
    {
        unsigned char payload[32]; memset(payload, 0xAB, sizeof(payload));
        int len = build_frame(frame, 0x0a000001, 0x7f000001, 12345, 50000, payload, sizeof(payload));
        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = frame, .data_size_in = len,
                    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        printf("case1 wrong_port: err=%d retval=%u (want XDP_PASS=%d)\n", err, opts.retval, XDP_PASS);
        if (err || opts.retval != XDP_PASS) rc = 1;
    }

    // case 2: matching port+addr but payload < 18 bytes -> XDP_DROP
    {
        unsigned char payload[4] = {0x01,0x02,0x03,0x04};
        int len = build_frame(frame, 0x0a000001, 0x7f000001, 12345, 40000, payload, sizeof(payload));
        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = frame, .data_size_in = len,
                    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        printf("case2 short_payload: err=%d retval=%u (want XDP_DROP=%d)\n", err, opts.retval, XDP_DROP);
        if (err || opts.retval != XDP_DROP) rc = 1;
    }

    printf(rc == 0 ? "PROG_TEST_RUN SPIKE: PASS\n" : "PROG_TEST_RUN SPIKE: FAIL\n");
    bpf_object__close(obj);
    return rc;
}
