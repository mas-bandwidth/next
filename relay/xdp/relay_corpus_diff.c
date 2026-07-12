// Relay conformance differential: fires the relaycorpus packet corpus at the real
// compiled relay_xdp.o via BPF_PROG_RUN and checks every verdict against the oracle
// stored in the corpus file. This is the exact, lossless half of the relay
// consolidation's step 1 -- see relay/CONSOLIDATION.md and modules/relaycorpus.
//
// For each packet we snapshot the basic- and advanced-filter drop counters (percpu,
// summed across cpus), run the program, and read the counters back:
//   basic counter incremented    -> the relay dropped it at the basic filter
//   advanced counter incremented -> dropped at the advanced filter
//   neither, and retval != DROP  -> the relay accepted it (reached a type handler)
// A mismatch against the corpus verdict is a divergence between the Go oracle (which the
// reference relay must also match) and the actual XDP relay -- exactly the four-way
// desync risk the corpus exists to catch. Requires the relay_module kfunc insmodded.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX   3

// must match relay/xdp/relay_constants.h
#define RELAY_NUM_COUNTERS 150
#define COUNTER_BASIC    4
#define COUNTER_ADVANCED 5

// must match modules/relaycorpus verdicts
#define V_DROP_BASIC    0
#define V_DROP_ADVANCED 1
#define V_PASS          2

static const char *verdict_name(int v) {
    switch (v) { case V_DROP_BASIC: return "drop-basic"; case V_DROP_ADVANCED: return "drop-advanced"; case V_PASS: return "pass"; }
    return "?";
}

static int put_u32be(unsigned char *p, unsigned int v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; return 4; }
static int put_u16be(unsigned char *p, unsigned int v) { p[0]=v>>8; p[1]=v; return 2; }

static int build_frame(unsigned char *out, const unsigned char from[4], const unsigned char to[4],
                       unsigned short dport, const unsigned char *payload, int payload_len) {
    int o = 0;
    memset(out + o, 0x11, 6); o += 6;                 // dst mac
    memset(out + o, 0x22, 6); o += 6;                 // src mac
    o += put_u16be(out + o, 0x0800);                  // ethertype ipv4
    out[o++] = 0x45; out[o++] = 0x00;                 // v4/ihl5, tos
    o += put_u16be(out + o, 20 + 8 + payload_len);    // total len
    o += put_u16be(out + o, 0); o += put_u16be(out + o, 0); // id, flags
    out[o++] = 64; out[o++] = 17;                     // ttl, proto udp
    o += put_u16be(out + o, 0);                       // ip csum
    out[o++] = from[0]; out[o++] = from[1]; out[o++] = from[2]; out[o++] = from[3];
    out[o++] = to[0];   out[o++] = to[1];   out[o++] = to[2];   out[o++] = to[3];
    o += put_u16be(out + o, 12345);                   // udp sport
    o += put_u16be(out + o, dport);                   // udp dport
    o += put_u16be(out + o, 8 + payload_len);         // udp len
    o += put_u16be(out + o, 0);                       // udp csum
    if (payload_len > 0) { memcpy(out + o, payload, payload_len); o += payload_len; }
    return o;
}

static int ncpu;
static __u64 *stats_buf; // ncpu * RELAY_NUM_COUNTERS
static int stats_fd;

// sum a percpu counter across all cpus
static __u64 read_counter(int index) {
    int zero = 0;
    if (bpf_map_lookup_elem(stats_fd, &zero, stats_buf)) return 0;
    __u64 sum = 0;
    for (int c = 0; c < ncpu; c++) sum += stats_buf[c * RELAY_NUM_COUNTERS + index];
    return sum;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <relay_xdp.o> <corpus.bin>\n", argv[0]); return 2; }
    const char *obj_path = argv[1];
    const char *corpus_path = argv[2];

    // read the corpus file
    FILE *f = fopen(corpus_path, "rb");
    if (!f) { fprintf(stderr, "FAIL: open corpus %s\n", corpus_path); return 2; }
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *corpus = malloc(fsz);
    if (fread(corpus, 1, fsz, f) != (size_t)fsz) { fprintf(stderr, "FAIL: read corpus\n"); return 2; }
    fclose(f);
    if (memcmp(corpus, "RLYC", 4) != 0) { fprintf(stderr, "FAIL: bad corpus magic\n"); return 2; }
    unsigned int count = corpus[8] | (corpus[9]<<8) | (corpus[10]<<16) | (corpus[11]<<24);

    // load relay_xdp.o
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "FAIL: open %s\n", obj_path); return 2; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "relay_xdp_filter");
    if (!prog) { fprintf(stderr, "FAIL: find prog\n"); return 2; }
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
    if (bpf_object__load(obj)) { fprintf(stderr, "FAIL: load (kfunc module insmodded?)\n"); return 2; }
    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    struct bpf_map *state_map = bpf_object__find_map_by_name(obj, "state_map");
    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!config_map || !state_map || !stats_map) { fprintf(stderr, "FAIL: find maps\n"); return 2; }
    stats_fd = bpf_map__fd(stats_map);

    ncpu = libbpf_num_possible_cpus();
    stats_buf = calloc(ncpu, RELAY_NUM_COUNTERS * sizeof(__u64));

    // corpus magic is the same for every entry -- read it from entry 0.
    // entry layout: verdict(1) from[4] to[4] magic[8] len(2) packet
    unsigned char *e0 = corpus + 12;
    unsigned char *corpus_magic = e0 + 1 + 4 + 4;

    // config: relay at 127.0.0.1:40000, distinct internal address
    size_t cvsize = bpf_map__value_size(config_map);
    unsigned char *config = calloc(1, cvsize);
    put_u32be(config + 4, 0x7f000001);   // relay_public_address (network order bytes)
    put_u32be(config + 8, 0x0a010101);   // relay_internal_address, distinct sentinel
    unsigned short port_be = htons(40000);
    memcpy(config + 12, &port_be, 2);    // relay_port
    int zero = 0;
    if (bpf_map_update_elem(bpf_map__fd(config_map), &zero, config, BPF_ANY)) { fprintf(stderr, "FAIL: config update\n"); return 2; }

    // state: current magic = corpus magic; previous/next distinct so wrong-magic packets
    // cannot accidentally match on those slots.
    size_t svsize = bpf_map__value_size(state_map);
    unsigned char *state = calloc(1, svsize);
    // struct relay_state: current_timestamp(u64)@0, current_magic[8]@8, previous_magic[8]@16, next_magic[8]@24, ...
    memcpy(state + 8, corpus_magic, 8);
    for (int i = 0; i < 8; i++) { state[16 + i] = corpus_magic[i] ^ 0xAA; state[24 + i] = corpus_magic[i] ^ 0x55; }
    if (bpf_map_update_elem(bpf_map__fd(state_map), &zero, state, BPF_ANY)) { fprintf(stderr, "FAIL: state update\n"); return 2; }

    unsigned char frame[2048], out[2048];
    unsigned int mismatches = 0, checked = 0;
    unsigned int by_verdict[3] = {0,0,0};

    unsigned char *p = corpus + 12;
    for (unsigned int i = 0; i < count; i++) {
        // entry layout: verdict(1) from[4] to[4] magic[8] len(2) packet
        int verdict = p[0];
        unsigned char from[4], to[4];
        memcpy(from, p + 1, 4);
        memcpy(to, p + 5, 4);
        int plen = p[17] | (p[18] << 8);
        unsigned char *packet = p + 19;
        p = packet + plen;

        int flen = build_frame(frame, from, to, 40000, packet, plen);

        __u64 basic_before = read_counter(COUNTER_BASIC);
        __u64 adv_before = read_counter(COUNTER_ADVANCED);

        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = frame, .data_size_in = flen,
                    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err) { fprintf(stderr, "FAIL: test_run entry %u err=%d\n", i, err); return 2; }

        __u64 basic_delta = read_counter(COUNTER_BASIC) - basic_before;
        __u64 adv_delta = read_counter(COUNTER_ADVANCED) - adv_before;

        int got;
        if (basic_delta > 0) got = V_DROP_BASIC;
        else if (adv_delta > 0) got = V_DROP_ADVANCED;
        else if (opts.retval == XDP_PASS || opts.retval == XDP_TX) got = V_PASS;
        else got = -1; // dropped for another reason (a passing packet reached a handler that dropped it)

        checked++;
        if (verdict >= 0 && verdict < 3) by_verdict[verdict]++;

        // a corpus 'pass' means it cleared the filters; a type handler may still DROP a
        // malformed-but-filter-passing packet, so treat handler drops as pass-equivalent.
        int ok;
        if (verdict == V_PASS) ok = (basic_delta == 0 && adv_delta == 0);
        else ok = (got == verdict);

        if (!ok) {
            if (mismatches < 20)
                fprintf(stderr, "MISMATCH entry %u: corpus=%s xdp=%s (retval=%u basic+%llu adv+%llu len=%d type=0x%02x)\n",
                        i, verdict_name(verdict), verdict_name(got), opts.retval,
                        (unsigned long long)basic_delta, (unsigned long long)adv_delta, plen, packet[0]);
            mismatches++;
        }
    }

    printf("corpus differential: %u checked (%u drop-basic, %u drop-advanced, %u pass), %u mismatches\n",
           checked, by_verdict[V_DROP_BASIC], by_verdict[V_DROP_ADVANCED], by_verdict[V_PASS], mismatches);
    printf(mismatches == 0 ? "CORPUS DIFFERENTIAL: PASS\n" : "CORPUS DIFFERENTIAL: FAIL\n");
    bpf_object__close(obj);
    return mismatches == 0 ? 0 : 1;
}
