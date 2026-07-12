// Relay conformance differential: fires the relaycorpus corpus at the real compiled
// relay_xdp.o via BPF_PROG_RUN and checks every entry's XDP action and expected counter
// against the oracle in the corpus file. This is the kernel-object half of the relay
// consolidation differential -- relay_userspace_test.c does the same against the
// userspace build, and both must agree with the Go oracle in modules/relaycorpus.
//
// The corpus carries a WORLD (relay config, state, and the relay/whitelist/session map
// contents). We load it into the BPF maps, reset the mutable maps before every entry so
// they are order-independent, run the program, and compare (retval, counter delta) to
// the entry. A mismatch is a divergence between the Go oracle and the actual XDP relay
// -- the desync risk the corpus exists to catch. Requires the relay_module kfunc
// insmodded (relay_xdp.c calls bpf_relay_sha256 / bpf_relay_xchacha20poly1305_decrypt).

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "relay_shared.h"
#include "relay_corpus.h"

#define RELAY_NUM_COUNTERS 150

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

static int put_u16be(unsigned char *p, unsigned int v) { p[0]=v>>8; p[1]=v; return 2; }

static int build_frame(unsigned char *out, const unsigned char from[4], unsigned short sport,
                       const unsigned char to[4], unsigned short dport,
                       const unsigned char *payload, int payload_len) {
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
    o += put_u16be(out + o, sport);                   // udp sport
    o += put_u16be(out + o, dport);                   // udp dport
    o += put_u16be(out + o, 8 + payload_len);         // udp len
    o += put_u16be(out + o, 0);                       // udp csum
    if (payload_len > 0) { memcpy(out + o, payload, payload_len); o += payload_len; }
    return o;
}

// addresses/ports are stored in the maps in network order, matching how the datapath
// keys them (ip->saddr = htonl(quad); udp->source = htons(port)).
static __u32 addr_quad(const __u8 a[4]) { return ((__u32)a[0] << 24) | ((__u32)a[1] << 16) | ((__u32)a[2] << 8) | a[3]; }
static __u32 net_addr(const __u8 a[4]) { return htonl(addr_quad(a)); }

static struct corpus g_corpus;
static int config_fd, state_fd, relay_fd, session_fd, whitelist_fd;

static void load_config_and_state(void) {
    int zero = 0;

    struct relay_config config;
    memset(&config, 0, sizeof(config));
    config.relay_public_address = net_addr(g_corpus.relay_public_address);
    config.relay_internal_address = net_addr(g_corpus.relay_internal_address);
    config.relay_port = htons(g_corpus.relay_port);
    memcpy(config.relay_secret_key, g_corpus.secret_key, RELAY_SECRET_KEY_BYTES);
    if (bpf_map_update_elem(config_fd, &zero, &config, BPF_ANY)) { fprintf(stderr, "FAIL: config update\n"); exit(2); }

    struct relay_state state;
    memset(&state, 0, sizeof(state));
    state.current_timestamp = g_corpus.timestamp;
    memcpy(state.current_magic, g_corpus.current_magic, 8);
    memcpy(state.previous_magic, g_corpus.previous_magic, 8);
    memcpy(state.next_magic, g_corpus.next_magic, 8);
    memcpy(state.ping_key, g_corpus.ping_key, RELAY_PING_KEY_BYTES);
    if (bpf_map_update_elem(state_fd, &zero, &state, BPF_ANY)) { fprintf(stderr, "FAIL: state update\n"); exit(2); }
}

// delete every key in a hash map (key_size bytes wide) so we can reload it fresh.
static void clear_map(int fd, int key_size) {
    unsigned char key[64], next[64];
    if (key_size > (int)sizeof(key)) { fprintf(stderr, "FAIL: key too wide\n"); exit(2); }
    int have = bpf_map_get_next_key(fd, NULL, key) == 0;
    while (have) {
        int have_next = bpf_map_get_next_key(fd, key, next) == 0;
        bpf_map_delete_elem(fd, key);
        if (!have_next) break;
        memcpy(key, next, key_size);
    }
}

// reset the mutable maps to the world (handlers create/delete entries; this isolates
// each corpus entry). config/state are loaded once and never mutated by the datapath.
static void reset_world_maps(void) {
    clear_map(relay_fd, sizeof(__u64));
    clear_map(session_fd, sizeof(struct session_key));
    clear_map(whitelist_fd, sizeof(struct whitelist_key));

    for (int i = 0; i < g_corpus.num_relays; i++) {
        __u64 key = (((__u64)net_addr(g_corpus.relays[i].address)) << 32) | htons(g_corpus.relays[i].port);
        __u64 value = 1;
        bpf_map_update_elem(relay_fd, &key, &value, BPF_ANY);
    }

    for (int i = 0; i < g_corpus.num_whitelist; i++) {
        struct whitelist_key key;
        memset(&key, 0, sizeof(key));
        key.address = net_addr(g_corpus.whitelist[i].address);
        key.port = htons(g_corpus.whitelist[i].port);
        struct whitelist_value value;
        memset(&value, 0, sizeof(value));
        value.expire_timestamp = g_corpus.whitelist[i].expire_timestamp;
        bpf_map_update_elem(whitelist_fd, &key, &value, BPF_ANY);
    }

    for (int i = 0; i < g_corpus.num_sessions; i++) {
        struct corpus_session *cs = &g_corpus.sessions[i];
        struct session_key key;
        memset(&key, 0, sizeof(key));
        key.session_id = cs->id;
        key.session_version = cs->version;

        struct session_data value;
        memset(&value, 0, sizeof(value));
        memcpy(value.session_private_key, cs->private_key, RELAY_SESSION_PRIVATE_KEY_BYTES);
        value.expire_timestamp = cs->expire_timestamp;
        value.session_id = cs->id;
        value.payload_client_to_server_sequence = cs->payload_client_to_server_sequence;
        value.payload_server_to_client_sequence = cs->payload_server_to_client_sequence;
        value.special_client_to_server_sequence = cs->special_client_to_server_sequence;
        value.special_server_to_client_sequence = cs->special_server_to_client_sequence;
        value.next_address = net_addr(cs->next_address);
        value.prev_address = net_addr(cs->prev_address);
        value.next_port = htons(cs->next_port);
        value.prev_port = htons(cs->prev_port);
        value.session_version = cs->version;
        value.next_internal = cs->next_internal;
        value.prev_internal = cs->prev_internal;
        value.first_hop = cs->first_hop;
        bpf_map_update_elem(session_fd, &key, &value, BPF_ANY);
    }
}

static const char *action_name(int a) {
    switch (a) { case CORPUS_ACTION_DROP: return "DROP"; case CORPUS_ACTION_PASS: return "PASS";
        case CORPUS_ACTION_TX: return "TX"; case CORPUS_ACTION_ANY: return "ANY"; }
    return "?";
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <relay_xdp.o> <corpus.bin>\n", argv[0]); return 2; }
    const char *obj_path = argv[1];
    const char *corpus_path = argv[2];

    if (corpus_parse(corpus_path, &g_corpus) != 0) return 2;

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
    struct bpf_map *relay_map = bpf_object__find_map_by_name(obj, "relay_map");
    struct bpf_map *session_map = bpf_object__find_map_by_name(obj, "session_map");
    struct bpf_map *whitelist_map = bpf_object__find_map_by_name(obj, "whitelist_map");
    if (!config_map || !state_map || !stats_map || !relay_map || !session_map || !whitelist_map) {
        fprintf(stderr, "FAIL: find maps\n"); return 2;
    }
    config_fd = bpf_map__fd(config_map);
    state_fd = bpf_map__fd(state_map);
    stats_fd = bpf_map__fd(stats_map);
    relay_fd = bpf_map__fd(relay_map);
    session_fd = bpf_map__fd(session_map);
    whitelist_fd = bpf_map__fd(whitelist_map);

    ncpu = libbpf_num_possible_cpus();
    stats_buf = calloc(ncpu, RELAY_NUM_COUNTERS * sizeof(__u64));

    load_config_and_state();

    unsigned char frame[2048], out[2048];
    unsigned int mismatches = 0, checked = 0;
    unsigned int drops = 0, txs = 0, passes = 0;

    for (unsigned int i = 0; i < g_corpus.count; i++) {
        struct corpus_entry *e = &g_corpus.entries[i];

        reset_world_maps();

        int flen = build_frame(frame, e->from, e->from_port, e->to, e->to_port, e->packet, e->packet_len);

        // snapshot the counter we assert (and the three guard counters, needed for the
        // NOT_DROPPED_GUARDS assertion) so we can read the delta this run produced.
        __u64 want_before = 0;
        if (e->expected_counter != CORPUS_COUNTER_ANY && e->expected_counter != CORPUS_COUNTER_NOT_DROPPED_GUARDS)
            want_before = read_counter(e->expected_counter);
        __u64 size_before = read_counter(CORPUS_COUNTER_TOO_SMALL);
        __u64 basic_before = read_counter(CORPUS_COUNTER_BASIC);
        __u64 adv_before = read_counter(CORPUS_COUNTER_ADVANCED);

        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = frame, .data_size_in = flen,
                    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err) { fprintf(stderr, "FAIL: test_run entry %u err=%d\n", i, err); return 2; }

        int counter_ok = 1;
        if (e->expected_counter == CORPUS_COUNTER_NOT_DROPPED_GUARDS) {
            counter_ok = read_counter(CORPUS_COUNTER_TOO_SMALL) == size_before &&
                         read_counter(CORPUS_COUNTER_BASIC) == basic_before &&
                         read_counter(CORPUS_COUNTER_ADVANCED) == adv_before;
        } else if (e->expected_counter != CORPUS_COUNTER_ANY) {
            counter_ok = read_counter(e->expected_counter) > want_before;
        }

        int action_ok = corpus_action_ok(e->expected_action, opts.retval);

        checked++;
        if (opts.retval == CORPUS_ACTION_DROP) drops++;
        else if (opts.retval == CORPUS_ACTION_TX) txs++;
        else if (opts.retval == CORPUS_ACTION_PASS) passes++;

        if (!action_ok || !counter_ok) {
            if (mismatches < 30)
                fprintf(stderr, "MISMATCH entry %u [%s]: want action=%s counter=%u; got retval=%u action_ok=%d counter_ok=%d (len=%d type=0x%02x)\n",
                        i, e->label, action_name(e->expected_action), e->expected_counter,
                        opts.retval, action_ok, counter_ok, e->packet_len, e->packet[0]);
            mismatches++;
        }
    }

    printf("corpus differential: %u checked (%u drop, %u tx, %u pass), %u mismatches\n",
           checked, drops, txs, passes, mismatches);
    printf(mismatches == 0 ? "CORPUS DIFFERENTIAL: PASS\n" : "CORPUS DIFFERENTIAL: FAIL\n");
    corpus_free(&g_corpus);
    bpf_object__close(obj);
    return mismatches == 0 ? 0 : 1;
}
