/*
    Conformance test for the userspace build of relay_xdp.c.

    Loads the relaycorpus WORLD (relay config, state, and the relay/whitelist/session
    maps) into the shim maps, then fires every corpus entry at the userspace-compiled
    relay_xdp_filter() and checks the XDP return value and the expected counter against
    the corpus. The mutable maps are reset to the world before each entry, so entries
    are order-independent. This is the userspace half of the three-way differential --
    relay_corpus_diff.c does the same against the real relay_xdp.o via BPF_PROG_RUN, and
    both must agree with the Go oracle in modules/relaycorpus. Zero mismatches proves the
    single datapath source behaves identically compiled as userspace, through the
    stateful handlers (tokens, sessions, whitelist), not just the filters.

    Usage: relay_userspace_test <corpus.bin>
*/

#include "relay_userspace.h"
#include "relay_constants.h"
#include "relay_shared.h"
#include "relay_corpus.h"

#include <sodium.h>

int relay_xdp_filter(struct xdp_md *ctx);
void us_maps_reset(void);

// the shim's crypto must be byte-exact with the kernel module's kfuncs. sha256 is
// checked against the same known-answer vector relay_module.c checks at insmod;
// the xchacha decrypt is checked round-trip against libsodium's encrypt (proving
// the shim's wiring: nonce/key offsets, in-place decrypt, appended-tag length) and
// that a tampered ciphertext is rejected.
static int crypto_self_test(void) {
	// SHA-256("test") -- the same vector relay/module/relay_module.c verifies at init
	static const unsigned char sha256_test_digest[32] = {
		0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
		0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
	};
	unsigned char digest[32];
	bpf_relay_sha256((void *)"test", 4, digest, 32);
	if (memcmp(digest, sha256_test_digest, 32) != 0) {
		fprintf(stderr, "FAIL: sha256 known answer\n");
		return 1;
	}

	// xchacha20poly1305: libsodium encrypt -> shim decrypt (in place), then tamper -> reject.
	// layout matches relay_xdp.c's chacha20poly1305_crypto: nonce[24] then key[32].
	unsigned char nonce_and_key[24 + 32];
	for (int i = 0; i < 24; i++) nonce_and_key[i] = (unsigned char)(100 + i);
	for (int i = 0; i < 32; i++) nonce_and_key[24 + i] = (unsigned char)i;

	static const unsigned char plaintext[47] = "the relay datapath is one source, two backends";
	unsigned char buffer[sizeof(plaintext) + 16];
	unsigned long long ciphertext_len = 0;
	crypto_aead_xchacha20poly1305_ietf_encrypt(buffer, &ciphertext_len, plaintext, sizeof(plaintext),
	                                           NULL, 0, NULL, nonce_and_key, nonce_and_key + 24);
	if (ciphertext_len != sizeof(buffer)) {
		fprintf(stderr, "FAIL: xchacha encrypt length\n");
		return 1;
	}

	if (bpf_relay_xchacha20poly1305_decrypt(buffer, (int)ciphertext_len,
	                                        (struct chacha20poly1305_crypto *)nonce_and_key) != 1) {
		fprintf(stderr, "FAIL: xchacha decrypt rejected valid ciphertext\n");
		return 1;
	}
	if (memcmp(buffer, plaintext, sizeof(plaintext)) != 0) {
		fprintf(stderr, "FAIL: xchacha decrypt wrong plaintext\n");
		return 1;
	}

	crypto_aead_xchacha20poly1305_ietf_encrypt(buffer, &ciphertext_len, plaintext, sizeof(plaintext),
	                                           NULL, 0, NULL, nonce_and_key, nonce_and_key + 24);
	buffer[3] ^= 0x01;
	if (bpf_relay_xchacha20poly1305_decrypt(buffer, (int)ciphertext_len,
	                                        (struct chacha20poly1305_crypto *)nonce_and_key) != 0) {
		fprintf(stderr, "FAIL: xchacha decrypt accepted tampered ciphertext\n");
		return 1;
	}

	printf("crypto self test: PASS\n");
	return 0;
}

static int put_u16be(unsigned char *p, unsigned int v) { p[0]=v>>8; p[1]=v; return 2; }

static int build_frame(unsigned char *out, const unsigned char from[4], unsigned short sport,
                       const unsigned char to[4], unsigned short dport,
                       const unsigned char *payload, int payload_len) {
	int o = 0;
	memset(out + o, 0x11, 6); o += 6;
	memset(out + o, 0x22, 6); o += 6;
	o += put_u16be(out + o, 0x0800);
	out[o++] = 0x45; out[o++] = 0x00;
	o += put_u16be(out + o, 20 + 8 + payload_len);
	o += put_u16be(out + o, 0); o += put_u16be(out + o, 0);
	out[o++] = 64; out[o++] = 17;
	o += put_u16be(out + o, 0);
	out[o++] = from[0]; out[o++] = from[1]; out[o++] = from[2]; out[o++] = from[3];
	out[o++] = to[0];   out[o++] = to[1];   out[o++] = to[2];   out[o++] = to[3];
	o += put_u16be(out + o, sport);
	o += put_u16be(out + o, dport);
	o += put_u16be(out + o, 8 + payload_len);
	o += put_u16be(out + o, 0);
	if (payload_len > 0) { memcpy(out + o, payload, payload_len); o += payload_len; }
	return o;
}

// address helpers: the relay stores addresses/ports in maps in network order (see the
// datapath -- ip->saddr is htonl(quad), udp->source is htons(port)). match that so the
// preloaded maps key exactly the way the datapath looks them up.
static __u32 addr_quad(const __u8 a[4]) { return ((__u32)a[0] << 24) | ((__u32)a[1] << 16) | ((__u32)a[2] << 8) | a[3]; }
static __u32 net_addr(const __u8 a[4]) { return us_htonl(addr_quad(a)); }

static struct corpus g_corpus;

// load the immutable relay config + state from the world (done once).
static void load_config_and_state(void) {
	int zero = 0;

	struct relay_config config;
	memset(&config, 0, sizeof(config));
	config.relay_public_address = net_addr(g_corpus.relay_public_address);
	config.relay_internal_address = net_addr(g_corpus.relay_internal_address);
	config.relay_port = us_htons(g_corpus.relay_port);
	memcpy(config.relay_secret_key, g_corpus.secret_key, RELAY_SECRET_KEY_BYTES);
	bpf_map_update_elem(&config_map, &zero, &config, BPF_ANY);

	struct relay_state state;
	memset(&state, 0, sizeof(state));
	state.current_timestamp = g_corpus.timestamp;
	memcpy(state.current_magic, g_corpus.current_magic, 8);
	memcpy(state.previous_magic, g_corpus.previous_magic, 8);
	memcpy(state.next_magic, g_corpus.next_magic, 8);
	memcpy(state.ping_key, g_corpus.ping_key, RELAY_PING_KEY_BYTES);
	bpf_map_update_elem(&state_map, &zero, &state, BPF_ANY);
}

// reset the mutable maps (relay / whitelist / session) to the world. handlers create
// and delete entries, so this runs before every corpus entry to isolate them.
static void reset_world_maps(void) {
	us_maps_reset();
	load_config_and_state();

	for (int i = 0; i < g_corpus.num_relays; i++) {
		__u64 key = (((__u64)net_addr(g_corpus.relays[i].address)) << 32) | us_htons(g_corpus.relays[i].port);
		__u64 value = 1;
		bpf_map_update_elem(&relay_map, &key, &value, BPF_ANY);
	}

	for (int i = 0; i < g_corpus.num_whitelist; i++) {
		struct whitelist_key key;
		memset(&key, 0, sizeof(key));
		key.address = net_addr(g_corpus.whitelist[i].address);
		key.port = us_htons(g_corpus.whitelist[i].port);
		struct whitelist_value value;
		memset(&value, 0, sizeof(value));
		value.expire_timestamp = g_corpus.whitelist[i].expire_timestamp;
		bpf_map_update_elem(&whitelist_map, &key, &value, BPF_ANY);
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
		value.next_port = us_htons(cs->next_port);
		value.prev_port = us_htons(cs->prev_port);
		value.session_version = cs->version;
		value.next_internal = cs->next_internal;
		value.prev_internal = cs->prev_internal;
		value.first_hop = cs->first_hop;
		bpf_map_update_elem(&session_map, &key, &value, BPF_ANY);
	}
}

static __u64 read_counter(int index) {
	int zero = 0;
	struct relay_stats *stats = (struct relay_stats *)bpf_map_lookup_elem(&stats_map, &zero);
	return stats ? stats->counters[index] : 0;
}

static const char *action_name(int a) {
	switch (a) { case CORPUS_ACTION_DROP: return "DROP"; case CORPUS_ACTION_PASS: return "PASS";
		case CORPUS_ACTION_TX: return "TX"; case CORPUS_ACTION_ANY: return "ANY"; }
	return "?";
}

int main(int argc, char **argv) {
	if (argc < 2) { fprintf(stderr, "usage: %s <corpus.bin>\n", argv[0]); return 2; }

	if (sodium_init() == -1) { fprintf(stderr, "FAIL: sodium_init\n"); return 2; }
	if (crypto_self_test() != 0) return 1;

	if (corpus_parse(argv[1], &g_corpus) != 0) return 2;

	unsigned char frame[2048];
	unsigned int mismatches = 0, checked = 0;
	unsigned int drops = 0, txs = 0, passes = 0;

	for (unsigned int i = 0; i < g_corpus.count; i++) {
		struct corpus_entry *e = &g_corpus.entries[i];

		reset_world_maps();

		int flen = build_frame(frame, e->from, e->from_port, e->to, e->to_port, e->packet, e->packet_len);

		struct xdp_md ctx;
		memset(&ctx, 0, sizeof(ctx));
		ctx.data = (__u64)(relay_uptr_t)frame;
		ctx.data_end = (__u64)(relay_uptr_t)(frame + flen);

		int retval = relay_xdp_filter(&ctx);

		// counter check
		int counter_ok = 1;
		if (e->expected_counter == CORPUS_COUNTER_NOT_DROPPED_GUARDS) {
			counter_ok = read_counter(CORPUS_COUNTER_TOO_SMALL) == 0 &&
			             read_counter(CORPUS_COUNTER_BASIC) == 0 &&
			             read_counter(CORPUS_COUNTER_ADVANCED) == 0;
		} else if (e->expected_counter != CORPUS_COUNTER_ANY) {
			counter_ok = read_counter(e->expected_counter) > 0;
		}

		int action_ok = corpus_action_ok(e->expected_action, retval);

		checked++;
		if (retval == CORPUS_ACTION_DROP) drops++;
		else if (retval == CORPUS_ACTION_TX) txs++;
		else if (retval == CORPUS_ACTION_PASS) passes++;

		if (!action_ok || !counter_ok) {
			if (mismatches < 30)
				fprintf(stderr, "MISMATCH entry %u [%s]: want action=%s counter=%u; got retval=%d action_ok=%d counter_ok=%d (len=%d type=0x%02x)\n",
						i, e->label, action_name(e->expected_action), e->expected_counter,
						retval, action_ok, counter_ok, e->packet_len, e->packet[0]);
			mismatches++;
		}
	}

	printf("userspace corpus: %u checked (%u drop, %u tx, %u pass), %u mismatches\n",
	       checked, drops, txs, passes, mismatches);
	printf(mismatches == 0 ? "USERSPACE CORPUS: PASS\n" : "USERSPACE CORPUS: FAIL\n");
	corpus_free(&g_corpus);
	return mismatches == 0 ? 0 : 1;
}
