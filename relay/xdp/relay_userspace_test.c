/*
    Local conformance test for the userspace build of relay_xdp.c.

    Fires the relaycorpus packet corpus at the userspace-compiled relay_xdp_filter() and
    checks every verdict against the oracle in the corpus file -- exactly what
    relay_corpus_diff.c does against the real relay_xdp.o via BPF_PROG_RUN in CI, but here
    the datapath runs as a plain function call, so it builds and runs on mac with no BPF.
    Zero mismatches proves the single datapath source behaves identically compiled as
    userspace. Usage: relay_userspace_test <corpus.bin>
*/

#include "relay_userspace.h"
#include "relay_constants.h"
#include "relay_shared.h"
#include <arpa/inet.h>

int relay_xdp_filter(struct xdp_md *ctx);
void us_maps_reset(void);

#define COUNTER_BASIC      4
#define COUNTER_ADVANCED   5
#define COUNTER_TOO_SMALL  121

#define V_DROP_BASIC 0
#define V_DROP_ADVANCED 1
#define V_PASS 2
#define V_DROP_SIZE 3

static const char *vname(int v) {
	switch (v) { case V_DROP_BASIC: return "drop-basic"; case V_DROP_ADVANCED: return "drop-advanced";
		case V_PASS: return "pass"; case V_DROP_SIZE: return "drop-size"; }
	return "?";
}

static int put_u32be(unsigned char *p, unsigned int v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; return 4; }
static int put_u16be(unsigned char *p, unsigned int v) { p[0]=v>>8; p[1]=v; return 2; }

static int build_frame(unsigned char *out, const unsigned char from[4], const unsigned char to[4],
                       unsigned short dport, const unsigned char *payload, int payload_len) {
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
	o += put_u16be(out + o, 12345);
	o += put_u16be(out + o, dport);
	o += put_u16be(out + o, 8 + payload_len);
	o += put_u16be(out + o, 0);
	if (payload_len > 0) { memcpy(out + o, payload, payload_len); o += payload_len; }
	return o;
}

static __u64 read_counter(int index) {
	int zero = 0;
	struct relay_stats *stats = (struct relay_stats *)bpf_map_lookup_elem(&stats_map, &zero);
	return stats ? stats->counters[index] : 0;
}

int main(int argc, char **argv) {
	if (argc < 2) { fprintf(stderr, "usage: %s <corpus.bin>\n", argv[0]); return 2; }

	FILE *f = fopen(argv[1], "rb");
	if (!f) { fprintf(stderr, "FAIL: open corpus\n"); return 2; }
	fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
	unsigned char *corpus = malloc(fsz);
	if (fread(corpus, 1, fsz, f) != (size_t)fsz) { fprintf(stderr, "FAIL: read\n"); return 2; }
	fclose(f);
	if (memcmp(corpus, "RLYC", 4) != 0) { fprintf(stderr, "FAIL: bad magic\n"); return 2; }
	unsigned int count = corpus[8] | (corpus[9]<<8) | (corpus[10]<<16) | (corpus[11]<<24);

	// config: relay at 127.0.0.1:40000, distinct internal address. corpus magic from entry 0.
	int zero = 0;
	struct relay_config config;
	memset(&config, 0, sizeof(config));
	config.relay_public_address = htonl(0x7f000001);
	config.relay_internal_address = htonl(0x0a010101);
	config.relay_port = htons(40000);
	bpf_map_update_elem(&config_map, &zero, &config, BPF_ANY);

	unsigned char *corpus_magic = corpus + 12 + 1 + 4 + 4;
	struct relay_state state;
	memset(&state, 0, sizeof(state));
	memcpy(state.current_magic, corpus_magic, 8);
	for (int i = 0; i < 8; i++) { state.previous_magic[i] = corpus_magic[i] ^ 0xAA; state.next_magic[i] = corpus_magic[i] ^ 0x55; }
	bpf_map_update_elem(&state_map, &zero, &state, BPF_ANY);

	unsigned char frame[2048];
	unsigned int mismatches = 0, checked = 0;
	unsigned int by_verdict[4] = {0,0,0,0};

	unsigned char *p = corpus + 12;
	for (unsigned int i = 0; i < count; i++) {
		int verdict = p[0];
		unsigned char from[4], to[4];
		memcpy(from, p + 1, 4);
		memcpy(to, p + 5, 4);
		int plen = p[17] | (p[18] << 8);
		unsigned char *packet = p + 19;
		p = packet + plen;

		int flen = build_frame(frame, from, to, 40000, packet, plen);

		// reset only the per-run counters (config/state persist); maps stay empty
		int z = 0;
		struct relay_stats *stats = (struct relay_stats *)bpf_map_lookup_elem(&stats_map, &z);
		memset(stats, 0, sizeof(*stats));

		struct xdp_md ctx;
		memset(&ctx, 0, sizeof(ctx));
		ctx.data = (__u64)(long)frame;
		ctx.data_end = (__u64)(long)(frame + flen);

		int retval = relay_xdp_filter(&ctx);

		__u64 size_d = read_counter(COUNTER_TOO_SMALL);
		__u64 basic_d = read_counter(COUNTER_BASIC);
		__u64 adv_d = read_counter(COUNTER_ADVANCED);

		int got;
		if (size_d > 0) got = V_DROP_SIZE;
		else if (basic_d > 0) got = V_DROP_BASIC;
		else if (adv_d > 0) got = V_DROP_ADVANCED;
		else got = V_PASS;
		(void)retval;

		checked++;
		if (verdict >= 0 && verdict < 4) by_verdict[verdict]++;

		if (got != verdict) {
			if (mismatches < 20)
				fprintf(stderr, "MISMATCH entry %u: corpus=%s userspace=%s (len=%d type=0x%02x)\n",
						i, vname(verdict), vname(got), plen, packet[0]);
			mismatches++;
		}
	}

	printf("userspace corpus: %u checked (%u drop-size, %u drop-basic, %u drop-advanced, %u pass), %u mismatches\n",
	       checked, by_verdict[V_DROP_SIZE], by_verdict[V_DROP_BASIC], by_verdict[V_DROP_ADVANCED], by_verdict[V_PASS], mismatches);
	printf(mismatches == 0 ? "USERSPACE CORPUS: PASS\n" : "USERSPACE CORPUS: FAIL\n");
	return mismatches == 0 ? 0 : 1;
}
