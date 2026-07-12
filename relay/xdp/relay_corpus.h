/*
    Shared reader for the relay conformance corpus (v2), produced by
    modules/relaycorpus (cmd/relaycorpus_gen). Both differential drivers include this --
    relay_userspace_test.c (userspace datapath, mac + CI) and relay_corpus_diff.c (the
    real relay_xdp.o via BPF_PROG_RUN, CI). It decodes the file into plain structs; each
    driver loads the world into its own map representation and runs the entries.

    Format (little endian) is documented in modules/relaycorpus/corpus.go. This header is
    the C side of that contract -- keep the two in lockstep.
*/

#ifndef RELAY_CORPUS_H
#define RELAY_CORPUS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORPUS_VERSION 2

// XDP actions asserted per entry (0xFF = do not check)
#define CORPUS_ACTION_DROP 1
#define CORPUS_ACTION_PASS 2
#define CORPUS_ACTION_TX   3
#define CORPUS_ACTION_ANY  0xFF

// counter assertions (mirrors modules/relaycorpus)
#define CORPUS_COUNTER_ANY                 0xFFFF  // do not check a counter
#define CORPUS_COUNTER_NOT_DROPPED_GUARDS  0xFFFE  // assert no size/basic/advanced drop

// guard counter indices used to interpret CORPUS_COUNTER_NOT_DROPPED_GUARDS
#define CORPUS_COUNTER_BASIC     4
#define CORPUS_COUNTER_ADVANCED  5
#define CORPUS_COUNTER_TOO_SMALL 121

struct corpus_relay {
	uint8_t  address[4];
	uint16_t port;
};

struct corpus_whitelist {
	uint8_t  address[4];
	uint16_t port;
	uint64_t expire_timestamp;
};

struct corpus_session {
	uint64_t id;
	uint8_t  version;
	uint64_t expire_timestamp;
	uint8_t  private_key[32];
	uint64_t payload_client_to_server_sequence;
	uint64_t payload_server_to_client_sequence;
	uint64_t special_client_to_server_sequence;
	uint64_t special_server_to_client_sequence;
	uint8_t  next_address[4];
	uint16_t next_port;
	uint8_t  prev_address[4];
	uint16_t prev_port;
	uint8_t  next_internal;
	uint8_t  prev_internal;
	uint8_t  first_hop;
};

struct corpus_entry {
	char          label[256];
	uint8_t       expected_action;
	uint16_t      expected_counter;
	uint8_t       from[4];
	uint16_t      from_port;
	uint8_t       to[4];
	uint16_t      to_port;
	const uint8_t *packet;
	int           packet_len;
};

struct corpus {
	uint8_t  *raw; // owns the file buffer; entry packet pointers point into it

	uint64_t timestamp;
	uint8_t  current_magic[8];
	uint8_t  previous_magic[8];
	uint8_t  next_magic[8];
	uint8_t  relay_public_address[4];
	uint8_t  relay_internal_address[4];
	uint16_t relay_port;
	uint8_t  ping_key[32];
	uint8_t  secret_key[32];

	struct corpus_relay     *relays;
	int                      num_relays;
	struct corpus_whitelist *whitelist;
	int                      num_whitelist;
	struct corpus_session   *sessions;
	int                      num_sessions;

	struct corpus_entry *entries;
	unsigned int         count;
};

// little-endian readers over a moving cursor
static inline uint16_t corpus_rd_u16(const uint8_t **p) { uint16_t v = (*p)[0] | ((*p)[1] << 8); *p += 2; return v; }
static inline uint32_t corpus_rd_u32(const uint8_t **p) { uint32_t v = (uint32_t)(*p)[0] | ((uint32_t)(*p)[1] << 8) | ((uint32_t)(*p)[2] << 16) | ((uint32_t)(*p)[3] << 24); *p += 4; return v; }
static inline uint64_t corpus_rd_u64(const uint8_t **p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= ((uint64_t)(*p)[i]) << (8 * i); *p += 8; return v; }
static inline void     corpus_rd_bytes(const uint8_t **p, void *dst, int n) { memcpy(dst, *p, n); *p += n; }

// parse a corpus file into *c. returns 0 on success, non-zero on error. on success the
// caller owns c->raw / c->relays / c->whitelist / c->sessions / c->entries (free via
// corpus_free). the packet pointers in entries alias c->raw.
static inline int corpus_parse(const char *path, struct corpus *c) {
	memset(c, 0, sizeof(*c));

	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "FAIL: open corpus %s\n", path); return 1; }
	fseek(f, 0, SEEK_END);
	long fsz = ftell(f);
	fseek(f, 0, SEEK_SET);
	c->raw = (uint8_t *)malloc(fsz);
	if (!c->raw || fread(c->raw, 1, fsz, f) != (size_t)fsz) { fprintf(stderr, "FAIL: read corpus\n"); fclose(f); return 1; }
	fclose(f);

	const uint8_t *p = c->raw;
	if (memcmp(p, "RLYC", 4) != 0) { fprintf(stderr, "FAIL: bad corpus magic\n"); return 1; }
	p += 4;
	uint32_t version = corpus_rd_u32(&p);
	if (version != CORPUS_VERSION) { fprintf(stderr, "FAIL: corpus version %u, want %u\n", version, CORPUS_VERSION); return 1; }
	c->count = corpus_rd_u32(&p);

	c->timestamp = corpus_rd_u64(&p);
	corpus_rd_bytes(&p, c->current_magic, 8);
	corpus_rd_bytes(&p, c->previous_magic, 8);
	corpus_rd_bytes(&p, c->next_magic, 8);
	corpus_rd_bytes(&p, c->relay_public_address, 4);
	corpus_rd_bytes(&p, c->relay_internal_address, 4);
	c->relay_port = corpus_rd_u16(&p);
	corpus_rd_bytes(&p, c->ping_key, 32);
	corpus_rd_bytes(&p, c->secret_key, 32);

	c->num_relays = (int)corpus_rd_u32(&p);
	c->relays = (struct corpus_relay *)calloc(c->num_relays ? c->num_relays : 1, sizeof(struct corpus_relay));
	for (int i = 0; i < c->num_relays; i++) {
		corpus_rd_bytes(&p, c->relays[i].address, 4);
		c->relays[i].port = corpus_rd_u16(&p);
	}

	c->num_whitelist = (int)corpus_rd_u32(&p);
	c->whitelist = (struct corpus_whitelist *)calloc(c->num_whitelist ? c->num_whitelist : 1, sizeof(struct corpus_whitelist));
	for (int i = 0; i < c->num_whitelist; i++) {
		corpus_rd_bytes(&p, c->whitelist[i].address, 4);
		c->whitelist[i].port = corpus_rd_u16(&p);
		c->whitelist[i].expire_timestamp = corpus_rd_u64(&p);
	}

	c->num_sessions = (int)corpus_rd_u32(&p);
	c->sessions = (struct corpus_session *)calloc(c->num_sessions ? c->num_sessions : 1, sizeof(struct corpus_session));
	for (int i = 0; i < c->num_sessions; i++) {
		struct corpus_session *s = &c->sessions[i];
		s->id = corpus_rd_u64(&p);
		s->version = *p++;
		s->expire_timestamp = corpus_rd_u64(&p);
		corpus_rd_bytes(&p, s->private_key, 32);
		s->payload_client_to_server_sequence = corpus_rd_u64(&p);
		s->payload_server_to_client_sequence = corpus_rd_u64(&p);
		s->special_client_to_server_sequence = corpus_rd_u64(&p);
		s->special_server_to_client_sequence = corpus_rd_u64(&p);
		corpus_rd_bytes(&p, s->next_address, 4);
		s->next_port = corpus_rd_u16(&p);
		corpus_rd_bytes(&p, s->prev_address, 4);
		s->prev_port = corpus_rd_u16(&p);
		s->next_internal = *p++;
		s->prev_internal = *p++;
		s->first_hop = *p++;
	}

	c->entries = (struct corpus_entry *)calloc(c->count ? c->count : 1, sizeof(struct corpus_entry));
	for (unsigned int i = 0; i < c->count; i++) {
		struct corpus_entry *e = &c->entries[i];
		int label_len = *p++;
		int copy_len = label_len < 255 ? label_len : 255;
		memcpy(e->label, p, copy_len);
		e->label[copy_len] = 0;
		p += label_len;
		e->expected_action = *p++;
		e->expected_counter = corpus_rd_u16(&p);
		corpus_rd_bytes(&p, e->from, 4);
		e->from_port = corpus_rd_u16(&p);
		corpus_rd_bytes(&p, e->to, 4);
		e->to_port = corpus_rd_u16(&p);
		e->packet_len = corpus_rd_u16(&p);
		e->packet = p;
		p += e->packet_len;
	}

	return 0;
}

static inline void corpus_free(struct corpus *c) {
	free(c->relays);
	free(c->whitelist);
	free(c->sessions);
	free(c->entries);
	free(c->raw);
	memset(c, 0, sizeof(*c));
}

// classify a run: given the XDP return value and the deltas of the three guard counters,
// return the driver's observed (action, counter-ish) so it can be compared to the entry.
// action_ok checks the return value against the expectation (ANY always passes).
static inline int corpus_action_ok(uint8_t expected, int retval) {
	if (expected == CORPUS_ACTION_ANY) return 1;
	return retval == expected;
}

#endif // RELAY_CORPUS_H
