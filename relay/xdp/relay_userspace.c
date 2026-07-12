/*
    Userspace shim implementation for relay_xdp.c (see relay_userspace.h).

    Backing storage for the six maps, a small chained hash table, the bpf_map_* helpers,
    the packet resize helpers, and the crypto kfuncs (libsodium). Compiled only in
    userspace (non-BPF) builds of the relay.
*/

#include "relay_userspace.h"
#include "relay_constants.h"
#include "relay_shared.h"

#include <sodium.h>
#include <stdarg.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#endif

// --- backing storage for the six maps

static __u8 config_storage[sizeof(struct relay_config)];
static __u8 state_storage[sizeof(struct relay_state)];
static __u8 stats_storage[sizeof(struct relay_stats)];

#define RELAY_HASH_BUCKETS   ( MAX_RELAYS * 4 )
#define SESSION_HASH_BUCKETS ( MAX_SESSIONS * 2 )

static struct us_hash_entry *relay_buckets[RELAY_HASH_BUCKETS];
static struct us_hash_entry *session_buckets[SESSION_HASH_BUCKETS];
static struct us_hash_entry *whitelist_buckets[SESSION_HASH_BUCKETS];

struct us_map config_map = {
	.kind = US_MAP_ARRAY, .key_size = sizeof(__u32), .value_size = sizeof(struct relay_config),
	.max_entries = 1, .array = config_storage,
};
struct us_map state_map = {
	.kind = US_MAP_ARRAY, .key_size = sizeof(__u32), .value_size = sizeof(struct relay_state),
	.max_entries = 1, .array = state_storage,
};
struct us_map stats_map = {
	.kind = US_MAP_ARRAY, .key_size = sizeof(__u32), .value_size = sizeof(struct relay_stats),
	.max_entries = 1, .array = stats_storage,
};
struct us_map relay_map = {
	.kind = US_MAP_HASH, .key_size = sizeof(__u64), .value_size = sizeof(__u64),
	.max_entries = MAX_RELAYS * 2, .buckets = relay_buckets, .num_buckets = RELAY_HASH_BUCKETS,
};
struct us_map session_map = {
	.kind = US_MAP_HASH, .key_size = sizeof(struct session_key), .value_size = sizeof(struct session_data),
	.max_entries = MAX_SESSIONS * 2, .buckets = session_buckets, .num_buckets = SESSION_HASH_BUCKETS,
};
struct us_map whitelist_map = {
	.kind = US_MAP_HASH, .key_size = sizeof(struct whitelist_key), .value_size = sizeof(struct whitelist_value),
	.max_entries = MAX_SESSIONS * 2, .buckets = whitelist_buckets, .num_buckets = SESSION_HASH_BUCKETS,
};

// --- hash table (FNV-1a over the key bytes)

static size_t hash_key(struct us_map *m, const void *key) {
	const __u8 *p = (const __u8 *)key;
	__u64 h = 1469598103934665603ULL;
	for (size_t i = 0; i < m->key_size; i++) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return (size_t)(h % (__u64)m->num_buckets);
}

void *bpf_map_lookup_elem(void *map, const void *key) {
	struct us_map *m = (struct us_map *)map;
	if (m->kind == US_MAP_ARRAY) {
		__u32 index = *(const __u32 *)key;
		if ((int)index >= m->max_entries) return NULL;
		return (__u8 *)m->array + (size_t)index * m->value_size;
	}
	size_t b = hash_key(m, key);
	for (struct us_hash_entry *e = m->buckets[b]; e; e = e->next) {
		if (memcmp(e->key, key, m->key_size) == 0) return e->value;
	}
	return NULL;
}

long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags) {
	struct us_map *m = (struct us_map *)map;
	if (m->kind == US_MAP_ARRAY) {
		__u32 index = *(const __u32 *)key;
		if ((int)index >= m->max_entries) return -1;
		memcpy((__u8 *)m->array + (size_t)index * m->value_size, value, m->value_size);
		return 0;
	}
	size_t b = hash_key(m, key);
	for (struct us_hash_entry *e = m->buckets[b]; e; e = e->next) {
		if (memcmp(e->key, key, m->key_size) == 0) {
			if (flags == BPF_NOEXIST) return -1;
			memcpy(e->value, value, m->value_size);
			return 0;
		}
	}
	if (flags == BPF_EXIST) return -1;
	// NOTE: no LRU eviction, unlike the BPF LRU_HASH maps -- fine by design: the
	// userspace relay is a test/dev harness only, never production (relay/CONSOLIDATION.md).
	struct us_hash_entry *e = (struct us_hash_entry *)malloc(sizeof(*e));
	e->key = malloc(m->key_size);
	e->value = malloc(m->value_size);
	memcpy(e->key, key, m->key_size);
	memcpy(e->value, value, m->value_size);
	e->next = m->buckets[b];
	m->buckets[b] = e;
	m->count++;
	return 0;
}

long bpf_map_delete_elem(void *map, const void *key) {
	struct us_map *m = (struct us_map *)map;
	if (m->kind != US_MAP_HASH) return -1;
	size_t b = hash_key(m, key);
	struct us_hash_entry **pp = &m->buckets[b];
	while (*pp) {
		struct us_hash_entry *e = *pp;
		if (memcmp(e->key, key, m->key_size) == 0) {
			*pp = e->next;
			free(e->key);
			free(e->value);
			free(e);
			m->count--;
			return 0;
		}
		pp = &e->next;
	}
	return -1;
}

// --- packet resize: relay_xdp.c only ever shrinks the tail (adjust_tail with a negative
//     delta) or grows the head; move data_end / data accordingly.

long bpf_xdp_adjust_tail(struct xdp_md *ctx, int delta) {
	ctx->data_end = (__u64)((relay_uptr_t)ctx->data_end + delta);
	return 0;
}

long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta) {
	ctx->data = (__u64)((relay_uptr_t)ctx->data + delta);
	return 0;
}

// --- crypto kfuncs (libsodium).
//
// These are the userspace stand-ins for the two kfuncs the relay kernel module
// (relay/module/relay_module.c) exports to the BPF program, and they must be
// byte-exact with it:
//
//  - bpf_relay_sha256 is plain SHA-256 (kernel crypto API "sha256" there,
//    crypto_hash_sha256 here -- the same standard function).
//  - bpf_relay_xchacha20poly1305_decrypt is the standard XChaCha20-Poly1305 IETF
//    construction (HChaCha20 subkey, 4 zero bytes || nonce[16:24], AD = NULL/0,
//    16-byte tag appended, decrypt in place). The kernel module open-codes the same
//    construction the kernel's chacha20poly1305 library uses; libsodium's
//    crypto_aead_xchacha20poly1305_ietf_decrypt is byte-identical. Already proven
//    end-to-end in production: the Go backend encrypts route tokens with
//    golang.org/x/crypto chacha20poly1305.NewX and both the XDP relay (kernel
//    crypto) and the retired reference relay (libsodium) decrypted them.

// mirrors the definition in relay_xdp.c (nonce, then key). that definition lives in a
// separate translation unit, so the struct is completed here with the same layout.
struct chacha20poly1305_crypto {
	__u8 nonce[24];
	__u8 key[32];
};

int bpf_relay_sha256(void *data, int data__sz, void *output, int output__sz) {
	(void)output__sz;
	crypto_hash_sha256((unsigned char *)output, (const unsigned char *)data, (unsigned long long)data__sz);
	return 0;
}

int bpf_relay_xchacha20poly1305_decrypt(void *data, int data__sz, struct chacha20poly1305_crypto *crypto) {
	unsigned long long decrypted_len = 0;
	return crypto_aead_xchacha20poly1305_ietf_decrypt((unsigned char *)data, &decrypted_len, NULL,
	                                                  (const unsigned char *)data, (unsigned long long)data__sz,
	                                                  NULL, 0, crypto->nonce, crypto->key) == 0;
}

// --- maps lock (see relay_userspace.h for the locking discipline)

#ifdef _WIN32

static SRWLOCK us_maps_mutex = SRWLOCK_INIT;

void us_maps_lock(void) {
	AcquireSRWLockExclusive(&us_maps_mutex);
}

void us_maps_unlock(void) {
	ReleaseSRWLockExclusive(&us_maps_mutex);
}

#else // #ifdef _WIN32

static pthread_mutex_t us_maps_mutex = PTHREAD_MUTEX_INITIALIZER;

void us_maps_lock(void) {
	pthread_mutex_lock(&us_maps_mutex);
}

void us_maps_unlock(void) {
	pthread_mutex_unlock(&us_maps_mutex);
}

#endif // #ifdef _WIN32

// --- hash map key iteration (bpf_map_get_next_key semantics). NULL or missing key
//     yields the first key; iteration order is bucket order then chain order. deleting
//     the CURRENT key after fetching the next one is safe (the standard bpf idiom the
//     control plane uses for timeout sweeps).

static struct us_hash_entry *us_map_first(struct us_map *m, int start_bucket) {
	for (int b = start_bucket; b < m->num_buckets; b++) {
		if (m->buckets[b]) return m->buckets[b];
	}
	return NULL;
}

int us_map_get_next_key(struct us_map *m, const void *key, void *next_key) {
	if (m->kind != US_MAP_HASH) return -1;
	struct us_hash_entry *e = NULL;
	if (key == NULL) {
		e = us_map_first(m, 0);
	} else {
		size_t b = hash_key(m, key);
		struct us_hash_entry *cur = m->buckets[b];
		while (cur && memcmp(cur->key, key, m->key_size) != 0) cur = cur->next;
		if (!cur) {
			e = us_map_first(m, 0);
		} else if (cur->next) {
			e = cur->next;
		} else {
			e = us_map_first(m, (int)b + 1);
		}
	}
	if (!e) return -1;
	memcpy(next_key, e->key, m->key_size);
	return 0;
}

// --- datapath debug print for RELAY_LOGS builds (one line per call, so the functional
//     tests can poll stdout)

#if RELAY_LOGS
void us_relay_printf(const char *format, ...) {
	va_list args;
	va_start(args, format);
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	printf("%s\n", buffer);
}
#endif

// --- reset all maps between test runs
void us_maps_reset(void) {
	memset(config_storage, 0, sizeof(config_storage));
	memset(state_storage, 0, sizeof(state_storage));
	memset(stats_storage, 0, sizeof(stats_storage));
	struct us_map *hashes[] = { &relay_map, &session_map, &whitelist_map };
	for (int h = 0; h < 3; h++) {
		struct us_map *m = hashes[h];
		for (int b = 0; b < m->num_buckets; b++) {
			struct us_hash_entry *e = m->buckets[b];
			while (e) {
				struct us_hash_entry *next = e->next;
				free(e->key); free(e->value); free(e);
				e = next;
			}
			m->buckets[b] = NULL;
		}
		m->count = 0;
	}
}
