/*
    Userspace compatibility shim for relay_xdp.c.

    The relay datapath lives in ONE file, relay_xdp.c. Compiled with a BPF target it is
    the kernel XDP program; compiled with -DRELAY_USERSPACE and this header it is a plain
    userspace C function relay_xdp_filter() that processes one synthetic ETH/IP/UDP frame
    and returns an XDP verdict. This is what lets the XDP relay run in a non-XDP mode on
    mac / windows / CI, so there is a single relay source (see relay/CONSOLIDATION.md).

    This shim provides userspace stand-ins for everything relay_xdp.c gets from the kernel:
    the __uN types, the ethernet/ip/udp structs, struct xdp_md over a userspace buffer, the
    six BPF maps (as userspace array/hash maps), the bpf_map_* helpers, the packet resize
    helpers, and the two crypto kfuncs. See relay/CONSOLIDATION.md.
*/

#ifndef RELAY_USERSPACE_H
#define RELAY_USERSPACE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint16_t __be16;
typedef uint32_t __be32;

// integer type that round-trips ctx->data / ctx->data_end to a pointer. the bpf build
// uses long (64 bits there); userspace must use uintptr_t -- long is only 32 bits on
// win64 and would truncate pointers.
typedef uintptr_t relay_uptr_t;

// --- ethernet / ip / udp (Linux layout, provided here because mac/windows lack linux/*.h)

// guard the constants: on Linux some system headers (netinet/in.h) also define these, and
// we must not fight them. we deliberately do NOT include any system net header.
#ifndef ETH_ALEN
#define ETH_ALEN   6
#endif
#ifndef ETH_P_IP
#define ETH_P_IP   0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// byte order helpers, little-endian hosts only (the relay is LE-only). provided here so
// the shim needs no system header (arpa/inet.h drags in conflicting net definitions).
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __constant_htons(x) ((__be16)__builtin_bswap16(x))
static inline __u16 us_htons(__u16 x) { return __builtin_bswap16(x); }
static inline __u32 us_htonl(__u32 x) { return __builtin_bswap32(x); }
#else
#define __constant_htons(x) ((__be16)(x))
static inline __u16 us_htons(__u16 x) { return x; }
static inline __u32 us_htonl(__u32 x) { return x; }
#endif
#define us_ntohs us_htons
#define us_ntohl us_htonl

struct ethhdr {
	__u8  h_dest[ETH_ALEN];
	__u8  h_source[ETH_ALEN];
	__be16 h_proto;
} __attribute__((packed));

struct iphdr {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl : 4;
	__u8 version : 4;
#else
	__u8 version : 4;
	__u8 ihl : 4;
#endif
	__u8   tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8   ttl;
	__u8   protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed));

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

// --- xdp context over a userspace buffer. relay_xdp.c does (void*)(long)ctx->data, so
//     data / data_end are stored as integer addresses of the buffer.

struct xdp_md {
	__u64 data;
	__u64 data_end;
	__u64 data_meta;
	__u64 ingress_ifindex;
	__u64 rx_queue_index;
};

// XDP verdicts (uapi/linux/bpf.h)
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

// attributes / section markers that are BPF-only -- no-ops in userspace
#define SEC(x)
#ifndef __always_inline
#define __always_inline inline
#endif
#define __bpf_kfunc
#define __ksym

// LIBBPF_PIN_BY_NAME appears in the (ifdef'd out) BPF map decls; define harmlessly
#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

// --- userspace maps. relay_xdp.c's six BPF maps are declared here (its own decls are
//     compiled out under RELAY_USERSPACE) as userspace array/hash maps.

enum us_map_kind { US_MAP_ARRAY, US_MAP_HASH };

struct us_hash_entry {
	struct us_hash_entry *next;
	void *key;
	void *value;
};

struct us_map {
	enum us_map_kind kind;
	size_t key_size;
	size_t value_size;
	int    max_entries;
	// array storage (kind == US_MAP_ARRAY): max_entries * value_size, key is a u32 index
	void  *array;
	// hash storage (kind == US_MAP_HASH): a tiny chained hash table
	struct us_hash_entry **buckets;
	int    num_buckets;
	int    count;
};

void *bpf_map_lookup_elem(void *map, const void *key);
long  bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
long  bpf_map_delete_elem(void *map, const void *key);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

// key iteration over a hash map, mirroring bpf_map_get_next_key: NULL or missing key
// returns the first key, otherwise the key after it; -1 when there are no more.
// caller must hold the maps lock.
int us_map_get_next_key(struct us_map *m, const void *key, void *next_key);

// One lock serializes the datapath against the control plane. BPF maps are safe for
// concurrent kernel/userspace access; the shim maps are not, and the datapath also
// mutates map values through pointers AFTER lookup (BPF relies on RCU for that).
// So: the datapath thread holds the lock across each whole relay_xdp_filter() call,
// and control-plane code holds it around every map operation or iteration. The
// bpf_map_* functions themselves do NOT lock. Single-threaded harnesses (the corpus
// test) can ignore the lock entirely.
void us_maps_lock(void);
void us_maps_unlock(void);

// the six maps (backing storage defined in relay_userspace.c)
extern struct us_map config_map;
extern struct us_map state_map;
extern struct us_map stats_map;
extern struct us_map relay_map;
extern struct us_map session_map;
extern struct us_map whitelist_map;

// --- packet resize helpers. relay_xdp.c holds the ctx; these adjust ctx->data_end / data.
long bpf_xdp_adjust_tail(struct xdp_md *ctx, int delta);
long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta);

// --- crypto kfuncs, implemented with libsodium in relay_userspace.c (byte-exact with
//     the kernel module's kfuncs -- see the comment there). chacha20poly1305_crypto is
//     defined by relay_xdp.c; forward-declare it here (relay_userspace.c completes it
//     with the identical layout in its own translation unit).
struct chacha20poly1305_crypto;
int bpf_relay_sha256(void *data, int data__sz, void *output, int output__sz);
int bpf_relay_xchacha20poly1305_decrypt(void *data, int data__sz, struct chacha20poly1305_crypto *crypto);

// --- datapath debug print. In BPF builds relay_printf is bpf_printk gated on
//     RELAY_DEBUG; in userspace builds it is gated on RELAY_LOGS and prints one line
//     per call to stdout -- the functional tests poll these lines. relay_xdp.c skips
//     its own definition under RELAY_USERSPACE.
#ifndef relay_printf
#if RELAY_LOGS
void us_relay_printf(const char *format, ...);
#define relay_printf us_relay_printf
#else
#define relay_printf(...) do { } while (0)
#endif
#endif

#endif // RELAY_USERSPACE_H
