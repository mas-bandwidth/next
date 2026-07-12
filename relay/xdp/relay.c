/*
    Network Next XDP Relay.

    Runs on Ubuntu 22.04 LTS 64bit with Linux Kernel 6.5 *ONLY*

    Setup:

        sudo apt install -y build-essential libsodium-dev libcurl4-openssl-dev clang linux-headers-generic linux-headers-`uname -r` unzip libc6-dev-i386 gcc-12 dwarves libelf-dev pkg-config m4 libpcap-dev net-tools

        sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/

        wget https://github.com/xdp-project/xdp-tools/releases/download/v1.4.2/xdp-tools-1.4.2.tar.gz
        tar -zxf xdp-tools-1.4.2.tar.gz
        cd xdp-tools-1.4.2
        ./configure
        make -j && sudo make install
        cd lib/libbpf/src
        make -j && sudo make install
*/

#include "relay.h"
#include "relay_platform.h"
#include "relay_main.h"
#include "relay_ping.h"
#include "relay_config.h"

#ifdef RELAY_USERSPACE
// system net headers must precede relay_userspace.h (guarded stand-in macros)
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#else // #ifdef _WIN32
#include <arpa/inet.h>
#endif // #ifdef _WIN32
#include "relay_userspace.h"
#include "relay_shared.h"
#include "relay_constants.h"
#include <inttypes.h>
#include <stdlib.h>
#else // #ifdef RELAY_USERSPACE
#include "relay_bpf.h"
#include "relay_debug.h"
#endif // #ifdef RELAY_USERSPACE

#include <memory.h>
#include <stdio.h>
#include <sodium.h>
#include <signal.h>

static struct config_t config;
#ifndef RELAY_USERSPACE
static struct bpf_t bpf;
#endif // #ifndef RELAY_USERSPACE
#if RELAY_DEBUG
static struct debug_t debug;
#else // #if RELAY_DEBUG
static struct main_t main_data;
static struct ping_t ping;
#endif // #if RELAY_DEBUG

volatile bool quit;
volatile bool relay_clean_shutdown = false;

void interrupt_handler( int signal )
{
    (void) signal; quit = true;
}

void clean_shutdown_handler( int signal )
{
    (void) signal;
    relay_clean_shutdown = true;
    quit = true;
}

static void cleanup()
{
#if RELAY_DEBUG
    debug_shutdown( &debug );
#else // #if RELAY_DEBUG
    ping_shutdown( &ping );
    main_shutdown( &main_data );
#ifndef RELAY_USERSPACE
    bpf_shutdown( &bpf );
#endif // #ifndef RELAY_USERSPACE
#endif // #if RELAY_DEBUG
    fflush( stdout );
}

#ifndef RELAY_VERSION
#define RELAY_VERSION "relay-release"
#endif // #ifndef RELAY_VERSION

int main( int argc, char *argv[] )
{
#if RELAY_LOGS
    // IMPORTANT: stdout must be line buffered so the functional tests can poll relay
    // debug output through a pipe while the relay is running
    setvbuf( stdout, NULL, _IOLBF, 0 );
#endif // #if RELAY_LOGS

    relay_platform_init();

    printf( "Network Next Relay (%s)\n", RELAY_VERSION );

    fflush( stdout );

    signal( SIGINT,  interrupt_handler );
    signal( SIGTERM, clean_shutdown_handler );
#ifdef _WIN32
    signal( SIGBREAK, clean_shutdown_handler );    // no SIGHUP on windows; ctrl+break = clean shutdown
#else // #ifdef _WIN32
    signal( SIGHUP,  clean_shutdown_handler );
#endif // #ifdef _WIN32

    printf( "Reading config\n" );

    fflush( stdout );

    if ( read_config( &config ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    fflush( stdout );

#ifndef RELAY_USERSPACE

    printf( "Initializing BPF\n" );

    fflush( stdout );

    if ( bpf_init( &bpf, config.relay_public_address, config.relay_internal_address, config.relay_name ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    fflush( stdout );

#endif // #ifndef RELAY_USERSPACE

#if RELAY_DEBUG

    // debug relay

    printf( "Starting debug relay\n" );

    fflush( stdout );

    if ( debug_init( &debug, &config, &bpf ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    fflush( stdout );

    int result = debug_run( &debug );

#else // #if RELAY_DEBUG

    printf( "Starting relay\n" );

    fflush( stdout );

#ifdef RELAY_USERSPACE
    struct bpf_t * bpf_ptr = NULL; // userspace mode: the shim maps replace BPF
#else // #ifdef RELAY_USERSPACE
    struct bpf_t * bpf_ptr = &bpf;
#endif // #ifdef RELAY_USERSPACE

    if ( main_init( &main_data, &config, bpf_ptr ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    if ( ping_init( &ping, &config, &main_data, bpf_ptr ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    if ( ping_start_thread( &ping ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    int result = main_run( &main_data );

    ping_join_thread( &ping );

#if defined(RELAY_USERSPACE) && RELAY_TEST

    // print counters for the functional tests. safe to read without the maps lock:
    // the datapath thread has joined, so nothing else touches the maps now.

    if ( getenv( "RELAY_PRINT_COUNTERS" ) )
    {
        printf( "\n===========================================================================\n" );

        __u32 zero = 0;
        struct relay_stats * stats = (struct relay_stats*) bpf_map_lookup_elem( &stats_map, &zero );
        if ( stats )
        {
            // fold in the ping thread's totals, the same way main_update does for the
            // backend (they are counted outside the datapath's stats map)
            stats->counters[RELAY_COUNTER_RELAY_PING_PACKET_SENT] += ping.pings_sent;
            stats->counters[RELAY_COUNTER_PACKETS_SENT] += ping.pings_sent;
            stats->counters[RELAY_COUNTER_BYTES_SENT] += ping.bytes_sent;

            for ( int i = 0; i < RELAY_NUM_COUNTERS; i++ )
            {
                if ( stats->counters[i] != 0 )
                {
                    printf( "counter %d: %" PRId64 "\n", i, (int64_t) stats->counters[i] );
                }
            }
        }

        printf( "===========================================================================\n\n" );
    }

#endif // #if defined(RELAY_USERSPACE) && RELAY_TEST

#endif // #if RELAY_DEBUG

    cleanup();

    printf( "Done.\n" );

    fflush( stdout );

    return result;
}
