/*
    Network Next XDP Relay -- Windows platform layer.

    Compiled ONLY on Windows, in place of relay_platform.c, for the userspace-mode
    relay (dev/test only, never production -- see relay/CONSOLIDATION.md). Mirrors
    relay_platform.c function for function: winsock2 sockets, win32 threads and
    critical sections, QueryPerformanceCounter time.
*/

#ifdef _WIN32

#include "relay_platform.h"

#include <ws2tcpip.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment( lib, "ws2_32.lib" )

// -----------------------------------------------------------------------------------------------------------------------------------------------

static double time_frequency;
static LARGE_INTEGER time_start;

int relay_platform_init()
{
    WSADATA wsa_data;
    if ( WSAStartup( MAKEWORD(2,2), &wsa_data ) != 0 )
    {
        printf( "error: failed to initialize winsock\n" );
        return RELAY_ERROR;
    }

    LARGE_INTEGER frequency;
    QueryPerformanceFrequency( &frequency );
    time_frequency = (double) frequency.QuadPart;
    QueryPerformanceCounter( &time_start );

    int result = sodium_init();
    (void) result;

    return RELAY_OK;
}

double relay_platform_time()
{
    LARGE_INTEGER current;
    QueryPerformanceCounter( &current );
    return ( (double) ( current.QuadPart - time_start.QuadPart ) ) / time_frequency;
}

void relay_platform_sleep( double time )
{
    Sleep( (DWORD) ( time * 1000 ) );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

void relay_platform_random_bytes( uint8_t * buffer, int bytes )
{
    randombytes_buf( buffer, bytes );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

int relay_platform_parse_address( char * address_string, uint32_t * address, uint16_t * port )
{
    assert( address_string );
    assert( address );
    assert( port );

    *port = 0;

    int address_string_length = (int) strlen( address_string );

    int base_index = address_string_length - 1;

    for ( int i = 0; i < 6; ++i )
    {
        const int index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            *port = (uint16_t)( atoi( &address_string[index + 1] ) );
            address_string[index] = '\0';
        }
    }

    if ( inet_pton( AF_INET, address_string, address ) != 1 )
        return RELAY_ERROR;

    *address = ntohl( *address );

    return RELAY_OK;
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct relay_platform_socket_t * relay_platform_socket_create( uint32_t address, uint16_t port, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size )
{
    struct relay_platform_socket_t * s = (struct relay_platform_socket_t*) malloc( sizeof( struct relay_platform_socket_t ) );

    assert( s );

    // create socket

    s->type = socket_type;

    s->handle = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

    if ( s->handle == INVALID_SOCKET )
    {
        printf( "error: failed to create socket\n" );
        free( s );
        return NULL;
    }

    // increase socket send and receive buffer sizes

    if ( setsockopt( s->handle, SOL_SOCKET, SO_SNDBUF, (char*)( &send_buffer_size ), sizeof( int ) ) != 0 )
    {
        printf( "failed to set socket send buffer size to %d\n", send_buffer_size );
        relay_platform_socket_destroy( s );
        return NULL;
    }

    if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVBUF, (char*)( &receive_buffer_size ), sizeof( int ) ) != 0 )
    {
        printf( "failed to set socket receive buffer size to %d\n", receive_buffer_size );
        relay_platform_socket_destroy( s );
        return NULL;
    }

    // bind to port

    struct sockaddr_in socket_address;
    memset( &socket_address, 0, sizeof( socket_address ) );
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr.s_addr = htonl( address );
    socket_address.sin_port = htons( port );
    if ( bind( s->handle, (struct sockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
    {
        printf( "failed to bind socket\n" );
        relay_platform_socket_destroy( s );
        return NULL;
    }

    // set non-blocking io and receive timeout

    if ( socket_type == RELAY_PLATFORM_SOCKET_NON_BLOCKING )
    {
        u_long non_blocking = 1;
        if ( ioctlsocket( s->handle, FIONBIO, &non_blocking ) != 0 )
        {
            printf( "failed to set socket to non-blocking\n" );
            relay_platform_socket_destroy( s );
            return NULL;
        }
    }
    else if ( timeout_seconds > 0.0f )
    {
        // set receive timeout (windows takes milliseconds as a DWORD)
        DWORD tv = (DWORD) ( timeout_seconds * 1000.0f );
        if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof( tv ) ) < 0 )
        {
            printf( "failed to set socket receive timeout\n" );
            relay_platform_socket_destroy( s );
            return NULL;
        }
    }
    else
    {
        // socket is blocking with no timeout
    }

    return s;
}

void relay_platform_socket_destroy( struct relay_platform_socket_t * socket )
{
    assert( socket );
    if ( socket->handle != INVALID_SOCKET )
    {
        closesocket( socket->handle );
    }
    free( socket );
}

void relay_platform_socket_send_packet( struct relay_platform_socket_t * socket, uint32_t to_address, uint16_t to_port, const void * packet_data, int packet_bytes )
{
    assert( socket );
    assert( packet_data );
    assert( packet_bytes > 0 );

    struct sockaddr_in socket_address;
    memset( &socket_address, 0, sizeof( socket_address ) );
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr.s_addr = htonl( to_address );
    socket_address.sin_port = htons( to_port );

    sendto( socket->handle, (const char*)( packet_data ), packet_bytes, 0, (struct sockaddr*)( &socket_address ), sizeof(struct sockaddr_in) );
}

int relay_platform_socket_receive_packet( struct relay_platform_socket_t * socket, uint32_t * from_address, uint16_t * from_port, void * packet_data, int max_packet_size )
{
    assert( socket );
    assert( from_address );
    assert( from_port );
    assert( packet_data );
    assert( max_packet_size > 0 );

    struct sockaddr_storage sockaddr_from;
    memset( &sockaddr_from, 0, sizeof( sockaddr_from ) );

    int from_length = sizeof( sockaddr_from );

    int result = recvfrom( socket->handle, (char*) packet_data, max_packet_size, 0, (struct sockaddr*) &sockaddr_from, &from_length );
    if ( result == SOCKET_ERROR || result <= 0 )
        return 0;

    if ( sockaddr_from.ss_family == AF_INET )
    {
        struct sockaddr_in * addr_ipv4 = (struct sockaddr_in*) &sockaddr_from;
        *from_address = ntohl( addr_ipv4->sin_addr.s_addr );
        *from_port = ntohs( addr_ipv4->sin_port );
        return result;
    }

    return 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

// CreateThread wants DWORD WINAPI (*)(LPVOID); trampoline the posix-style thread function

struct thread_trampoline_t
{
    relay_platform_thread_func_t * thread_function;
    void * arg;
};

static DWORD WINAPI thread_trampoline( LPVOID context )
{
    struct thread_trampoline_t * trampoline = (struct thread_trampoline_t*) context;
    relay_platform_thread_func_t * thread_function = trampoline->thread_function;
    void * arg = trampoline->arg;
    free( trampoline );
    thread_function( arg );
    return 0;
}

struct relay_platform_thread_t * relay_platform_thread_create( relay_platform_thread_func_t * thread_function, void * arg )
{
    struct relay_platform_thread_t * thread = (struct relay_platform_thread_t*) malloc( sizeof( struct relay_platform_thread_t) );

    assert( thread );

    struct thread_trampoline_t * trampoline = (struct thread_trampoline_t*) malloc( sizeof( struct thread_trampoline_t ) );
    trampoline->thread_function = thread_function;
    trampoline->arg = arg;

    thread->handle = CreateThread( NULL, 0, thread_trampoline, trampoline, 0, NULL );

    if ( thread->handle == NULL )
    {
        free( trampoline );
        free( thread );
        return NULL;
    }

    return thread;
}

void relay_platform_thread_join( struct relay_platform_thread_t * thread )
{
    assert( thread );
    WaitForSingleObject( thread->handle, INFINITE );
}

void relay_platform_thread_destroy( struct relay_platform_thread_t * thread )
{
    assert( thread );
    CloseHandle( thread->handle );
    free( thread );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct relay_platform_mutex_t * relay_platform_mutex_create()
{
    struct relay_platform_mutex_t * mutex = (struct relay_platform_mutex_t*) malloc( sizeof(struct relay_platform_mutex_t) );

    assert( mutex );

    InitializeCriticalSection( &mutex->handle );

    return mutex;
}

void relay_platform_mutex_acquire( struct relay_platform_mutex_t * mutex )
{
    assert( mutex );
    EnterCriticalSection( &mutex->handle );
}

void relay_platform_mutex_release( struct relay_platform_mutex_t * mutex )
{
    assert( mutex );
    LeaveCriticalSection( &mutex->handle );
}

void relay_platform_mutex_destroy( struct relay_platform_mutex_t * mutex )
{
    assert( mutex );
    DeleteCriticalSection( &mutex->handle );
    free( mutex );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

#endif // #ifdef _WIN32
