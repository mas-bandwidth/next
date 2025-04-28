/*
    Network Next. Copyright © 2017 - 2025 Network Next, Inc.
    
    Licensed under the Network Next Source Available License 1.0

    If you use this software with a game, you must add this to your credits:

    "This game uses Network Next (networknext.com)"
*/

#include "relay.h"

#ifndef RELAY_MAC_H
#define RELAY_MAC_H

#if RELAY_PLATFORM == RELAY_PLATFORM_MAC

#include <pthread.h>
#include <unistd.h>

#define RELAY_PLATFORM_HAS_IPV6                  1
#define RELAY_PLATFORM_SOCKET_NON_BLOCKING       0
#define RELAY_PLATFORM_SOCKET_BLOCKING           1

// -------------------------------------

typedef int relay_platform_socket_handle_t;

struct relay_platform_socket_t
{
    relay_platform_socket_handle_t handle;
};

// -------------------------------------

struct relay_platform_thread_t
{
    pthread_t handle;
};

typedef void * relay_platform_thread_return_t;

#define RELAY_PLATFORM_THREAD_RETURN() do { return NULL; } while ( 0 )

#define RELAY_PLATFORM_THREAD_FUNC

typedef relay_platform_thread_return_t (RELAY_PLATFORM_THREAD_FUNC relay_platform_thread_func_t)(void*);

// -------------------------------------

struct relay_platform_mutex_t
{
    pthread_mutex_t handle;
};

// -------------------------------------

#endif // #if RELAY_PLATFORM == RELAY_PLATFORM_MAC

#endif // #ifndef RELAY_MAC_H