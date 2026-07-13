/*
    Network Next. Copyright 2017 - 2026 Network Next, Inc.
    Licensed under the Network Next Source Available License 1.0
*/

/*
    The standard serialize_* macros (serialize_int, serialize_bits, serialize_bool,
    serialize_float, serialize_double, serialize_uint8/16/32/64, serialize_bytes,
    serialize_string, serialize_align, serialize_object, ...) are provided by the
    vendored canonical serialize library via next_stream.h.

    This header only defines the SDK specific serialization helpers that are not part
    of the canonical library:

        - serialize_address (serializes a next_address_t)
*/

#ifndef NEXT_SERIALIZE_H
#define NEXT_SERIALIZE_H

#include "next.h"
#include "next_stream.h"
#include <string.h>

namespace next
{
template <typename Stream>
bool serialize_address_internal( Stream & stream, next_address_t & address )
{
    serialize_bits( stream, address.type, 2 );
    if ( address.type == NEXT_ADDRESS_IPV4 )
    {
        serialize_bytes( stream, address.data.ipv4, 4 );
        serialize_bits( stream, address.port, 16 );
    }
    else if ( address.type == NEXT_ADDRESS_IPV6 )
    {
        for ( int i = 0; i < 8; ++i )
        {
            serialize_bits( stream, address.data.ipv6[i], 16 );
        }
        serialize_bits( stream, address.port, 16 );
    }
    else
    {
        if ( Stream::IsReading )
        {
            memset( &address, 0, sizeof( next_address_t ) );
        }
    }
    return true;
}

#define serialize_address( stream, address )                        \
    do                                                              \
    {                                                               \
        if ( !next::serialize_address_internal( stream, address ) ) \
        {                                                           \
            return false;                                           \
        }                                                           \
    } while ( 0 )
}

#endif // #ifndef NEXT_SERIALIZE_H
