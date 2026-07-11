/*
    Network Next. Copyright 2017 - 2026 Network Next, Inc.

    This header vendors the canonical "serialize" library (sdk/serialize/serialize.h,
    https://github.com/mas-bandwidth/serialize) as the SDK's bitpacker and stream
    implementation, and adapts it into the "next" namespace. serialize.h is treated as
    canonical and is updated verbatim from upstream — do not edit it here. Any SDK
    specific serialization lives in next_serialize.h.
*/

#ifndef NEXT_BITPACKER_H
#define NEXT_BITPACKER_H

#include "next.h"

// route serialize's asserts through the SDK assert handler before including it

#ifndef serialize_assert
#define serialize_assert next_assert
#endif // #ifndef serialize_assert

#include "serialize.h"

namespace next
{
    using serialize::BitWriter;
    using serialize::BitReader;
}

#endif // #ifndef NEXT_BITPACKER_H
