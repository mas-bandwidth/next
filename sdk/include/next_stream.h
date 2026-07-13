/*
    Network Next. Copyright 2017 - 2026 Network Next, Inc.

    The stream classes and the standard serialize_* macros come from the vendored
    canonical serialize library (see next_bitpacker.h). This header just adapts the
    stream classes into the "next" namespace. SDK specific serialization is in
    next_serialize.h.
*/

#ifndef NEXT_STREAM_H
#define NEXT_STREAM_H

#include "next_bitpacker.h"

namespace next
{
using serialize::BaseStream;
using serialize::MeasureStream;
using serialize::ReadStream;
using serialize::WriteStream;
}

#endif // #ifndef NEXT_STREAM_H
