/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef NEXT_AUTODETECT_H
#define NEXT_AUTODETECT_H

#include "next.h"

void next_set_http_request_function( bool (*function)( const char * url, const char * header, char * output, size_t output_size ) );

bool next_autodetect_google( char * output_datacenter, size_t output_datacenter_size );

bool next_autodetect_amazon( char * output_datacenter, size_t output_datacenter_size );

bool next_autodetect_datacenter( const char * input_datacenter, const char * public_address, char * output_datacenter, size_t output_datacenter_size );

#endif // #ifndef NEXT_AUTODETECT_H
