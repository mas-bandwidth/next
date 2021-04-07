#pragma once

#include "console.hpp"

extern util::Console _console_;

// Log levels are excluded at compile time for performance reasons. Save every cpu cycle we can

#if RELAY_LOG_LEVEL >= 5 or defined LOG_ALL
#define LOG_TRACE(...)
// #define LOG_TRACE(...) 	_console_.log("trace ", __FILE__, " (", __LINE__, "): ", __VA_ARGS__)
#else
#define LOG_TRACE(...)
#endif

#if RELAY_LOG_LEVEL >= 4 or defined LOG_ALL
#define LOG_DEBUG(...)
// #define LOG_DEBUG(...) 	_console_.log("", __VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

#if RELAY_LOG_LEVEL >= 3 or defined LOG_ALL
#define LOG_INFO(...)   _console_.log("", __VA_ARGS__)
#else
#define LOG_INFO(...)
#endif

#if RELAY_LOG_LEVEL >= 2 or defined LOG_ALL
#define LOG_WARN(...)   _console_.log("warning: ", __VA_ARGS__)
#else
#define LOG_WARN(...)
#endif

#if RELAY_LOG_LEVEL >= 1 or defined LOG_ALL
#define LOG_ERROR(...) 	_console_.log("error: ", __VA_ARGS__)
#else
#define LOG_ERROR(...)
#endif

#if RELAY_LOG_LEVEL == 0 or defined LOG_ALL
#define LOG_FATAL(...) 	_console_.log("error: ", __VA_ARGS__); std::exit(1)
#else
#define LOG_FATAL(...) std::exit(1)
#endif

#define LOG(level, ...) LOG_##level(__VA_ARGS__)
