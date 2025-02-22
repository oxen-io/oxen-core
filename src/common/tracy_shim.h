#pragma once

// NOTE: We choose not to link to Tracy::TracyClient in CMake to avoid
// processing Tracy's cmake file and incurring any cost of incorporating that
// into our build step.
//
// Compiling with Tracy::TracyClient however is what gives us access to
// <tracy/Tracy.hpp> and related headers. In absence of that here we define the
// macros that we used from those headers to compile to nothing.
//
// This lets us build the project without linking to Tracy whilst preserving
// all the profiling markers and turning them into no-ops. When building with
// Tracy is enabled, TRACY_ENABLE is defined which allows us to use their
// headers and the correct definitions for their profiling markers.

#if defined(TRACY_ENABLE)
#include <tracy/TracyC.h>

#include <tracy/Tracy.hpp>
#else
#define ZoneScoped
#define ZoneScopedN(...)
#define TracyCZoneN(...)
#define TracyCZoneEnd(...)
#endif
