#pragma once

#ifdef __GNUC__
#define EXPORT __attribute__((visibility("default"))) __attribute__((used))
#else
#define EXPORT
#endif
