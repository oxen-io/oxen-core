#include "epee/int-util.h"

uint32_t rol32(uint32_t x, int r);
uint64_t rol64(uint64_t x, int r);
uint64_t hi_dword(uint64_t val);
uint64_t lo_dword(uint64_t val);
uint64_t div_with_remainder(uint64_t dividend, uint32_t divisor, uint32_t* remainder);
bool shl128(uint64_t* hi, uint64_t* lo);
uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi);
void div128_32(uint64_t dividend_hi, uint64_t dividend_lo, uint32_t divisor, uint64_t* quotient_hi, uint64_t* quotient_lo);
void div128_64(uint64_t dividend_hi, uint64_t dividend_lo, uint64_t divisor, uint64_t* quotient_hi, uint64_t* quotient_lo);
uint64_t mul128_div64(uint64_t a, uint64_t b, uint64_t c);
void memcpy_swap64le(void *dst, const void *src, size_t n);
