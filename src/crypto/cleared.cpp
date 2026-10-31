#include "cleared.h"

#include <sodium/utils.h>

namespace crypto {

void sodium_zero_buffer(void* ptr, size_t size) {
    if (ptr)
        sodium_memzero(ptr, size);
}

}  // namespace crypto
