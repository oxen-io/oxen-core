// Copyright (c) 2017, SUMOKOIN
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2014-2017, The Monero Project
// Parts of this file are originally copyright (c) 2012-2013, The Cryptonote developers

#pragma once

#include <boost/align/aligned_alloc.hpp>
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86) || defined(_M_X64)
#define HAS_INTEL_HW
#elif defined(__aarch64__)
#define HAS_ARM_HW
#endif

#if defined(HAS_INTEL_HW) || defined(HAS_ARM_HW)
inline bool force_software_aes() {
    const char* env = getenv("OXEN_USE_SOFTWARE_AES");
    return env && strcmp(env, "0") && strcmp(env, "no");
}
#endif
extern "C" const bool cpu_aes_enabled;

// This cruft avoids casting-galore and allows us not to worry about sizeof(void*)
class cn_sptr {
  public:
    cn_sptr() : base_ptr(nullptr) {}
    cn_sptr(uint64_t* ptr) { base_ptr = ptr; }
    cn_sptr(uint32_t* ptr) { base_ptr = ptr; }
    cn_sptr(uint8_t* ptr) { base_ptr = ptr; }

    inline void set(void* ptr) { base_ptr = ptr; }
    inline cn_sptr offset(size_t i) { return reinterpret_cast<uint8_t*>(base_ptr) + i; }
    inline const cn_sptr offset(size_t i) const { return reinterpret_cast<uint8_t*>(base_ptr) + i; }

    inline void* as_void() { return base_ptr; }
    inline uint8_t& as_byte(size_t i) { return *(reinterpret_cast<uint8_t*>(base_ptr) + i); }
    inline uint8_t* as_byte() { return reinterpret_cast<uint8_t*>(base_ptr); }
    inline uint64_t& as_uqword(size_t i) { return *(reinterpret_cast<uint64_t*>(base_ptr) + i); }
    inline const uint64_t& as_uqword(size_t i) const {
        return *(reinterpret_cast<uint64_t*>(base_ptr) + i);
    }
    inline uint64_t* as_uqword() { return reinterpret_cast<uint64_t*>(base_ptr); }
    inline const uint64_t* as_uqword() const { return reinterpret_cast<uint64_t*>(base_ptr); }
    inline int64_t& as_qword(size_t i) { return *(reinterpret_cast<int64_t*>(base_ptr) + i); }
    inline int32_t& as_dword(size_t i) { return *(reinterpret_cast<int32_t*>(base_ptr) + i); }
    inline uint32_t& as_udword(size_t i) { return *(reinterpret_cast<uint32_t*>(base_ptr) + i); }
    inline const uint32_t& as_udword(size_t i) const {
        return *(reinterpret_cast<uint32_t*>(base_ptr) + i);
    }

  private:
    void* base_ptr;
};

template <size_t MEMORY, size_t ITER, size_t VERSION>
class cn_heavy_hash;
using cn_heavy_hash_v1 = cn_heavy_hash<2 * 1024 * 1024, 0x80000, 0>;
using cn_heavy_hash_v2 = cn_heavy_hash<4 * 1024 * 1024, 0x40000, 1>;

template <size_t MEMORY, size_t ITER, size_t VERSION>
class cn_heavy_hash {
  public:
    cn_heavy_hash() : borrowed_pad(false) {
        lpad.set(boost::alignment::aligned_alloc(4096, MEMORY));
        spad.set(boost::alignment::aligned_alloc(4096, 4096));
    }

    // Factory function enabling to temporaliy turn v2 object into v1
    // It is caller's responsibility to ensure that v2 object is not hashing at the same time!!
    static cn_heavy_hash_v1 make_borrowed(cn_heavy_hash_v2& t) {
        return {t.lpad.as_void(), t.spad.as_void()};
    }

    // Disable copy/move ctors; copying, in particular, is going to be really inefficient and we
    // don't need to move it anywhere in OXEN code anyway.
    cn_heavy_hash(const cn_heavy_hash& other) = delete;
    cn_heavy_hash(cn_heavy_hash&& other) = delete;
    cn_heavy_hash& operator=(const cn_heavy_hash& other) = delete;
    cn_heavy_hash& operator=(cn_heavy_hash&& other) = delete;

    ~cn_heavy_hash() { free_mem(); }

    void hash(const void* in, size_t len, void* out, bool prehashed = false) {
        if (cpu_aes_enabled)
            hardware_hash(in, len, out, prehashed);
        else
            software_hash(in, len, out, prehashed);
    }

    void software_hash(const void* in, size_t len, void* out, bool prehashed);

#if !defined(HAS_INTEL_HW) && !defined(HAS_ARM_HW)
    inline void hardware_hash(const void* in, size_t len, void* out, bool prehashed) {
        assert(false);
    }
#else
    void hardware_hash(const void* in, size_t len, void* out, bool prehashed);
#endif

  private:
    static constexpr size_t MASK = ((MEMORY - 1) >> 4) << 4;
    friend cn_heavy_hash_v1;
    friend cn_heavy_hash_v2;

    // Constructor enabling v1 hash to borrow v2's buffer
    cn_heavy_hash(void* lptr, void* sptr) {
        lpad.set(lptr);
        spad.set(sptr);
        borrowed_pad = true;
    }

    inline void free_mem() {
        if (!borrowed_pad) {
            if (lpad.as_void() != nullptr)
                boost::alignment::aligned_free(lpad.as_void());
            if (lpad.as_void() != nullptr)
                boost::alignment::aligned_free(spad.as_void());
        }

        lpad.set(nullptr);
        spad.set(nullptr);
    }

    inline cn_sptr scratchpad_ptr(uint32_t idx) { return lpad.as_byte() + (idx & MASK); }

#if !defined(HAS_INTEL_HW) && !defined(HAS_ARM_HW)
    inline void explode_scratchpad_hard() { assert(false); }
    inline void implode_scratchpad_hard() { assert(false); }
#else
    void explode_scratchpad_hard();
    void implode_scratchpad_hard();
#endif

    void explode_scratchpad_soft();
    void implode_scratchpad_soft();

    cn_sptr lpad;
    cn_sptr spad;
    bool borrowed_pad;
};

extern template class cn_heavy_hash<2 * 1024 * 1024, 0x80000, 0>;
extern template class cn_heavy_hash<4 * 1024 * 1024, 0x40000, 1>;
