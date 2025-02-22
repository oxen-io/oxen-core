// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

#include "rctSigs.h"

#include "bulletproofs.h"
#include "common/threadpool.h"
#include "common/util.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "epee/misc_log_ex.h"

namespace rct {
static auto logcat = log::Cat("ringct");

static rct::Bulletproof make_dummy_bulletproof(
        const std::vector<uint64_t>& outamounts, rct::keyV& C, rct::keyV& masks) {
    const size_t n_outs = outamounts.size();
    const rct::key I = rct::identity();
    size_t nrl = 0;
    while ((1u << nrl) < n_outs)
        ++nrl;
    nrl += 6;

    C.resize(n_outs);
    masks.resize(n_outs);
    for (size_t i = 0; i < n_outs; ++i) {
        masks[i] = I;
        rct::key sv8, sv;
        sv = rct::zero();
        sv.bytes[0] = outamounts[i] & 255;
        sv.bytes[1] = (outamounts[i] >> 8) & 255;
        sv.bytes[2] = (outamounts[i] >> 16) & 255;
        sv.bytes[3] = (outamounts[i] >> 24) & 255;
        sv.bytes[4] = (outamounts[i] >> 32) & 255;
        sv.bytes[5] = (outamounts[i] >> 40) & 255;
        sv.bytes[6] = (outamounts[i] >> 48) & 255;
        sv.bytes[7] = (outamounts[i] >> 56) & 255;
        sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
        rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
    }

    return rct::Bulletproof{
            rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I), I, I, I};
}

Bulletproof proveRangeBulletproof(
        keyV& C,
        keyV& masks,
        const std::vector<uint64_t>& amounts,
        epee::span<const key> sk,
        hw::device& hwdev) {
    CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
    masks.resize(amounts.size());
    for (size_t i = 0; i < masks.size(); ++i)
        masks[i] = hwdev.genCommitmentMask(sk[i]);
    Bulletproof proof = bulletproof_PROVE(amounts, masks);
    CHECK_AND_ASSERT_THROW_MES(
            proof.V.size() == amounts.size(), "V does not have the expected size");
    C = proof.V;
    return proof;
}

bool verBulletproof(const Bulletproof& proof) {
    try {
        return bulletproof_VERIFY(proof);
    }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (...) {
        return false;
    }
}

bool verBulletproof(const std::vector<const Bulletproof*>& proofs) {
    try {
        return bulletproof_VERIFY(proofs);
    }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (...) {
        return false;
    }
}

// Borromean (c.f. gmax/andytoshi's paper)
bool verifyBorromean(const boroSig& bb, const ge_p3 P1[64], const ge_p3 P2[64]) {
    key64 Lv1;
    key chash, LL;
    int ii = 0;
    ge_p2 p2;
    for (ii = 0; ii < 64; ii++) {
        // equivalent of: addKeys2(LL, bb.s0[ii], bb.ee, P1[ii]);
        ge_double_scalarmult_base_vartime(&p2, bb.ee.bytes, &P1[ii], bb.s0[ii].bytes);
        ge_tobytes(LL.bytes, &p2);
        chash = hash_to_scalar(LL);
        // equivalent of: addKeys2(Lv1[ii], bb.s1[ii], chash, P2[ii]);
        ge_double_scalarmult_base_vartime(&p2, chash.bytes, &P2[ii], bb.s1[ii].bytes);
        ge_tobytes(Lv1[ii].bytes, &p2);
    }
    key eeComputed = hash_to_scalar(Lv1);  // hash function fine
    return equalKeys(eeComputed, bb.ee);
}

bool verifyBorromean(const boroSig& bb, const key64 P1, const key64 P2) {
    ge_p3 P1_p3[64], P2_p3[64];
    for (size_t i = 0; i < 64; ++i) {
        if (ge_frombytes_vartime(&P1_p3[i], P1[i].bytes) != 0 ||
            ge_frombytes_vartime(&P2_p3[i], P2[i].bytes) != 0) {
            log::info(log::Cat("verify"), "point conv failed");
            return false;
        }
    }
    return verifyBorromean(bb, P1_p3, P2_p3);
}

// Generate a CLSAG signature
// See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
//
// The keys are set as follows:
//   P[l] == p*G
//   C[l] == z*G
//   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
clsag CLSAG_Gen(
        const key& message,
        const keyV& P,
        const key& p,
        const keyV& C,
        const key& z,
        const keyV& C_nonzero,
        const key& C_offset,
        const unsigned int l,
        const multisig_kLRki* kLRki,
        key* mscout,
        key* mspout,
        hw::device& hwdev) {
    clsag sig;
    size_t n = P.size();  // ring size
    CHECK_AND_ASSERT_THROW_MES(
            n == C.size(), "Signing and commitment key vector sizes must match!");
    CHECK_AND_ASSERT_THROW_MES(
            n == C_nonzero.size(), "Signing and commitment key vector sizes must match!");
    CHECK_AND_ASSERT_THROW_MES(l < n, "Signing index out of range!");
    CHECK_AND_ASSERT_THROW_MES(
            (kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");
    CHECK_AND_ASSERT_THROW_MES(
            (mscout && mspout) || !kLRki, "Multisig pointers are not all present");

    // Key images
    ge_p3 H_p3;
    hash_to_p3(H_p3, P[l]);
    key H;
    ge_p3_tobytes(H.bytes, &H_p3);

    key D;

    // Initial values
    key a;
    key aG;
    key aH;

    // Multisig
    if (kLRki) {
        sig.I = kLRki->ki;
        scalarmultKey(D, H, z);
    } else {
        hwdev.clsag_prepare(p, z, sig.I, D, H, a, aG, aH);
    }

    geDsmp I_precomp;
    geDsmp D_precomp;
    precomp(I_precomp.k, sig.I);
    precomp(D_precomp.k, D);

    // Offset key image
    scalarmultKey(sig.D, D, INV_EIGHT);

    // Aggregation hashes
    keyV mu_P_to_hash(2 * n + 4);  // domain, I, D, P, C, C_offset
    keyV mu_C_to_hash(2 * n + 4);  // domain, I, D, P, C, C_offset
    sc_0(mu_P_to_hash[0].bytes);
    memcpy(mu_P_to_hash[0].bytes,
           cryptonote::hashkey::CLSAG_AGG_0.data(),
           cryptonote::hashkey::CLSAG_AGG_0.size());
    sc_0(mu_C_to_hash[0].bytes);
    memcpy(mu_C_to_hash[0].bytes,
           cryptonote::hashkey::CLSAG_AGG_1.data(),
           cryptonote::hashkey::CLSAG_AGG_1.size());
    for (size_t i = 1; i < n + 1; ++i) {
        mu_P_to_hash[i] = P[i - 1];
        mu_C_to_hash[i] = P[i - 1];
    }
    for (size_t i = n + 1; i < 2 * n + 1; ++i) {
        mu_P_to_hash[i] = C_nonzero[i - n - 1];
        mu_C_to_hash[i] = C_nonzero[i - n - 1];
    }
    mu_P_to_hash[2 * n + 1] = sig.I;
    mu_P_to_hash[2 * n + 2] = sig.D;
    mu_P_to_hash[2 * n + 3] = C_offset;
    mu_C_to_hash[2 * n + 1] = sig.I;
    mu_C_to_hash[2 * n + 2] = sig.D;
    mu_C_to_hash[2 * n + 3] = C_offset;
    key mu_P, mu_C;
    mu_P = hash_to_scalar(mu_P_to_hash);
    mu_C = hash_to_scalar(mu_C_to_hash);

    // Initial commitment
    keyV c_to_hash(2 * n + 5);  // domain, P, C, C_offset, message, aG, aH
    key c;
    sc_0(c_to_hash[0].bytes);
    memcpy(c_to_hash[0].bytes,
           cryptonote::hashkey::CLSAG_ROUND.data(),
           cryptonote::hashkey::CLSAG_ROUND.size());
    for (size_t i = 1; i < n + 1; ++i) {
        c_to_hash[i] = P[i - 1];
        c_to_hash[i + n] = C_nonzero[i - 1];
    }
    c_to_hash[2 * n + 1] = C_offset;
    c_to_hash[2 * n + 2] = message;

    // Multisig data is present
    if (kLRki) {
        a = kLRki->k;
        c_to_hash[2 * n + 3] = kLRki->L;
        c_to_hash[2 * n + 4] = kLRki->R;
    } else {
        c_to_hash[2 * n + 3] = aG;
        c_to_hash[2 * n + 4] = aH;
    }
    hwdev.clsag_hash(c_to_hash, c);

    size_t i;
    i = (l + 1) % n;
    if (i == 0)
        copy(sig.c1, c);

    // Decoy indices
    sig.s = keyV(n);
    key c_new;
    key L;
    key R;
    key c_p;  // = c[i]*mu_P
    key c_c;  // = c[i]*mu_C
    geDsmp P_precomp;
    geDsmp C_precomp;
    geDsmp H_precomp;
    ge_p3 Hi_p3;

    while (i != l) {
        sig.s[i] = skGen();
        sc_0(c_new.bytes);
        sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
        sc_mul(c_c.bytes, mu_C.bytes, c.bytes);

        // Precompute points
        precomp(P_precomp.k, P[i]);
        precomp(C_precomp.k, C[i]);

        // Compute L
        addKeys_aGbBcC(L, sig.s[i], c_p, P_precomp.k, c_c, C_precomp.k);

        // Compute R
        hash_to_p3(Hi_p3, P[i]);
        ge_dsm_precomp(H_precomp.k, &Hi_p3);
        addKeys_aAbBcC(R, sig.s[i], H_precomp.k, c_p, I_precomp.k, c_c, D_precomp.k);

        c_to_hash[2 * n + 3] = L;
        c_to_hash[2 * n + 4] = R;
        hwdev.clsag_hash(c_to_hash, c_new);
        copy(c, c_new);

        i = (i + 1) % n;
        if (i == 0)
            copy(sig.c1, c);
    }

    // Compute final scalar
    hwdev.clsag_sign(c, a, p, z, mu_P, mu_C, sig.s[l]);
    memwipe(&a, sizeof(key));

    if (mscout)
        *mscout = c;
    if (mspout)
        *mspout = mu_P;

    return sig;
}

clsag CLSAG_Gen(
        const key& message,
        const keyV& P,
        const key& p,
        const keyV& C,
        const key& z,
        const keyV& C_nonzero,
        const key& C_offset,
        const unsigned int l) {
    return CLSAG_Gen(
            message,
            P,
            p,
            C,
            z,
            C_nonzero,
            C_offset,
            l,
            NULL,
            NULL,
            NULL,
            hw::get_device("default"));
}

// MLSAG signatures
// See paper by Noether (https://eprint.iacr.org/2015/1098)
// This generalization allows for some dimensions not to require linkability;
//   this is used in practice for commitment data within signatures
// Note that using more than one linkable dimension is not recommended.
bool MLSAG_Ver(const key& message, const keyM& pk, const mgSig& rv, size_t dsRows) {
    size_t cols = pk.size();
    CHECK_AND_ASSERT_MES(cols >= 2, false, "Signature must contain more than one public key");
    size_t rows = pk[0].size();
    CHECK_AND_ASSERT_MES(rows >= 1, false, "Bad total row number");
    for (size_t i = 1; i < cols; ++i) {
        CHECK_AND_ASSERT_MES(pk[i].size() == rows, false, "Bad public key matrix dimensions");
    }
    CHECK_AND_ASSERT_MES(rv.II.size() == dsRows, false, "Wrong number of key images present");
    CHECK_AND_ASSERT_MES(rv.ss.size() == cols, false, "Bad scalar matrix dimensions");
    for (size_t i = 0; i < cols; ++i) {
        CHECK_AND_ASSERT_MES(rv.ss[i].size() == rows, false, "Bad scalar matrix dimensions");
    }
    CHECK_AND_ASSERT_MES(dsRows <= rows, false, "Non-double-spend rows cannot exceed total rows");

    for (size_t i = 0; i < rv.ss.size(); ++i) {
        for (size_t j = 0; j < rv.ss[i].size(); ++j) {
            CHECK_AND_ASSERT_MES(sc_check(rv.ss[i][j].bytes) == 0, false, "Bad signature scalar");
        }
    }
    CHECK_AND_ASSERT_MES(sc_check(rv.cc.bytes) == 0, false, "Bad initial signature hash");

    size_t i = 0, j = 0, ii = 0;
    key c, L, R;
    key c_old = copy(rv.cc);
    std::vector<geDsmp> Ip(dsRows);
    for (i = 0; i < dsRows; i++) {
        CHECK_AND_ASSERT_MES(!(rv.II[i] == rct::identity()), false, "Bad key image");
        precomp(Ip[i].k, rv.II[i]);
    }
    size_t ndsRows = 3 * dsRows;  // number of dimensions not requiring linkability
    keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
    toHash[0] = message;
    i = 0;
    while (i < cols) {
        sc_0(c.bytes);
        for (j = 0; j < dsRows; j++) {
            addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);

            // Compute R directly
            ge_p3 hash8_p3;
            hash_to_p3(hash8_p3, pk[i][j]);
            ge_p2 R_p2;
            ge_double_scalarmult_precomp_vartime(
                    &R_p2, rv.ss[i][j].bytes, &hash8_p3, c_old.bytes, Ip[j].k);
            ge_tobytes(R.bytes, &R_p2);

            toHash[3 * j + 1] = pk[i][j];
            toHash[3 * j + 2] = L;
            toHash[3 * j + 3] = R;
        }
        for (j = dsRows, ii = 0; j < rows; j++, ii++) {
            addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
            toHash[ndsRows + 2 * ii + 1] = pk[i][j];
            toHash[ndsRows + 2 * ii + 2] = L;
        }
        c = hash_to_scalar(toHash);
        CHECK_AND_ASSERT_MES(!(c == rct::zero()), false, "Bad signature hash");
        copy(c_old, c);
        i = (i + 1);
    }
    sc_sub(c.bytes, c_old.bytes, rv.cc.bytes);
    return sc_isnonzero(c.bytes) == 0;
}

// proveRange and verRange
// proveRange gives C, and mask such that \sumCi = C
//    c.f. https://eprint.iacr.org/2015/1098 section 5.1
//    and Ci is a commitment to either 0 or 2^i, i=0,...,63
//    thus this proves that "amount" is in [0, 2^64]
//    mask is a such that C = aG + bH, and b = amount
// verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
bool verRange(const key& C, const rangeSig& as) {
    try {
        ge_p3 CiH[64], asCi[64];
        int i = 0;
        ge_p3 Ctmp_p3 = ge_p3_identity;
        for (i = 0; i < 64; i++) {
            // faster equivalent of:
            // subKeys(CiH[i], as.Ci[i], H2[i]);
            // addKeys(Ctmp, Ctmp, as.Ci[i]);
            ge_cached cached;
            ge_p3 p3;
            ge_p1p1 p1;
            if (ge_frombytes_vartime(&p3, H2[i].bytes) != 0) {
                log::info(log::Cat("verify"), "point conv failed");
                return false;
            }
            ge_p3_to_cached(&cached, &p3);
            if (ge_frombytes_vartime(&asCi[i], as.Ci[i].bytes) != 0) {
                log::info(log::Cat("verify"), "point conv failed");
                return false;
            }
            ge_sub(&p1, &asCi[i], &cached);
            ge_p3_to_cached(&cached, &asCi[i]);
            ge_p1p1_to_p3(&CiH[i], &p1);
            ge_add(&p1, &Ctmp_p3, &cached);
            ge_p1p1_to_p3(&Ctmp_p3, &p1);
        }
        key Ctmp;
        ge_p3_tobytes(Ctmp.bytes, &Ctmp_p3);
        if (!equalKeys(C, Ctmp))
            return false;
        if (!verifyBorromean(as.asig, asCi, CiH))
            return false;
        return true;
    }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (...) {
        return false;
    }
}

key get_pre_clsag_hash(const rctSig& rv, hw::device& hwdev) {
    keyV hashes;
    hashes.reserve(3);
    hashes.push_back(rv.message);
    crypto::hash h;

    CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
    const size_t inputs = is_rct_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
    const size_t outputs = rv.ecdhInfo.size();
    key prehash;
    std::string blob;
    {
        serialization::binary_string_archiver ba;
        const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs);
        blob = ba.str();
    }
    cryptonote::get_blob_hash(blob, h);
    hashes.push_back(hash2rct(h));

    keyV kv;
    if (rct::is_rct_bulletproof(rv.type)) {
        kv.reserve((6 * 2 + 9) * rv.p.bulletproofs.size());
        for (const auto& p : rv.p.bulletproofs) {
            // V are not hashed as they're expanded from outPk.mask
            // (and thus hashed as part of rctSigBase above)
            kv.push_back(p.A);
            kv.push_back(p.S);
            kv.push_back(p.T1);
            kv.push_back(p.T2);
            kv.push_back(p.taux);
            kv.push_back(p.mu);
            for (size_t n = 0; n < p.L.size(); ++n)
                kv.push_back(p.L[n]);
            for (size_t n = 0; n < p.R.size(); ++n)
                kv.push_back(p.R[n]);
            kv.push_back(p.a);
            kv.push_back(p.b);
            kv.push_back(p.t);
        }
    } else {
        kv.reserve((64 * 3 + 1) * rv.p.rangeSigs.size());
        for (const auto& r : rv.p.rangeSigs) {
            for (size_t n = 0; n < 64; ++n)
                kv.push_back(r.asig.s0[n]);
            for (size_t n = 0; n < 64; ++n)
                kv.push_back(r.asig.s1[n]);
            kv.push_back(r.asig.ee);
            for (size_t n = 0; n < 64; ++n)
                kv.push_back(r.Ci[n]);
        }
    }
    hashes.push_back(cn_fast_hash(kv));
    hwdev.clsag_prehash(blob, inputs, outputs, hashes, rv.outPk, prehash);
    return prehash;
}

clsag proveRctCLSAGSimple(
        const key& message,
        const ctkeyV& pubs,
        const ctkey& inSk,
        const key& a,
        const key& Cout,
        const multisig_kLRki* kLRki,
        key* mscout,
        key* mspout,
        unsigned int index,
        hw::device& hwdev) {
    // setup vars
    size_t rows = 1;
    size_t cols = pubs.size();
    CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
    CHECK_AND_ASSERT_THROW_MES(
            (kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");
    keyV tmp(rows + 1);
    keyV sk(rows + 1);
    size_t i;
    keyM M(cols, tmp);

    keyV P, C, C_nonzero;
    P.reserve(pubs.size());
    C.reserve(pubs.size());
    C_nonzero.reserve(pubs.size());
    for (const ctkey& k : pubs) {
        P.push_back(k.dest);
        C_nonzero.push_back(k.mask);
        rct::key tmp;
        subKeys(tmp, k.mask, Cout);
        C.push_back(tmp);
    }

    sk[0] = copy(inSk.dest);
    sc_sub(sk[1].bytes, inSk.mask.bytes, a.bytes);
    clsag result = CLSAG_Gen(
            message, P, sk[0], C, sk[1], C_nonzero, Cout, index, kLRki, mscout, mspout, hwdev);
    memwipe(sk.data(), sk.size() * sizeof(key));
    return result;
}

// Ring-ct MG sigs
// Prove:
//    c.f. https://eprint.iacr.org/2015/1098 section 4. definition 10.
//    This does the MG sig on the "dest" part of the given key matrix, and
//    the last row is the sum of input commitments from that column - sum output commitments
//    this shows that sum inputs = sum outputs
// Ver:
//    verifies the above sig is created corretly
bool verRctMG(
        const mgSig& mg,
        const ctkeyM& pubs,
        const ctkeyV& outPk,
        const key& txnFeeKey,
        const key& message) {
    // setup vars
    size_t cols = pubs.size();
    CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
    size_t rows = pubs[0].size();
    CHECK_AND_ASSERT_MES(rows >= 1, false, "Empty pubs");
    for (size_t i = 1; i < cols; ++i) {
        CHECK_AND_ASSERT_MES(pubs[i].size() == rows, false, "pubs is not rectangular");
    }

    keyV tmp(rows + 1);
    size_t i = 0, j = 0;
    for (i = 0; i < rows + 1; i++) {
        identity(tmp[i]);
    }
    keyM M(cols, tmp);

    // create the matrix to mg sig
    for (j = 0; j < rows; j++) {
        for (i = 0; i < cols; i++) {
            M[i][j] = pubs[i][j].dest;
            addKeys(M[i][rows], M[i][rows], pubs[i][j].mask);  // add Ci in last row
        }
    }
    for (i = 0; i < cols; i++) {
        for (j = 0; j < outPk.size(); j++) {
            subKeys(M[i][rows], M[i][rows], outPk[j].mask);  // subtract output Ci's in last row
        }
        // subtract txn fee output in last row
        subKeys(M[i][rows], M[i][rows], txnFeeKey);
    }
    return MLSAG_Ver(message, M, mg, rows);
}

// Ring-ct Simple MG sigs
// Ver:
// This does a simplified version, assuming only post Rct
// inputs
bool verRctMGSimple(const key& message, const mgSig& mg, const ctkeyV& pubs, const key& C) {
    try {
        // setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
        keyV tmp(rows + 1);
        size_t i;
        keyM M(cols, tmp);
        ge_p3 Cp3;
        if (ge_frombytes_vartime(&Cp3, C.bytes) != 0) {
            log::info(log::Cat("verify"), "point conv failed");
            return false;
        }
        ge_cached Ccached;
        ge_p3_to_cached(&Ccached, &Cp3);
        ge_p1p1 p1;
        // create the matrix to mg sig
        for (i = 0; i < cols; i++) {
            M[i][0] = pubs[i].dest;
            ge_p3 p3;
            if (ge_frombytes_vartime(&p3, pubs[i].mask.bytes) != 0) {
                log::info(log::Cat("verify"), "point conv failed");
                return false;
            }
            ge_sub(&p1, &p3, &Ccached);
            ge_p1p1_to_p3(&p3, &p1);
            ge_p3_tobytes(M[i][1].bytes, &p3);
        }
        // DP(C);
        return MLSAG_Ver(message, M, mg, rows);
    } catch (...) {
        return false;
    }
}

bool verRctCLSAGSimple(
        const key& message, const clsag& sig, const ctkeyV& pubs, const key& C_offset) {
    try {
        const size_t n = pubs.size();

        // Check data
        CHECK_AND_ASSERT_MES(n >= 1, false, "Empty pubs");
        CHECK_AND_ASSERT_MES(
                n == sig.s.size(), false, "Signature scalar vector is the wrong size!");
        for (size_t i = 0; i < n; ++i)
            CHECK_AND_ASSERT_MES(sc_check(sig.s[i].bytes) == 0, false, "Bad signature scalar!");
        CHECK_AND_ASSERT_MES(sc_check(sig.c1.bytes) == 0, false, "Bad signature commitment!");
        CHECK_AND_ASSERT_MES(!(sig.I == rct::identity()), false, "Bad key image!");

        // Cache commitment offset for efficient subtraction later
        ge_p3 C_offset_p3;
        CHECK_AND_ASSERT_MES(
                ge_frombytes_vartime(&C_offset_p3, C_offset.bytes) == 0,
                false,
                "point conv failed");
        ge_cached C_offset_cached;
        ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

        // Prepare key images
        key c = copy(sig.c1);
        key D_8 = scalarmult8(sig.D);
        CHECK_AND_ASSERT_MES(!(D_8 == rct::identity()), false, "Bad auxiliary key image!");
        geDsmp I_precomp;
        geDsmp D_precomp;
        precomp(I_precomp.k, sig.I);
        precomp(D_precomp.k, D_8);

        // Aggregation hashes
        keyV mu_P_to_hash(2 * n + 4);  // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2 * n + 4);  // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].bytes);
        memcpy(mu_P_to_hash[0].bytes,
               cryptonote::hashkey::CLSAG_AGG_0.data(),
               cryptonote::hashkey::CLSAG_AGG_0.size());
        sc_0(mu_C_to_hash[0].bytes);
        memcpy(mu_C_to_hash[0].bytes,
               cryptonote::hashkey::CLSAG_AGG_1.data(),
               cryptonote::hashkey::CLSAG_AGG_1.size());
        for (size_t i = 1; i < n + 1; ++i) {
            mu_P_to_hash[i] = pubs[i - 1].dest;
            mu_C_to_hash[i] = pubs[i - 1].dest;
        }
        for (size_t i = n + 1; i < 2 * n + 1; ++i) {
            mu_P_to_hash[i] = pubs[i - n - 1].mask;
            mu_C_to_hash[i] = pubs[i - n - 1].mask;
        }
        mu_P_to_hash[2 * n + 1] = sig.I;
        mu_P_to_hash[2 * n + 2] = sig.D;
        mu_P_to_hash[2 * n + 3] = C_offset;
        mu_C_to_hash[2 * n + 1] = sig.I;
        mu_C_to_hash[2 * n + 2] = sig.D;
        mu_C_to_hash[2 * n + 3] = C_offset;
        key mu_P, mu_C;
        mu_P = hash_to_scalar(mu_P_to_hash);
        mu_C = hash_to_scalar(mu_C_to_hash);

        // Set up round hash
        keyV c_to_hash(2 * n + 5);  // domain, P, C, C_offset, message, L, R
        sc_0(c_to_hash[0].bytes);
        memcpy(c_to_hash[0].bytes,
               cryptonote::hashkey::CLSAG_ROUND.data(),
               cryptonote::hashkey::CLSAG_ROUND.size());
        for (size_t i = 1; i < n + 1; ++i) {
            c_to_hash[i] = pubs[i - 1].dest;
            c_to_hash[i + n] = pubs[i - 1].mask;
        }
        c_to_hash[2 * n + 1] = C_offset;
        c_to_hash[2 * n + 2] = message;
        key c_p;  // = c[i]*mu_P
        key c_c;  // = c[i]*mu_C
        key c_new;
        key L;
        key R;
        geDsmp P_precomp;
        geDsmp C_precomp;
        geDsmp H_precomp;
        size_t i = 0;
        ge_p3 hash8_p3;
        geDsmp hash_precomp;
        ge_p3 temp_p3;
        ge_p1p1 temp_p1;

        while (i < n) {
            sc_0(c_new.bytes);
            sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
            sc_mul(c_c.bytes, mu_C.bytes, c.bytes);

            // Precompute points for L/R
            precomp(P_precomp.k, pubs[i].dest);

            CHECK_AND_ASSERT_MES(
                    ge_frombytes_vartime(&temp_p3, pubs[i].mask.bytes) == 0,
                    false,
                    "point conv failed");
            ge_sub(&temp_p1, &temp_p3, &C_offset_cached);
            ge_p1p1_to_p3(&temp_p3, &temp_p1);
            ge_dsm_precomp(C_precomp.k, &temp_p3);

            // Compute L
            addKeys_aGbBcC(L, sig.s[i], c_p, P_precomp.k, c_c, C_precomp.k);

            // Compute R
            hash_to_p3(hash8_p3, pubs[i].dest);
            ge_dsm_precomp(hash_precomp.k, &hash8_p3);
            addKeys_aAbBcC(R, sig.s[i], hash_precomp.k, c_p, I_precomp.k, c_c, D_precomp.k);

            c_to_hash[2 * n + 3] = L;
            c_to_hash[2 * n + 4] = R;
            c_new = hash_to_scalar(c_to_hash);
            CHECK_AND_ASSERT_MES(!(c_new == rct::zero()), false, "Bad signature hash");
            copy(c, c_new);

            i = i + 1;
        }
        sc_sub(c_new.bytes, c.bytes, sig.c1.bytes);
        return sc_isnonzero(c_new.bytes) == 0;
    } catch (...) {
        return false;
    }
}

// These functions get keys from blockchain
// replace these when connecting blockchain
// populateFromBlockchain creates a keymatrix with "mixin" + 1 columns and one of the columns is
// inPk
//    the return value are the key matrix, and the index where inPk was put (random).
std::pair<ctkeyM, xmr_amount> populateFromBlockchain(const ctkeyV& inPk, int mixin) {
    std::pair<ctkeyM, xmr_amount> result;
    auto& [rv, index] = result;
    rv.resize(mixin + 1, inPk);
    index = randXmrAmount(mixin);
    for (size_t i = 0; i < rv.size(); i++) {
        if (i != index)
            for (auto& a : rv[i])
                a.randomize();
    }
    return result;
}

// These functions get keys from blockchain
// replace these when connecting blockchain
// populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
//    the return value are the key matrix, and the index where inPk was put (random).
xmr_amount populateFromBlockchainSimple(ctkeyV& mixRing, const ctkey& inPk, int mixin) {
    int index = randXmrAmount(mixin);
    int i = 0;
    for (i = 0; i <= mixin; i++) {
        if (i != index) {
            mixRing[i].randomize();
        } else {
            mixRing[i] = inPk;
        }
    }
    return index;
}

// RCT simple
// for post-rct only
rctSig genRctSimple(
        const key& message,
        const ctkeyV& inSk,
        const keyV& destinations,
        const std::vector<xmr_amount>& inamounts,
        const std::vector<xmr_amount>& outamounts,
        xmr_amount txnFee,
        const ctkeyM& mixRing,
        const keyV& amount_keys,
        const std::vector<multisig_kLRki>* kLRki,
        multisig_out* msout,
        const std::vector<unsigned int>& index,
        ctkeyV& outSk,
        const RCTConfig& rct_config,
        hw::device& hwdev) {
    CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
    CHECK_AND_ASSERT_THROW_MES(
            inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
    CHECK_AND_ASSERT_THROW_MES(
            outamounts.size() == destinations.size(), "Different number of amounts/destinations");
    CHECK_AND_ASSERT_THROW_MES(
            amount_keys.size() == destinations.size(),
            "Different number of amount_keys/destinations");
    CHECK_AND_ASSERT_THROW_MES(index.size() == inSk.size(), "Different number of index/inSk");
    CHECK_AND_ASSERT_THROW_MES(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
    for (size_t n = 0; n < mixRing.size(); ++n) {
        CHECK_AND_ASSERT_THROW_MES(index[n] < mixRing[n].size(), "Bad index into mixRing");
    }
    CHECK_AND_ASSERT_THROW_MES(
            (kLRki && msout) || (!kLRki && !msout), "Only one of kLRki/msout is present");
    if (kLRki && msout) {
        CHECK_AND_ASSERT_THROW_MES(
                kLRki->size() == inamounts.size(), "Mismatched kLRki/inamounts sizes");
    }

    CHECK_AND_ASSERT_THROW_MES(
            rct_config.range_proof_type != RangeProofType::Borromean &&
                    (rct_config.bp_version == 3 ||
                     rct_config.bp_version == 0),  // 0 means latest version
            "Unable to generate rct for non-CLSAG-bulletproof");

    rctSig rv;
    rv.type = RCTType::CLSAG;
    rv.message = message;
    rv.outPk.resize(destinations.size());
    rv.ecdhInfo.resize(destinations.size());

    size_t i;
    keyV masks(destinations.size());  // sk mask..
    outSk.resize(destinations.size());
    for (i = 0; i < destinations.size(); i++) {
        // add destination to sig
        rv.outPk[i].dest = copy(destinations[i]);
    }

    rv.p.bulletproofs.clear();
    size_t n_amounts = outamounts.size();
    size_t amounts_proved = 0;
    if (rct_config.range_proof_type == RangeProofType::PaddedBulletproof) {
        rct::keyV C, masks;
        if (hwdev.get_mode() == hw::device::mode::TRANSACTION_CREATE_FAKE) {
            // use a fake bulletproof for speed
            rv.p.bulletproofs.push_back(make_dummy_bulletproof(outamounts, C, masks));
        } else {
            const epee::span<const key> keys{&amount_keys[0], amount_keys.size()};
            rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, outamounts, keys, hwdev));
#ifdef DBG
            CHECK_AND_ASSERT_THROW_MES(
                    verBulletproof(rv.p.bulletproofs.back()),
                    "verBulletproof failed on newly created proof");
#endif
        }
        for (i = 0; i < outamounts.size(); ++i) {
            rv.outPk[i].mask = rct::scalarmult8(C[i]);
            outSk[i].mask = masks[i];
        }
    } else
        while (amounts_proved < n_amounts) {
            size_t batch_size = 1;
            if (rct_config.range_proof_type == RangeProofType::MultiOutputBulletproof)
                while (batch_size * 2 + amounts_proved <= n_amounts &&
                       batch_size * 2 <= cryptonote::TX_BULLETPROOF_MAX_OUTPUTS)
                    batch_size *= 2;
            rct::keyV C, masks;
            std::vector<uint64_t> batch_amounts(batch_size);
            for (i = 0; i < batch_size; ++i)
                batch_amounts[i] = outamounts[i + amounts_proved];
            if (hwdev.get_mode() == hw::device::mode::TRANSACTION_CREATE_FAKE) {
                // use a fake bulletproof for speed
                rv.p.bulletproofs.push_back(make_dummy_bulletproof(batch_amounts, C, masks));
            } else {
                const epee::span<const key> keys{&amount_keys[amounts_proved], batch_size};
                rv.p.bulletproofs.push_back(
                        proveRangeBulletproof(C, masks, batch_amounts, keys, hwdev));
#ifdef DBG
                CHECK_AND_ASSERT_THROW_MES(
                        verBulletproof(rv.p.bulletproofs.back()),
                        "verBulletproof failed on newly created proof");
#endif
            }
            for (i = 0; i < batch_size; ++i) {
                rv.outPk[i + amounts_proved].mask = rct::scalarmult8(C[i]);
                outSk[i + amounts_proved].mask = masks[i];
            }
            amounts_proved += batch_size;
        }

    key sumout = zero();
    for (i = 0; i < outSk.size(); ++i) {
        sc_add(sumout.bytes, outSk[i].mask.bytes, sumout.bytes);

        // mask amount and mask
        rv.ecdhInfo[i].mask = copy(outSk[i].mask);
        rv.ecdhInfo[i].amount = d2h(outamounts[i]);
        hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], true);
    }

    rv.txnFee = txnFee;
    rv.mixRing = mixRing;
    keyV& pseudoOuts = rv.p.pseudoOuts;
    pseudoOuts.resize(inamounts.size());
    rv.p.CLSAGs.resize(inamounts.size());
    key sumpouts = zero();  // sum pseudoOut masks
    keyV a(inamounts.size());
    for (i = 0; i < inamounts.size() - 1; i++) {
        skGen(a[i]);
        sc_add(sumpouts.bytes, a[i].bytes, sumpouts.bytes);
        genC(pseudoOuts[i], a[i], inamounts[i]);
    }
    sc_sub(a[i].bytes, sumout.bytes, sumpouts.bytes);
    genC(pseudoOuts[i], a[i], inamounts[i]);
    DP(pseudoOuts[i]);

    key full_message = get_pre_clsag_hash(rv, hwdev);
    if (msout) {
        msout->c.resize(inamounts.size());
        msout->mu_p.resize(inamounts.size());
    }
    for (i = 0; i < inamounts.size(); i++) {
        rv.p.CLSAGs[i] = proveRctCLSAGSimple(
                full_message,
                rv.mixRing[i],
                inSk[i],
                a[i],
                pseudoOuts[i],
                kLRki ? &(*kLRki)[i] : NULL,
                msout ? &msout->c[i] : NULL,
                msout ? &msout->mu_p[i] : NULL,
                index[i],
                hwdev);
    }
    return rv;
}

rctSig genRctSimple(
        const key& message,
        const ctkeyV& inSk,
        const ctkeyV& inPk,
        const keyV& destinations,
        const std::vector<xmr_amount>& inamounts,
        const std::vector<xmr_amount>& outamounts,
        const keyV& amount_keys,
        const std::vector<multisig_kLRki>* kLRki,
        multisig_out* msout,
        xmr_amount txnFee,
        unsigned int mixin,
        const RCTConfig& rct_config,
        hw::device& hwdev) {
    std::vector<unsigned int> index;
    index.resize(inPk.size());
    ctkeyM mixRing;
    ctkeyV outSk;
    mixRing.resize(inPk.size());
    for (size_t i = 0; i < inPk.size(); ++i) {
        mixRing[i].resize(mixin + 1);
        index[i] = populateFromBlockchainSimple(mixRing[i], inPk[i], mixin);
    }
    return genRctSimple(
            message,
            inSk,
            destinations,
            inamounts,
            outamounts,
            txnFee,
            mixRing,
            amount_keys,
            kLRki,
            msout,
            index,
            outSk,
            rct_config,
            hwdev);
}

// RingCT protocol
// genRct:
//    creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns
//    one of the columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//    Also contains masked "amount" and "mask" so the receiver can see how much they received
// verRct:
//    verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
// decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
//    uses the attached ecdh info to find the amounts represented by each output commitment
//    must know the destination private key to find the correct amount, else will return a random
//    number
bool verRct(const rctSig& rv, bool semantics) {
    CHECK_AND_ASSERT_MES(rv.type == RCTType::Full, false, "verRct called on non-full rctSig");
    if (semantics) {
        CHECK_AND_ASSERT_MES(
                rv.outPk.size() == rv.p.rangeSigs.size(),
                false,
                "Mismatched sizes of outPk and rv.p.rangeSigs");
        CHECK_AND_ASSERT_MES(
                rv.outPk.size() == rv.ecdhInfo.size(),
                false,
                "Mismatched sizes of outPk and rv.ecdhInfo");
        CHECK_AND_ASSERT_MES(rv.p.MGs.size() == 1, false, "full rctSig has not one MG");
    } else {
        // semantics check is early, we don't have the MGs resolved yet
    }

    // some rct ops can throw
    try {
        if (semantics) {
            tools::threadpool& tpool = tools::threadpool::getInstance();
            tools::threadpool::waiter waiter;
            std::deque<bool> results(rv.outPk.size(), false);
            DP("range proofs verified?");
            for (size_t i = 0; i < rv.outPk.size(); i++)
                tpool.submit(&waiter, [&, i] {
                    results[i] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]);
                });
            waiter.wait(&tpool);

            for (size_t i = 0; i < results.size(); ++i) {
                if (!results[i]) {
                    log::info(logcat, "Range proof verified failed for proof {}", i);
                    return false;
                }
            }
        }

        if (!semantics) {
            // compute txn fee
            key txnFeeKey = scalarmultH(d2h(rv.txnFee));
            bool mgVerd = verRctMG(
                    rv.p.MGs[0],
                    rv.mixRing,
                    rv.outPk,
                    txnFeeKey,
                    get_pre_clsag_hash(rv, hw::get_device("default")));
            DP("mg sig verified?");
            DP(mgVerd);
            if (!mgVerd) {
                log::info(logcat, "MG signature verification failed");
                return false;
            }
        }

        return true;
    } catch (const std::exception& e) {
        log::info(logcat, "Error in verRct: {}", e.what());
        return false;
    } catch (...) {
        log::info(logcat, "Error in verRct, but not an actual exception");
        return false;
    }
}

// ver RingCT simple
// assumes only post-rct style inputs (at least for max anonymity)
bool verRctSemanticsSimple(const std::vector<const rctSig*>& rvv) {
    try {

        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter;
        std::deque<bool> results;
        std::vector<const Bulletproof*> proofs;
        size_t max_non_bp_proofs = 0, offset = 0;

        for (const rctSig* rvp : rvv) {
            CHECK_AND_ASSERT_MES(rvp, false, "rctSig pointer is NULL");
            const rctSig& rv = *rvp;
            CHECK_AND_ASSERT_MES(
                    rct::is_rct_simple(rv.type),
                    false,
                    "verRctSemanticsSimple called on non simple rctSig");
            const bool bulletproof = is_rct_bulletproof(rv.type);
            if (bulletproof) {
                CHECK_AND_ASSERT_MES(
                        rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs),
                        false,
                        "Mismatched sizes of outPk and bulletproofs");
                if (rv.type == RCTType::CLSAG) {
                    CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs are not empty for CLSAG");
                    CHECK_AND_ASSERT_MES(
                            rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(),
                            false,
                            "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
                } else {
                    CHECK_AND_ASSERT_MES(
                            rv.p.CLSAGs.empty(), false, "CLSAGs are not empty for MLSAG");
                    CHECK_AND_ASSERT_MES(
                            rv.p.pseudoOuts.size() == rv.p.MGs.size(),
                            false,
                            "Mismatched sizes of rv.p.pseudoOuts and rv.p.MGs");
                }
                CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
            } else {
                CHECK_AND_ASSERT_MES(
                        rv.outPk.size() == rv.p.rangeSigs.size(),
                        false,
                        "Mismatched sizes of outPk and rv.p.rangeSigs");
                CHECK_AND_ASSERT_MES(
                        rv.pseudoOuts.size() == rv.p.MGs.size(),
                        false,
                        "Mismatched sizes of rv.pseudoOuts and rv.p.MGs");
                CHECK_AND_ASSERT_MES(
                        rv.p.pseudoOuts.empty(), false, "rv.p.pseudoOuts is not empty");
            }
            CHECK_AND_ASSERT_MES(
                    rv.outPk.size() == rv.ecdhInfo.size(),
                    false,
                    "Mismatched sizes of outPk and rv.ecdhInfo");

            if (!bulletproof)
                max_non_bp_proofs += rv.p.rangeSigs.size();
        }

        results.resize(max_non_bp_proofs);
        for (const rctSig* rvp : rvv) {
            const rctSig& rv = *rvp;

            const bool bulletproof = is_rct_bulletproof(rv.type);
            const keyV& pseudoOuts = bulletproof ? rv.p.pseudoOuts : rv.pseudoOuts;

            rct::keyV masks(rv.outPk.size());
            for (size_t i = 0; i < rv.outPk.size(); i++) {
                masks[i] = rv.outPk[i].mask;
            }
            key sumOutpks = addKeys(masks);
            DP(sumOutpks);
            const key txnFeeKey = scalarmultH(d2h(rv.txnFee));
            addKeys(sumOutpks, txnFeeKey, sumOutpks);

            key sumPseudoOuts = addKeys(pseudoOuts);
            DP(sumPseudoOuts);

            // check pseudoOuts vs Outs..
            if (!equalKeys(sumPseudoOuts, sumOutpks)) {
                log::info(logcat, "Sum check failed");
                return false;
            }

            if (bulletproof) {
                for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
                    proofs.push_back(&rv.p.bulletproofs[i]);
            } else {
                for (size_t i = 0; i < rv.p.rangeSigs.size(); i++)
                    tpool.submit(&waiter, [&, i, offset] {
                        results[i + offset] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]);
                    });
                offset += rv.p.rangeSigs.size();
            }
        }
        if (!proofs.empty() && !verBulletproof(proofs)) {
            log::info(logcat, "Aggregate range proof verified failed");
            return false;
        }

        waiter.wait(&tpool);
        for (size_t i = 0; i < results.size(); ++i) {
            if (!results[i]) {
                log::info(logcat, "Range proof verified failed for proof {}", i);
                return false;
            }
        }

        return true;
    }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (const std::exception& e) {
        log::info(logcat, "Error in verRctSemanticsSimple: {}", e.what());
        return false;
    } catch (...) {
        log::info(logcat, "Error in verRctSemanticsSimple, but not an actual exception");
        return false;
    }
}

bool verRctSemanticsSimple(const rctSig& rv) {
    return verRctSemanticsSimple(std::vector<const rctSig*>(1, &rv));
}

// ver RingCT simple
// assumes only post-rct style inputs (at least for max anonymity)
bool verRctNonSemanticsSimple(const rctSig& rv) {
    try {

        CHECK_AND_ASSERT_MES(
                rct::is_rct_simple(rv.type),
                false,
                "verRctNonSemanticsSimple called on non simple rctSig");
        const bool bulletproof = is_rct_bulletproof(rv.type);
        // semantics check is early, and mixRing/MGs aren't resolved yet
        if (bulletproof)
            CHECK_AND_ASSERT_MES(
                    rv.p.pseudoOuts.size() == rv.mixRing.size(),
                    false,
                    "Mismatched sizes of rv.p.pseudoOuts and mixRing");
        else
            CHECK_AND_ASSERT_MES(
                    rv.pseudoOuts.size() == rv.mixRing.size(),
                    false,
                    "Mismatched sizes of rv.pseudoOuts and mixRing");

        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter;

        const keyV& pseudoOuts = bulletproof ? rv.p.pseudoOuts : rv.pseudoOuts;

        const key message = get_pre_clsag_hash(rv, hw::get_device("default"));

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0; i < rv.mixRing.size(); i++) {
            tpool.submit(&waiter, [&, i] {
                if (rv.type == RCTType::CLSAG)
                    results[i] = verRctCLSAGSimple(
                            message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
                else
                    results[i] = verRctMGSimple(message, rv.p.MGs[i], rv.mixRing[i], pseudoOuts[i]);
            });
        }
        waiter.wait(&tpool);

        for (size_t i = 0; i < results.size(); ++i) {
            if (!results[i]) {
                log::info(logcat, "verRctMGSimple/verRctCLSAGSimple failed for input {}", i);
                return false;
            }
        }

        return true;
    }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (const std::exception& e) {
        log::info(logcat, "Error in verRctNonSemanticsSimple: {}", e.what());
        return false;
    } catch (...) {
        log::info(logcat, "Error in verRctNonSemanticsSimple, but not an actual exception");
        return false;
    }
}

// RingCT protocol
// genRct:
//    creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns
//    one of the columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//    Also contains masked "amount" and "mask" so the receiver can see how much they received
// verRct:
//    verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
// decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
//    uses the attached ecdh info to find the amounts represented by each output commitment
//    must know the destination private key to find the correct amount, else will return a random
//    number
xmr_amount decodeRct(
        const rctSig& rv, const key& sk, unsigned int i, key& mask, hw::device& hwdev) {
    CHECK_AND_ASSERT_MES(rv.type == RCTType::Full, false, "decodeRct called on non-full rctSig");
    CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
    CHECK_AND_ASSERT_THROW_MES(
            rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

    // mask amount and mask
    ecdhTuple ecdh_info = rv.ecdhInfo[i];
    hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG);
    mask = ecdh_info.mask;
    key amount = ecdh_info.amount;
    key C = rv.outPk[i].mask;
    DP("C");
    DP(C);
    key Ctmp;
    CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
    CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
    addKeys2(Ctmp, mask, amount, H);
    DP("Ctmp");
    DP(Ctmp);
    if (equalKeys(C, Ctmp) == false) {
        CHECK_AND_ASSERT_THROW_MES(
                false, "warning, amount decoded incorrectly, will be unable to spend");
    }
    return h2d(amount);
}

xmr_amount decodeRct(const rctSig& rv, const key& sk, unsigned int i, hw::device& hwdev) {
    key mask;
    return decodeRct(rv, sk, i, mask, hwdev);
}

xmr_amount decodeRctSimple(
        const rctSig& rv, const key& sk, unsigned int i, key& mask, hw::device& hwdev) {
    CHECK_AND_ASSERT_MES(
            rct::is_rct_simple(rv.type), false, "decodeRct called on non simple rctSig");
    CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
    CHECK_AND_ASSERT_THROW_MES(
            rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

    // mask amount and mask
    ecdhTuple ecdh_info = rv.ecdhInfo[i];
    hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTType::Bulletproof2 || rv.type == RCTType::CLSAG);
    mask = ecdh_info.mask;
    key amount = ecdh_info.amount;
    key C = rv.outPk[i].mask;
    DP("C");
    DP(C);
    key Ctmp;
    CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
    CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
    addKeys2(Ctmp, mask, amount, H);
    DP("Ctmp");
    DP(Ctmp);
    if (equalKeys(C, Ctmp) == false) {
        CHECK_AND_ASSERT_THROW_MES(
                false, "warning, amount decoded incorrectly, will be unable to spend");
    }
    return h2d(amount);
}

xmr_amount decodeRctSimple(const rctSig& rv, const key& sk, unsigned int i, hw::device& hwdev) {
    key mask;
    return decodeRctSimple(rv, sk, i, mask, hwdev);
}

bool signMultisigMLSAG(
        rctSig& rv,
        const std::vector<unsigned int>& indices,
        const keyV& k,
        const multisig_out& msout,
        const key& secret_key) {
    CHECK_AND_ASSERT_MES(
            tools::equals_any(
                    rv.type,
                    RCTType::Full,
                    RCTType::Simple,
                    RCTType::Bulletproof,
                    RCTType::Bulletproof2),
            false,
            "unsupported rct type");
    CHECK_AND_ASSERT_MES(indices.size() == k.size(), false, "Mismatched k/indices sizes");
    CHECK_AND_ASSERT_MES(k.size() == rv.p.MGs.size(), false, "Mismatched k/MGs size");
    CHECK_AND_ASSERT_MES(k.size() == msout.c.size(), false, "Mismatched k/msout.c size");
    CHECK_AND_ASSERT_MES(rv.p.CLSAGs.empty(), false, "CLSAGs not empty for MLSAGs");
    if (rv.type == RCTType::Full) {
        CHECK_AND_ASSERT_MES(rv.p.MGs.size() == 1, false, "MGs not a single element");
    }
    for (size_t n = 0; n < indices.size(); ++n) {
        CHECK_AND_ASSERT_MES(indices[n] < rv.p.MGs[n].ss.size(), false, "Index out of range");
        CHECK_AND_ASSERT_MES(!rv.p.MGs[n].ss[indices[n]].empty(), false, "empty ss line");
    }

    // MLSAG: each player contributes a share to the secret-index ss: k - cc*secret_key_share
    //     cc: msout.c[n], secret_key_share: secret_key
    for (size_t n = 0; n < indices.size(); ++n) {
        rct::key diff;
        sc_mulsub(diff.bytes, msout.c[n].bytes, secret_key.bytes, k[n].bytes);
        sc_add(rv.p.MGs[n].ss[indices[n]][0].bytes,
               rv.p.MGs[n].ss[indices[n]][0].bytes,
               diff.bytes);
    }
    return true;
}

bool signMultisigCLSAG(
        rctSig& rv,
        const std::vector<unsigned int>& indices,
        const keyV& k,
        const multisig_out& msout,
        const key& secret_key) {
    CHECK_AND_ASSERT_MES(rv.type == RCTType::CLSAG, false, "unsupported rct type");
    CHECK_AND_ASSERT_MES(indices.size() == k.size(), false, "Mismatched k/indices sizes");
    CHECK_AND_ASSERT_MES(k.size() == rv.p.CLSAGs.size(), false, "Mismatched k/CLSAGs size");
    CHECK_AND_ASSERT_MES(k.size() == msout.c.size(), false, "Mismatched k/msout.c size");
    CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs not empty for CLSAGs");
    CHECK_AND_ASSERT_MES(msout.c.size() == msout.mu_p.size(), false, "Bad mu_p size");
    for (size_t n = 0; n < indices.size(); ++n) {
        CHECK_AND_ASSERT_MES(indices[n] < rv.p.CLSAGs[n].s.size(), false, "Index out of range");
    }

    // CLSAG: each player contributes a share to the secret-index ss: k - cc*mu_p*secret_key_share
    // cc: msout.c[n], mu_p, msout.mu_p[n], secret_key_share: secret_key
    for (size_t n = 0; n < indices.size(); ++n) {
        rct::key diff, sk;
        sc_mul(sk.bytes, msout.mu_p[n].bytes, secret_key.bytes);
        sc_mulsub(diff.bytes, msout.c[n].bytes, sk.bytes, k[n].bytes);
        sc_add(rv.p.CLSAGs[n].s[indices[n]].bytes, rv.p.CLSAGs[n].s[indices[n]].bytes, diff.bytes);
    }
    return true;
}

bool signMultisig(
        rctSig& rv,
        const std::vector<unsigned int>& indices,
        const keyV& k,
        const multisig_out& msout,
        const key& secret_key) {
    if (rv.type == RCTType::CLSAG)
        return signMultisigCLSAG(rv, indices, k, msout, secret_key);
    else
        return signMultisigMLSAG(rv, indices, k, msout, secret_key);
}
}  // namespace rct
