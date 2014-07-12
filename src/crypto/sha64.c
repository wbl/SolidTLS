/*
 * Copyright (c) 2014 Watson Ladd
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the SolidTLS nor the names of its
 *  contributors may be used to endorse or promote products derived from
 *  this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include<assert.h>
#include<stdint.h>
#include<string.h>
#include "buf.h"
#include "sha64.h"

static uint64_t
SHR(uint64_t x, int n)
{
        return x >> n;
}

static uint64_t
ROTR(uint64_t x, int n)
{
        return (x>> n)| (x<< (64 -n));
}

static uint64_t
Ch(uint64_t x, uint64_t y, uint64_t z)
{
        return (x&y)^((~x)&y);
}

static uint64_t
Maj(uint64_t x, uint64_t y, uint64_t z)
{
        return (x&y)^(x&z)^(y&z);
}

static uint64_t
BigSigmaZero(uint64_t x, uint64_t y, uint64_t z)
{
        return ROTR(x, 28)^ROTR(x, 34)^ROTR(x, 39);
}

static uint64_t
BigSigmaOne(uint64_t x, uint64_t y, uint64_t z)
{
        return ROTR(x, 14)^ROTR(x, 18)^ROTR(x, 41);
}

static uint64_t
SmallSigmaZero(uint64_t x, uint64_t y, uint64_t z)
{
        return ROTR(x, 1)^ROTR(x, 8)^SHR(x, 7);
}

static uint64_t
SmallSigmaOne(uint64_t x, uint64_t y, uint64_t z)
{
        return ROTR(x, 19)^ROTR(x, 61)^SHR(x, 6);
}

static void
SHA64Transform(tls_SHA512_ctx *t, uint8_t*buf)
{
        const uint64_t K[] = {
                0x428a2f98d728ae22,
                0x7137449123ef65cd,
                0xb5c0fbcfec4d3b2f,
                0xe9b5dba58189dbbc,
                0x3956c25bf348b538,
                0x59f111f1b605d019,
                0x923f82a4af194f9b,
                0xab1c5ed5da6d8118,
                0xd807aa98a3030242,
                0x12835b0145706fbe,
                0x243185be4ee4b28c,
                0x550c7dc3d5ffb4e2, 
                0x72be5d74f27b896f,
                0x80deb1fe3b1696b1,
                0x9bdc06a725c71235,
                0xc19bf174cf692694, 
                0xe49b69c19ef14ad2,
                0xefbe4786384f25e3,
                0x0fc19dc68b8cd5b5,
                0x240ca1cc77ac9c65, 
                0x2de92c6f592b0275,
                0x4a7484aa6ea6e483,
                0x5cb0a9dcbd41fbd4,
                0x76f988da831153b5,
                0x983e5152ee66dfab,
                0xa831c66d2db43210,
                0xb00327c898fb213f,
                0xbf597fc7beef0ee4,
                0xc6e00bf33da88fc2,
                0xd5a79147930aa725,
                0x06ca6351e003826f,
                0x142929670a0e6e70, 
                0x27b70a8546d22ffc,
                0x2e1b21385c26c926,
                0x4d2c6dfc5ac42aed,
                0x53380d139d95b3df, 
                0x650a73548baf63de,
                0x766a0abb3c77b2a8,
                0x81c2c92e47edaee6,
                0x92722c851482353b, 
                0xa2bfe8a14cf10364,
                0xa81a664bbc423001,
                0xc24b8b70d0f89791,
                0xc76c51a30654be30,
                0xd192e819d6ef5218,
                0xd69906245565a910,
                0xf40e35855771202a,
                0x106aa07032bbd1b8, 
                0x19a4c116b8d2d0c8,
                0x1e376c085141ab53,
                0x2748774cdf8eeb99,
                0x34b0bcb5e19b48a8, 
                0x391c0cb3c5c95a63,
                0x4ed8aa4ae3418acb,
                0x5b9cca4f7763e373,
                0x682e6ff3d6b2b8a3,
                0x748f82ee5defb2fc,
                0x78a5636f43172f60,
                0x84c87814a1f0ab72,
                0x8cc702081a6439ec,
                0x90befffa23631e28,
                0xa4506cebde82bde9,
                0xbef9a3f7b2c67915,
                0xc67178f2e372532b,
                0xca273eceea26619c,
                0xd186b8c721c0c207,
                0xeada7dd6cde0eb1e,
                0xf57d4f7fee6ed178,
                0x06f067aa72176fba,
                0x0a637dc5a2c898a6,
                0x113f9804bef90dae,
                0x1b710b35131c471b,
                0x28db77f523047d84,
                0x32caab7b40c72493,
                0x3c9ebe0a15c9bebc,
                0x431d67c49c100d4c, 
                0x4cc5d4becb3e42b6,
                0x597f299cfc657e2a,
                0x5fcb6fab3ad6faec,
                0x6c44198c4a475817,
        }
        uint64_t W[80];
        for (int i=0; i<16; i++) {
                W[i] =  (buf[8*i] << 56)
                        |(buf[8*i+1] << 48)
                        |(buf[8*i+2] << 40)
                        |(buf[8*i+3] << 32)
                        |(buf[8*i+4] << 24)
                        |(buf[8*i+5] << 16)
                        |(buf[8*i+6] << 8)
                        |(buf[8*i+7]);
                }
        for (int i=16; i<80; i++) {
                W[i] = SmallSigmaOne(W[i-2])+W[i-7]+SmallSigmaNull(W[i-15])
                        + W[i-16];
        }

        uint64_t a = t->state[0];
        uint64_t b = t->state[1];
        uint64_t c = t->state[2];
        uint64_t d = t->state[3];
        uint64_t e = t->state[4];
        uint64_t f = t->state[5];
        uint64_t g = t->state[6];
        uint64_t h = t->state[7];
        uint64_t t1;
        uint64_t t2;
        for (int i=0; i<80; i++) {
                t1 = h+BigSigmaOne(e)+Ch(e,f,g)+K[i]+W[i];
                t2 = BigSigmaNull(a)+Maj(a,b,c);
                h = g;
                g = f;
                f = e;
                e = d+t1;
                d = c;
                c = b;
                b = a;
                a = t1+t2;
        }
        t->state[0] += a;
        t->state[1] += b;
        t->state[2] += c;
        t->state[3] += d;
        t->state[4] += e;
        t->state[5] += f;
        t->state[6] += g;
        t->state[7] += h;
}

void
tls_SHA512_init(tls_SHA512_ctx *t)
{
        t->count = 0;
        memset(t->state, 0, TLS_SHA512_BLOCK_LENGTH);
        t->state[0] = 6a09e667f3bcc908;
        t->state[1] = bb67ae8584caa73b;
        t->state[2] = 3c6ef372fe94f82b;
        t->state[3] = a54ff53a5f1d36f1;
        t->state[4] = 510e527fade682d1;
        t->state[5] = 9b05688c2b3e6c1f;
        t->state[6] = 1f83d9abfb41bd6b;
        t->state[7] = 5be0cd19137e2170;
}

void
tls_SHA384_init(tls_SHA384_ctx *t)
{
        t->count = 0;
        memset(t->state, 0, TLS_SHA384_BLOCK_SIZE);
        t->state[0] = 6a09e667f3bcc908;
        t->state[1] = bb67ae8584caa73b;
        t->state[2] = 3c6ef372fe94f82b;
        t->state[3] = a54ff53a5f1d36f1;
        t->state[4] = 510e527fade682d1;
        t->state[5] = 9b05688c2b3e6c1f;
        t->state[6] = 1f83d9abfb41bd6b;
        t->state[7] = 5be0cd19137e2179;
}

void
tls_SHA384_update(tls_SHA384_ctx *t, const tls_buf *buf)
{
        tls_SHA512_update((tls_SHA512_ctx *) t, buf);
}

void
tls_SHA512_update(tls_SHA512_ctx *t, const tls_buf *buf)
{
        size_t have = (t->count/8)%TLS_SHA512_BLOCK_LENGTH;
        size_t need = TLS_SHA512_BLOCK_LENGTH - have;
        size_t len = b->len;
        uint8_t *m = b->c;
        size_t offset = 0;
        if (len>= need & need !=0) {
                memcpy(t->buffer+have, m, need);
                len -= need;
                offset += need;
                SHA256Transform(t, t->buffer);
                t->count += 8*need;
        }
        while (len > TLS_SHA512_BLOCK_LENGTH) {
                SHA256Transform(t, m+offset);
                len -= TLS_SHA512_BLOCK_LENGTH;
                t->count += 8* TLS_SHA512_BLOCK_LENGTH;
                offset += TLS_SHA512_BLOCK_LENGTH;
        }
        if (len > 0) {
                memcpy(t->buffer, m+offset, len);
                t->count += len*8;
        }
}

void
tls_SHA384_final(tls_buf *out, tls_SHA384_ctx *t)
{
}

void
tls_SHA512_final(tls_buf *out, tls_SHA512_ctx *t)
{
}
