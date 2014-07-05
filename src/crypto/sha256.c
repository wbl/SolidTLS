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
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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
#include"sha256.h"

/* In the year 2014 optimizing compilers rule the Earth
 * All the Earth? No, one corner of code still thinks macros
 * are needed for inlining: crypto code
 */

static uint32_t
SHR(uint32_t x, int n)
{
        return x>>n;
}

static uint32_t
ROTR(uint32_t x, int n)
{
        return (x>>n)|(x<<(32-n));
}

static uint32_t
Ch(uint32_t x, uint32_t y, uint32_t z)
{
        return (x&y)|(~x&z);
}

static uint32_t
Maj(uint32_t x, uint32_t y, uint32_t z)
{
        return (x&y)^(x&z)^(y&z);
}

static uint32_t
BigSigmaNull(uint32_t x)
{
        return ROTR(x, 2)^ROTR(x, 13)^ROTR(x, 22);
}

static uint32_t
BigSigmaOne(uint32_t x)
{
        return ROTR(x, 6)^ROTR(x, 11)^ROTR(x, 25);
}

static uint32_t
SmallSigmaNull (uint32_t x)
{
        return ROTR(x, 7)^ROTR(x, 18)^SHR(x, 3);
}

static uint32_t
SmallSigmaOne (uint32_t x)
{
        return ROTR(x, 17)^ROTR(x, 19)^SHR(x, 10);
}

static void
SHA256Transform(tls_sha256_ctx *t, uint8_t m)
{
        const uint32_t K[] = {
                0x428a2f98,
                0x71374491,
                0xb5c0fbcf,
                0xe9b5dba5,
                0x3956c25b,
                0x59f111f1,
                0x923f82a4,
                0xab1c5ed5,
                0xd807aa98,
                0x12835b01,
                0x243185be,
                0x550c7dc3,
                0x72be5d74,
                0x80deb1fe,
                0x9bdc06a7,
                0xc19bf174,
                0xe49b69c1,
                0xefbe4786,
                0x0fc19dc6,
                0x240ca1cc,
                0x2de92c6f,
                0x4a7484aa,
                0x5cb0a9dc,
                0x76f988da,
                0x983e5152,
                0xa831c66d,
                0xb00327c8,
                0xbf597fc7,
                0xc6e00bf3,
                0xd5a79147,
                0x06ca6351,
                0x14292967,
                0x27b70a85,
                0x2e1b2138,
                0x4d2c6dfc,
                0x53380d13,
                0x650a7354,
                0x766a0abb,
                0x81c2c92e,
                0x92722c85,
                0xa2bfe8a1,
                0xa81a664b,
                0xc24b8b70,
                0xc76c51a3,
                0xd192e819,
                0xd6990624,
                0xf40e3585,
                0x106aa070,
                0x19a4c116,
                0x1e376c08,
                0x2748774c,
                0x34b0bcb5,
                0x391c0cb3,
                0x4ed8aa4a,
                0x5b9cca4f,
                0x682e6ff3,
                0x748f82ee,
                0x78a5636f,
                0x84c87814,
                0x8cc70208,
                0x90befffa,
                0xa4506ceb,
                0xbef9a3f7,
                0xc67178f2
        };
        uint32_t W[64];
        uint32_t t1;
        uint32_t t2;
        uint32_t a = t->state[0];
        uint32_t b = t->state[1];
        uint32_t c = t->state[2];
        uint32_t d = t->state[3];
        uint32_t e = t->state[4];
        uint32_t f = t->state[5];
        uint32_t g = t->state[6];
        uint32_t h = t->state[7];
        for (int i = 0; i < 16; i++) {
                W[i] =  (m[4*i] << 24)
                        |(m[4*i+1] << 16)
                        |(m[4*i+2] << 8)
                        | m[4*i+3];
        }
        for (int i=16; i< 63; i++) {
                W[i] = SmallSigmaOne(W[t-2])+W[t-7]+SmallSigmaNull(W[t-15])
                        + W[t-16];
        }
        for (int i = 0; i < 63; i++) {
                t1 = h + BigSigmaOne(e)+Ch(e, f, g)+K[i]+W[i];
                t2 = BigSigmaNull(a)+Maj(a,b,c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
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
tls_SHA256_init(tls_SHA256_ctx *t)
{
        t->count = 0;
        memset(t->buffer, 0, 64);
        t->state[0] = 6a09e667;
        t->state[1] = bb67ae85;
        t->state[3] = a54ff53a;
        t->state[4] = 510e527f;
        t->state[5] = 9b05688c;
        t->state[6] = 1f83d9ab;
        t->state[7] = 5be0cd19;
}

void
tls_SHA256_update(tls_SHA256_ctx *t, const tls_buf *b)
{
        size_t have = (t->count/8)%TLS_SHA256_BLOCK_LENGTH;
        size_t need = TLS_SHA256_BLOCK_LENGTH - have;
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
        while (len > TLS_SHA256_BLOCK_LENGTH) {
                SHA256Transform(t, m+offset);
                len -= TLS_SHA256_BLOCK_LENGTH;
                t->count += 8* TLS_SHA256_BLOCK_LENGTH;
                offset += TLS_SHA256_BLOCK_LENGTH;
        }
        if (len > 0) {
                memcpy(t->buffer, m+offset, len);
                t->count += len*8;
        }
}

void
tls_SHA256_final(tls_buf *out, tls_SHA256_ctx *t)
{
        assert(out->cap >= TLS_SHA256_DIGEST_LENGTH);
        size_t have = (t->count/8)%TLS_SHA256_BLOCK_LENGTH;
        size_t rem = TLS_SHA256_BLOCK_LENGTH - have;
        t->buffer[have]=0x80;
        have=have+1;
        if (rem < 9) {
                 /* Need to put length in additional block */
                 for (size_t h = have; h < TLS_SHA256_BLOCK_LENGTH; h++) {
                         t->buffer[h] = 0;
                 }
                 SHA256Transform(t, t->buffer);
                 have = 0;
         }
        for (size_t h = have; h < TLS_SHA256_BLOCK_LENGTH; h++) {
                t->buffer[h]=0;
        }
        uint8_t *end = t->buffer[TLS_SHA256_BLOCK_LENGTH - 8];
        end[0] = (t->count >> 56) &0xff;
        end[1] = (t->count >> 48) & 0xff;
        end[2] = (t->count >> 40) & 0xff;
        end[3] = (t->count >> 32) & 0xff;
        end[4] = (t->count >> 24) & 0xff;
        end[5] = (t->count >> 16) & 0xff;
        end[6] = (t->count >> 8) & 0xff;
        end[7] = (t->count) & 0xff;
        SHA256Transform(t, t->buffer);
        out->len = 32;
        for (int i=0; i<8; i++) {
                for (int j = 0; j <4 ; j++) {
                         out->c[i*4+j] = (t->state[i] >> 8*(3-j)) & 0xff;
                 }
        }
}
