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
#include"sha1.h"

#define ROT32(x, m) \
        ((((x) << (m)) | ((x)>>(32-(m)))))

static void
SHA1Transform(tls_SHA1_ctx *t, const uint8_t m[TLS_SHA1_BLOCK_LENGTH])
{
        const uint32_t K[] = {
                0x5A827999,
                0x6ED9EBA1,
                0x8F1BBCDC,
                0xCA62C1D6
        };
        
        uint32_t temp;
        uint32_t W[80];
       
        uint32_t a = t->state[0];
        uint32_t b = t->state[1];
        uint32_t c = t->state[2];
        uint32_t d = t->state[3];
        uint32_t e = t->state[4];
        
        for (int t = 0; t < 16; t++) {
                W[t] =  (uint32_t)m[t*4] << 24;
                W[t] |= (uint32_t)m[t*4+1] << 16;
                W[t] |= (uint32_t)m[t*4+2] << 8;
                W[t] |= (uint32_t)m[t*4+3];
        }
        for (int t = 16; t < 80; t++) {
                W[t] = ROT32(W[t-3]^W[t-8]^W[t-14]^W[t-16], 1);
        }
        for (int t = 0; t < 20; t++) {
                temp = ROT32(a, 5)+((b&c)|((~b)&d))+e+W[t]+K[0];
                e = d;
                d = c;
                c = ROT32(b, 30);
                b = a;
                a = temp;
        }
        for (int t = 20; t < 40; t++) {
                temp = ROT32(a, 5)+(b^c^d)+e+W[t]+K[1];
                e = d;
                d = c;
                c = ROT32(b, 30);
                b = a;
                a = temp;
        }
        for (int t = 40; t < 60; t++) {
                temp = ROT32(a, 5)+((b&c)|(b&d)|(c&d))+e+W[t]+K[2];
                e = d;
                d = c;
                c = ROT32(b, 30);
                b = a;
                a = temp;
        }
        for (int t = 60; t < 80; t++) {
                temp = ROT32(a, 5)+(b^c^d)+e+W[t]+K[3];
                e = d;
                d = c;
                c = ROT32(b, 30);
                b = a;
                a = temp;
        }
        t->state[0] += a;
        t->state[1] += b;
        t->state[2] += c;
        t->state[3] += d;
        t->state[4] += e;
}

void
tls_SHA1_init(tls_SHA1_ctx *t)
{
        memset(t->buffer, 0, 64);
        t->count = 0;
        t->state[0] = 0x67452301;
        t->state[1] = 0xefcdab89;
        t->state[2] = 0x98badcfe;
        t->state[3] = 0x10325476;
        t->state[4] = 0xc3d2e1f0;
}

void
tls_SHA1_update(tls_SHA1_ctx *t, const tls_buf * dat)
{
        size_t len = dat->len;
        size_t have = (t->count/8) % TLS_SHA1_BLOCK_LENGTH;
        size_t need = TLS_SHA1_BLOCK_LENGTH - have;
        size_t offset = 0;
        uint8_t *m = dat->c;
        if (len >= need && need !=0) {
                /*
                 * We should never leave a block waiting in the buffer
                 */
                memcpy(t->buffer+have, m, need);
                len -= need;
                offset += need;
                SHA1Transform(t, t->buffer);
                t->count += need*8;
        }
        
        while (len > TLS_SHA1_BLOCK_LENGTH) {
                SHA1Transform(t, m+offset);
                len -= TLS_SHA1_BLOCK_LENGTH;
                offset += TLS_SHA1_BLOCK_LENGTH;
                t->count += TLS_SHA1_BLOCK_LENGTH*8;
        }
        if (len > 0) {
                memcpy(t->buffer, m+offset, len);
                t->count += len*8;
        }
}

void
tls_SHA1_final(tls_buf *out, tls_SHA1_ctx *t)
{
        assert(out->cap >=20);
         size_t have = (t->count/8) % TLS_SHA1_BLOCK_LENGTH;
         size_t rem = TLS_SHA1_BLOCK_LENGTH - have;
         t->buffer[have]=0x80;
         have=have+1;
         if (rem < 9) {
                 /* Need to put length in additional block */
                 for (size_t h = have; h < TLS_SHA1_BLOCK_LENGTH; h++) {
                         t->buffer[h] = 0;
                 }
                 SHA1Transform(t, t->buffer);
                 have = 0;
         }
         for (size_t h = have; h < TLS_SHA1_BLOCK_LENGTH; h++) {
                 t->buffer[h] = 0;
         }
         uint8_t *end = &t->buffer[TLS_SHA1_BLOCK_LENGTH-8];
         end[0] = (t->count >> 56) & 0xff;
         end[1] = (t->count >> 48) & 0xff;
         end[2] = (t->count >> 40) & 0xff;
         end[3] = (t->count >> 32) & 0xff;
         end[4] = (t->count >> 24) & 0xff;
         end[5] = (t->count >> 16) & 0xff;
         end[6] = (t->count >> 8) & 0xff;
         end[7] = (t->count) & 0xff;
         SHA1Transform(t, t->buffer);
         out->len=20;
         for (int i = 0; i < 5; i++) {
                 for (int j = 0; j <4 ; j++) {
                         out->c[i*4+j] = (t->state[i] >> 8*(3-j)) & 0xff;
                 }
         }
}
