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
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include "buf.h"

void
tls_buf_init(tls_buf *t)
{
        t->c = NULL;
        t->cap = 0;
        t->len = 0;
}

uint8_t
tls_buf_get(const tls_buf *t, size_t index)
{
        assert(index < t->len);
        return t->c[index];
}

int
tls_buf_ensure_cap(tls_buf *t, size_t cap)
{                
        uint8_t *space;
        size_t oldcap = t->cap;
        while (cap >= t->cap) {
                space = realloc(t->c, 2*t->cap+1);
                if (space == NULL) {
                        free(t->c);
                        return -1;
                }
                t->c = space;
                t->cap = 2*t->cap+1;
        }
        for (size_t i = oldcap; i < t->cap; i++){
                t->c[i] = 0;
        }
        return 0;
}

int
tls_buf_set(tls_buf *t, size_t index, uint8_t value)
{
        if (tls_buf_ensure_cap(t, index) == -1) {
                return -1;
        }
        if (t->len <= index) {
                t->len = index+1;
        }
        t->c[index] = value;
        return 0;
}

int
tls_buf_clone (tls_buf *dst, const tls_buf* src)
{
        dst->cap = src->len;
        dst->len = src->len;
        dst->c = malloc(src->len);
        if (dst->c == NULL) {
                return -1;
        }
        memcpy(dst->c, src->c, src->len);
        return 0;
}

int
tls_buf_copy_string(tls_buf *dst, const char * src)
{
        free(dst->c);
        dst->len = strlen(src);
        dst->cap = dst->len;
        dst->c = malloc(dst->cap);
        if (dst->c == NULL) {
                return -1;
        }
        for (size_t i = 0; src[i]; i++) {
                dst->c[i]=src[i];
        }
        return 0;
}

size_t
tls_buf_len(const tls_buf *t)
{
        return t->len;
}

int
tls_buf_append(tls_buf *dst, const tls_buf *src)
{
        return tls_buf_copy(dst, src, tls_buf_len(dst), 0, tls_buf_len(src));
}


void
tls_buf_clean(tls_buf *t)
{
        free(t->c);
        t->len = 0;
        t->cap = 0;
}

int
tls_buf_copy(tls_buf* dst, const tls_buf* src, size_t dst_off, size_t src_off,
             size_t len)
{
        /*
         * The below is slow as molassas, but is safe.
         */
        uint8_t b;
        for (size_t i = 0; i < len; i++) {
                b = tls_buf_get(src, src_off+i);
                if (tls_buf_set(dst, dst_off+i, b)) {
                        return -1;
                }
        }
        return 0;
}
