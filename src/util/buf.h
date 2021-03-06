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

typedef struct {
  uint8_t *c;
  size_t len;
  size_t cap;
}  tls_buf;

void tls_buf_init(tls_buf* t);
int tls_buf_copy_string(tls_buf* t, const char * str);
uint8_t tls_buf_get(const tls_buf* t, size_t index);
int tls_buf_set(tls_buf* t, size_t index, uint8_t value);
int tls_buf_clone(tls_buf *dst, const tls_buf* src);
int tls_buf_append(tls_buf *dst, const tls_buf* src);
int tls_buf_copy(tls_buf *dst, const tls_buf* src, size_t dst_off,
                     size_t src_off, size_t len);
void tls_buf_clean(tls_buf *t);
size_t tls_buf_len(const tls_buf *t);
int tls_buf_ensure_cap(tls_buf *t, size_t cap);
