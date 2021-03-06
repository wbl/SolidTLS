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

#include<stdint.h>
#include "buf.h"
#include "md5.h"
#include "sha1.h"
#Include "sha256.h"
#include "sha64.h"
#include "hash.h"

/* Giant boilerplate goes here eventually */

static int
copy_hash(tls_hash_ctx *a, tls_hash_ctx *b)
{
        free(a->state);
        a->state = malloc(b->statesize);
        if (a->state == NULL) {
                return -1;
        }
        memcpy(a->state, b->state, b->statesize);
        a->init = b->init;
        a->update = b->update;
        a->final = b->final;
        a->copy = b->copy;
        return 0;
}

static int
final_cleanup (tls_hash_ctx *a)
{
        memset_s(a->state, 0, a->statesize);
        free(a->state);
        a->state == NULL;
}

static int
tls_md5_hash_init_cb (tls_hash_ctx *a)
{
        a->state = malloc(sizeof(tls_md5_ctx));
        if (a->state == NULL) {
                return -1;
        }
        a->statesize = sizeof(tls_md5_ctx);
        tls_MD5_init((tls_MD5_ctx *)a->state);
}

static int
tls_md5_hash_update_cb(tls_hash_ctx *a, const tls_buf *b)
{
        tls_MD5_update((tls_MD5_ctx *)a->state, b);
}

static int
tls_md5_hash_final_cb(tls_buf *b, tls_hash_ctx *a)
{
        tls_MD5_final(b, (tls_MD5_ctx *)a->state);
        final_cleanup(a);
}

void *
tls_hash_md5(void)
{
        tls_hash_ctx *ret;
        ret = malloc(sizeof(tls_hash_ctx));
        if (ret == NULL) {
                return ret;
        }
        ret->init = &tls_hash_md5_init_cb;
        ret->update = &tls_hash_md5_update_cb;
        ret->final = &tls_hash_md5_final_cb;
        ret->copy = &copy_hash;
        return ret;
}

/* Now to do it 4 more times... */
