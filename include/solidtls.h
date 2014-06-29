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

/*
 * The basic level: TLS connections
 */
typedef void* tls_config; /* Opaque handle */

tls_config tls_config_new(); /* Returns NULL or a tls_config */
void tls_config_free(tls_config t); /* Cleanup */

/*
 * TODO: X509 information, resumption information, DANE/OCSP, ciphersuites
 * Resumption is likely to involve talking about threads too much
 *
 */

typedef void* tls_contex; /* Opaque representing connection */

tls_contex tls_contex_new(tls_config cfg); /* Create a new TLS context */
void tls_config_free(tls_config t);

/* 
 * Set read and write callbacks.
 */
enum tls_direction {TLS_CLIENT, TLS_SERVER};

void tls_contex_set_write(tls_context ctx,
                           int (* write)(void *, void *, size_t));
void tls_contex_set_read(tls_context ctx,
                           int (* read)(void *, void *, size_t));

void tls_set_direction(tls_context ctx, enum tls_direction);
int tls_handshake(tls_context ctx); /* Returns 0 on success */
bool tls_valid_hostname(tls_context ctx, char *host);

/* True if so, false if not*/

/* Read and write data to the other side */
int tls_write(tls_context ctx, char *data, size_t len);
int tls_read(tls_context ctx, char *data, size_t len);

int tls_close(tls_context ctx); /* Return 0, unless something goes wrong */