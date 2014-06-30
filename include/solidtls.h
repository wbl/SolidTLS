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
typedef struct tls_config_struct* tls_config; /* Opaque handle */

tls_config tls_config_new(); /* Returns NULL or a tls_config */
void tls_config_free(tls_config t); /* Cleanup */
void tls_config_setciphersuites(tls_config t, int *suites);
/*Sets ciphersuites*/

typedef tls_X509_struct* tls_X509;
tls_X509 tls_X509_new(); /* Allocate a new X509 list */
void tls_X509_free(tls_X509); /* And destroy it */
int tls_X509_addcerts(tls_X509 set, char *path);
int tls_X509_addcerts_mem(tls_X509 set, uint8_t* mem, size_t len);
/*
 * Add certs in path. Return -1 if error, 0 otherwise.
 */
int tls_X509_keypair(tls_X509 set, char *keypath, char *certpath);
int tls_X509_keypair_mem(tls_X509 set, uint8_t *kmem, int klen,
                         uint8_t *certmem, int certlen);
/*
 * Load a cert with a private key we can use to authenticate
 */

void tls_config_set_roots(tls_config t, tls_X509 roots); /* Set the roots */
void tls_config_set_certchain(tls_config t, tls_X509 key); /* What we send */

/* TODO: consider multiple client certificate issue */

/*
 * TODO: resumption information, DANE/OCSP
 * Resumption is likely to involve talking about threads too much
 */

typedef tls_context_struct * tls_contex; /* Opaque representing connection */

tls_contex tls_context_new(tls_config cfg); /* Create a new TLS context */
void tls_context_free(tls_context t);

/* 
 * Set read and write callbacks.
 */
enum tls_direction {TLS_CLIENT, TLS_SERVER};

void tls_context_set_write(tls_context ctx, void * dat,
                           int (* write)(void *, void *, size_t));
void tls_context_set_read(tls_context ctx, void * dat,
                           int (* read)(void *, void *, size_t));

void tls_set_direction(tls_context ctx, enum tls_direction);
int tls_handshake(tls_context ctx); /* Returns 0 on success */
bool tls_valid_hostname(tls_context ctx, char *host);

/* True if so, false if not*/

/* Read and write data to the other side */
int tls_write(tls_context ctx, char *data, size_t len);
int tls_read(tls_context ctx, char *data, size_t len);

int tls_close(tls_context ctx); /* Return 0, unless something goes wrong */
