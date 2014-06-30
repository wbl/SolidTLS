/*	$OpenBSD: md5.h,v 1.2 2012/12/05 23:20:15 deraadt Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#define	TLS_MD5_BLOCK_LENGTH		64
#define	TLS_MD5_DIGEST_LENGTH		16

typedef struct TLS_MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t count;			/* number of bits, mod 2^64 */
	u_int8_t buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} TLS_MD5_CTX;


void	 tls_MD5_init(TLS_MD5_CTX *);
void	 tls_MD5_update(TLS_MD5_CTX *, const uint8_t *, size_t);
void	 tls_MD5_final(uint8_t [TLS_MD5_DIGEST_LENGTH], TLS_MD5_CTX *);

