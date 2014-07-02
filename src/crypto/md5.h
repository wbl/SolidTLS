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

typedef struct {
	uint32_t state[4];			/* state */
	uint64_t count;			/* number of bits, mod 2^64 */
	uint8_t buffer[TLS_MD5_BLOCK_LENGTH];	/* input buffer */
} tls_MD5_ctx;


void	 tls_MD5_init(tls_MD5_ctx *);
void	 tls_MD5_update(tls_MD5_ctx *, const tls_buf *);
void	 tls_MD5_final(tls_buf*, tls_MD5_ctx *);


