#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include "buf.h"
#include "sha64.h"

/*
 * Compare results to those obtained from where?
 */

int
main()
{
        tls_SHA384_ctx ctx;
        printf("SHA384 test suite:\n");
        tls_buf hash;
        tls_buf tests[7];
        tls_buf_init(&hash);
        tls_buf_ensure_cap(&hash, TLS_SHA384_DIGEST_LENGTH);
        for (int i=0; i<7; i++) {
                tls_buf_init(&(tests[i]));
        }
        
        tls_buf_copy_string(&tests[0], "");
        tls_buf_copy_string(&tests[1] ,"a");
        tls_buf_copy_string(&tests[2], "abc");
        tls_buf_copy_string(&tests[3], "message digest");
        tls_buf_copy_string(&tests[4], "abcdefghijklmnopqrstuvwxyz");
        tls_buf_copy_string(&tests[5], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        tls_buf_copy_string(&tests[6] ,"1234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890");
        for(int i = 0; i < 7; i++){
                tls_SHA384_init(&ctx);
                tls_SHA384_update(&ctx, &tests[i]);
                tls_SHA384_final(&hash, &ctx);
                for (int j = 0; j < 48; j++) {
                        printf("%02x", tls_buf_get(&hash, j));
                } 
                printf("\n");
        }
}
