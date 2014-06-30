#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include "md5.h"

int main(){
  TLS_MD5_CTX ctx;
  printf("MD5 test suite:\n");
  uint8_t hash[16];
  char * tests[7];
  tests[0] = "";
  tests[1] = "a";
  tests[2] = "abc";
  tests[3] = "message digest";
  tests[4] = "abcdefghijklmnopqrstuvwxyz";
  tests[5] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  tests[6] = "123456789012345678901234567890123456789012345678901234567890"
    "12345678901234567890";
  for(int i = 0; i < 7; i++){
    tls_MD5_init(&ctx);
    tls_MD5_update(&ctx, tests[i], strlen(tests[i]));
    tls_MD5_final(hash, &ctx);
    printf("MD5 (\"%s\") = ", tests[i]);
    for(int j = 0; j < 16; j++){
      printf("%02x", hash[j]);
    }
    printf("\n");
  }
}
