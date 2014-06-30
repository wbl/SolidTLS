#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include "md5.h"

int main(){
  TLS_MD5_CTX ctx;
  printf("MD5 test suite:\n")
  uint8_t hash[16];
  char * tests[7];
  for(int i=0; i<7; i++){
    tls_md5_init(&ctx);
    tls_md5_update(&ctx, test[i], strlen(test[i]));
    tls_md5_finalize(hash, ctx);
    printf("MD5 (\"%s\") = ", test[i]);
    for(int j=0; j<16; j++){
      printf("%2x", hash[j]);
    }
    printf("\n");
  }
}
