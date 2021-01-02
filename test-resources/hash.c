#include <sodium.h>
#include <stdio.h>
#include <stdint.h>

int main() {

  sodium_init();

  uint8_t out[32];
  uint8_t in[256];
  size_t in_len = 0;
  size_t out_len = sizeof out;

  for (int i=0; i<256; i++) {
    in[i] = i;
  }

  printf("[\n");
  for (int j=0; j<256; j=j+1) {
    in_len = j;
    crypto_generichash_blake2b(out, sizeof out, in, in_len, NULL, 0);
    printf("{ \"out\":\"");
    for (int i=0; i<out_len; i=i+1) { 
      printf("%02x", out[i]);
    }
    printf("\",\"input\":\"");
    for (int i=0; i<in_len; i=i+1) { 
      printf("%02x", in[i]);
    }
    if (j==255) {
      printf("\"}\n");
    }
    else {
      printf("\"},\n");
    }
  }
  printf("]");
  printf("\n");
  return 0;
}
