#include <sodium.h>
#include <stdio.h>
#include <stdint.h>

int main() {

  sodium_init();
  #define CONTEXT "fogpack"
  uint8_t master_key[crypto_kdf_KEYBYTES];
  uint8_t subkey1[32];
  crypto_kdf_keygen(master_key);
  crypto_kdf_derive_from_key(subkey1, sizeof subkey1, 1, CONTEXT, master_key);

  printf("Key: ");
  for (int i=0; i<32; i=i+1) { 
    printf("%02x ", master_key[i]);
  }
  printf("\n");
  printf("Subkey: ");
  for (int i=0; i<32; i=i+1) { 
    printf("%02x ", subkey1[i]);
  }
  printf("\n");
  return 0;
}
