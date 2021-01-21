# fog-crypto

fog-crypto defines a simplified cryptographic interface for working with 
private-key and symmetric-key cryptography. This can be used to more easily 
sign & encrypt blocks of data and manage keys.

This library provides a few useful cryptographic primitives. The algorithm used 
for each is versioned; this takes the place of traditional crypto-agility. The 
available primitives are:

- `Hash`: a cryptographic hash of a byte sequence. It can be incrementally 
	generated using a `HashState`.
- `StreamKey`: A symmetric key for encrypting/decrypting a block of bytes. 
  Identical byte blocks do not produce identical ciphertexts.
- `Key`: A private key for signing or decrypting a block of bytes. Has an 
	associated `Identity`.
- `Identity`: A public key for verifying a signature or encrypting a block of 
	bytes for a specific recipient. Has an associated `Key`.
- `Lockbox`: A container for encrypted data. Can hold a `StreamKey`, `Key`, or 
	arbitrary block of bytes.
- `Vault`: Stores cryptographic secrets, namely the actual private keys used by 
	`Key` and the actual symmetric keys used by `StreamKey`.

All keys are generated and managed by a Vault. Vaults perform the actual signing 
and encryption, while the program only has a reference to a given key. This 
allows future implementors of a Vault to use secure enclaves or OS-managed keys.


