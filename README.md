# fog-crypto

[![Build](https://github.com/Cognoscan/fog-crypto/workflows/Rust/badge.svg)](
https://github.com/Cognoscan/fog-crypto/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](
https://github.com/Cognoscan/fog-crypto)
[![Cargo](https://img.shields.io/crates/v/fog-crypto.svg)](
https://crates.io/crates/fog-crypto)
[![Documentation](https://docs.rs/fog-crypto/badge.svg)](
https://docs.rs/fog-crypto)

A simple storage-oriented cryptographic library that offers you freedom from choice. It
supports hashing, public key signatures, public key & symmetric key encryption, key
export/import, and basic key storage.

Getting cryptography right can be hard. This library attempts to make things easy by only
providing a small number of cryptographic primitives, makes strong decisions about the
cryptographic algorithms and their implementations, and tries to limit the number of bad things
an end user can do. Changing algorithms should be infrequent, and follows a planned process
(see [Cryptographic Versioning](#cryptographic-versioning)). On the plus side, it's pretty hard
to misuse this library in ways that leak secrets and compromise security. On the downside, this
library is pretty strongly meant for working with stored data, not communication protocols, and
cannot support even remotely unusual cryptographic operations. Forcing use of a single preferred
set of algorithms also greatly limits hardware compatibility.

# User Guidelines

You probably shouldn't be using this library directly. Portions of it should instead be 
exported by an implementor of a Vault, and you should use those. Alternately, you might be 
using this through [`fog-pack`](https://crates.io/crates/fog-pack), which also re-exports 
portions of this library. You can expect to see these primitives:

General:
- `Vault`: A structure that can hold onto your cryptographic keys.

Hashing:
- `Hash`: The cryptographic hash of a sequence of bytes.
- `HashState`: A structure for iteratively feeding in bytes to create a `Hash`.

Signatures:
- `Signature`: A validated cryptographic signature of a `Hash`.
- `UnverifiedSignature`: A cryptographic signature that hasn't been verified yet.
- `IdentityKey`: A private key for signing hashes.
- `Identity`: A public key identity to indicate which `IdentityKey` created a given `Signature`.

Symmetric-Key Encryption:
- `StreamKey`: A shared symmetric key for encrypting & decrypting data.
- `StreamId`: A public, unique identifier for indicating what `StreamKey` should be used
  for decrypting encrypted data.

Public-Key Encryption:
- `LockKey`: A private key for decrypting data.
- `LockId`: A public key to indicate what `LockKey` should be used for decrypting encrypted
  data.

Encrypted Storage:
- `IdentityLockbox`: An encrypted container that holds a `IdentityKey`.
- `StreamLockbox`: An encrypted container that holds a `StreamKey`.
- `LockLockbox`: An encrypted container that holds a `LockKey`.
- `DataLockbox`: An encrypted container that holds a byte sequence.

# Vault Implementor Guidelines

First, re-export the structs listed in the user guidelines. If your vault is entirely in
software, you probably want to use the various `ContainedXXX` structs for holding keys, and
store them by exporting them for some master key. Avoid letting the keys sit around in some
unencrypted form. Your master key can be created by obtaining a 32-byte random byte sequence,
prepending it with a 1 (the version byte), and using `ContainedStreamKey`'s `try_from`
implementation to encapsulate the sequence. Make sure to zeroize the master key after doing
this!

If your vault has a hardware or OS component, your hardware vault's capabilities may be
limited in its ability to store all types of keys. In this case, you will need to have a
software-side implementation to make up for the missing storage. A recommended approach here is
to actually accept a reference to a pure-software vault on creation, and let it handle any
unsupported operations. Your vault can then capture all operations that it does support.

Alternately, if your hardware / OS component supports an extremely small subset of
functionality, cannot perform any type of key import/export, and is meant for high risk
scenarios, consider not supporting the Vault trait at all. Instead, create your own key store
interface, and provide backer implementations for just the supported interfaces (your options
being `SignInterface`, `StreamInterface`, and `LockInterface`).

# Cryptographic Algorithms Used

The currently used algorithms are:

- Hashing: Blake2B with a 32-byte digest
- Signing: Ed25519 with ["strict" verification][StrictVerification]
- Symmetric Encryption: AEAD cipher using XChaCha20 and Poly1305.
- Diffie-Hellman key exchange: X25519

# Cryptographic Versioning

This library has 4 core cryptographic algorithms that may be upgraded over time:

- The hash algorithm
- The signing algorithm
- The symmetric encryption algorithm (including bulk encryption, AEAD construction, and HMAC)
- The Diffie-Hellman (DH) key exchange algorithm (used for encrypting data with a public key)

Upgrades should be infrequent, and are done roughly when an existing recommended algorithm is
regarded as weak but not yet broken.

The ideal upgrade process is:

1. A new algorithm is selected to replace an existing one.
2. The new algorithm is implemented. The relevant MAX_VERSION constant is incremented.
3. After being deployed for 1 year, the relevant DEFAULT_VERSION constant is incremented. This
   gives time for library users to support the new algorithm without breaking non-updated
   deployments.
4. After 2 more years, the relevant MIN_VERSION constant is incremented. This gives time for
   library users to increment the default version on all deployments, then upgrade all existing
   stored data as required.

This is the best-case upgrade scenario. If an existing algorithm is considered broken, the
DEFAULT_VERSION and MIN_VERSION will be incremented as soon as possible. "Broken" here means it
is feasible for a well-funded attacker to compromise the algorithm. Breaking compatibility with
deployed code is considered an acceptable choice when security is compromised.

We are almost certainly going to upgrade the signing and DH exchange algorithms in the future,
as we will need to move to post-quantum algorithms. There's no similar looming threat for the
hash & symmetric encryption algorithms.

[StrictVerification]: https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.PublicKey.html#method.verify_strict
