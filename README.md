# cl-post-quantum

Pure Common Lisp implementation of post-quantum cryptographic algorithms with **zero external dependencies**.

## Features

- **Kyber**: CRYSTALS-Kyber key encapsulation (ML-KEM)
- **Dilithium**: CRYSTALS-Dilithium signatures (ML-DSA)
- **SPHINCS+**: Hash-based signatures
- **NTRU**: Lattice-based encryption
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-post-quantum)
```

## Quick Start

```lisp
(use-package :cl-post-quantum)

;; Kyber key encapsulation
(multiple-value-bind (public-key secret-key)
    (kyber-keygen :kyber768)
  ;; Encapsulate
  (multiple-value-bind (ciphertext shared-secret)
      (kyber-encapsulate public-key)
    ;; Decapsulate
    (kyber-decapsulate ciphertext secret-key)))

;; Dilithium signatures
(multiple-value-bind (public-key secret-key)
    (dilithium-keygen :dilithium3)
  (let ((signature (dilithium-sign message secret-key)))
    (dilithium-verify message signature public-key)))
```

## API Reference

### Kyber (ML-KEM)

- `(kyber-keygen variant)` - Generate keypair (:kyber512, :kyber768, :kyber1024)
- `(kyber-encapsulate public-key)` - Encapsulate shared secret
- `(kyber-decapsulate ciphertext secret-key)` - Decapsulate shared secret

### Dilithium (ML-DSA)

- `(dilithium-keygen variant)` - Generate keypair
- `(dilithium-sign message secret-key)` - Sign message
- `(dilithium-verify message signature public-key)` - Verify signature

## Testing

```lisp
(asdf:test-system :cl-post-quantum)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
