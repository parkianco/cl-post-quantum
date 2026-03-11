;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; package.lisp - Package definition for CL-POST-QUANTUM
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Pure Common Lisp implementation of post-quantum cryptographic algorithms.
;;;; Implements NIST FIPS 203 (Kyber/ML-KEM) and FIPS 204 (Dilithium/ML-DSA).

(in-package #:cl-user)

(defpackage #:cl-post-quantum
  (:use #:cl)
  (:nicknames #:pq #:pqc)
  (:documentation
   "Post-quantum cryptographic primitives for Common Lisp.

Implements NIST-standardized algorithms:
  - CRYSTALS-Kyber (ML-KEM): Lattice-based Key Encapsulation
  - CRYSTALS-Dilithium (ML-DSA): Lattice-based Digital Signatures

All algorithms are pure Common Lisp with no external dependencies.")

  (:export
   ;; ============================================================================
   ;; Kyber (ML-KEM) - Key Encapsulation Mechanism
   ;; ============================================================================

   ;; Parameter sets
   #:+kyber-512+
   #:+kyber-768+
   #:+kyber-1024+

   ;; Key types
   #:kyber-public-key
   #:kyber-private-key
   #:kyber-keypair
   #:kyber-keypair-public-key
   #:kyber-keypair-private-key

   ;; Key generation
   #:kyber-keygen
   #:kyber-keygen-512
   #:kyber-keygen-768
   #:kyber-keygen-1024

   ;; Encapsulation/Decapsulation
   #:kyber-encapsulate
   #:kyber-decapsulate

   ;; Serialization
   #:kyber-serialize-public-key
   #:kyber-deserialize-public-key
   #:kyber-serialize-private-key
   #:kyber-deserialize-private-key
   #:kyber-serialize-ciphertext
   #:kyber-deserialize-ciphertext

   ;; Size queries
   #:kyber-public-key-bytes
   #:kyber-private-key-bytes
   #:kyber-ciphertext-bytes
   #:kyber-shared-secret-bytes

   ;; ============================================================================
   ;; Dilithium (ML-DSA) - Digital Signatures
   ;; ============================================================================

   ;; Parameter sets
   #:+dilithium2+
   #:+dilithium3+
   #:+dilithium5+

   ;; Key types
   #:dilithium-public-key
   #:dilithium-private-key
   #:dilithium-keypair
   #:dilithium-keypair-public-key
   #:dilithium-keypair-private-key

   ;; Key generation
   #:dilithium-keygen
   #:dilithium-keygen-2
   #:dilithium-keygen-3
   #:dilithium-keygen-5

   ;; Signing and verification
   #:dilithium-sign
   #:dilithium-verify

   ;; Serialization
   #:dilithium-serialize-public-key
   #:dilithium-deserialize-public-key
   #:dilithium-serialize-private-key
   #:dilithium-deserialize-private-key
   #:dilithium-serialize-signature
   #:dilithium-deserialize-signature

   ;; Size queries
   #:dilithium-public-key-bytes
   #:dilithium-private-key-bytes
   #:dilithium-signature-bytes

   ;; ============================================================================
   ;; NTT (Number Theoretic Transform) - Low-level operations
   ;; ============================================================================

   #:ntt-forward
   #:ntt-inverse
   #:ntt-multiply
   #:ntt-add
   #:ntt-sub

   ;; ============================================================================
   ;; Polynomial Operations
   ;; ============================================================================

   #:sample-uniform-poly
   #:sample-error-poly
   #:compress-poly
   #:decompress-poly
   #:pack-poly
   #:unpack-poly

   ;; ============================================================================
   ;; Conditions
   ;; ============================================================================

   #:post-quantum-error
   #:kyber-error
   #:dilithium-error
   #:key-generation-error
   #:encapsulation-error
   #:decapsulation-error
   #:signature-error
   #:verification-error
   #:invalid-parameter-error
   ))
