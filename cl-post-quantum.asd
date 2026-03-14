;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-post-quantum.asd - Post-Quantum Cryptography for Common Lisp
;;;;
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem #:cl-post-quantum
  :version "0.1.0"
  :author "Parkian Company LLC"
  :license "MIT"
  :description "Pure Common Lisp implementation of post-quantum cryptographic algorithms"
  :long-description
  "CL-POST-QUANTUM provides NIST-standardized post-quantum cryptographic primitives:

   - CRYSTALS-Kyber (ML-KEM): Lattice-based Key Encapsulation Mechanism
   - CRYSTALS-Dilithium (ML-DSA): Lattice-based Digital Signatures

   Features:
   - Pure Common Lisp, no external dependencies
   - SBCL optimized with type declarations
   - Constant-time operations for side-channel resistance
   - NIST FIPS 203/204 compliant

   Security Levels:
   - Kyber-512/768/1024: NIST Level 1/3/5
   - Dilithium2/3/5: NIST Level 2/3/5"

  :depends-on ()  ; No external dependencies - pure CL
  :serial t
  :components
  ((:file "package")
   (:module "src"
    :serial t
    :components
    ((:file "util")      ; Helpers, byte operations
     (:file "ntt")       ; Number Theoretic Transform
     (:file "poly")      ; Polynomial operations
     (:file "kyber")     ; CRYSTALS-Kyber KEM
     (:file "dilithium") ; CRYSTALS-Dilithium signatures
     )))
  :in-order-to ((asdf:test-op (test-op #:cl-post-quantum/test))))

(asdf:defsystem #:cl-post-quantum/test
  :version "0.1.0"
  :author "Parkian Company LLC"
  :license "MIT"
  :description "Tests for CL-POST-QUANTUM"
  :depends-on (#:cl-post-quantum)
  :serial t
  :components
  ((:module "test"
    :serial t
    :components
    ((:file "test-pq"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-post-quantum/test :run-all-tests)))
               (unless result
                 (error "Tests failed")))))
