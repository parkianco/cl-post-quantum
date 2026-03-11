;;;; dilithium.lisp - CRYSTALS-Dilithium Digital Signatures
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Pure Common Lisp implementation of CRYSTALS-Dilithium (ML-DSA).
;;;; Implements NIST FIPS 204 for post-quantum digital signatures.
;;;;
;;;; Security Levels:
;;;;   - Dilithium2: NIST Level 2 (~128-bit post-quantum)
;;;;   - Dilithium3: NIST Level 3 (~192-bit post-quantum)
;;;;   - Dilithium5: NIST Level 5 (~256-bit post-quantum)

(in-package #:cl-post-quantum)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Dilithium Constants
;;; ============================================================================

(defconstant +dilithium-n+ 256
  "Polynomial degree for Dilithium ring R_q = Z_q[X]/(X^256 + 1)")

(defconstant +dilithium-q+ 8380417
  "Modulus q for Dilithium. Prime with q = 1 (mod 512).")

(defconstant +dilithium-root+ 1753
  "Primitive 512th root of unity mod q.")

(defconstant +dilithium-d+ 13
  "Number of dropped bits from t for compression.")

;;; ============================================================================
;;; Dilithium Parameter Sets
;;; ============================================================================

(defstruct (dilithium-params (:constructor %make-dilithium-params))
  "Dilithium parameter set.
   K: Number of rows in matrix A
   L: Number of columns in matrix A
   ETA: Secret key coefficient bound
   TAU: Number of ones in challenge polynomial
   BETA: Signature bound (tau * eta)
   GAMMA1: y coefficient bound (2^17 or 2^19)
   GAMMA2: Low-order rounding range ((q-1)/88 or (q-1)/32)
   OMEGA: Maximum number of ones in hint"
  (k 4 :type (member 4 6 8) :read-only t)
  (l 4 :type (member 4 5 7) :read-only t)
  (eta 2 :type (member 2 4) :read-only t)
  (tau 39 :type (integer 39 60) :read-only t)
  (beta 78 :type integer :read-only t)
  (gamma1 (ash 1 17) :type integer :read-only t)
  (gamma2 (floor (1- +dilithium-q+) 88) :type integer :read-only t)
  (omega 80 :type (integer 55 120) :read-only t))

(defun make-dilithium-params (&key (k 4) (l 4) (eta 2) (tau 39) (beta 78)
                                    (gamma1 (ash 1 17))
                                    (gamma2 (floor (1- +dilithium-q+) 88))
                                    (omega 80))
  "Create Dilithium parameters with validation."
  (unless (member k '(4 6 8))
    (error 'invalid-parameter-error :parameter :k :value k))
  (%make-dilithium-params :k k :l l :eta eta :tau tau :beta beta
                          :gamma1 gamma1 :gamma2 gamma2 :omega omega))

;; Dilithium2 (NIST Level 2)
(defparameter +dilithium2+
  (make-dilithium-params :k 4 :l 4 :eta 2 :tau 39 :beta 78
                         :gamma1 (ash 1 17)
                         :gamma2 (floor (1- +dilithium-q+) 88)
                         :omega 80)
  "Dilithium2 parameters (ML-DSA-44, NIST Level 2).")

;; Dilithium3 (NIST Level 3)
(defparameter +dilithium3+
  (make-dilithium-params :k 6 :l 5 :eta 4 :tau 49 :beta 196
                         :gamma1 (ash 1 19)
                         :gamma2 (floor (1- +dilithium-q+) 32)
                         :omega 55)
  "Dilithium3 parameters (ML-DSA-65, NIST Level 3).")

;; Dilithium5 (NIST Level 5)
(defparameter +dilithium5+
  (make-dilithium-params :k 8 :l 7 :eta 2 :tau 60 :beta 120
                         :gamma1 (ash 1 19)
                         :gamma2 (floor (1- +dilithium-q+) 32)
                         :omega 75)
  "Dilithium5 parameters (ML-DSA-87, NIST Level 5).")

;;; ============================================================================
;;; Size Calculations
;;; ============================================================================

(defun dilithium-public-key-bytes (params)
  "Calculate public key size in bytes."
  (let ((k (dilithium-params-k params)))
    (+ 32                          ; seed rho
       (* k 320))))                ; t1 (k * 10 bits * 256 / 8)

(defun dilithium-private-key-bytes (params)
  "Calculate private key size in bytes."
  (let ((k (dilithium-params-k params))
        (l (dilithium-params-l params))
        (eta (dilithium-params-eta params)))
    (+ 32                          ; rho
       32                          ; K (key)
       32                          ; tr (H(pk))
       (* l (if (= eta 2) 96 128)) ; s1 (l * eta_bits * 256 / 8)
       (* k (if (= eta 2) 96 128)) ; s2
       (* k 416))))                ; t0 (k * 13 bits * 256 / 8)

(defun dilithium-signature-bytes (params)
  "Calculate signature size in bytes."
  (let ((k (dilithium-params-k params))
        (l (dilithium-params-l params))
        (gamma1 (dilithium-params-gamma1 params))
        (omega (dilithium-params-omega params)))
    (+ 32                                    ; c~ (challenge seed)
       (* l (if (= gamma1 (ash 1 17)) 576 640)) ; z
       (+ omega k))))                        ; h (hint)

;;; ============================================================================
;;; Key Structures
;;; ============================================================================

(defstruct (dilithium-public-key (:constructor %make-dilithium-public-key))
  "Dilithium public key containing seed rho and polynomial vector t1."
  (params nil :type dilithium-params :read-only t)
  (rho nil :type (simple-array (unsigned-byte 8) (32)) :read-only t)
  (t1 nil :read-only t))  ; Vector of k polynomials

(defstruct (dilithium-private-key (:constructor %make-dilithium-private-key))
  "Dilithium private key containing secrets and public key components."
  (params nil :type dilithium-params :read-only t)
  (rho nil :type (simple-array (unsigned-byte 8) (32)) :read-only t)
  (k-seed nil :type (simple-array (unsigned-byte 8) (32)) :read-only t)
  (tr nil :type (simple-array (unsigned-byte 8) (32)) :read-only t)
  (s1 nil :read-only t)   ; Secret vector l polynomials
  (s2 nil :read-only t)   ; Secret vector k polynomials
  (t0 nil :read-only t))  ; Low bits of t

(defstruct (dilithium-keypair (:constructor %make-dilithium-keypair))
  "A Dilithium key pair."
  (public-key nil :type dilithium-public-key :read-only t)
  (private-key nil :type dilithium-private-key :read-only t))

;;; ============================================================================
;;; Matrix and Vector Generation
;;; ============================================================================

(defun dilithium-expand-a (rho k l)
  "Expand seed rho to k x l matrix A using SHAKE128."
  (let ((matrix (make-array (list k l))))
    (dotimes (i k matrix)
      (dotimes (j l)
        (let ((nonce (+ (* i 256) j)))
          (setf (aref matrix i j)
                (sample-uniform-poly rho nonce :n +dilithium-n+ :modulus +dilithium-q+)))))))

(defun dilithium-sample-secret (seed nonce eta n)
  "Sample secret polynomial with coefficients in [-eta, eta]."
  (sample-error-poly seed nonce :n n :eta eta))

;;; ============================================================================
;;; Power2Round and Decompose
;;; ============================================================================

(defun dilithium-power2round (r d)
  "Decompose r into r1 and r0 where r = r1*2^d + r0.
   Returns: (VALUES r1 r0)"
  (let* ((r (mod r +dilithium-q+))
         (r0 (mod r (ash 1 d)))
         (r0 (if (> r0 (ash 1 (1- d))) (- r0 (ash 1 d)) r0))
         (r1 (ash (- r r0) (- d))))
    (values r1 r0)))

(defun dilithium-decompose (r gamma2)
  "High-order/low-order decomposition of r.
   Returns: (VALUES r1 r0) where r = r1*alpha + r0"
  (let* ((alpha (* 2 gamma2))
         (r (mod r +dilithium-q+))
         (r0 (mod r alpha)))
    (when (> r0 gamma2)
      (decf r0 alpha))
    (if (= (- r r0) (1- +dilithium-q+))
        (values 0 (1- r0))
        (values (floor (- r r0) alpha) r0))))

(defun dilithium-highbits (r gamma2)
  "Extract high bits of r."
  (multiple-value-bind (r1 r0) (dilithium-decompose r gamma2)
    (declare (ignore r0))
    r1))

(defun dilithium-lowbits (r gamma2)
  "Extract low bits of r."
  (multiple-value-bind (r1 r0) (dilithium-decompose r gamma2)
    (declare (ignore r1))
    r0))

;;; ============================================================================
;;; Hint Functions
;;; ============================================================================

(defun dilithium-make-hint (z r gamma2)
  "Compute hint bit: 1 if highbits(r) != highbits(r+z)."
  (let ((r1 (dilithium-highbits r gamma2))
        (rz1 (dilithium-highbits (+ r z) gamma2)))
    (if (= r1 rz1) 0 1)))

(defun dilithium-use-hint (hint r gamma2)
  "Recover high bits using hint."
  (let* ((alpha (* 2 gamma2))
         (r1 (dilithium-highbits r gamma2)))
    (if (zerop hint)
        r1
        (let ((m (floor +dilithium-q+ alpha)))
          (mod (if (plusp (dilithium-lowbits r gamma2))
                   (1+ r1)
                   (1- r1))
               m)))))

;;; ============================================================================
;;; Challenge Generation
;;; ============================================================================

(defun dilithium-sample-challenge (seed tau)
  "Sample challenge polynomial c with exactly tau ones in {-1,1}."
  (let ((c (make-zero-poly +dilithium-n+))
        (xof (shake256 seed 136)))
    ;; Fisher-Yates shuffle to place tau non-zero coefficients
    (loop with pos = 0
          for i from (- +dilithium-n+ tau) below +dilithium-n+
          do (let ((j (mod (aref xof pos) (1+ i))))
               (incf pos)
               ;; Swap
               (setf (aref c i) (aref c j))
               ;; Set random sign
               (setf (aref c j) (if (oddp (aref xof pos)) 1 -1))
               (incf pos)))
    c))

;;; ============================================================================
;;; Key Generation
;;; ============================================================================

(defun dilithium-keygen (&optional (params +dilithium3+))
  "Generate a Dilithium key pair.
   PARAMS: Parameter set (default Dilithium3)
   Returns: DILITHIUM-KEYPAIR"
  (let* ((k (dilithium-params-k params))
         (l (dilithium-params-l params))
         (eta (dilithium-params-eta params))
         ;; Generate random seed
         (xi (get-random-bytes 32))
         ;; Expand seed
         (expanded (shake256 xi 128))
         (rho (subseq expanded 0 32))
         (rho-prime (subseq expanded 32 96))
         (k-seed (subseq expanded 96 128))
         ;; Expand matrix A
         (a-hat (dilithium-expand-a rho k l))
         ;; Generate secret vectors
         (s1 (make-array l))
         (s2 (make-array k)))

    ;; Sample s1 and s2
    (dotimes (i l)
      (setf (aref s1 i)
            (dilithium-sample-secret rho-prime i eta +dilithium-n+)))
    (dotimes (i k)
      (setf (aref s2 i)
            (dilithium-sample-secret rho-prime (+ l i) eta +dilithium-n+)))

    ;; Compute t = A*s1 + s2
    (let ((s1-hat (make-array l))
          (t-vec (make-array k)))
      ;; NTT of s1
      (dotimes (i l)
        (setf (aref s1-hat i)
              (ntt-forward (aref s1 i) :modulus +dilithium-q+ :root +dilithium-root+)))
      ;; A * s1
      (dotimes (i k)
        (let ((sum (make-zero-poly +dilithium-n+)))
          (dotimes (j l)
            (let ((a-ij-hat (ntt-forward (aref a-hat i j)
                                          :modulus +dilithium-q+ :root +dilithium-root+)))
              (setf sum (ntt-add sum
                                 (ntt-multiply a-ij-hat (aref s1-hat j) :modulus +dilithium-q+)
                                 :modulus +dilithium-q+))))
          (setf (aref t-vec i)
                (ntt-add (ntt-inverse sum :modulus +dilithium-q+ :root +dilithium-root+)
                         (aref s2 i)
                         :modulus +dilithium-q+))))

      ;; Power2Round t to get t1, t0
      (let ((t1 (make-array k))
            (t0 (make-array k)))
        (dotimes (i k)
          (let ((t1-i (make-zero-poly +dilithium-n+))
                (t0-i (make-zero-poly +dilithium-n+)))
            (dotimes (j +dilithium-n+)
              (multiple-value-bind (hi lo)
                  (dilithium-power2round (aref (aref t-vec i) j) +dilithium-d+)
                (setf (aref t1-i j) hi)
                (setf (aref t0-i j) lo)))
            (setf (aref t1 i) t1-i)
            (setf (aref t0 i) t0-i)))

        ;; Create public key and hash it
        (let* ((pk (%make-dilithium-public-key :params params :rho rho :t1 t1))
               (pk-bytes (dilithium-serialize-public-key pk))
               (tr (sha3-256 pk-bytes))
               (sk (%make-dilithium-private-key
                    :params params :rho rho :k-seed k-seed :tr tr
                    :s1 s1 :s2 s2 :t0 t0)))
          (%make-dilithium-keypair :public-key pk :private-key sk))))))

;; Convenience functions
(defun dilithium-keygen-2 ()
  "Generate Dilithium2 keypair (NIST Level 2)."
  (dilithium-keygen +dilithium2+))

(defun dilithium-keygen-3 ()
  "Generate Dilithium3 keypair (NIST Level 3)."
  (dilithium-keygen +dilithium3+))

(defun dilithium-keygen-5 ()
  "Generate Dilithium5 keypair (NIST Level 5)."
  (dilithium-keygen +dilithium5+))

;;; ============================================================================
;;; Signing
;;; ============================================================================

(defun dilithium-sign (message private-key)
  "Sign message with Dilithium private key.
   MESSAGE: Byte vector to sign
   PRIVATE-KEY: Dilithium private key
   Returns: Signature as byte vector"
  (let* ((params (dilithium-private-key-params private-key))
         (k (dilithium-params-k params))
         (l (dilithium-params-l params))
         (eta (dilithium-params-eta params))
         (tau (dilithium-params-tau params))
         (beta (dilithium-params-beta params))
         (gamma1 (dilithium-params-gamma1 params))
         (gamma2 (dilithium-params-gamma2 params))
         (omega (dilithium-params-omega params))
         (rho (dilithium-private-key-rho private-key))
         (k-seed (dilithium-private-key-k-seed private-key))
         (tr (dilithium-private-key-tr private-key))
         (s1 (dilithium-private-key-s1 private-key))
         (s2 (dilithium-private-key-s2 private-key))
         (t0 (dilithium-private-key-t0 private-key))
         ;; Hash message with tr
         (mu (sha3-256 (concat-bytes tr message)))
         ;; Compute rho' for masking
         (rho-prime (sha3-256 (concat-bytes k-seed mu)))
         ;; Expand matrix A
         (a-hat (dilithium-expand-a rho k l))
         ;; NTT of secrets
         (s1-hat (make-array l))
         (s2-hat (make-array k))
         (t0-hat (make-array k)))

    ;; Precompute NTTs
    (dotimes (i l)
      (setf (aref s1-hat i)
            (ntt-forward (aref s1 i) :modulus +dilithium-q+ :root +dilithium-root+)))
    (dotimes (i k)
      (setf (aref s2-hat i)
            (ntt-forward (aref s2 i) :modulus +dilithium-q+ :root +dilithium-root+))
      (setf (aref t0-hat i)
            (ntt-forward (aref t0 i) :modulus +dilithium-q+ :root +dilithium-root+)))

    ;; Rejection sampling loop
    (let ((kappa 0))
      (loop
        ;; Sample y with coefficients in [-gamma1+1, gamma1]
        (let ((y (make-array l)))
          (dotimes (i l)
            (let ((yi (make-zero-poly +dilithium-n+)))
              (dotimes (j +dilithium-n+)
                (setf (aref yi j)
                      (- (mod (+ (aref (shake256 (concat-bytes rho-prime
                                                               (integer-to-bytes kappa 2))
                                                 (* 4 +dilithium-n+))
                                       (* i +dilithium-n+) j)
                                 (* 2 gamma1))
                              (* 2 gamma1))
                         gamma1)))
              (setf (aref y i) yi))
            (incf kappa))

          ;; w = A*y
          (let ((y-hat (make-array l))
                (w (make-array k)))
            (dotimes (i l)
              (setf (aref y-hat i)
                    (ntt-forward (aref y i) :modulus +dilithium-q+ :root +dilithium-root+)))
            (dotimes (i k)
              (let ((sum (make-zero-poly +dilithium-n+)))
                (dotimes (j l)
                  (let ((a-ij-hat (ntt-forward (aref a-hat i j)
                                                :modulus +dilithium-q+ :root +dilithium-root+)))
                    (setf sum (ntt-add sum
                                       (ntt-multiply a-ij-hat (aref y-hat j) :modulus +dilithium-q+)
                                       :modulus +dilithium-q+))))
                (setf (aref w i)
                      (ntt-inverse sum :modulus +dilithium-q+ :root +dilithium-root+))))

            ;; w1 = HighBits(w)
            (let ((w1 (make-array k)))
              (dotimes (i k)
                (let ((w1-i (make-zero-poly +dilithium-n+)))
                  (dotimes (j +dilithium-n+)
                    (setf (aref w1-i j) (dilithium-highbits (aref (aref w i) j) gamma2)))
                  (setf (aref w1 i) w1-i)))

              ;; Challenge c = H(mu || w1)
              (let* ((w1-bytes (make-octet-vector (* k 32)))
                     (_ (dotimes (i k)
                          (replace w1-bytes (pack-poly (aref w1 i) 8)
                                   :start1 (* i 32))))
                     (c-seed (sha3-256 (concat-bytes mu w1-bytes)))
                     (c (dilithium-sample-challenge c-seed tau))
                     (c-hat (ntt-forward c :modulus +dilithium-q+ :root +dilithium-root+)))
                (declare (ignore _))

                ;; z = y + c*s1
                (let ((z (make-array l))
                      (reject nil))
                  (dotimes (i l)
                    (let ((cs1 (ntt-inverse
                                (ntt-multiply c-hat (aref s1-hat i) :modulus +dilithium-q+)
                                :modulus +dilithium-q+ :root +dilithium-root+)))
                      (setf (aref z i)
                            (ntt-add (aref y i) cs1 :modulus +dilithium-q+))
                      ;; Check norm
                      (dotimes (j +dilithium-n+)
                        (let ((zj (aref (aref z i) j)))
                          (when (>= (ct-abs zj) (- gamma1 beta))
                            (setf reject t))))))

                  (unless reject
                    ;; Check w - c*s2
                    (let ((cs2 (make-array k)))
                      (dotimes (i k)
                        (setf (aref cs2 i)
                              (ntt-inverse
                               (ntt-multiply c-hat (aref s2-hat i) :modulus +dilithium-q+)
                               :modulus +dilithium-q+ :root +dilithium-root+)))
                      ;; w0 = LowBits(w - c*s2)
                      (dotimes (i k)
                        (unless reject
                          (dotimes (j +dilithium-n+)
                            (let* ((wcs2 (mod (- (aref (aref w i) j) (aref (aref cs2 i) j))
                                              +dilithium-q+))
                                   (w0 (dilithium-lowbits wcs2 gamma2)))
                              (when (>= (abs w0) (- gamma2 beta))
                                (setf reject t)))))))

                    (unless reject
                      ;; Compute hint h
                      (let ((h (make-array k))
                            (h-count 0))
                        (dotimes (i k)
                          (let ((hi (make-zero-poly +dilithium-n+)))
                            (dotimes (j +dilithium-n+)
                              (let* ((ct0 (ntt-inverse
                                           (ntt-multiply c-hat (aref t0-hat i) :modulus +dilithium-q+)
                                           :modulus +dilithium-q+ :root +dilithium-root+))
                                     (wcs2ct0 (mod (+ (aref (aref w i) j)
                                                      (- (aref ct0 j))
                                                      (- (aref (aref cs2 i) j)))
                                                   +dilithium-q+))
                                     (hint (dilithium-make-hint (aref ct0 j) wcs2ct0 gamma2)))
                                (setf (aref hi j) hint)
                                (incf h-count hint)))
                            (setf (aref h i) hi)))

                        (unless (> h-count omega)
                          ;; Success! Encode signature
                          (return
                            (dilithium-encode-signature params c-seed z h)))))))))))))))

;;; ============================================================================
;;; Verification
;;; ============================================================================

(defun dilithium-verify (message signature public-key)
  "Verify Dilithium signature.
   MESSAGE: Original message
   SIGNATURE: Signature from dilithium-sign
   PUBLIC-KEY: Dilithium public key
   Returns: T if valid, NIL otherwise"
  (handler-case
      (let* ((params (dilithium-public-key-params public-key))
             (k (dilithium-params-k params))
             (l (dilithium-params-l params))
             (tau (dilithium-params-tau params))
             (beta (dilithium-params-beta params))
             (gamma1 (dilithium-params-gamma1 params))
             (gamma2 (dilithium-params-gamma2 params))
             (omega (dilithium-params-omega params))
             (rho (dilithium-public-key-rho public-key))
             (t1 (dilithium-public-key-t1 public-key)))

        ;; Parse signature
        (multiple-value-bind (c-seed z h)
            (dilithium-decode-signature signature params)

          ;; Check z norms
          (dotimes (i l)
            (dotimes (j +dilithium-n+)
              (when (>= (ct-abs (aref (aref z i) j)) (- gamma1 beta))
                (return-from dilithium-verify nil))))

          ;; Expand matrix A
          (let ((a-hat (dilithium-expand-a rho k l))
                ;; Hash public key
                (tr (sha3-256 (dilithium-serialize-public-key public-key)))
                ;; Sample challenge
                (c (dilithium-sample-challenge c-seed tau)))

            ;; Compute mu = H(tr || M)
            (let* ((mu (sha3-256 (concat-bytes tr message)))
                   ;; NTTs
                   (z-hat (make-array l))
                   (c-hat (ntt-forward c :modulus +dilithium-q+ :root +dilithium-root+)))

              (dotimes (i l)
                (setf (aref z-hat i)
                      (ntt-forward (aref z i) :modulus +dilithium-q+ :root +dilithium-root+)))

              ;; w' = A*z - c*t1*2^d
              (let ((w-prime (make-array k)))
                (dotimes (i k)
                  (let ((sum (make-zero-poly +dilithium-n+)))
                    ;; A*z
                    (dotimes (j l)
                      (let ((a-ij-hat (ntt-forward (aref a-hat i j)
                                                    :modulus +dilithium-q+ :root +dilithium-root+)))
                        (setf sum (ntt-add sum
                                           (ntt-multiply a-ij-hat (aref z-hat j) :modulus +dilithium-q+)
                                           :modulus +dilithium-q+))))
                    ;; - c*t1*2^d
                    (let ((t1-scaled (make-zero-poly +dilithium-n+)))
                      (dotimes (j +dilithium-n+)
                        (setf (aref t1-scaled j)
                              (ash (aref (aref t1 i) j) +dilithium-d+)))
                      (let ((ct1 (ntt-multiply c-hat
                                               (ntt-forward t1-scaled :modulus +dilithium-q+ :root +dilithium-root+)
                                               :modulus +dilithium-q+)))
                        (setf sum (ntt-sub sum ct1 :modulus +dilithium-q+))))
                    (setf (aref w-prime i)
                          (ntt-inverse sum :modulus +dilithium-q+ :root +dilithium-root+))))

                ;; Use hints to recover w1
                (let ((w1-prime (make-array k)))
                  (dotimes (i k)
                    (let ((w1i (make-zero-poly +dilithium-n+)))
                      (dotimes (j +dilithium-n+)
                        (setf (aref w1i j)
                              (dilithium-use-hint (aref (aref h i) j)
                                                  (aref (aref w-prime i) j)
                                                  gamma2)))
                      (setf (aref w1-prime i) w1i)))

                  ;; Recompute challenge
                  (let* ((w1-bytes (make-octet-vector (* k 32))))
                    (dotimes (i k)
                      (replace w1-bytes (pack-poly (aref w1-prime i) 8)
                               :start1 (* i 32)))
                    (let ((c-seed-prime (sha3-256 (concat-bytes mu w1-bytes))))
                      ;; Verify challenge matches
                      (equalp c-seed c-seed-prime)))))))))
    (error () nil)))

;;; ============================================================================
;;; Signature Encoding/Decoding
;;; ============================================================================

(defun dilithium-encode-signature (params c-seed z h)
  "Encode signature components to bytes."
  (let* ((l (dilithium-params-l params))
         (k (dilithium-params-k params))
         (gamma1 (dilithium-params-gamma1 params))
         (sig-len (dilithium-signature-bytes params))
         (sig (make-octet-vector sig-len))
         (pos 0))
    ;; c-seed (32 bytes)
    (replace sig c-seed)
    (incf pos 32)
    ;; z (l polynomials)
    (let ((z-bits (if (= gamma1 (ash 1 17)) 18 20)))
      (dotimes (i l)
        (let ((packed (pack-poly (aref z i) z-bits)))
          (replace sig packed :start1 pos)
          (incf pos (length packed)))))
    ;; h (hints)
    (let ((h-pos 0))
      (dotimes (i k)
        (dotimes (j +dilithium-n+)
          (when (= 1 (aref (aref h i) j))
            (setf (aref sig (+ pos h-pos)) j)
            (incf h-pos)))
        (setf (aref sig (+ pos (dilithium-params-omega params) i)) h-pos)))
    sig))

(defun dilithium-decode-signature (sig params)
  "Decode signature bytes to components.
   Returns: (VALUES c-seed z h)"
  (let* ((l (dilithium-params-l params))
         (k (dilithium-params-k params))
         (gamma1 (dilithium-params-gamma1 params))
         (omega (dilithium-params-omega params))
         (pos 0)
         ;; c-seed
         (c-seed (subseq sig 0 32))
         ;; z
         (z (make-array l))
         (z-bits (if (= gamma1 (ash 1 17)) 18 20)))
    (incf pos 32)
    (dotimes (i l)
      (let ((z-bytes (if (= z-bits 18) 576 640)))
        (setf (aref z i)
              (unpack-poly (subseq sig pos (+ pos z-bytes)) z-bits :n +dilithium-n+))
        ;; Recenter
        (dotimes (j +dilithium-n+)
          (when (>= (aref (aref z i) j) gamma1)
            (decf (aref (aref z i) j) (* 2 gamma1))))
        (incf pos z-bytes)))
    ;; h
    (let ((h (make-array k)))
      (dotimes (i k)
        (setf (aref h i) (make-zero-poly +dilithium-n+)))
      ;; Decode hints
      (let ((h-pos 0)
            (h-offset pos))
        (dotimes (i k)
          (let ((end (aref sig (+ h-offset omega i))))
            (loop while (< h-pos end)
                  do (setf (aref (aref h i) (aref sig (+ h-offset h-pos))) 1)
                     (incf h-pos)))))
      (values c-seed z h))))

;;; ============================================================================
;;; Serialization
;;; ============================================================================

(defun dilithium-serialize-public-key (public-key)
  "Serialize public key to bytes."
  (let* ((params (dilithium-public-key-params public-key))
         (k (dilithium-params-k params))
         (rho (dilithium-public-key-rho public-key))
         (t1 (dilithium-public-key-t1 public-key))
         (output (make-octet-vector (dilithium-public-key-bytes params)))
         (pos 0))
    ;; rho
    (replace output rho)
    (incf pos 32)
    ;; t1 (10 bits per coefficient)
    (dotimes (i k)
      (let ((packed (pack-poly (aref t1 i) 10)))
        (replace output packed :start1 pos)
        (incf pos (length packed))))
    output))

(defun dilithium-deserialize-public-key (bytes params)
  "Deserialize public key from bytes."
  (let* ((k (dilithium-params-k params))
         (rho (subseq bytes 0 32))
         (t1 (make-array k))
         (pos 32))
    (dotimes (i k)
      (setf (aref t1 i)
            (unpack-poly (subseq bytes pos (+ pos 320)) 10 :n +dilithium-n+))
      (incf pos 320))
    (%make-dilithium-public-key :params params :rho rho :t1 t1)))

(defun dilithium-serialize-private-key (private-key)
  "Serialize private key to bytes."
  (let* ((params (dilithium-private-key-params private-key))
         (k (dilithium-params-k params))
         (l (dilithium-params-l params))
         (eta (dilithium-params-eta params))
         (output (make-octet-vector (dilithium-private-key-bytes params)))
         (pos 0)
         (eta-bits (if (= eta 2) 3 4)))
    ;; rho, K, tr
    (replace output (dilithium-private-key-rho private-key))
    (incf pos 32)
    (replace output (dilithium-private-key-k-seed private-key) :start1 pos)
    (incf pos 32)
    (replace output (dilithium-private-key-tr private-key) :start1 pos)
    (incf pos 32)
    ;; s1
    (dotimes (i l)
      (let ((packed (pack-poly (aref (dilithium-private-key-s1 private-key) i) eta-bits)))
        (replace output packed :start1 pos)
        (incf pos (length packed))))
    ;; s2
    (dotimes (i k)
      (let ((packed (pack-poly (aref (dilithium-private-key-s2 private-key) i) eta-bits)))
        (replace output packed :start1 pos)
        (incf pos (length packed))))
    ;; t0 (13 bits)
    (dotimes (i k)
      (let ((packed (pack-poly (aref (dilithium-private-key-t0 private-key) i) 13)))
        (replace output packed :start1 pos)
        (incf pos (length packed))))
    output))

(defun dilithium-deserialize-private-key (bytes params)
  "Deserialize private key from bytes."
  (let* ((k (dilithium-params-k params))
         (l (dilithium-params-l params))
         (eta (dilithium-params-eta params))
         (eta-bits (if (= eta 2) 3 4))
         (eta-bytes (* eta-bits 32))
         (pos 0)
         (rho (subseq bytes 0 32))
         (k-seed (subseq bytes 32 64))
         (tr (subseq bytes 64 96))
         (s1 (make-array l))
         (s2 (make-array k))
         (t0 (make-array k)))
    (incf pos 96)
    ;; s1
    (dotimes (i l)
      (setf (aref s1 i)
            (unpack-poly (subseq bytes pos (+ pos eta-bytes)) eta-bits :n +dilithium-n+))
      (incf pos eta-bytes))
    ;; s2
    (dotimes (i k)
      (setf (aref s2 i)
            (unpack-poly (subseq bytes pos (+ pos eta-bytes)) eta-bits :n +dilithium-n+))
      (incf pos eta-bytes))
    ;; t0
    (dotimes (i k)
      (setf (aref t0 i)
            (unpack-poly (subseq bytes pos (+ pos 416)) 13 :n +dilithium-n+))
      (incf pos 416))
    (%make-dilithium-private-key :params params :rho rho :k-seed k-seed
                                  :tr tr :s1 s1 :s2 s2 :t0 t0)))

(defun dilithium-serialize-signature (sig params)
  "Serialize signature (already bytes)."
  (declare (ignore params))
  sig)

(defun dilithium-deserialize-signature (bytes params)
  "Deserialize signature from bytes."
  (declare (ignore params))
  bytes)
