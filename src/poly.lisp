;;;; poly.lisp - Polynomial operations for lattice cryptography
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Provides polynomial sampling, compression, and serialization
;;;; operations used by Kyber and Dilithium.

(in-package #:cl-post-quantum)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Polynomial Sampling
;;; ============================================================================

(defun sample-uniform-poly (seed nonce &key (n 256) (modulus 3329))
  "Sample polynomial with uniform coefficients in [0, q).
   Uses rejection sampling from SHAKE128 output.
   SEED: 32-byte seed
   NONCE: 2-byte nonce for domain separation
   Returns: Polynomial with uniform random coefficients"
  (let ((poly (make-zero-poly n))
        (input (make-octet-vector 34)))
    (replace input seed)
    (setf (aref input 32) (ldb (byte 8 0) nonce))
    (setf (aref input 33) (ldb (byte 8 8) nonce))
    (let ((xof-output (shake128 input (* 3 n 2)))
          (coeff-idx 0)
          (byte-idx 0))
      (loop while (< coeff-idx n)
            do (let* ((b0 (aref xof-output byte-idx))
                      (b1 (aref xof-output (1+ byte-idx)))
                      (b2 (aref xof-output (+ byte-idx 2)))
                      ;; Extract two 12-bit values
                      (d1 (logior b0 (ash (logand b1 #x0F) 8)))
                      (d2 (logior (ash b1 -4) (ash b2 4))))
                 (incf byte-idx 3)
                 ;; Rejection sampling
                 (when (< d1 modulus)
                   (setf (aref poly coeff-idx) d1)
                   (incf coeff-idx))
                 (when (and (< coeff-idx n) (< d2 modulus))
                   (setf (aref poly coeff-idx) d2)
                   (incf coeff-idx)))))
    poly))

(defun sample-error-poly (seed nonce &key (n 256) (eta 2))
  "Sample polynomial from centered binomial distribution CBD_eta.
   Coefficients are in [-eta, eta].
   SEED: 32-byte seed
   NONCE: Single byte nonce
   ETA: Distribution parameter (2 or 3 for Kyber)
   Returns: Polynomial with small coefficients"
  (let* ((poly (make-zero-poly n))
         (input (make-octet-vector 33)))
    (replace input seed)
    (setf (aref input 32) nonce)
    (let ((prf-output (shake256 input (* 64 eta)))
          (byte-idx 0))
      (loop for i from 0 below n by 2
            do (let ((a 0) (b 0))
                 ;; Sample eta bits for a, eta bits for b
                 (dotimes (j eta)
                   (let ((byte (aref prf-output byte-idx)))
                     (incf a (+ (ldb (byte 1 0) byte)
                                (ldb (byte 1 1) byte)))
                     (incf b (+ (ldb (byte 1 2) byte)
                                (ldb (byte 1 3) byte)))
                     (incf byte-idx)))
                 (setf (aref poly i) (- a b))
                 (when (< (1+ i) n)
                   (let ((a2 0) (b2 0))
                     (dotimes (j eta)
                       (let ((byte (aref prf-output byte-idx)))
                         (incf a2 (+ (ldb (byte 1 4) byte)
                                     (ldb (byte 1 5) byte)))
                         (incf b2 (+ (ldb (byte 1 6) byte)
                                     (ldb (byte 1 7) byte)))
                         (incf byte-idx)))
                     (setf (aref poly (1+ i)) (- a2 b2)))))))
    poly))

(defun sample-ternary-poly (seed nonce &key (n 256) (weight nil))
  "Sample polynomial with ternary coefficients {-1, 0, 1}.
   SEED: 32-byte seed
   NONCE: Single byte nonce
   WEIGHT: If specified, exactly WEIGHT non-zero coefficients
   Returns: Polynomial with ternary coefficients"
  (let ((poly (make-zero-poly n)))
    (if weight
        ;; Fixed-weight ternary
        (let* ((input (make-octet-vector 33))
               (positions (make-array weight :element-type 'fixnum))
               (pos-idx 0)
               (byte-idx 0))
          (replace input seed)
          (setf (aref input 32) nonce)
          (let ((xof (shake256 input (* 2 n))))
            ;; Sample weight distinct positions
            (loop while (< pos-idx weight)
                  do (let ((pos (mod (logior (aref xof byte-idx)
                                             (ash (aref xof (1+ byte-idx)) 8))
                                     n)))
                       (incf byte-idx 2)
                       (unless (find pos positions :end pos-idx)
                         (setf (aref positions pos-idx) pos)
                         (incf pos-idx))))
            ;; Set coefficients to +1 or -1
            (dotimes (i weight)
              (let ((pos (aref positions i))
                    (sign (if (oddp (aref xof (+ (* 2 weight) i))) -1 1)))
                (setf (aref poly pos) sign)))))
        ;; Random ternary
        (let* ((input (make-octet-vector 33)))
          (replace input seed)
          (setf (aref input 32) nonce)
          (let ((xof (shake256 input (ceiling n 4))))
            (dotimes (i n)
              (let* ((byte-pos (floor i 4))
                     (bit-pos (* 2 (mod i 4)))
                     (bits (ldb (byte 2 bit-pos) (aref xof byte-pos))))
                (setf (aref poly i) (case bits
                                      (0 0)
                                      (1 1)
                                      (2 -1)
                                      (3 0))))))))
    poly))

;;; ============================================================================
;;; Compression and Decompression
;;; ============================================================================

(defun compress-coeff (x d modulus)
  "Compress coefficient x to d bits.
   Computes round(2^d/q * x) mod 2^d"
  (let ((scale (ash 1 d)))
    (mod (round (* scale x) modulus) scale)))

(defun decompress-coeff (x d modulus)
  "Decompress d-bit value to coefficient.
   Computes round(q/2^d * x)"
  (let ((scale (ash 1 d)))
    (round (* modulus x) scale)))

(defun compress-poly (poly d &key (modulus 3329))
  "Compress all polynomial coefficients to d bits."
  (declare (type poly-vector poly)
           (type (integer 1 16) d)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length poly))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (setf (aref result i) (compress-coeff (aref poly i) d modulus)))))

(defun decompress-poly (poly d &key (modulus 3329))
  "Decompress polynomial coefficients from d bits."
  (declare (type poly-vector poly)
           (type (integer 1 16) d)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length poly))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (setf (aref result i) (decompress-coeff (aref poly i) d modulus)))))

;;; ============================================================================
;;; Packing and Unpacking
;;; ============================================================================

(defun pack-poly (poly bits-per-coeff)
  "Pack polynomial coefficients into byte vector.
   BITS-PER-COEFF: Number of bits per coefficient (e.g., 12 for Kyber)
   Returns: Byte vector"
  (declare (type poly-vector poly)
           (type (integer 1 32) bits-per-coeff)
           (optimize (speed 3) (safety 1)))
  (let* ((n (length poly))
         (total-bits (* n bits-per-coeff))
         (total-bytes (ceiling total-bits 8))
         (output (make-octet-vector total-bytes))
         (bit-pos 0))
    (dotimes (i n output)
      (let* ((coeff (aref poly i))
             (byte-pos (floor bit-pos 8))
             (bit-offset (mod bit-pos 8))
             (remaining-in-byte (- 8 bit-offset))
             (first-part (min bits-per-coeff remaining-in-byte)))
        ;; Write first part to current byte
        (setf (aref output byte-pos)
              (logior (aref output byte-pos)
                      (ash (logand coeff (1- (ash 1 first-part))) bit-offset)))
        ;; Write remaining parts
        (let ((written first-part))
          (loop while (< written bits-per-coeff)
                do (incf byte-pos)
                   (let ((to-write (min 8 (- bits-per-coeff written))))
                     (setf (aref output byte-pos)
                           (logand (ash coeff (- written)) (1- (ash 1 to-write))))
                     (incf written to-write))))
        (incf bit-pos bits-per-coeff)))))

(defun unpack-poly (bytes bits-per-coeff &key (n 256))
  "Unpack byte vector into polynomial.
   BITS-PER-COEFF: Number of bits per coefficient
   N: Number of coefficients to extract
   Returns: Polynomial vector"
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type (integer 1 32) bits-per-coeff)
           (optimize (speed 3) (safety 1)))
  (let ((poly (make-zero-poly n))
        (bit-pos 0))
    (dotimes (i n poly)
      (let* ((byte-pos (floor bit-pos 8))
             (bit-offset (mod bit-pos 8))
             (coeff 0)
             (bits-read 0))
        ;; Read coefficient across byte boundaries
        (loop while (< bits-read bits-per-coeff)
              do (let* ((available (- 8 (if (zerop bits-read) bit-offset 0)))
                        (to-read (min available (- bits-per-coeff bits-read)))
                        (shift (if (zerop bits-read) (- bit-offset) 0))
                        (byte-val (if (< byte-pos (length bytes))
                                      (aref bytes byte-pos)
                                      0))
                        (extracted (logand (ash byte-val shift)
                                           (1- (ash 1 to-read)))))
                   (setf coeff (logior coeff (ash extracted bits-read)))
                   (incf bits-read to-read)
                   (incf byte-pos)))
        (setf (aref poly i) coeff)
        (incf bit-pos bits-per-coeff)))))

;;; ============================================================================
;;; Additional Polynomial Operations
;;; ============================================================================

(defun poly-scalar-mul (poly scalar &key (modulus 3329))
  "Multiply polynomial by scalar."
  (declare (type poly-vector poly)
           (type (signed-byte 32) scalar)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length poly))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (setf (aref result i) (mod (* (aref poly i) scalar) modulus)))))

(defun poly-inner-product (a b &key (modulus 3329))
  "Compute inner product of two polynomial vectors."
  (declare (type poly-vector a b)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let ((sum 0))
    (dotimes (i (length a) (mod sum modulus))
      (incf sum (* (aref a i) (aref b i))))))

(defun poly-schoolbook-mul (a b &key (modulus 3329))
  "Schoolbook polynomial multiplication in R_q = Z_q[X]/(X^n + 1).
   Slower than NTT but useful for testing."
  (declare (type poly-vector a b)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 1)))
  (let* ((n (length a))
         (temp (make-array (* 2 n) :element-type '(signed-byte 64)
                                   :initial-element 0))
         (result (make-zero-poly n)))
    ;; Convolution
    (dotimes (i n)
      (dotimes (j n)
        (incf (aref temp (+ i j)) (* (aref a i) (aref b j)))))
    ;; Reduce by X^n + 1
    (dotimes (i n result)
      (setf (aref result i)
            (mod (- (aref temp i) (aref temp (+ i n))) modulus)))))
