;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; ntt.lisp - Number Theoretic Transform for lattice cryptography
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Implements NTT operations for polynomial multiplication in Z_q[X]/(X^n+1).
;;;; Used by both Kyber and Dilithium for efficient polynomial arithmetic.

(in-package #:cl-post-quantum)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Polynomial Types
;;; ============================================================================

(deftype coefficient () '(signed-byte 32))
(deftype poly-vector () '(simple-array (signed-byte 32) (*)))

(defconstant +default-n+ 256
  "Default polynomial degree (both Kyber and Dilithium use 256).")

;;; ============================================================================
;;; Polynomial Constructors
;;; ============================================================================

(defun make-zero-poly (&optional (n +default-n+))
  "Create a zero polynomial of degree n-1."
  (make-array n :element-type '(signed-byte 32) :initial-element 0))

(defun make-one-poly (&optional (n +default-n+))
  "Create polynomial with constant term 1."
  (let ((p (make-zero-poly n)))
    (setf (aref p 0) 1)
    p))

(defun copy-poly (p)
  "Create a copy of polynomial p."
  (copy-seq p))

;;; ============================================================================
;;; NTT Forward Transform (Cooley-Tukey)
;;; ============================================================================

(defun ntt-forward (poly &key (modulus 3329) (root 17))
  "Compute forward NTT of polynomial.
   POLY: Coefficient vector in standard form
   MODULUS: Prime modulus q
   ROOT: Primitive 2nth root of unity mod q
   Returns: Polynomial in NTT domain"
  (declare (type poly-vector poly)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 1)))
  (let* ((n (length poly))
         (result (copy-poly poly))
         (k 1)
         (len (ash n -1)))
    ;; Precompute zetas (powers of root)
    (let ((zetas (make-array n :element-type '(signed-byte 32))))
      (loop with z = 1
            for i from 0 below n
            do (setf (aref zetas i) z)
               (setf z (mod (* z root) modulus)))
      ;; Cooley-Tukey butterfly
      (loop while (>= len 1) do
        (loop for start from 0 below n by (* 2 len)
              for zeta = (aref zetas k)
              do (incf k)
                 (loop for j from start below (+ start len)
                       for t-val = (mod (* zeta (aref result (+ j len))) modulus)
                       do (setf (aref result (+ j len))
                                (mod (- (aref result j) t-val) modulus))
                          (setf (aref result j)
                                (mod (+ (aref result j) t-val) modulus))))
        (setf len (ash len -1))))
    result))

;;; ============================================================================
;;; NTT Inverse Transform (Gentleman-Sande)
;;; ============================================================================

(defun ntt-inverse (poly &key (modulus 3329) (root 17))
  "Compute inverse NTT of polynomial.
   POLY: Polynomial in NTT domain
   MODULUS: Prime modulus q
   ROOT: Primitive 2nth root of unity mod q
   Returns: Polynomial in standard form"
  (declare (type poly-vector poly)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 1)))
  (let* ((n (length poly))
         (result (copy-poly poly))
         (len 1))
    ;; Compute inverse root
    (let ((root-inv (mod-inverse root modulus)))
      ;; Precompute inverse zetas
      (let ((zetas-inv (make-array n :element-type '(signed-byte 32))))
        (loop with z = 1
              for i from 0 below n
              do (setf (aref zetas-inv i) z)
                 (setf z (mod (* z root-inv) modulus)))
        ;; Gentleman-Sande butterfly
        (let ((k (1- n)))
          (loop while (< len n) do
            (loop for start from 0 below n by (* 2 len)
                  for zeta-inv = (aref zetas-inv k)
                  do (decf k)
                     (loop for j from start below (+ start len)
                           for t-val = (aref result j)
                           do (setf (aref result j)
                                    (mod (+ t-val (aref result (+ j len))) modulus))
                              (setf (aref result (+ j len))
                                    (mod (* zeta-inv (- t-val (aref result (+ j len))))
                                         modulus))))
            (setf len (ash len 1))))
        ;; Final scaling by n^(-1)
        (let ((n-inv (mod-inverse n modulus)))
          (dotimes (i n)
            (setf (aref result i) (mod (* (aref result i) n-inv) modulus))))))
    result))

;;; ============================================================================
;;; NTT Arithmetic Operations
;;; ============================================================================

(defun ntt-multiply (a b &key (modulus 3329))
  "Multiply two polynomials in NTT domain (pointwise).
   Both A and B must already be in NTT form.
   Returns: Product in NTT domain"
  (declare (type poly-vector a b)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length a))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (setf (aref result i) (mod (* (aref a i) (aref b i)) modulus)))))

(defun ntt-add (a b &key (modulus 3329))
  "Add two polynomials (works in any domain).
   Returns: Sum modulo q"
  (declare (type poly-vector a b)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length a))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (setf (aref result i) (mod (+ (aref a i) (aref b i)) modulus)))))

(defun ntt-sub (a b &key (modulus 3329))
  "Subtract two polynomials (works in any domain).
   Returns: Difference modulo q"
  (declare (type poly-vector a b)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length a))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (setf (aref result i) (mod (- (aref a i) (aref b i)) modulus)))))

;;; ============================================================================
;;; Polynomial Reduction
;;; ============================================================================

(defun poly-reduce (poly modulus)
  "Fully reduce all coefficients to [0, modulus)."
  (declare (type poly-vector poly)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length poly))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (let ((c (mod (aref poly i) modulus)))
        (setf (aref result i) (if (< c 0) (+ c modulus) c))))))

(defun poly-centered-reduce (poly modulus)
  "Reduce coefficients to centered representation [-q/2, q/2)."
  (declare (type poly-vector poly)
           (type (unsigned-byte 32) modulus)
           (optimize (speed 3) (safety 0)))
  (let* ((n (length poly))
         (half-q (ash modulus -1))
         (result (make-zero-poly n)))
    (dotimes (i n result)
      (let ((c (mod (aref poly i) modulus)))
        (setf (aref result i)
              (if (> c half-q) (- c modulus) c))))))

;;; ============================================================================
;;; Polynomial Norm Operations (Constant-Time)
;;; ============================================================================

(defun poly-infinity-norm (poly)
  "Compute infinity norm (max absolute coefficient) in constant time."
  (declare (type poly-vector poly)
           (optimize (speed 3) (safety 0)))
  (let ((max-val 0))
    (dotimes (i (length poly) max-val)
      (let ((abs-c (ct-abs (aref poly i))))
        (setf max-val (ct-max max-val abs-c))))))

(defun ct-check-norm (poly bound)
  "Constant-time check if infinity norm of polynomial is less than bound.
   Returns 1 if norm < bound, 0 otherwise."
  (declare (type poly-vector poly)
           (type (signed-byte 32) bound)
           (optimize (speed 3) (safety 0)))
  (let ((exceeds 0))
    (dotimes (i (length poly))
      (let ((ge-bound (if (>= (ct-abs (aref poly i)) bound) 1 0)))
        (setf exceeds (logior exceeds ge-bound))))
    (if (zerop exceeds) 1 0)))

;;; ============================================================================
;;; Vector/Matrix Operations
;;; ============================================================================

(defun poly-vector-add (a b k &key (modulus 3329))
  "Add two vectors of k polynomials."
  (let ((result (make-array k)))
    (dotimes (i k result)
      (setf (aref result i) (ntt-add (aref a i) (aref b i) :modulus modulus)))))

(defun poly-vector-sub (a b k &key (modulus 3329))
  "Subtract two vectors of k polynomials."
  (let ((result (make-array k)))
    (dotimes (i k result)
      (setf (aref result i) (ntt-sub (aref a i) (aref b i) :modulus modulus)))))

(defun matrix-vector-ntt-mul (mat vec k &key (modulus 3329))
  "Multiply k x k matrix by vector, both in NTT domain.
   Returns vector of k polynomials."
  (let ((result (make-array k)))
    (dotimes (i k result)
      (let ((sum (make-zero-poly)))
        (dotimes (j k)
          (setf sum (ntt-add sum
                             (ntt-multiply (aref mat i j) (aref vec j)
                                           :modulus modulus)
                             :modulus modulus)))
        (setf (aref result i) sum)))))
