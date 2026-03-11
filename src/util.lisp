;;;; util.lisp - Utility functions for CL-POST-QUANTUM
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Provides:
;;;;   - Byte vector operations
;;;;   - Modular arithmetic
;;;;   - SHA-256 and SHA-3/SHAKE implementations
;;;;   - Random number generation
;;;;   - Constant-time primitives

(in-package #:cl-post-quantum)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; Type Declarations
;;; ============================================================================

(deftype octet () '(unsigned-byte 8))
(deftype octet-vector () '(simple-array (unsigned-byte 8) (*)))
(deftype index () '(integer 0 #.most-positive-fixnum))

;;; ============================================================================
;;; Byte Vector Operations
;;; ============================================================================

(declaim (inline make-octet-vector))
(defun make-octet-vector (size &optional (initial-element 0))
  "Create a new byte vector of SIZE bytes."
  (make-array size :element-type '(unsigned-byte 8) :initial-element initial-element))

(defun concat-bytes (&rest vectors)
  "Concatenate byte vectors."
  (let* ((total-len (reduce #'+ vectors :key #'length))
         (result (make-octet-vector total-len))
         (pos 0))
    (dolist (v vectors result)
      (replace result v :start1 pos)
      (incf pos (length v)))))

(defun bytes-to-integer (bytes &key (start 0) (end (length bytes)) (big-endian t))
  "Convert byte vector to integer."
  (let ((result 0))
    (if big-endian
        (loop for i from start below end
              do (setf result (logior (ash result 8) (aref bytes i))))
        (loop for i from (1- end) downto start
              do (setf result (logior (ash result 8) (aref bytes i)))))
    result))

(defun integer-to-bytes (n size &key (big-endian t))
  "Convert integer to byte vector of SIZE bytes."
  (let ((result (make-octet-vector size)))
    (if big-endian
        (loop for i from (1- size) downto 0
              for shift from 0 by 8
              do (setf (aref result i) (ldb (byte 8 shift) n)))
        (loop for i from 0 below size
              for shift from 0 by 8
              do (setf (aref result i) (ldb (byte 8 shift) n))))
    result))

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(declaim (inline mod-add mod-sub mod-mul))

(defun mod-add (a b modulus)
  "Modular addition."
  (declare (type integer a b modulus))
  (mod (+ a b) modulus))

(defun mod-sub (a b modulus)
  "Modular subtraction."
  (declare (type integer a b modulus))
  (mod (- a b) modulus))

(defun mod-mul (a b modulus)
  "Modular multiplication."
  (declare (type integer a b modulus))
  (mod (* a b) modulus))

(defun mod-inverse (a modulus)
  "Compute modular multiplicative inverse using extended Euclidean algorithm.
   Returns x such that (a * x) mod modulus = 1."
  (declare (type integer a modulus))
  (let ((t0 0)
        (t1 1)
        (r0 modulus)
        (r1 (mod a modulus)))
    (loop while (plusp r1)
          do (let ((q (floor r0 r1)))
               (psetf t0 t1
                      t1 (- t0 (* q t1))
                      r0 r1
                      r1 (- r0 (* q r1)))))
    (if (> r0 1)
        (error "~A has no inverse mod ~A" a modulus)
        (if (minusp t0) (+ t0 modulus) t0))))

(defun mod-exp (base exponent modulus)
  "Modular exponentiation using square-and-multiply."
  (declare (type integer base exponent modulus))
  (let ((result 1)
        (base (mod base modulus)))
    (loop while (plusp exponent)
          do (when (oddp exponent)
               (setf result (mod (* result base) modulus)))
             (setf exponent (ash exponent -1))
             (setf base (mod (* base base) modulus)))
    result))

;;; ============================================================================
;;; Constant-Time Primitives
;;; ============================================================================

(declaim (inline ct-select ct-eq ct-lt ct-gt ct-abs ct-max))

(defun ct-select (flag a b)
  "Constant-time select: return A if FLAG=1, B if FLAG=0."
  (declare (type (integer 0 1) flag)
           (type (signed-byte 32) a b))
  (let ((mask (- flag)))
    (logxor b (logand mask (logxor a b)))))

(defun ct-eq (a b)
  "Constant-time equality. Returns 1 if a=b, 0 otherwise."
  (declare (type (signed-byte 32) a b))
  (let ((x (logxor a b)))
    (logand 1 (lognot (logior x (- x))))))

(defun ct-lt (a b)
  "Constant-time less-than. Returns 1 if a<b, 0 otherwise."
  (declare (type (signed-byte 32) a b))
  (logand 1 (ash (- a b) -31)))

(defun ct-gt (a b)
  "Constant-time greater-than. Returns 1 if a>b, 0 otherwise."
  (ct-lt b a))

(defun ct-abs (x)
  "Constant-time absolute value."
  (declare (type (signed-byte 32) x))
  (let ((mask (ash x -31)))
    (logxor (+ x mask) mask)))

(defun ct-max (a b)
  "Constant-time maximum."
  (declare (type (signed-byte 32) a b))
  (ct-select (ct-gt a b) a b))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(defconstant +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants.")

(defconstant +sha256-init+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values.")

(declaim (inline sha256-rotr sha256-ch sha256-maj sha256-sigma0 sha256-sigma1 sha256-Sigma0 sha256-Sigma1))

(defun sha256-rotr (x n)
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (logior (ash x (- n)) (logand #xFFFFFFFF (ash x (- 32 n)))))

(defun sha256-ch (x y z)
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ash x -3)))

(defun sha256-sigma1 (x)
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ash x -10)))

(defun sha256-Sigma0 (x)
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-Sigma1 (x)
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-process-block (block hash)
  "Process a 64-byte block."
  (declare (type (simple-array (unsigned-byte 8) (64)) block)
           (type (simple-array (unsigned-byte 32) (8)) hash))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          do (setf (aref w i)
                   (logior (ash (aref block (* i 4)) 24)
                           (ash (aref block (+ (* i 4) 1)) 16)
                           (ash (aref block (+ (* i 4) 2)) 8)
                           (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand #xFFFFFFFF
                           (+ (sha256-sigma1 (aref w (- i 2)))
                              (aref w (- i 7))
                              (sha256-sigma0 (aref w (- i 15)))
                              (aref w (- i 16))))))
    ;; Working variables
    (let ((a (aref hash 0)) (b (aref hash 1)) (c (aref hash 2)) (d (aref hash 3))
          (e (aref hash 4)) (f (aref hash 5)) (g (aref hash 6)) (h (aref hash 7)))
      (declare (type (unsigned-byte 32) a b c d e f g h))
      ;; Main loop
      (loop for i from 0 below 64
            do (let* ((t1 (logand #xFFFFFFFF
                                  (+ h (sha256-Sigma1 e) (sha256-ch e f g)
                                     (aref +sha256-k+ i) (aref w i))))
                      (t2 (logand #xFFFFFFFF
                                  (+ (sha256-Sigma0 a) (sha256-maj a b c)))))
                 (setf h g g f f e
                       e (logand #xFFFFFFFF (+ d t1))
                       d c c b b a
                       a (logand #xFFFFFFFF (+ t1 t2)))))
      ;; Update hash
      (setf (aref hash 0) (logand #xFFFFFFFF (+ (aref hash 0) a)))
      (setf (aref hash 1) (logand #xFFFFFFFF (+ (aref hash 1) b)))
      (setf (aref hash 2) (logand #xFFFFFFFF (+ (aref hash 2) c)))
      (setf (aref hash 3) (logand #xFFFFFFFF (+ (aref hash 3) d)))
      (setf (aref hash 4) (logand #xFFFFFFFF (+ (aref hash 4) e)))
      (setf (aref hash 5) (logand #xFFFFFFFF (+ (aref hash 5) f)))
      (setf (aref hash 6) (logand #xFFFFFFFF (+ (aref hash 6) g)))
      (setf (aref hash 7) (logand #xFFFFFFFF (+ (aref hash 7) h))))))

(defun sha256 (message)
  "Compute SHA-256 hash of MESSAGE.
   MESSAGE: byte vector
   Returns: 32-byte hash"
  (let* ((msg-len (length message))
         (bit-len (* msg-len 8))
         ;; Pad to 512-bit boundary: msg + 1 + zeros + 64-bit length
         (pad-len (- 64 (mod (+ msg-len 9) 64)))
         (pad-len (if (minusp pad-len) (+ pad-len 64) pad-len))
         (total-len (+ msg-len 1 pad-len 8))
         (padded (make-octet-vector total-len))
         (hash (copy-seq +sha256-init+)))
    ;; Copy message and add padding
    (replace padded message)
    (setf (aref padded msg-len) #x80)
    ;; Append length in bits (big-endian)
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (ldb (byte 8 (* i 8)) bit-len)))
    ;; Process blocks
    (loop for i from 0 below total-len by 64
          do (sha256-process-block
              (make-array 64 :element-type '(unsigned-byte 8)
                             :displaced-to padded
                             :displaced-index-offset i)
              hash))
    ;; Convert hash to bytes
    (let ((result (make-octet-vector 32)))
      (loop for i from 0 below 8
            do (setf (aref result (* i 4)) (ldb (byte 8 24) (aref hash i)))
               (setf (aref result (+ (* i 4) 1)) (ldb (byte 8 16) (aref hash i)))
               (setf (aref result (+ (* i 4) 2)) (ldb (byte 8 8) (aref hash i)))
               (setf (aref result (+ (* i 4) 3)) (ldb (byte 8 0) (aref hash i))))
      result)))

;;; ============================================================================
;;; SHA-3 / Keccak Implementation
;;; ============================================================================

(defconstant +keccak-rounds+ 24)

(defconstant +keccak-rc+
  #(#x0000000000000001 #x0000000000008082 #x800000000000808a #x8000000080008000
    #x000000000000808b #x0000000080000001 #x8000000080008081 #x8000000000008009
    #x000000000000008a #x0000000000000088 #x0000000080008009 #x000000008000000a
    #x000000008000808b #x800000000000008b #x8000000000008089 #x8000000000008003
    #x8000000000008002 #x8000000000000080 #x000000000000800a #x800000008000000a
    #x8000000080008081 #x8000000000008080 #x0000000080000001 #x8000000080008008)
  "Keccak round constants.")

(defconstant +keccak-rho+
  #(0 1 62 28 27 36 44 6 55 20 3 10 43 25 39 41 45 15 21 8 18 2 61 56 14)
  "Keccak rotation offsets.")

(defconstant +keccak-pi+
  #(0 10 20 5 15 16 1 11 21 6 7 17 2 12 22 23 8 18 3 13 14 24 9 19 4)
  "Keccak permutation indices.")

(declaim (inline keccak-rotl64))
(defun keccak-rotl64 (x n)
  "64-bit left rotate."
  (logior (ldb (byte 64 0) (ash x n))
          (ash x (- n 64))))

(defun keccak-f (state)
  "Keccak-f[1600] permutation."
  (declare (type (simple-array (unsigned-byte 64) (25)) state))
  (let ((c (make-array 5 :element-type '(unsigned-byte 64)))
        (d (make-array 5 :element-type '(unsigned-byte 64)))
        (b (make-array 25 :element-type '(unsigned-byte 64))))
    (dotimes (round +keccak-rounds+)
      ;; Theta
      (dotimes (x 5)
        (setf (aref c x)
              (logxor (aref state x)
                      (aref state (+ x 5))
                      (aref state (+ x 10))
                      (aref state (+ x 15))
                      (aref state (+ x 20)))))
      (dotimes (x 5)
        (setf (aref d x)
              (logxor (aref c (mod (+ x 4) 5))
                      (keccak-rotl64 (aref c (mod (+ x 1) 5)) 1))))
      (dotimes (i 25)
        (setf (aref state i)
              (logxor (aref state i) (aref d (mod i 5)))))
      ;; Rho and Pi
      (dotimes (i 25)
        (setf (aref b (aref +keccak-pi+ i))
              (keccak-rotl64 (aref state i) (aref +keccak-rho+ i))))
      ;; Chi
      (dotimes (y 5)
        (let ((y5 (* y 5)))
          (dotimes (x 5)
            (setf (aref state (+ y5 x))
                  (logxor (aref b (+ y5 x))
                          (logand (lognot (aref b (+ y5 (mod (+ x 1) 5))))
                                  (aref b (+ y5 (mod (+ x 2) 5)))))))))
      ;; Iota
      (setf (aref state 0) (logxor (aref state 0) (aref +keccak-rc+ round)))))
  state)

(defun keccak-absorb (state data rate)
  "Absorb data into Keccak state."
  (let ((pos 0)
        (data-len (length data)))
    (loop while (< pos data-len)
          do (let ((block-size (min (- data-len pos) rate)))
               ;; XOR data into state
               (loop for i from 0 below block-size
                     for byte-idx = (floor i 8)
                     for bit-offset = (* (mod i 8) 8)
                     do (setf (aref state byte-idx)
                              (logxor (aref state byte-idx)
                                      (ash (aref data (+ pos i)) bit-offset))))
               (incf pos block-size)
               (when (= block-size rate)
                 (keccak-f state)))))
  state)

(defun keccak-squeeze (state output-len rate)
  "Squeeze output from Keccak state."
  (let ((output (make-octet-vector output-len))
        (pos 0))
    (loop while (< pos output-len)
          do (let ((block-size (min (- output-len pos) rate)))
               ;; Extract bytes from state
               (loop for i from 0 below block-size
                     for byte-idx = (floor i 8)
                     for bit-offset = (* (mod i 8) 8)
                     do (setf (aref output (+ pos i))
                              (ldb (byte 8 bit-offset) (aref state byte-idx))))
               (incf pos block-size)
               (when (< pos output-len)
                 (keccak-f state))))
    output))

(defun sha3-256 (message)
  "Compute SHA3-256 hash of MESSAGE."
  (let* ((rate 136)  ; (1600 - 256*2) / 8
         (state (make-array 25 :element-type '(unsigned-byte 64) :initial-element 0))
         (padded-len (+ (length message) 1 (mod (- rate (mod (+ (length message) 1) rate)) rate)))
         (padded (make-octet-vector padded-len)))
    (replace padded message)
    (setf (aref padded (length message)) #x06)  ; SHA3 domain separator
    (setf (aref padded (1- padded-len)) (logior (aref padded (1- padded-len)) #x80))
    (keccak-absorb state padded rate)
    (keccak-f state)
    (keccak-squeeze state 32 rate)))

(defun shake128 (message output-len)
  "Compute SHAKE128 XOF output."
  (let* ((rate 168)  ; (1600 - 128*2) / 8
         (state (make-array 25 :element-type '(unsigned-byte 64) :initial-element 0))
         (padded-len (+ (length message) 1 (mod (- rate (mod (+ (length message) 1) rate)) rate)))
         (padded (make-octet-vector padded-len)))
    (replace padded message)
    (setf (aref padded (length message)) #x1F)  ; SHAKE domain separator
    (setf (aref padded (1- padded-len)) (logior (aref padded (1- padded-len)) #x80))
    (keccak-absorb state padded rate)
    (keccak-f state)
    (keccak-squeeze state output-len rate)))

(defun shake256 (message output-len)
  "Compute SHAKE256 XOF output."
  (let* ((rate 136)  ; (1600 - 256*2) / 8
         (state (make-array 25 :element-type '(unsigned-byte 64) :initial-element 0))
         (padded-len (+ (length message) 1 (mod (- rate (mod (+ (length message) 1) rate)) rate)))
         (padded (make-octet-vector padded-len)))
    (replace padded message)
    (setf (aref padded (length message)) #x1F)  ; SHAKE domain separator
    (setf (aref padded (1- padded-len)) (logior (aref padded (1- padded-len)) #x80))
    (keccak-absorb state padded rate)
    (keccak-f state)
    (keccak-squeeze state output-len rate)))

;;; ============================================================================
;;; Random Number Generation
;;; ============================================================================

(defun get-random-bytes (n)
  "Generate N cryptographically random bytes.
   Uses system random source when available."
  (let ((bytes (make-octet-vector n)))
    #+sbcl
    (with-open-file (f "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence bytes f))
    #-sbcl
    (dotimes (i n)
      (setf (aref bytes i) (random 256)))
    bytes))

;;; ============================================================================
;;; Condition Types
;;; ============================================================================

(define-condition post-quantum-error (error)
  ((message :initarg :message :reader post-quantum-error-message)
   (algorithm :initarg :algorithm :reader post-quantum-error-algorithm :initform nil))
  (:report (lambda (c s)
             (format s "Post-quantum error~@[ in ~A~]: ~A"
                     (post-quantum-error-algorithm c)
                     (post-quantum-error-message c)))))

(define-condition kyber-error (post-quantum-error)
  ()
  (:default-initargs :algorithm :kyber))

(define-condition dilithium-error (post-quantum-error)
  ()
  (:default-initargs :algorithm :dilithium))

(define-condition key-generation-error (post-quantum-error) ())
(define-condition encapsulation-error (kyber-error) ())
(define-condition decapsulation-error (kyber-error) ())
(define-condition signature-error (post-quantum-error) ())
(define-condition verification-error (post-quantum-error) ())

(define-condition invalid-parameter-error (post-quantum-error)
  ((parameter :initarg :parameter :reader invalid-parameter-name)
   (value :initarg :value :reader invalid-parameter-value))
  (:report (lambda (c s)
             (format s "Invalid parameter ~A: ~A"
                     (invalid-parameter-name c)
                     (invalid-parameter-value c)))))
