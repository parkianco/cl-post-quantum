;;;; test/test-pq.lisp - Tests for CL-POST-QUANTUM

(defpackage #:cl-post-quantum/test
  (:use #:cl #:cl-post-quantum)
  (:export #:run-all-tests))

(in-package #:cl-post-quantum/test)

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "  PASS: ~A~%" ',name))
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~A - ~A~%" ',name e)))))

(defmacro assert-true (form &optional message)
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,message)))

(defmacro assert-equal (expected actual &optional message)
  `(unless (equal ,expected ,actual)
     (error "Expected ~S but got ~S~@[: ~A~]" ,expected ,actual ,message)))

;;; ============================================================================
;;; NTT Tests
;;; ============================================================================

(deftest test-ntt-roundtrip
  "NTT forward then inverse is identity"
  (let* ((poly (make-array 256 :element-type 'fixnum :initial-element 0)))
    (dotimes (i 256)
      (setf (aref poly i) (mod i 3329)))
    (let* ((original (copy-seq poly))
           (transformed (ntt-forward poly))
           (recovered (ntt-inverse transformed)))
      (assert-true (equalp original recovered)
                   "NTT roundtrip failed"))))

;;; ============================================================================
;;; Polynomial Tests
;;; ============================================================================

(deftest test-ntt-add
  "Polynomial addition via NTT"
  (let ((a (make-array 256 :element-type 'fixnum :initial-element 1))
        (b (make-array 256 :element-type 'fixnum :initial-element 2)))
    (let ((c (ntt-add a b)))
      (assert-equal 3 (aref c 0) "Addition element 0"))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-all-tests ()
  "Run all tests and return T on success."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)
  (format t "~&Running cl-post-quantum tests...~%~%")

  (format t "NTT Tests:~%")
  (test-ntt-roundtrip)
  (test-ntt-add)

  (format t "~%========================================~%")
  (format t "Results: ~D/~D passed (~D failed)~%"
          *pass-count* *test-count* *fail-count*)
  (format t "========================================~%")
  (zerop *fail-count*))
