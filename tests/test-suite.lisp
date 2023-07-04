;; Copyright (c) 2023 Marin Atanasov Nikolov <dnaeon@gmail.com>
;; All rights reserved.
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:
;;
;;  1. Redistributions of source code must retain the above copyright
;;     notice, this list of conditions and the following disclaimer
;;     in this position and unchanged.
;;  2. Redistributions in binary form must reproduce the above copyright
;;     notice, this list of conditions and the following disclaimer in the
;;     documentation and/or other materials provided with the distribution.
;;
;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
;; IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
;; OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
;; IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
;; INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
;; NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
;; THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(in-package :cl-user)
(defpackage :cl-jwk.test
  (:use :cl :rove)
  (:import-from :cl-jwk)
  (:nicknames :jwk.test)
  (:import-from :cl-jwk))
(in-package :cl-jwk.test)

(defun jwk-file-contents (file)
  "Returns the contents of the given test JWK file"
  (let* ((test-keys (asdf:system-relative-pathname :cl-jwk.test "tests/test-keys/"))
         (jwk-path (merge-pathnames test-keys file)))
    (uiop:read-file-string jwk-path)))

(deftest rsa-keys
  (testing "decode RSA 2048 public key"
    (let ((key (cl-jwk:decode :json (jwk-file-contents "rsa-2048-pub.json"))))
      (ok (string= "RSA" (cl-jwk:jwk-kty key)) "kty matches")
      (ok (string= "sig" (cl-jwk:jwk-use key)) "use matches")
      (ok (string= "test-id" (cl-jwk:jwk-kid key)) "kid matches")
      (ok (equal :RS256 (cl-jwk:jwk-alg key)) "alg matches")
      (ok (typep (cl-jwk:jwk-key key) 'ironclad:rsa-public-key) "public key type matches")
      (ok (= 2048
             (integer-length (ironclad:rsa-key-modulus (cl-jwk:jwk-key key))))
          "key bits match")))

  (testing "decode RSA 3072 public key"
    (let ((key (cl-jwk:decode :json (jwk-file-contents "rsa-3072-pub.json"))))
      (ok (string= "RSA" (cl-jwk:jwk-kty key)) "kty matches")
      (ok (string= "sig" (cl-jwk:jwk-use key)) "use matches")
      (ok (string= "test-id" (cl-jwk:jwk-kid key)) "kid matches")
      (ok (equal :PS256 (cl-jwk:jwk-alg key)) "alg matches")
      (ok (typep (cl-jwk:jwk-key key) 'ironclad:rsa-public-key) "public key type matches")
      (ok (= 3072
             (integer-length (ironclad:rsa-key-modulus (cl-jwk:jwk-key key))))
          "key bits match"))))

(deftest ec-keys
  (testing "decode secp256r1 public key"
    (let ((key (cl-jwk:decode :json (jwk-file-contents "secp256r1-pub.json"))))
      (ok (string= "EC" (cl-jwk:jwk-kty key)) "kty matches")
      (ok (string= "sig" (cl-jwk:jwk-use key)) "use matches")
      (ok (string= "test-id" (cl-jwk:jwk-kid key)) "kid matches")
      (ok (equal :ES256 (cl-jwk:jwk-alg key)) "alg matches")
      (ok (typep (cl-jwk:jwk-key key) 'ironclad:secp256r1-public-key) "public key type matches")))

  (testing "decode secp384r1 public key"
    (let ((key (cl-jwk:decode :json (jwk-file-contents "secp384r1-pub.json"))))
      (ok (string= "EC" (cl-jwk:jwk-kty key)) "kty matches")
      (ok (string= "sig" (cl-jwk:jwk-use key)) "use matches")
      (ok (string= "test-id" (cl-jwk:jwk-kid key)) "kid matches")
      (ok (equal :ES384 (cl-jwk:jwk-alg key)) "alg matches")
      (ok (typep (cl-jwk:jwk-key key) 'ironclad:secp384r1-public-key) "public key type matches")))

  (testing "decode secp521r1 public key"
    (let ((key (cl-jwk:decode :json (jwk-file-contents "secp521r1-pub.json"))))
      (ok (string= "EC" (cl-jwk:jwk-kty key)) "kty matches")
      (ok (string= "sig" (cl-jwk:jwk-use key)) "use matches")
      (ok (string= "test-id" (cl-jwk:jwk-kid key)) "kid matches")
      (ok (equal :ES512 (cl-jwk:jwk-alg key)) "alg matches")
      (ok (typep (cl-jwk:jwk-key key) 'ironclad:secp521r1-public-key) "public key type matches")))

  (testing "decode secp256k1 public key"
    (let ((key (cl-jwk:decode :json (jwk-file-contents "secp256k1-pub.json"))))
      (ok (string= "EC" (cl-jwk:jwk-kty key)) "kty matches")
      (ok (string= "sig" (cl-jwk:jwk-use key)) "use matches")
      (ok (string= "test-id" (cl-jwk:jwk-kid key)) "kid matches")
      (ok (equal :ES256K (cl-jwk:jwk-alg key)) "alg matches")
      (ok (typep (cl-jwk:jwk-key key) 'ironclad:secp256k1-public-key) "public key type matches"))))
