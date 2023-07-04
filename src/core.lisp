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
(defpackage :cl-jwk.core
  (:use :cl)
  (:nicknames :cl-jwk.core)
  (:import-from :alexandria)
  (:import-from :ironclad)
  (:import-from :jonathan)
  (:import-from :dexador)
  (:export
   ;; vars
   :*user-agent*

   ;; client and accessors
   :client
   :client-scheme
   :client-port
   :client-hostname
   :client-api-prefix
   :make-client

   ;; jwk and readers
   :jwk
   :jwk-kty
   :jwk-use
   :jwk-kid
   :jwk-alg
   :jwk-key-ops
   :jwk-key

   ;; generics
   :make-api-uri
   :openid-provider-metadata
   :public-keys
   :decode

   ;; conditions
   :invalid-key
   :invalid-key-message
   :invalid-key-data))
(in-package :cl-jwk.core)

(defparameter *user-agent*
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.4 Safari/605.1.15"
  "User-Agent header to use")

(defgeneric openid-provider-metadata (client)
  (:documentation "Returns the OpenID Provider Metadata"))

(defgeneric make-api-uri (client path &key query-params)
  (:documentation "Returns an URI to the given API path"))

(defgeneric public-keys (client)
  (:documentation "Returns the public keys used to verify the authenticity of tokens"))

(defgeneric decode (kind data)
  (:documentation "Decodes a JWK key of the given kind using the provided data"))

(define-condition invalid-key (simple-error)
  ((message
    :initarg :message
    :initform (error "Must specify error message")
    :reader invalid-key-message
    :documentation "Human-friendly error message")
   (data
    :initarg :data
    :initform (error "Must specify key data")
    :reader invalid-key-data
    :documentation "The data of the invalid key"))
  (:documentation "Condition which is signalled when an invalid key is detected")
  (:report (lambda (condition stream)
             (format stream "~A" (invalid-key-message condition)))))

(defun keywordize (name)
  "Returns a keyword from the given NAME"
  (intern (string name) :keyword))

(defclass jwk ()
  ((kty
    :initarg :kty
    :initform (error "Must specify key type")
    :reader jwk-kty
    :documentation "Key Type parameter")
    (use
     :initarg :use
     :initform nil
     :reader jwk-use
     :documentation "Public Key Use parameter")
    (kid
     :initarg :kid
     :initform nil
     :reader jwk-kid
     :documentation "Key ID parameter")
    (alg
     :initarg :alg
     :initform nil
     :reader jwk-alg
     :documentation "Algorithm parameter")
    (key-ops
     :initarg :key-ops
     :initform nil
     :reader jwk-key-ops
     :documentation "Key Operations Parameter")
    (key
     :initarg :key
     :initform (error "Must specify public key")
     :reader jwk-key
     :documentation "The associated public key"))
  (:documentation "JWK represents a public JSON Web Key (JWK) as per RFC 7517"))

(defclass client ()
  ((scheme
    :initarg :scheme
    :initform "https"
    :accessor client-scheme
    :documentation "Scheme to use")
   (port
    :initarg :port
    :initform 443
    :accessor client-port
    :documentation "Port to connect to")
   (hostname
    :initarg :hostname
    :initform (error "Must specify hostname")
    :accessor client-hostname
    :documentation "Hostname to connect to")
   (api-prefix
    :initarg :api-prefix
    :initform ""
    :accessor client-api-prefix
    :documentation "API prefix"))
  (:documentation "API client for interfacing with an OpenID Provider endpoint"))

(defun make-client (&rest rest)
  "Creates a new client for interfacing with the CSP APIs"
  (apply #'make-instance 'client rest))

(defmethod make-api-uri ((client client) path &key query-params)
  "Creates an URI to the given API path"
  (quri:make-uri :scheme (client-scheme client)
                 :port (client-port client)
                 :host (client-hostname client)
                 :path (format nil "~a~a" (client-api-prefix client) path)
                 :query query-params))

(defmethod openid-provider-metadata ((client client))
  "Returns the OpenID Provider Metadata"
  (let* ((headers `(("Accept" . "application/json")
                    ("User-Agent" . ,*user-agent*)
                    ("Content-Type" . "application/json")))
         (uri (make-api-uri client "/.well-known/openid-configuration"))
         (resp (dexador:get uri :headers headers)))
    (jonathan:parse resp :as :plist)))

(defmethod decode ((kind (eql :json)) json-string)
  "Decodes JWK public key from the given JSON string"
  (decode :key (jonathan:parse json-string :as :plist)))

(defmethod decode ((kind (eql :key)) data)
  "Decodes a JWK public key by inferring the key from the given plist
data and dispatches further decoding to the respective implementation"
  (let* ((use (getf data :|use|))
         (alg (getf data :|alg|))
         (kid (getf data :|kid|))
         (kty (getf data :|kty|))
         (key-ops (getf data :|key_ops|))
         (key (alexandria:switch (kty :test #'string=)
                ("RSA" (decode :rsa data))
                ("EC" (decode :ec data))
                ("oct" (decode :oct data))
                (t (error 'invalid-key :message "Unsupported public key type" :data data)))))
    (make-instance 'jwk
                   :kty kty
                   :use use
                   :kid kid
                   :alg (and alg (keywordize alg))
                   :key-ops key-ops
                   :key key)))

(defmethod decode ((kind (eql :ec)) data)
  "Decodes an Elliptic Curve public key from the given data"
  (let ((crv (getf data :|crv|)))
    (alexandria:switch (crv :test #'string=)
      ("P-256" (decode :secp256r1 data))
      ("P-384" (decode :secp384r1 data))
      ("P-521" (decode :secp521r1 data))
      ("secp256k1" (decode :secp256k1 data))
      (t (error 'invalid-key :message "Unsupported Elliptic Curve public key" :data data)))))

(defmethod decode ((kind (eql :rsa)) data)
  "Decodes RSA public key using the provided plist data.
See RFC 7517 about the JWK format and RFC 7518, Section 6.3 about the
RSA key parameters."
  (let ((e (getf data :|e|))
        (n (getf data :|n|)))
    (unless n
      (error 'invalid-key :message "Missing modulus parameter" :data data))
    (unless e
      (error 'invalid-key :message "Missing exponent parameter" :data data))
    ;; The RSA public key parameters are Base64urlUInt-encoded values
    (let* ((e-decoded (ironclad:octets-to-integer
                       (binascii:decode-base64url e)))
           (n-decoded (ironclad:octets-to-integer
                       (binascii:decode-base64url n))))
      (ironclad:make-public-key :rsa :n n-decoded :e e-decoded))))

(defmethod decode ((kind (eql :secp256r1)) data)
  "Decodes Secp256r1 (NIST P-256) public key from the given plist data.
See RFC 7518, Section 6.2.1 for more details about Elliptic Curve
public keys format."
  (let ((x (getf data :|x|))
        (y (getf data :|y|)))
    (unless x
      (error 'invalid-key :message "Missing X coordinate parameter" :data data))
    (unless y
      (error 'invalid-key :message "Missing Y coordinate parameter" :data data))
    ;; The X and Y coordinates are Base64urlUInt-encoded values
    (let* ((x-octets (binascii:decode-base64url x))
           (y-octets (binascii:decode-base64url y))
           (x-uint (ironclad::ec-decode-scalar :secp256r1 x-octets))
           (y-uint (ironclad::ec-decode-scalar :secp256r1 y-octets))
           (point (make-instance 'ironclad::secp256r1-point :x x-uint :y y-uint :z 1)))
      (unless (and (= (length x-octets) 32)
                   (= (length y-octets) 32))
        (error 'invalid-key :message "Coordinates should be 32 bytes for Secp256r1 key" :data data))
      (ironclad:make-public-key :secp256r1 :y (ironclad::ec-encode-point point)))))

(defmethod decode ((kind (eql :secp384r1)) data)
  "Decodes Secp384r1 (NIST P-384) public key from the given plist data.
See RFC 7518, Section 6.2.1 for more details about Elliptic Curve
public keys format."
  (let ((x (getf data :|x|))
        (y (getf data :|y|)))
    (unless x
      (error 'invalid-key :message "Missing X coordinate parameter" :data data))
    (unless y
      (error 'invalid-key :message "Missing Y coordinate parameter" :data data))
    ;; The X and Y coordinates are Base64urlUInt-encoded values
    (let* ((x-octets (binascii:decode-base64url x))
           (y-octets (binascii:decode-base64url y))
           (x-uint (ironclad::ec-decode-scalar :secp384r1 x-octets))
           (y-uint (ironclad::ec-decode-scalar :secp384r1 y-octets))
           (point (make-instance 'ironclad::secp384r1-point :x x-uint :y y-uint :z 1)))
      (unless (and (= (length x-octets) 48)
                   (= (length y-octets) 48))
        (error 'invalid-key :message "Coordinates should be 48 bytes for Secp384r1 key" :data data))
      (ironclad:make-public-key :secp384r1 :y (ironclad::ec-encode-point point)))))

(defmethod decode ((kind (eql :secp521r1)) data)
  "Decodes Secp521r1 (NIST P-521) public key from the given plist data.
See RFC 7518, Section 6.2.1 for more details about Elliptic Curve
public keys format."
  (let ((x (getf data :|x|))
        (y (getf data :|y|)))
    (unless x
      (error 'invalid-key :message "Missing X coordinate parameter" :data data))
    (unless y
      (error 'invalid-key :message "Missing Y coordinate parameter" :data data))
    ;; The X and Y coordinates are Base64urlUInt-encoded values
    (let* ((x-octets (binascii:decode-base64url x))
           (y-octets (binascii:decode-base64url y))
           (x-uint (ironclad::ec-decode-scalar :secp521r1 x-octets))
           (y-uint (ironclad::ec-decode-scalar :secp521r1 y-octets))
           (point (make-instance 'ironclad::secp521r1-point :x x-uint :y y-uint :z 1)))
      (unless (and (= (length x-octets) 66)
                   (= (length y-octets) 66))
        (error 'invalid-key :message "Coordinates should be 66 bytes for Secp521r1 key" :data data))
      (ironclad:make-public-key :secp521r1 :y (ironclad::ec-encode-point point)))))

(defmethod decode ((kind (eql :secp256k1)) data)
  "Decodes Secp256k1 public key from the given plist data.
See RFC 7518, Section 6.2.1 for more details about Elliptic Curve
public keys format."
  (let ((x (getf data :|x|))
        (y (getf data :|y|)))
    (unless x
      (error 'invalid-key :message "Missing X coordinate parameter" :data data))
    (unless y
      (error 'invalid-key :message "Missing Y coordinate parameter" :data data))
    ;; The X and Y coordinates are Base64urlUInt-encoded values
    (let* ((x-octets (binascii:decode-base64url x))
           (y-octets (binascii:decode-base64url y))
           (x-uint (ironclad::ec-decode-scalar :secp256k1 x-octets))
           (y-uint (ironclad::ec-decode-scalar :secp256k1 y-octets))
           (point (make-instance 'ironclad::secp256k1-point :x x-uint :y y-uint :z 1)))
      (unless (and (= (length x-octets) 32)
                   (= (length y-octets) 32))
        (error 'invalid-key :message "Coordinates should be 32 bytes for Secp256k1 key" :data data))
      (ironclad:make-public-key :secp256k1 :y (ironclad::ec-encode-point point)))))

(defun %get-hmac (key alg data)
  (alexandria:switch (alg :test #'string=)
    ("HS256" (ironclad:make-hmac key :sha256))
    ("HS384" (ironclad:make-hmac key :sha384))
    ("HS512" (ironclad:make-hmac key :sha512))
    (t (error 'invalid-key :message "Unsupported symmetric key algorithm" :data data))))

(defmethod decode ((kind (eql :oct)) data)
  "Decodes a JWK `octet-sequence' symmetric key from the given plist data.
See RFC 7518, Section 6.4 for more details about Symmetric Keys format."
  (let ((k (getf data :|k|))
        (alg (getf data :|alg|)))
    (unless k
      (error 'invalid-key :message "Missing octet sequence" :data data))
    (unless alg
      (error 'invalid-key :message "Missing algorithm identifier" :data data))
    (%get-hmac (binascii:decode-base64url k) alg data)))
