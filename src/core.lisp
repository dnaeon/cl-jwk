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

   ;; generics
   :make-api-uri
   :openid-provider-metadata
   :public-keys
   :parse-key

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

(defgeneric parse-key (kind data)
  (:documentation "Parses a JWK key of the given kind using the provided data"))

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

(defmethod parse-key ((kind (eql :rsa)) data)
  "Parses RSA public key using the provided plist data.
See RFC 7517 about the JWK format and RFC 7518, Section 6.3 about the
RSA key parameters."
  (let ((use (getf data :|use|))
        (alg (getf data :|alg|))
        (kid (getf data :|kid|))
        (kty (getf data :|kty|))
        (e (getf data :|e|))
        (n (getf data :|n|)))
    (unless (string= kty "RSA")
      (error 'invalid-key :message "Invalid RSA public key" :data data))
    (unless n
      (error 'invalid-key :message "Missing modulus parameter" :data data))
    (unless e
      (error 'invalid-key :message "Missing exponent parameter" :data data))
    ;; The RSA public key parameters are Base64urlUInt-encoded values
    (let* ((e-decoded (ironclad:octets-to-integer
                       (binascii:decode-base64url
                        (babel:string-to-octets e))))
           (n-decoded (ironclad:octets-to-integer
                       (binascii:decode-base64url
                        (babel:string-to-octets n))))
           (key (ironclad:make-public-key :rsa :n n-decoded :e e-decoded)))
      (list :use use :alg alg :kid kid :kty kty :key key))))
