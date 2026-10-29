(in-package #:pazuzu)

(defun constant-time-equal (left right)
  (let ((diff (logxor (length left) (length right))))
    (loop for index below (max (length left) (length right))
          for a = (if (< index (length left)) (char-code (char left index)) 0)
          for b = (if (< index (length right)) (char-code (char right index)) 0)
          do (setf diff (logior diff (logxor a b))))
    (zerop diff)))

(defun quoted-realm (realm)
  "RFC 9110 §§5.6.4 and 11.5. A challenge realm is one quoted-string.
DQUOTE and backslash are sent as quoted-pairs."
  (with-output-to-string (out)
    (write-char #\" out)
    (loop for character across realm
          for code = (char-code character)
          do (unless (or (char= character #\Tab)
                         (char= character #\Space)
                         (<= 33 code 126)
                         (<= 128 code 255))
               (error "Realm is not a quoted-string."))
             (when (or (char= character #\") (char= character #\\))
               (write-char #\\ out))
             (write-char character out))
    (write-char #\" out)))

(defun unauthorized (scheme realm)
  (make-response :status 401
                 :content-type "text/plain; charset=utf-8"
                 :headers `(("www-authenticate" . ,(format nil "~a realm=~a" scheme (quoted-realm realm))))
                 :body "Unauthorized"))

(defun basic-credentials (request)
  (let ((header (request-header request "authorization")))
    (when (and header (> (length header) 6) (string-equal header "Basic " :end1 6))
      (handler-case
          (let* ((decoded (babel:octets-to-string
                           (cl-base64:base64-string-to-usb8-array
                            (string-trim '(#\Space #\Tab) (subseq header 6)))
                           :encoding :utf-8))
                 (colon (position #\: decoded)))
            (when colon
              (values (subseq decoded 0 colon) (subseq decoded (1+ colon)))))
        (error () nil)))))

(defvar *reject-before-content* (make-hash-table :test #'eq :weakness :key))

(defun register-reject-before-content (handler check)
  "Remember CHECK for HANDLER. CHECK returns a final response, or NIL when
the content is still required. HANDLER is what add-route stores."
  (setf (gethash handler *reject-before-content*) check)
  handler)

(defun reject-before-content (handler request)
  "A final response HANDLER can decide without the content, or NIL.
RFC 9110 §10.1.1. The inner handler is not called."
  (let ((check (and (functionp handler)
                    (gethash handler *reject-before-content*))))
    (when check
      (funcall check request))))

(defun basic-authorized-p (request user password)
  (multiple-value-bind (got-user got-password) (basic-credentials request)
    (and got-user
         (constant-time-equal got-user user)
         (constant-time-equal got-password password))))

(defun require-basic (handler &key user password (realm "pazuzu"))
  "Wrap HANDLER so it runs only after a matching Basic credential (RFC 7617)."
  (register-reject-before-content
   (lambda (request)
     (if (basic-authorized-p request user password)
         (funcall handler request)
         (unauthorized "Basic" realm)))
   (lambda (request)
     (if (basic-authorized-p request user password)
         (reject-before-content handler request)
         (unauthorized "Basic" realm)))))

(defun bearer-token (request)
  (let ((header (request-header request "authorization")))
    (when (and header (> (length header) 7) (string-equal header "Bearer " :end1 7))
      (let ((token (string-trim '(#\Space #\Tab) (subseq header 7))))
        (when (and (plusp (length token))
                   (every (lambda (character)
                            (let ((code (char-code character)))
                              (<= 33 code 126)))
                          token))
          token)))))

(defun bearer-authorized-p (request token)
  (let ((got (bearer-token request)))
    (and got (constant-time-equal got token))))

(defun require-bearer (handler &key token (realm "pazuzu"))
  "Wrap HANDLER so it runs only after a matching Bearer token (RFC 6750)."
  (register-reject-before-content
   (lambda (request)
     (if (bearer-authorized-p request token)
         (funcall handler request)
         (unauthorized "Bearer" realm)))
   (lambda (request)
     (if (bearer-authorized-p request token)
         (reject-before-content handler request)
         (unauthorized "Bearer" realm)))))

(defvar *digest-lock* (bt:make-lock "pazuzu-digest"))
(defvar *digest-nonces* (make-hash-table :test #'equal))

(defstruct digest-nonce
  expiry
  opaque
  (seen (make-hash-table :test #'equal)))

(defun sha256-hex (text)
  (string-downcase
   (ironclad:byte-array-to-hex-string
    (ironclad:digest-sequence :sha256 (utf8-octets text)))))

(defun random-hex (count)
  (string-downcase
   (ironclad:byte-array-to-hex-string (ironclad:random-data count))))

(defun fresh-digest-nonce ()
  (let ((nonce (random-hex 16))
        (record (make-digest-nonce :expiry (+ (get-universal-time) 300)
                                   :opaque (random-hex 8))))
    (bt:with-lock-held (*digest-lock*)
      (maphash (lambda (key value)
                 (when (< (digest-nonce-expiry value) (get-universal-time))
                   (remhash key *digest-nonces*)))
               *digest-nonces*)
      (setf (gethash nonce *digest-nonces*) record))
    (values nonce (digest-nonce-opaque record))))

(defun digest-challenge (realm &key stale)
  "RFC 7616 §3.3. stale is a token, not a quoted string, and is sent
only when the nonce is invalid and the rest of the digest matches."
  (multiple-value-bind (nonce opaque) (fresh-digest-nonce)
    (make-response :status 401
                   :content-type "text/plain; charset=utf-8"
                   :headers `(("www-authenticate"
                               . ,(format nil "Digest realm=~a, nonce=\"~a\", algorithm=SHA-256, qop=\"auth\", opaque=\"~a\"~:[~;, stale=true~]"
                                          (quoted-realm realm) nonce opaque stale)))
                   :body "Unauthorized")))

(defun digest-hash-matches-p (user password realm method uri nonce nc cnonce qop response)
  (let* ((ha1 (sha256-hex (format nil "~a:~a:~a" user realm password)))
         (ha2 (sha256-hex (format nil "~a:~a" method uri)))
         (expect (sha256-hex (format nil "~a:~a:~a:~a:~a:~a"
                                     ha1 nonce nc cnonce qop ha2))))
    (constant-time-equal (string-downcase response) expect)))

(defun parse-digest-params (text)
  (let ((index 0)
        (end (length text))
        (params nil))
    (labels ((skip ()
               (loop while (and (< index end)
                                (member (char text index) '(#\Space #\Tab #\,)))
                     do (incf index)))
             (token ()
               (let ((start index))
                 (loop while (and (< index end) (token-char-p (char text index)))
                       do (incf index))
                 (subseq text start index)))
             (value ()
               (skip)
               (unless (and (< index end) (char= (char text index) #\=))
                 (return-from parse-digest-params nil))
               (incf index)
               (skip)
               (cond ((and (< index end) (char= (char text index) #\"))
                      (incf index)
                      (let ((out (make-array 0 :element-type 'character :adjustable t :fill-pointer 0)))
                        (loop while (< index end)
                              for character = (char text index)
                              do (incf index)
                                 (cond ((char= character #\\)
                                        (when (< index end)
                                          (vector-push-extend (char text index) out)
                                          (incf index)))
                                       ((char= character #\")
                                        (return))
                                       (t (vector-push-extend character out))))
                        out))
                     (t (token)))))
      (loop while (< index end)
            do (skip)
            until (>= index end)
            do (let ((name (string-downcase (token))))
                 (when (zerop (length name))
                   (return-from parse-digest-params nil))
                 (let ((field (value)))
                   (unless field
                     (return-from parse-digest-params nil))
                   (push (cons name field) params)))))
    params))

(defun digest-authorized-p (request user password realm &key (commit t))
  "Return authorized and stale. COMMIT nil checks the digest without storing nc."
  (let* ((header (request-header request "authorization"))
         (params (and header
                      (> (length header) 7)
                      (string-equal header "Digest " :end1 7)
                      (parse-digest-params (subseq header 7)))))
    (unless params
      (return-from digest-authorized-p nil))
    (let ((got-user (cdr (assoc "username" params :test #'string=)))
          (realm-got (cdr (assoc "realm" params :test #'string=)))
          (nonce (cdr (assoc "nonce" params :test #'string=)))
          (uri (cdr (assoc "uri" params :test #'string=)))
          (response (cdr (assoc "response" params :test #'string=)))
          (algorithm (cdr (assoc "algorithm" params :test #'string=)))
          (cnonce (cdr (assoc "cnonce" params :test #'string=)))
          (nc (cdr (assoc "nc" params :test #'string=)))
          (qop (cdr (assoc "qop" params :test #'string=)))
          (opaque (cdr (assoc "opaque" params :test #'string=))))
      (unless (and got-user realm-got nonce uri response algorithm cnonce nc qop opaque
                   (string-equal algorithm "SHA-256")
                   (string-equal qop "auth")
                   (= (length nc) 8)
                   (every (lambda (character) (digit-char-p character 16)) nc)
                   (string= uri (request-target request))
                   (constant-time-equal got-user user)
                   (constant-time-equal realm-got realm))
        (return-from digest-authorized-p (values nil nil)))
      (bt:with-lock-held (*digest-lock*)
        (let ((found (gethash nonce *digest-nonces*))
              (count (string-downcase nc)))
          (unless (and found
                       (constant-time-equal opaque (digest-nonce-opaque found))
                       (digest-hash-matches-p user password realm
                                              (request-method request) uri
                                              nonce nc cnonce qop response))
            ;; A wrong digest does not consume nc. The count is recorded
            ;; only after the response matches (RFC 7616 §3.4).
            (return-from digest-authorized-p (values nil nil)))
          (cond ((>= (get-universal-time) (digest-nonce-expiry found))
                 ;; Nonce invalid, digest otherwise valid. Do not record nc.
                 (values nil t))
                ((gethash count (digest-nonce-seen found))
                 (values nil nil))
                (t
                 (when commit
                   (setf (gethash count (digest-nonce-seen found)) t))
                 (values t nil))))))))

(defun require-digest (handler &key user password (realm "pazuzu"))
  "Wrap HANDLER so it runs only after a matching Digest credential.
Only SHA-256 with qop=auth is accepted (RFC 7616). MD5 is rejected.
A failed digest is known from the Authorization field, so Expect:
100-continue can be answered before the content is read."
  (register-reject-before-content
   (lambda (request)
     (multiple-value-bind (authorized stale)
         (digest-authorized-p request user password realm)
       (if authorized
           (funcall handler request)
           (digest-challenge realm :stale stale))))
   (lambda (request)
     ;; Do not record nc until the request is accepted. A probe that
     ;; succeeds must leave the count usable for that acceptance.
     (multiple-value-bind (authorized stale)
         (digest-authorized-p request user password realm :commit nil)
       (if authorized
           (reject-before-content handler request)
           (digest-challenge realm :stale stale))))))
