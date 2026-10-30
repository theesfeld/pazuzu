;;; HTTP/1.1 checks.

(in-package #:pazuzu/tests)

(defun header-section-before-apply-test (port)
  "RFC 9110 §5.3. The origin does not apply a request to the target
resource until the entire header section has arrived."
  (check "a request is not applied before its header section ends"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (setf *header-applies* 0)
             (write-sequence
              (octets (with-output-to-string (out)
                        (write-string "GET /applied HTTP/1.1" out)
                        (write-char #\Return out)
                        (write-char #\Newline out)
                        (write-string "Host: 127.0.0.1" out)
                        (write-char #\Return out)
                        (write-char #\Newline out)))
              stream)
             (finish-output stream)
             (sleep 0.3)
             (unless (zerop *header-applies*)
               (fail "applied ~d before the header section ended" *header-applies*))
             (when (usocket:wait-for-input socket :timeout 0 :ready-only t)
               (fail "response before the header section ended"))
             (write-sequence (octets (format nil "~c~c" #\Return #\Newline)) stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "applied")
                 (fail "body ~s" (body-text reply)))
               (unless (= *header-applies* 1)
                 (fail "applied ~d" *header-applies*))))
        (ignore-errors (usocket:socket-close socket))))))

(defun single-range-test (port)
  "RFC 9110 §§15.3.7.1 and 15.3.7.2. A single range is a 206 with
Content-Range and that extent, not a multipart response."
  (check "a single range is not a multipart response"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-3"))))
      (expect-status reply 206)
      (unless (string= (body-text reply) "abcd")
        (fail "body ~s" (body-text reply)))
      (unless (string= (header reply "content-range") "bytes 0-3/10")
        (fail "content-range ~s" (header reply "content-range")))
      (let ((type (or (header reply "content-type") "")))
        (when (search "multipart" type :test #'char-equal)
          (fail "content-type ~s" type))))))

(defun long-target-test (port)
  "RFC 9112 §3. A request-target longer than the server is willing to
parse is 414. The request-line limit is 8000 octets. A line of that
length is parsed. One more octet is URI Too Long."
  (check "a request-target longer than the server parses is 414"
    (let* ((prefix "GET /")
           (suffix " HTTP/1.1")
           (room (- 8000 (length prefix) (length suffix))))
      (expect-status
       (exchange port (request-text
                       (concatenate 'string prefix
                                    (make-string room :initial-element #\a)
                                    suffix)
                       "Host: 127.0.0.1"))
       404)
      (expect-status
       (exchange port (request-text
                       (concatenate 'string prefix
                                    (make-string (1+ room) :initial-element #\a)
                                    suffix)
                       "Host: 127.0.0.1"))
       414))))

(defun too-many-fields-test (port)
  "RFC 9110 §5.4. The origin accepts 100 field lines. One more is 431,
and the target resource is not returned."
  (check "too many header fields is 431"
    (let* ((extra (loop for index from 1 to 100
                        collect (format nil "X-Extra-~d: v" index)))
           (reply (exchange port (apply #'request-text
                                        "GET / HTTP/1.1"
                                        "Host: 127.0.0.1"
                                        extra))))
      (expect-status reply 431)
      (unless (search "Request Header Fields Too Large" (body-text reply))
        (fail "body ~s" (body-text reply)))
      (when (search "pazuzu" (body-text reply))
        (fail "resource body ~s" (body-text reply))))))

(defun long-field-line-test (port)
  "RFC 9110 §5.4. A header field line longer than 8000 octets is a 4xx.
The target resource is not returned."
  (check "a header field line longer than 8000 octets is 400"
    (let* ((value (make-string 7993 :initial-element #\a))
           (reply (exchange port (request-text "GET / HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               (format nil "X-Long: ~a" value)))))
      (expect-status reply 400)
      (unless (search "Bad Request" (body-text reply))
        (fail "body ~s" (body-text reply)))
      (when (search "pazuzu" (body-text reply))
        (fail "resource body ~s" (body-text reply))))))

(defun large-field-section-test (port)
  "RFC 9110 §5.4. Eleven field lines whose section exceeds 65536 octets
is 431. The field count stays within 100, and GET / is not returned."
  (check "a header section larger than 65536 octets is 431"
    (let* ((value (make-string 7000 :initial-element #\b))
           (extra (loop for index from 1 to 10
                        collect (format nil "X-Big-~d: ~a" index value)))
           (reply (exchange port (apply #'request-text
                                        "GET / HTTP/1.1"
                                        "Host: 127.0.0.1"
                                        extra))))
      (expect-status reply 431)
      (unless (search "Request Header Fields Too Large" (body-text reply))
        (fail "body ~s" (body-text reply)))
      (when (search "pazuzu" (body-text reply))
        (fail "resource body ~s" (body-text reply))))))

(defun read-protocol-line (stream)
  "Read one CRLF-terminated protocol line, including the CRLF.
A CR that is not followed by LF fails the current check."
  (let ((line (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte stream)
          do (cond ((= byte 13)
                    (let ((next (read-byte stream)))
                      (vector-push-extend byte line)
                      (vector-push-extend next line)
                      (unless (= next 10)
                        (fail "bare CR"))
                      (return line)))
                   (t (vector-push-extend byte line))))))

(defun response-no-bare-cr-test (port)
  "RFC 9112 §2.2. The status line, field lines, and chunk-size lines of
a generated response contain no bare CR. GET / returns pazuzu. GET
/events is chunked and still returns its event."
  (check "a generated response has no bare CR"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1")) stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (loop for index from 0 below (length head)
                     when (= (aref head index) 13)
                       do (unless (and (< (1+ index) (length head))
                                       (= (aref head (1+ index)) 10))
                            (fail "bare CR at ~d" index)))
               (multiple-value-bind (status status-line headers)
                   (parse-headers (latin1 (subseq head 0 (- (length head) 4))))
                 (unless (and (= status 200)
                              (search "HTTP/1.1 200" status-line))
                   (fail "status ~s" status-line))
                 (let ((body (read-n stream (parse-integer
                                             (or (cdr (assoc "content-length" headers :test #'string=))
                                                 (fail "no content-length"))))))
                   (unless (string= (babel:octets-to-string body :encoding :utf-8) "pazuzu")
                     (fail "body ~s" body))))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (content (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
             (write-sequence (octets (request-text "GET /events HTTP/1.1" "Host: 127.0.0.1")) stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (loop for index from 0 below (length head)
                     when (= (aref head index) 13)
                       do (unless (and (< (1+ index) (length head))
                                       (= (aref head (1+ index)) 10))
                            (fail "chunked bare CR at ~d" index)))
               (multiple-value-bind (status status-line headers)
                   (parse-headers (latin1 (subseq head 0 (- (length head) 4))))
                 (unless (= status 200)
                   (fail "events status ~s" status-line))
                 (unless (search "chunked" (or (cdr (assoc "transfer-encoding" headers :test #'string=)) "")
                                 :test #'char-equal)
                   (fail "transfer-encoding ~s" headers))))
             (loop for line = (read-protocol-line stream)
                   for text = (latin1 (subseq line 0 (- (length line) 2)))
                   for semi = (position #\; text)
                   for size = (parse-integer (if semi (subseq text 0 semi) text) :radix 16)
                   do (when (plusp size)
                        (let ((payload (read-n stream size)))
                          (loop for byte across payload do (vector-push-extend byte content)))
                        (let ((end (read-n stream 2)))
                          (unless (and (= (length end) 2)
                                       (= (aref end 0) 13)
                                       (= (aref end 1) 10))
                            (fail "chunk delimiter ~s" end))))
                      (when (zerop size)
                        (loop for trailer = (read-protocol-line stream)
                              until (= (length trailer) 2))
                        (unless (search "hello" (babel:octets-to-string content :encoding :utf-8))
                          (fail "events ~s" content))
                        (return))))
        (ignore-errors (usocket:socket-close socket))))))

(defun response-field-colon-test (port)
  "RFC 9112 §5.1 and RFC 9110 §2.2. A generated field line places the
colon immediately after the field name. GET / returns pazuzu."
  (check "a generated field line has no whitespace before the colon"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1")) stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (multiple-value-bind (status status-line headers)
                   (parse-headers (latin1 (subseq head 0 (- (length head) 4))))
                 (unless (and (= status 200)
                              (search "HTTP/1.1 200" status-line))
                   (fail "status ~s" status-line))
                 (let ((body (read-n stream (parse-integer
                                             (or (cdr (assoc "content-length" headers :test #'string=))
                                                 (fail "no content-length"))))))
                   (unless (string= (babel:octets-to-string body :encoding :utf-8) "pazuzu")
                     (fail "body ~s" body)))
                 (let ((fields 0))
                   (dolist (line (uiop:split-string
                                  (latin1 (subseq head 0 (- (length head) 2)))
                                  :separator '(#\Newline)))
                     (let ((raw (string-right-trim '(#\Return) line)))
                       (unless (or (zerop (length raw))
                                   (eql 0 (search "HTTP/" raw)))
                         (let ((colon (position #\: raw)))
                           (unless colon
                             (fail "no colon ~s" raw))
                           (let ((name (subseq raw 0 colon)))
                             (unless (pazuzu::token-string-p name)
                               (fail "name ~s" raw))
                             (incf fields))))))
                   (unless (plusp fields)
                     (fail "no fields"))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun response-nul-field-test (port)
  "RFC 9110 §§2.2 and 5.5. Field values exclude NUL, so a sender must not
generate one. The handler value contains NUL. One 500 is sent, and that
NUL is not in the status line, the field section, or the body."
  (check "a response field with NUL is a single 500"
    (let ((reply (exchange port (request-text "GET /nul-header HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 500)
      (unless (and (reply-status-line reply)
                   (search "500" (reply-status-line reply))
                   (not (find #\Nul (reply-status-line reply))))
        (fail "status line ~s" (reply-status-line reply)))
      (unless (string= (body-text reply) "Internal Server Error")
        (fail "body ~s" (body-text reply)))
      (when (search "nope" (body-text reply))
        (fail "handler body ~s" (body-text reply)))
      (when (header reply "x-pad")
        (fail "sent ~s" (header reply "x-pad")))
      (dolist (pair (reply-headers reply))
        (when (or (find #\Nul (car pair)) (and (stringp (cdr pair)) (find #\Nul (cdr pair))))
          (fail "nul header ~s" pair)))
      (when (find 0 (reply-body reply))
        (fail "nul body")))))

(defun response-lf-field-test (port)
  "RFC 9110 §§2.2 and 5.5. Field values exclude LF, so a sender must not
generate one. The handler value contains only LF, not CR. One 500 is
sent, and that LF is not in the status line, the field section, or the body."
  (check "a response field with LF is a single 500"
    (let ((reply (exchange port (request-text "GET /lf-header HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 500)
      (unless (and (reply-status-line reply)
                   (search "500" (reply-status-line reply))
                   (not (find #\Newline (reply-status-line reply))))
        (fail "status line ~s" (reply-status-line reply)))
      (unless (string= (body-text reply) "Internal Server Error")
        (fail "body ~s" (body-text reply)))
      (when (search "nope" (body-text reply))
        (fail "handler body ~s" (body-text reply)))
      (when (header reply "x-pad")
        (fail "sent ~s" (header reply "x-pad")))
      (dolist (pair (reply-headers reply))
        (when (or (find #\Newline (car pair))
                  (and (stringp (cdr pair)) (find #\Newline (cdr pair))))
          (fail "lf header ~s" pair)))
      (when (find 10 (reply-body reply))
        (fail "lf body")))))

(defun get-asterisk-test (port)
  "RFC 9110 §7.1. Asterisk-form is not used with a method other than
OPTIONS. GET * is 400. Treating * as the root resource would answer 200."
  (check "GET * is rejected"
    (let ((reply (exchange port (request-text "GET * HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 400)
      (when (search "pazuzu" (or (ignore-errors (body-text reply)) ""))
        (fail "served ~s" (body-text reply))))))

(defun authority-form-method-test (port)
  "RFC 9110 §7.1 and RFC 9112 §3.2.3. Authority-form is the host and port
used for CONNECT. A GET whose request-target is that form is 400, not a
representation of the root resource."
  (check "authority-form is not used with GET"
    (let ((reply (exchange port (request-text "GET 127.0.0.1:80 HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 400)
      (when (search "pazuzu" (or (ignore-errors (body-text reply)) ""))
        (fail "served ~s" (body-text reply))))))

(defun if-match-strong-test (port)
  "RFC 9110 §13.1.1. If-Match uses the strong comparison function.
A weak tag does not match the strong validator of GET /etag. The same
opaque tag without the weak prefix does, and the body is tagged."
  (check "If-Match uses strong comparison"
    (let ((weak (exchange port (request-text "GET /etag HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "If-Match: W/\"v1\""))))
      (expect-status weak 412)
      (when (search "tagged" (or (ignore-errors (body-text weak)) ""))
        (fail "weak tag selected ~s" (ignore-errors (body-text weak)))))
    (let ((strong (exchange port (request-text "GET /etag HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "If-Match: \"v1\""))))
      (expect-status strong 200)
      (unless (string= (body-text strong) "tagged")
        (fail "strong body ~s" (ignore-errors (body-text strong)))))))

(defun if-match-case-test (port)
  "RFC 9110 §8.8.3.2. Opaque-tags match character-by-character.
If-Match: \"V1\" does not select the representation tagged \"v1\"."
  (check "an entity-tag comparison is case-sensitive"
    (let ((folded (exchange port (request-text "GET /etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Match: \"V1\""))))
      (expect-status folded 412)
      (when (search "tagged" (or (ignore-errors (body-text folded)) ""))
        (fail "case folded ~s" (ignore-errors (body-text folded)))))
    (let ((exact (exchange port (request-text "GET /etag HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "If-Match: \"v1\""))))
      (expect-status exact 200)
      (unless (string= (body-text exact) "tagged")
        (fail "exact body ~s" (ignore-errors (body-text exact)))))))

(defun range-unit-case-test (port)
  "RFC 9110 §14.1. Range unit names are case-insensitive. BYTES selects
the same extent as bytes. Treating the unit as unknown would answer 200."
  (check "a range unit name ignores case"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Range: BYTES=0-3"))))
      (expect-status reply 206)
      (unless (string= (body-text reply) "abcd")
        (fail "body ~s" (ignore-errors (body-text reply))))
      (unless (string= (header reply "content-range") "bytes 0-3/10")
        (fail "content-range ~s" (header reply "content-range"))))))

(defun content-coding-case-test (port)
  "RFC 9110 §8.4.1. Content coding names are case-insensitive.
Accept-Encoding: GZIP selects gzip. Content-Encoding: GZIP is removed
before the body is delivered."
  (check "a content coding name ignores case"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept-Encoding: GZIP"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "content-encoding") "gzip")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (babel:octets-to-string
                        (decode-coding (reply-body reply) "gzip")
                        :encoding :utf-8)
                       "abcdefghij")
        (fail "gzip body ~s" (ignore-errors (body-text reply)))))
    (let* ((raw (octets "layered"))
           (once (salza2:compress-data raw 'salza2:gzip-compressor))
           (socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence
              (octets (request-text "POST /echo HTTP/1.1"
                                    "Host: 127.0.0.1"
                                    (format nil "Content-Length: ~d" (length once))
                                    "Content-Encoding: GZIP"))
              stream)
             (write-sequence once stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (equalp (reply-body reply) raw)
                 (fail "request coding ~s" (ignore-errors (body-text reply))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun media-type-case-test (port)
  "RFC 9110 §8.3.1. Media type and subtype tokens are case-insensitive.
Accept: Text/HTML selects the html representation. A case-sensitive
match would answer 406."
  (check "a media type name ignores case"
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept: Text/HTML"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "html")
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun language-tag-case-test (port)
  "RFC 9110 §8.5. A language tag's subtags are case-insensitive.
Accept-Language: DA selects the da representation. EN also matches
en-gb, so it does not identify the comparison. A case-sensitive
match would answer 406."
  (check "a language tag ignores case"
    (let ((reply (exchange port (request-text "GET /lang HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept-Language: DA"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "da")
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun parameter-name-case-test (port)
  "RFC 9110 §5.6.6. Parameter names are case-insensitive.
Accept: text/plain;Note=\"x;q=0\" selects GET /noted. A case-sensitive
name comparison would answer 406."
  (check "a parameter name ignores case"
    (let ((reply (exchange port (request-text "GET /noted HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept: text/plain;Note=\"x;q=0\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "noted")
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun charset-case-test (port)
  "RFC 9110 §8.3.2. Charset names are matched case-insensitively.
Accept: text/plain;charset=UTF-8 selects the utf-8 representation.
A case-sensitive value comparison would answer 406."
  (check "a charset name ignores case"
    (let ((reply (exchange port (request-text "GET /charset HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept: text/plain;charset=UTF-8"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "utf8")
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun transfer-coding-case-test (port)
  "RFC 9112 §7. Transfer-coding names are case-insensitive.
Transfer-Encoding: CHUNKED is the chunked coding. A case-sensitive
match rejects the message before the body is echoed."
  (check "a transfer-coding name ignores case"
    (let ((reply (exchange port (format nil "~a5~c~chello~c~c0~c~c~c~c"
                                        (request-text "POST /echo HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: CHUNKED")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "chunked ~s" (ignore-errors (body-text reply)))))))

(defun expect-case-test (port)
  "RFC 9110 §10.1.1. The Expect field value is case-insensitive.
100-CONTINUE is the 100-continue expectation, so the origin sends 100
before it reads the content. A case-sensitive match is 417."
  (check "an expectation token ignores case"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "POST /echo HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Content-Length: 4"
                                                   "Expect: 100-CONTINUE"))
                             stream)
             (finish-output stream)
             (let ((interim (read-reply-headers-only stream)))
               (unless (= (reply-status interim) 100)
                 (fail "status ~d" (reply-status interim))))
             (write-sequence (octets "echo") stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "echo")
                 (fail "body ~s" (ignore-errors (body-text reply))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun connection-option-case-test (port)
  "RFC 9110 §7.6.1. Connection options are case-insensitive.
Connection: CLOSE closes the connection. The pipelined GET is not
answered. A case-sensitive match would keep the connection open."
  (check "a connection option ignores case"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Connection: CLOSE")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "pazuzu")
                 (fail "body ~s" (body-text reply)))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after close" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun auth-scheme-case-test (port)
  "RFC 9110 §11.1. An authentication scheme is a case-insensitive token.
Authorization: BASIC is the Basic scheme. A case-sensitive match is 401."
  (check "an authentication scheme ignores case"
    (let* ((token (cl-base64:usb8-array-to-base64-string (octets "ada:secret")))
           (reply (exchange port (request-text "GET /basic HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               (format nil "Authorization: BASIC ~a" token)))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "welcome")
        (fail "basic ~s" (ignore-errors (body-text reply)))))))

(defun challenge-parameter-once-test (port)
  "RFC 9110 §11.2. Each authentication parameter name occurs once
per challenge. A repeated name on WWW-Authenticate fails the check."
  (check "a challenge parameter name occurs once"
    (labels ((times (needle haystack)
               (loop for start = 0 then (+ pos (length needle))
                     for pos = (search needle haystack :start2 start)
                     while pos
                     count 1)))
      (let ((basic (exchange port (request-text "GET /basic HTTP/1.1"
                                               "Host: 127.0.0.1"))))
        (expect-status basic 401)
        (let ((www (or (header basic "www-authenticate") "")))
          (unless (= (times "realm=" www) 1)
            (fail "basic ~s" www))))
      (let ((digest (exchange port (request-text "GET /digest HTTP/1.1"
                                                "Host: 127.0.0.1"))))
        (expect-status digest 401)
        (let ((www (or (header digest "www-authenticate") "")))
          (dolist (name '("realm=" "nonce=" "algorithm=" "qop=" "opaque="))
            (unless (= (times name www) 1)
              (fail "~a in ~s" name www))))))))

(defun auth-parameter-case-test (port)
  "RFC 9110 §11.2. Authentication parameter names are matched
case-insensitively. Username selects the digest user. A case-sensitive
name comparison is 401."
  (check "an authentication parameter name ignores case"
    (let ((challenge (exchange port (request-text "GET /digest HTTP/1.1"
                                                 "Host: 127.0.0.1"))))
      (expect-status challenge 401)
      (let* ((www (or (header challenge "www-authenticate") (fail "no challenge")))
             (nonce (ppcre-or-scan www "nonce=\"([^\"]+)\""))
             (opaque (ppcre-or-scan www "opaque=\"([^\"]+)\""))
             (nc "00000001")
             (cnonce "abcdef01")
             (ha1 (sha256-hex "ada:pazuzu:secret"))
             (ha2 (sha256-hex "GET:/digest"))
             (response (sha256-hex (format nil "~a:~a:~a:~a:auth:~a"
                                           ha1 nonce nc cnonce ha2)))
             (reply (exchange port
                              (request-text
                               "GET /digest HTTP/1.1"
                               "Host: 127.0.0.1"
                               (format nil "Authorization: Digest Username=\"ada\", realm=\"pazuzu\", nonce=\"~a\", uri=\"/digest\", algorithm=SHA-256, response=\"~a\", qop=auth, nc=~a, cnonce=\"~a\", opaque=\"~a\""
                                       nonce response nc cnonce opaque)))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "digest-ok")
          (fail "digest ~s" (ignore-errors (body-text reply))))))))

(defun websocket-upgrade-case-test (port)
  "RFC 6455 §4.2.2. The Upgrade value websocket is an ASCII
case-insensitive match. WEBSOCKET completes the handshake. A
case-sensitive match does not switch protocols."
  (check "a WebSocket upgrade token ignores case"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: WEBSOCKET"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-connection-case-test (port)
  "RFC 6455 §4.2.2. The Connection token Upgrade is an ASCII
case-insensitive match. UPGRADE completes the handshake. A
case-sensitive match does not switch protocols."
  (check "a WebSocket connection token ignores case"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: UPGRADE"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))))
        (ignore-errors (usocket:socket-close socket))))))

(defun chunk-size-case-test (port)
  "RFC 9112 §7.1. A recipient parses chunked coding. chunk-size is
HEXDIG, so A is ten octets. A lowercase-only parser rejects the chunk."
  (check "a chunk-size accepts uppercase hex"
    (let ((reply (exchange port (format nil "~aA~c~c0123456789~c~c0~c~c~c~c"
                                        (request-text "POST /echo HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: chunked")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "0123456789")
        (fail "chunk ~s" (ignore-errors (body-text reply)))))))

(defun percent-hex-case-test (port)
  "RFC 9110 §4. The request-target is a URI. Percent-encoding uses
HEXDIG, so %4A is J. A lowercase-only decoder rejects the query."
  (check "a percent-encoding accepts uppercase hex"
    (let ((reply (exchange port (request-text "GET /q?a=%4A&c=z HTTP/1.1"
                                             "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "a=J;c=z")
        (fail "query ~s" (ignore-errors (body-text reply)))))))

(defun last-chunk-zeros-test (port)
  "RFC 9112 §7.1. The last chunk is one or more zero digits. A
chunk-size of 00 ends the body. Requiring a single 0 rejects it."
  (check "a last chunk may be more than one zero"
    (let ((reply (exchange port (format nil "~a5~c~chello~c~c00~c~c~c~c"
                                        (request-text "POST /echo HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: chunked")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "chunk ~s" (ignore-errors (body-text reply)))))))

(defun asctime-date-test (port)
  "RFC 9110 §5.6.7. A recipient that parses an HTTP-date accepts
asctime-date. The single-digit day is padded with one SP. That instant
matches Last-Modified, so the response is 304. Rejecting the format
ignores If-Modified-Since and returns the representation."
  (check "an asctime-date is an HTTP-date"
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: Sat Jan  1 00:00:00 2000"))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "asctime body ~s" (ignore-errors (body-text reply)))))))

(defun chunked-trailer-terminator-test (port)
  "RFC 9112 §7.1. chunked-body is the chunks, the last chunk, the trailer
section, and a final CRLF. A request line in place of that terminator is
not the next request. Skipping the trailer section would answer it."
  (check "a chunked body reads the trailer terminator"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (format nil "~a5~c~chello~c~c0~c~c"
                                                          (request-text "POST /echo HTTP/1.1"
                                                                        "Host: 127.0.0.1"
                                                                        "Transfer-Encoding: chunked")
                                                          #\Return #\Newline
                                                          #\Return #\Newline
                                                          #\Return #\Newline)
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after trailer" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun leap-second-date-test (port)
  "RFC 9110 §5.6.7. time-of-day allows a leap second, 23:59:60.
That HTTP-date is accepted. Rejecting it ignores If-Modified-Since."
  (check "a leap second is an HTTP-date"
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: Sat, 01 Jan 2000 23:59:60 GMT"))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "leap body ~s" (ignore-errors (body-text reply)))))))

(defun if-none-match-before-range-test (port)
  "RFC 9110 §13.2.2. A false If-None-Match is a 304 before Range is
applied. Applying the range first would answer 206."
  (check "If-None-Match precedes Range"
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"p1\""
                                              "Range: bytes=0-3"))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "range won ~s" (ignore-errors (body-text reply))))
      (when (header reply "content-range")
        (fail "content-range ~s" (header reply "content-range"))))))

(defun if-match-before-none-test (port)
  "RFC 9110 §13.2.2. If-Match is step 1. A false result is 412 and does
not continue to If-None-Match. A true result continues, so a matching
If-None-Match on GET is still 304."
  (check "If-Match precedes If-None-Match"
    (let ((failed (exchange port (request-text "GET /etag HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "If-Match: \"no\""
                                               "If-None-Match: \"v1\""))))
      (expect-status failed 412)
      (when (search "tagged" (or (ignore-errors (body-text failed)) ""))
        (fail "none selected ~s" (ignore-errors (body-text failed)))))
    (let ((continued (exchange port (request-text "GET /etag HTTP/1.1"
                                                  "Host: 127.0.0.1"
                                                  "If-Match: \"v1\""
                                                  "If-None-Match: \"v1\""))))
      (expect-status continued 304)
      (unless (zerop (length (reply-body continued)))
        (fail "continued body ~s" (ignore-errors (body-text continued))))
      (unless (string= (header continued "etag") "\"v1\"")
        (fail "etag ~s" (header continued "etag"))))))

(defun if-unmodified-before-none-test (port)
  "RFC 9110 §13.2.2. When If-Match is absent, If-Unmodified-Since is
step 2. A false result is 412 and does not continue to If-None-Match.
A true result continues, so a matching If-None-Match on GET is 304."
  (check "If-Unmodified-Since precedes If-None-Match"
    (setf *unmodified-calls* 0)
    (let ((failed (exchange port (request-text "GET /unmodified HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"
                                               "If-None-Match: \"u1\""))))
      (expect-status failed 412)
      (when (search "kept" (or (ignore-errors (body-text failed)) ""))
        (fail "none selected ~s" (ignore-errors (body-text failed))))
      (unless (zerop *unmodified-calls*)
        (fail "false handler ~d" *unmodified-calls*)))
    (setf *unmodified-calls* 0)
    (let ((continued (exchange port (request-text "GET /unmodified HTTP/1.1"
                                                  "Host: 127.0.0.1"
                                                  "If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT"
                                                  "If-None-Match: \"u1\""))))
      (expect-status continued 304)
      (unless (zerop (length (reply-body continued)))
        (fail "continued body ~s" (ignore-errors (body-text continued))))
      (unless (string= (header continued "etag") "\"u1\"")
        (fail "etag ~s" (header continued "etag")))
      (unless (zerop *unmodified-calls*)
        (fail "true handler ~d" *unmodified-calls*)))))

(defun realm-quoted-token-test (port)
  "RFC 9110 §11.5. A realm that matches token is still one quoted-string.
Basic realm=pazuzu is the token form and is not this challenge."
  (check "a token realm is a quoted-string"
    (let ((basic (exchange port (request-text "GET /basic HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status basic 401)
      (unless (string= (header basic "www-authenticate")
                       "Basic realm=\"pazuzu\"")
        (fail "basic ~s" (header basic "www-authenticate"))))
    (let* ((digest (exchange port (request-text "GET /digest HTTP/1.1"
                                                "Host: 127.0.0.1")))
           (www (or (header digest "www-authenticate") "")))
      (expect-status digest 401)
      (unless (search "realm=\"pazuzu\"" www)
        (fail "digest ~s" www)))))

(defun switching-upgrade-test (port)
  "RFC 9110 §§7.8 and 15.2.2. A 101 names the protocol in Upgrade.
That field is also a Connection option."
  (check "a 101 names the upgraded protocol"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string-equal (header reply "upgrade") "websocket")
                 (fail "upgrade ~s" (header reply "upgrade")))
               (unless (member "upgrade" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection")))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-post-handshake-test (port)
  "RFC 6455 §4.2.1. The client's opening handshake is an HTTP/1.1 GET.
A POST that carries the other handshake fields does not match, so the
server does not send 101 or Sec-WebSocket-Accept."
  (check "a WebSocket handshake is a GET"
    (let ((reply (exchange port (request-text
                                 "POST /ws HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Version: 13"))))
      (unless (= (reply-status reply) 426)
        (fail "status ~d" (reply-status reply)))
      (when (header reply "sec-websocket-accept")
        (fail "accept ~s" (header reply "sec-websocket-accept")))))
  (check "a missing WebSocket key is not a handshake"
    ;; RFC 6455 §4.2.1. Upgrade and version 13 are present. The key is
    ;; not. This is not an opening handshake, so the server returns an
    ;; HTTP error and the next request is still HTTP.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (unless (= (reply-status reply) 426)
                 (fail "status ~d" (reply-status reply)))
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept"))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after missing key ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-absolute-target-test (port)
  "RFC 6455 §4.2.1. The opening handshake Request-URI may be an absolute
HTTP URI that contains the resource name. That request is the handshake,
so the server returns 101, the sample accept value, and echoes the
first data frame."
  (check "an absolute WebSocket target is a handshake"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence
              (octets (request-text
                       (format nil "GET http://127.0.0.1:~d/ws HTTP/1.1" port)
                       "Host: 127.0.0.1"
                       "Upgrade: websocket"
                       "Connection: Upgrade"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                       "Sec-WebSocket-Version: 13"))
              stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "accept ~s" (header reply "sec-websocket-accept"))))
             (write-masked-frame stream 1 "hi")
             (let ((echo (read-server-text stream)))
               (unless (string= echo "hi")
                 (fail "echo ~s" echo))))
        (ignore-errors (usocket:socket-close socket))))))

(defun separate-user-agent-test (port)
  "RFC 9110 §3.3. A server does not assume that two requests on one
connection are from the same user agent. A credential on the first
request does not authorize the next request."
  (check "a later request on the same connection is a separate user agent"
    (let ((socket (connect port))
          (token (cl-base64:usb8-array-to-base64-string (octets "ada:secret"))))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /basic HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      (format nil "Authorization: Basic ~a" token)))
                             stream)
             (finish-output stream)
             (let ((first (read-reply stream)))
               (expect-status first 200)
               (unless (string= (body-text first) "welcome")
                 (fail "first ~s" (body-text first))))
             (write-sequence (octets (request-text "GET /basic HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 401)
               (unless (search "Basic" (or (header second "www-authenticate") ""))
                 (fail "challenge ~s" (header second "www-authenticate")))
               (when (search "welcome" (or (ignore-errors (body-text second)) ""))
                 (fail "second ~s" (ignore-errors (body-text second))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun no-content-date-test (port)
  "RFC 9110 §6.6.1. An origin with a clock sends Date on every 2xx.
204 and 205 have no representation, and both still send that field
as IMF-fixdate."
  (check "a 204 and a 205 send Date"
    (let ((none (exchange port (request-text "GET /none HTTP/1.1"
                                             "Host: 127.0.0.1"))))
      (expect-status none 204)
      (unless (imf-fixdate-p (header none "date"))
        (fail "204 date ~s" (header none "date"))))
    (let ((reset (exchange port (request-text "GET /reset HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reset 205)
      (unless (imf-fixdate-p (header reset "date"))
        (fail "205 date ~s" (header reset "date"))))))

(defun if-match-list-test (port)
  "RFC 9110 §13.1.1. If-Match is true when any listed entity tag matches
with a strong comparison. The field value includes every field line, in
order. A list in which no member matches is false and the method is not
performed."
  (check "an If-Match list matches any member"
    (let ((second (exchange port (request-text "GET /etag HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "If-Match: \"no\", \"v1\""))))
      (expect-status second 200)
      (unless (string= (body-text second) "tagged")
        (fail "second member ~s" (ignore-errors (body-text second)))))
    (let ((first (exchange port (request-text "GET /etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Match: \"v1\", \"no\""))))
      (expect-status first 200)
      (unless (string= (body-text first) "tagged")
        (fail "first member ~s" (ignore-errors (body-text first)))))
    (let ((none (exchange port (request-text "GET /etag HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "If-Match: \"no\", \"also\""))))
      (expect-status none 412)
      (when (search "tagged" (or (ignore-errors (body-text none)) ""))
        (fail "none selected ~s" (ignore-errors (body-text none)))))
    (let ((lines (exchange port (request-text "GET /etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Match: \"no\""
                                              "If-Match: \"v1\""))))
      (expect-status lines 200)
      (unless (string= (body-text lines) "tagged")
        (fail "second line ~s" (ignore-errors (body-text lines)))))
    (let ((earlier (exchange port (request-text "GET /etag HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-Match: \"v1\""
                                                "If-Match: \"no\""))))
      (expect-status earlier 200)
      (unless (string= (body-text earlier) "tagged")
        (fail "first line ~s" (ignore-errors (body-text earlier)))))))

(defun if-match-star-test (port)
  "RFC 9110 §13.1.1. If-Match: * is true when the origin has a current
representation. That is not an entity-tag comparison, so a weak validator
still selects the representation and an unsafe method is performed."
  (check "If-Match star succeeds when a representation exists"
    (let ((tagged (exchange port (request-text "GET /etag HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "If-Match: *"))))
      (expect-status tagged 200)
      (unless (string= (body-text tagged) "tagged")
        (fail "tagged ~s" (ignore-errors (body-text tagged)))))
    (let ((file (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "If-Match: *"))))
      (expect-status file 200)
      (unless (string= (body-text file) "static-hello")
        (fail "weak file ~s" (ignore-errors (body-text file))))
      (let ((etag (header file "etag")))
        (unless (and etag (>= (length etag) 2)
                     (char= (char etag 0) #\W)
                     (char= (char etag 1) #\/))
          (fail "file etag ~s" etag))))
    (setf *put-calls* 0)
    (let ((wrote (exchange port (request-text "PUT /item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Match: *"))))
      (expect-status wrote 200)
      (unless (string= (body-text wrote) "wrote")
        (fail "put ~s" (ignore-errors (body-text wrote))))
      (unless (= *put-calls* 1)
        (fail "put calls ~d" *put-calls*)))))

(defun range-method-test (port)
  "RFC 9110 §14.2. Range handling is defined only for GET. A server
ignores Range on every other method, including an unrecognized method.
Applying the range would shorten the body and send Content-Range."
  (check "Range on a non-GET method is ignored"
    (setf *put-calls* 0)
    (let ((wrote (exchange port (request-text "PUT /item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "Range: bytes=0-1"))))
      (expect-status wrote 200)
      (unless (string= (body-text wrote) "wrote")
        (fail "put ~s" (ignore-errors (body-text wrote))))
      (when (header wrote "content-range")
        (fail "put content-range ~s" (header wrote "content-range")))
      (unless (= *put-calls* 1)
        (fail "put calls ~d" *put-calls*)))
    (let ((opt (exchange port (request-text "OPTIONS /opt HTTP/1.1"
                                            "Host: 127.0.0.1"
                                            "Range: bytes=0-0"))))
      (expect-status opt 200)
      (unless (string= (body-text opt) "opt")
        (fail "options ~s" (ignore-errors (body-text opt))))
      (when (header opt "content-range")
        (fail "options content-range ~s" (header opt "content-range"))))
    (let ((unknown (exchange port (request-text "FOO / HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Range: bytes=0-2"))))
      (expect-status unknown 501)
      (unless (string= (body-text unknown) "Not Implemented")
        (fail "unknown ~s" (ignore-errors (body-text unknown))))
      (when (header unknown "content-range")
        (fail "unknown content-range ~s" (header unknown "content-range"))))))

(defun accept-specificity-test (port)
  "RFC 9110 §12.5.1. When more than one media range matches, the most
specific range sets the quality. text/plain;q=0.2 loses to text/*;q=0.8
for text/html, and text/plain;q=0.8 beats text/*;q=0.2 for text/plain."
  (check "a more specific media range wins"
    (let ((broad (exchange port (request-text "GET /neg HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain;q=0.2, text/*;q=0.8"))))
      (expect-status broad 200)
      (unless (string= (body-text broad) "html")
        (fail "broader ~s" (ignore-errors (body-text broad))))
      (unless (search "text/html" (or (header broad "content-type") ""))
        (fail "broader type ~s" (header broad "content-type"))))
    (let ((narrow (exchange port (request-text "GET /neg HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "Accept: text/*;q=0.2, text/plain;q=0.8"))))
      (expect-status narrow 200)
      (unless (string= (body-text narrow) "plain")
        (fail "narrower ~s" (ignore-errors (body-text narrow))))
      (unless (search "text/plain" (or (header narrow "content-type") ""))
        (fail "narrower type ~s" (header narrow "content-type"))))))

(defun identity-q0-test (port)
  "RFC 9110 §12.5.3. An uncoded representation is unacceptable when
Accept-Encoding states identity;q=0. A positive quality still selects
that representation and does not apply a content coding."
  (check "identity;q=0 excludes the uncoded representation"
    (let ((excluded (exchange port (request-text "GET /range HTTP/1.1"
                                                 "Host: 127.0.0.1"
                                                 "Accept-Encoding: identity;q=0"))))
      (expect-status excluded 406)
      (when (search "abcdefghij" (or (ignore-errors (body-text excluded)) ""))
        (fail "excluded body ~s" (ignore-errors (body-text excluded))))
      (when (header excluded "content-encoding")
        (fail "excluded coding ~s" (header excluded "content-encoding"))))
    (let ((kept (exchange port (request-text "GET /range HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept-Encoding: identity;q=0.001"))))
      (expect-status kept 200)
      (when (header kept "content-encoding")
        (fail "kept coding ~s" (header kept "content-encoding")))
      (unless (string= (body-text kept) "abcdefghij")
        (fail "kept body ~s" (ignore-errors (body-text kept)))))))

(defun user-agent-semantics-test (port)
  "RFC 9110 §2.4. User-Agent does not change the meaning of another
field. identity;q=0 still excludes the uncoded representation."
  (check "User-Agent does not change content-coding semantics"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "User-Agent: broken-browser"
                                             "Accept-Encoding: identity;q=0"))))
      (expect-status reply 406)
      (when (header reply "content-encoding")
        (fail "coding ~s" (header reply "content-encoding")))
      (when (search "abcdefghij" (or (ignore-errors (body-text reply)) ""))
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun handler-allow-test (port)
  "RFC 9110 §§10.2.1 and 15.5.6. A 405 from the handler, including one
that named a shorter Allow list, sends the methods the resource allows."
  (check "a handler 405 carries the resource Allow list"
    (let ((reply (exchange port (request-text "GET /method-no HTTP/1.1"
                                             "Host: 127.0.0.1"))))
      (expect-status reply 405)
      (unless (string= (header reply "allow") "GET, HEAD, POST, OPTIONS")
        (fail "allow ~s" (header reply "allow"))))
    (let ((posted (exchange port (request-text "POST /method-no HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"))))
      (expect-status posted 405)
      (unless (string= (header posted "allow") "GET, HEAD, POST, OPTIONS")
        (fail "post allow ~s" (header posted "allow"))))
    (let ((own (exchange port (request-text "POST /method-own HTTP/1.1"
                                           "Host: 127.0.0.1"
                                           "Content-Length: 0"))))
      (expect-status own 405)
      (unless (string= (header own "allow") "GET, HEAD, POST, OPTIONS")
        (fail "replaced allow ~s" (header own "allow"))))))

(defun via-members-test (port)
  "RFC 9110 §7.6.3. Two Via members with different received-protocol
values stay two members. Joining the lines with comma SP does that.
Folding them into one member would drop a protocol."
  (check "Via members with different protocols stay distinct"
    (let ((reply (exchange port (request-text "GET /via HTTP/1.1"
                                             "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (header reply "via") "1.0 fred, 1.1 p.example.net")
        (fail "via ~s" (header reply "via"))))))

(defun qvalue-digits-test (port)
  "RFC 9110 §12.4.2. A generated qvalue has at most three fraction digits.
A quoted qvalue and a value that is not a weight parameter are unchanged."
  (check "a generated qvalue has at most three fraction digits"
    (let ((reply (exchange port (request-text "GET /long-q HTTP/1.1"
                                             "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (let ((coding (or (header reply "accept-encoding") "")))
        (unless (and (search "gzip;q=0.000" coding)
                     (search "br;q=1.000" coding)
                     (not (search "0.0001" coding))
                     (not (search "1.0000" coding)))
          (fail "accept-encoding ~s" coding)))
      (unless (string= (header reply "x-note") "q=0.0001")
        (fail "note ~s" (header reply "x-note")))
      (unless (string= (header reply "x-quoted") "\"q=0.0001\"")
        (fail "quoted ~s" (header reply "x-quoted"))))))

(defun product-identifier-test (port)
  "RFC 9110 §10.1.5. The product identifier this origin generates is
the name pazuzu. The response does not carry User-Agent, and Server
has no extra token."
  (check "the server product identifier is only the product name"
    (let ((reply (exchange port (request-text "GET / HTTP/1.1"
                                             "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (when (header reply "user-agent")
        (fail "user-agent ~s" (header reply "user-agent")))
      (unless (string= (header reply "server") "pazuzu")
        (fail "server ~s" (header reply "server"))))))

(defun empty-accept-encoding-test (port)
  "RFC 9110 §12.5.3. An empty Accept-Encoding field means the user agent
does not want any content coding. The uncoded representation is sent.
Treating the empty field as unacceptable would answer 406."
  (check "an empty Accept-Encoding wants no content coding"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding:"))))
      (expect-status reply 200)
      (when (header reply "content-encoding")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (body-text reply) "abcdefghij")
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun coding-q0-test (port)
  "RFC 9110 §12.5.3. A listed content coding with q=0 is not acceptable.
identity stays acceptable, so the response is the uncoded representation
rather than gzip or 406."
  (check "a coding with q=0 is not selected"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: gzip;q=0"))))
      (expect-status reply 200)
      (when (header reply "content-encoding")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (body-text reply) "abcdefghij")
        (fail "body ~s" (ignore-errors (body-text reply)))))))

(defun coding-quality-test (port)
  "RFC 9110 §12.5.3. Among content codings that serve the same purpose,
the highest non-zero quality is preferred. identity is excluded so the
default uncoded quality does not decide. br is not selected ahead of a
higher-quality gzip, and gzip is not selected ahead of a higher-quality br."
  (check "the higher content-coding quality wins"
    (let ((gzip (exchange port (request-text "GET /range HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Accept-Encoding: br;q=0.5, gzip;q=0.8, identity;q=0"))))
      (expect-status gzip 200)
      (unless (string-equal (header gzip "content-encoding") "gzip")
        (fail "gzip quality ~s" (header gzip "content-encoding")))
      (unless (string= (babel:octets-to-string
                        (decode-coding (reply-body gzip) "gzip")
                        :encoding :utf-8)
                       "abcdefghij")
        (fail "gzip body")))
    (let ((br (exchange port (request-text "GET /range HTTP/1.1"
                                           "Host: 127.0.0.1"
                                           "Accept-Encoding: br;q=0.8, gzip;q=0.5, identity;q=0"))))
      (expect-status br 200)
      (unless (string-equal (header br "content-encoding") "br")
        (fail "br quality ~s" (header br "content-encoding")))
      (unless (string= (babel:octets-to-string
                        (decode-coding (reply-body br) "br")
                        :encoding :utf-8)
                       "abcdefghij")
        (fail "br body")))))

(defun if-none-match-continues-test (port)
  "RFC 9110 §13.2.2. A true If-None-Match continues to step 5. A
matching If-Range still returns the requested bytes. A false If-Range
ignores Range and returns the selected representation. Stopping after
If-None-Match would omit Content-Range, or would honor Range when
If-Range does not match."
  (check "a true If-None-Match continues to Range"
    (let ((partial (exchange port (request-text "GET /partial HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-None-Match: \"no\""
                                                "Range: bytes=0-3"
                                                "If-Range: \"p1\""))))
      (expect-status partial 206)
      (unless (string= (body-text partial) "abcd")
        (fail "partial body ~s" (ignore-errors (body-text partial))))
      (unless (string= (header partial "content-range") "bytes 0-3/10")
        (fail "partial range ~s" (header partial "content-range"))))
    (let ((whole (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"no\""
                                              "Range: bytes=0-3"
                                              "If-Range: \"other\""))))
      (expect-status whole 200)
      (unless (string= (body-text whole) "abcdefghij")
        (fail "whole body ~s" (ignore-errors (body-text whole))))
      (when (header whole "content-range")
        (fail "whole range ~s" (header whole "content-range"))))))

(defun head-if-range-test (port)
  "RFC 9110 §§8.6, 13.1.5, and 13.2.2. Step 5 applies to GET. A false
If-Range ignores Range, so HEAD advertises the full GET length. A true
If-Range makes that GET partial, so HEAD is not 206 and does not
advertise the full length."
  (check "HEAD with a false If-Range keeps the full length"
    (let ((whole (exchange port (request-text "HEAD /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-3"
                                              "If-Range: \"other\"")
                           :headers-only t)))
      (expect-status whole 200)
      (unless (string= (header whole "content-length") "10")
        (fail "whole length ~s" (header whole "content-length")))
      (when (header whole "content-range")
        (fail "whole range ~s" (header whole "content-range"))))
    (let ((partial (exchange port (request-text "HEAD /partial HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Range: bytes=0-3"
                                                "If-Range: \"p1\"")
                             :headers-only t)))
      (expect-status partial 200)
      (when (string= (header partial "content-length") "10")
        (fail "partial length ~s" (header partial "content-length")))
      (when (header partial "content-range")
        (fail "partial range ~s" (header partial "content-range"))))))

(defun if-range-unsupported-test (port)
  "RFC 9110 §13.1.5. A target that does not support Range requests
ignores If-Range. GET /events is a stream, so a false If-Range and a
byte range still return the event."
  (check "If-Range is ignored when the resource does not support ranges"
    (let ((reply (exchange port (request-text "GET /events HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-0"
                                              "If-Range: \"no\""))))
      (expect-status reply 200)
      (unless (search "hello" (body-text reply))
        (fail "if-range stream ~s" (body-text reply)))
      (when (header reply "content-range")
        (fail "if-range content-range ~s" (header reply "content-range"))))))

(defun websocket-repeated-key-test (port)
  "RFC 6455 §11.3.1. Sec-WebSocket-Key appears once in the request.
Two fields, each a valid key, are not an opening handshake."
  (check "a repeated WebSocket key is rejected"
    (let ((reply (exchange port (request-text
                                 "GET /ws HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Version: 13"))))
      (expect-status reply 400)
      (when (header reply "sec-websocket-accept")
        (fail "repeated key accept ~s" (header reply "sec-websocket-accept")))
      (when (string-equal (header reply "upgrade") "websocket")
        (fail "repeated key upgraded")))))

(defun websocket-accept-once-test (port)
  "RFC 6455 §11.3.3. Sec-WebSocket-Accept appears once in the response.
A second field line would still match the first value."
  (check "a WebSocket accept field is sent once"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let* ((reply (read-reply-headers-only stream))
                    (accepts (loop for pair in (reply-headers reply)
                                   when (string= (car pair) "sec-websocket-accept")
                                     collect (cdr pair))))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (equal accepts '("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="))
                 (fail "accept ~s" accepts))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-missing-service-test (port)
  "RFC 6455 §4.2.2. A WebSocket opening handshake for a resource the
server does not provide is an HTTP error. The handshake is not completed."
  (check "a missing WebSocket service is not a handshake"
    (let ((reply (exchange port (request-text
                                 "GET /missing HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Version: 13"))))
      (expect-status reply 404)
      (when (header reply "sec-websocket-accept")
        (fail "accept ~s" (header reply "sec-websocket-accept")))
      (when (string-equal (header reply "upgrade") "websocket")
        (fail "upgrade ~s" (header reply "upgrade"))))))

(defun response-chunk-size-test (port)
  "RFC 9112 §7.1. A generated chunk-size is one or more hex digits, with
no whitespace before those digits. The last chunk is one or more zero
digits. GET /events still returns its event."
  (check "a generated chunk-size is hexadecimal"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (content (make-array 0 :element-type '(unsigned-byte 8)
                                      :adjustable t :fill-pointer 0))
                 (chunks 0))
             (write-sequence (octets (request-text "GET /events HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8)
                                     :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (multiple-value-bind (status status-line headers)
                   (parse-headers (latin1 (subseq head 0 (- (length head) 4))))
                 (unless (and (= status 200) (search "HTTP/1.1 200" status-line))
                   (fail "status ~s" status-line))
                 (unless (search "chunked" (or (cdr (assoc "transfer-encoding" headers
                                                           :test #'string=))
                                               "")
                                 :test #'char-equal)
                   (fail "transfer-encoding ~s" headers))))
             (loop
               (let ((line (read-protocol-line stream)))
                 (unless (and (>= (length line) 3)
                              (= (aref line (- (length line) 2)) 13)
                              (= (aref line (1- (length line))) 10))
                   (fail "chunk line ~s" line))
                 (let ((end (- (length line) 2)))
                   (when (or (= (aref line 0) 32) (= (aref line 0) 9))
                     (fail "leading whitespace ~s" line))
                   (let ((index 0)
                         (value 0)
                         (digits 0))
                     (loop while (< index end)
                           for digit = (digit-char-p (code-char (aref line index)) 16)
                           while digit
                           do (setf value (+ (* value 16) digit))
                              (incf index)
                              (incf digits))
                     (unless (plusp digits)
                       (fail "no size ~s" line))
                     (when (< index end)
                       (let ((mark (aref line index)))
                         (unless (or (= mark 32) (= mark 9) (= mark 59))
                           (fail "tail ~s" line))))
                     (when (zerop value)
                       (loop for octet-index from 0 below digits
                             unless (= (aref line octet-index) 48)
                               do (fail "last chunk ~s" line))
                       (loop for trailer = (read-protocol-line stream)
                             until (= (length trailer) 2))
                       (return))
                     (incf chunks)
                     (let ((payload (read-n stream value)))
                       (loop for byte across payload
                             do (vector-push-extend byte content)))
                     (let ((delim (read-n stream 2)))
                       (unless (and (= (aref delim 0) 13) (= (aref delim 1) 10))
                         (fail "data crlf ~s" delim)))))))
             (unless (plusp chunks)
               (fail "no chunks"))
             (unless (search "hello" (babel:octets-to-string content :encoding :utf-8))
               (fail "events ~s" content)))
        (ignore-errors (usocket:socket-close socket))))))

(defun chunked-no-trailer-test (port)
  "RFC 9110 §6.5.1. A sender generates a trailer field only when that
field's definition permits trailers. This origin generates none. GET
/events is chunked, and the line after the last chunk is empty."
  (check "a chunked response sends no trailer field"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (content (make-array 0 :element-type '(unsigned-byte 8)
                                      :adjustable t :fill-pointer 0))
                 (chunks 0))
             (write-sequence (octets (request-text "GET /events HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8)
                                     :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (multiple-value-bind (status status-line headers)
                   (parse-headers (latin1 (subseq head 0 (- (length head) 4))))
                 (unless (and (= status 200) (search "HTTP/1.1 200" status-line))
                   (fail "status ~s" status-line))
                 (unless (search "chunked"
                                 (or (cdr (assoc "transfer-encoding" headers
                                                 :test #'string=))
                                     "")
                                 :test #'char-equal)
                   (fail "transfer-encoding ~s" headers))))
             (loop
               (let ((line (read-protocol-line stream)))
                 (unless (and (>= (length line) 3)
                              (= (aref line (- (length line) 2)) 13)
                              (= (aref line (1- (length line))) 10))
                   (fail "chunk line ~s" line))
                 (let ((end (- (length line) 2))
                       (index 0)
                       (value 0)
                       (digits 0))
                   (loop while (< index end)
                         for digit = (digit-char-p (code-char (aref line index)) 16)
                         while digit
                         do (setf value (+ (* value 16) digit))
                            (incf index)
                            (incf digits))
                   (unless (plusp digits)
                     (fail "no size ~s" line))
                   (when (zerop value)
                     (let ((trailer (read-protocol-line stream)))
                       (unless (and (= (length trailer) 2)
                                    (= (aref trailer 0) 13)
                                    (= (aref trailer 1) 10))
                         (fail "trailer ~s" trailer)))
                     (return))
                   (incf chunks)
                   (let ((payload (read-n stream value)))
                     (loop for byte across payload
                           do (vector-push-extend byte content)))
                   (let ((delim (read-n stream 2)))
                     (unless (and (= (aref delim 0) 13) (= (aref delim 1) 10))
                       (fail "data crlf ~s" delim))))))
             (unless (plusp chunks)
               (fail "no chunks"))
             (unless (search "hello" (babel:octets-to-string content :encoding :utf-8))
               (fail "events ~s" content)))
        (ignore-errors (usocket:socket-close socket))))))

(defun octet-message-test (port)
  "RFC 9112 §2.2. A message is parsed as octets in a superset of
US-ASCII. The field-value octets 192 128 98 are not decoded as UTF-8.
GET /header-value returns those octets."
  (check "a message is parsed as octets"
    (let ((socket (connect port))
          (note (coerce #(192 128 98) '(simple-array (unsigned-byte 8) (*)))))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets-cat (octets "GET /header-value HTTP/1.1")
                                         #(13 10)
                                         (octets "Host: 127.0.0.1")
                                         #(13 10)
                                         (octets "X-Note: ")
                                         note
                                         #(13 10 13 10))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (equalp (reply-body reply)
                               (babel:string-to-octets (map 'string #'code-char note)
                                                       :encoding :utf-8))
                 (fail "body ~s" (reply-body reply)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun content-length-list-test (port)
  "RFC 9112 §6.3 item 5. One Content-Length field that lists the same
decimal more than once is that length. Differing decimals are
unrecoverable framing."
  (check "a list of identical content-lengths is one length"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: 5, 05")
                                                  "hello"
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "hello")
                 (fail "body ~s" (ignore-errors (body-text reply)))))
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after list ~s" (ignore-errors (body-text second))))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: 5, 6")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after differing content-length"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun chunk-terminator-test (port)
  "RFC 9112 §7.1. Decoding reads chunk-data and then CRLF. Two other
octets before a valid zero chunk are not that terminator. Accepting
them echoes hello and answers the next request."
  (check "a chunk without CRLF after the data is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (format nil "~a5~c~chelloXX0~c~c~c~c"
                                                          (request-text "POST /echo HTTP/1.1"
                                                                        "Host: 127.0.0.1"
                                                                        "Transfer-Encoding: chunked")
                                                          #\Return #\Newline
                                                          #\Return #\Newline
                                                          #\Return #\Newline)
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection")))
               (when (string= (ignore-errors (body-text reply)) "hello")
                 (fail "echoed chunk data")))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after chunk terminator"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun missing-target-precondition-test (port)
  "RFC 9110 §13.2.1. A status other than 2xx or 412 that is known before
the request content is processed takes precedence over preconditions.
A missing target is 404, a method the target does not allow is 405, and
an unrecognized method is 501. The same If-Match on an allowed GET is 412."
  (check "a 404 and a 405 ignore preconditions"
    (setf *guard-calls* 0
          *unmodified-calls* 0)
    (expect-status (exchange port (request-text "GET /no-such-precondition HTTP/1.1"
                                                "Host: 127.0.0.1"))
                   404)
    (dolist (field '("If-Match: \"no\""
                     "If-Match: *"
                     "If-None-Match: *"
                     "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"
                     "If-Modified-Since: Sat, 01 Jan 2099 00:00:00 GMT"))
      (let ((reply (exchange port (request-text "GET /no-such-precondition HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                field))))
        (unless (= (reply-status reply) 404)
          (fail "~a -> ~d" field (reply-status reply)))))
    (let ((denied (exchange port (request-text "POST /guarded HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "Content-Length: 0"
                                               "If-Match: \"no\""))))
      (expect-status denied 405)
      (unless (search "GET" (or (header denied "allow") ""))
        (fail "allow ~s" (header denied "allow"))))
    (let ((matched (exchange port (request-text "POST /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-Match: \"g1\""))))
      (expect-status matched 405)
      (unless (search "GET" (or (header matched "allow") ""))
        (fail "matched allow ~s" (header matched "allow"))))
    (let ((dated (exchange port (request-text "POST /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))))
      (expect-status dated 405)
      (unless (and (search "GET" (or (header dated "allow") ""))
                   (search "PUT" (or (header dated "allow") "")))
        (fail "dated allow ~s" (header dated "allow"))))
    (expect-status (exchange port (request-text "FOO /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-Match: \"no\""))
                   501)
    (unless (and (zerop *guard-calls*) (zerop *unmodified-calls*))
      (fail "handlers ran ~d ~d" *guard-calls* *unmodified-calls*))
    (expect-status (exchange port (request-text "GET /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-Match: \"no\""))
                   412)
    (unless (zerop *guard-calls*)
      (fail "412 ran the handler"))))

(defun status-line-space-test (port)
  "RFC 9112 §4. The status line sends the space that separates the status
code from the reason phrase. That space is present on HTTP/1.1 and HTTP/1.0."
  (check "the status line keeps the space after the status code"
    (let ((reply (exchange port (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (reply-status-line reply) "HTTP/1.1 200 OK")
        (fail "status line ~s" (reply-status-line reply))))
    (let ((reply (exchange port (request-text "GET / HTTP/1.0"))))
      (expect-status reply 200)
      (unless (string= (reply-status-line reply) "HTTP/1.0 200 OK")
        (fail "http/1.0 status line ~s" (reply-status-line reply))))))

(defun unread-request-body-test (port)
  "RFC 9112 §9.3. A final response sent before the request body is read
closes the connection. The unread body is not parsed as the next request."
  (check "an unread request body is not the next request"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "POST /basic-continue HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Content-Length: 5"
                                                   "Expect: 100-continue"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 401)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (ignore-errors
               (write-sequence (octets (concatenate 'string
                                                    "hello"
                                                    (request-text "GET / HTTP/1.1"
                                                                  "Host: 127.0.0.1")))
                               stream)
               (finish-output stream))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after an unread body" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun field-value-whitespace-test (port)
  "RFC 9110 §5.5. HTTP/1 allows optional whitespace around a field value.
That whitespace is not part of the value, so it is removed before the
value is used as a host or as a content length."
  (check "optional whitespace around a field value is excluded"
    (let ((reply (exchange port (request-text "GET /who HTTP/1.1"
                                              "Host:   127.0.0.1  "))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "127.0.0.1")
        (fail "host ~s" (body-text reply))))
    (let ((reply (exchange port (concatenate 'string
                                              (request-text "POST /echo HTTP/1.1"
                                                            "Host: 127.0.0.1"
                                                            "Content-Length:  4  ")
                                              "ping"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "ping")
        (fail "body ~s" (body-text reply))))))

(defun put-create-test (port)
  "RFC 9110 §9.3.4. PUT /create has no current representation. The
successful create is 201 and the body is created."
  (check "a PUT that creates a representation is 201"
    (setf *create-calls* 0)
    (let ((reply (exchange port (concatenate 'string
                                             (request-text "PUT /create HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Content-Type: text/plain"
                                                           "Content-Length: 3")
                                             "new"))))
      (expect-status reply 201)
      (unless (string= (body-text reply) "created")
        (fail "body ~s" (body-text reply)))
      (unless (= *create-calls* 1)
        (fail "handler ran ~d" *create-calls*)))))

(defun put-existing-representation-test (port)
  "RFC 9110 §9.3.4. PUT /item has a current representation. A successful
modification of that representation is 200 or 204. This response is 200
and the body is wrote."
  (check "a successful PUT of an existing representation is 200 or 204"
    (setf *put-calls* 0)
    (let* ((reply (exchange port (concatenate 'string
                                              (request-text "PUT /item HTTP/1.1"
                                                            "Host: 127.0.0.1"
                                                            "Content-Type: text/plain"
                                                            "Content-Length: 4")
                                              "item")))
           (status (reply-status reply)))
      (unless (member status '(200 204))
        (fail "status ~d" status))
      (unless (= *put-calls* 1)
        (fail "handler ran ~d" *put-calls*))
      (when (= status 200)
        (unless (string= (body-text reply) "wrote")
          (fail "body ~s" (body-text reply))))
      (when (= status 204)
        (unless (zerop (length (reply-body reply)))
          (fail "204 body ~d" (length (reply-body reply))))))))

(defun put-store-then-modify-test (port)
  "RFC 9110 §9.3.4. The validator is read before the handler stores the
representation. The first PUT, while the store is empty, is 201. The next
PUT on that same store, whose validator now returns a tag, stays 200 or 204."
  (check "a PUT into an empty store is 201 and the next is 200 or 204"
    (setf *shelf* nil)
    (let ((first (exchange port (concatenate 'string
                                             (request-text "PUT /shelf HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Content-Type: text/plain"
                                                           "Content-Length: 3")
                                             "one"))))
      (expect-status first 201)
      (unless (string= (body-text first) "shelved")
        (fail "first body ~s" (body-text first)))
      (unless (string= *shelf* "kept")
        (fail "store ~s" *shelf*)))
    (let* ((second (exchange port (concatenate 'string
                                               (request-text "PUT /shelf HTTP/1.1"
                                                             "Host: 127.0.0.1"
                                                             "Content-Type: text/plain"
                                                             "Content-Length: 3")
                                               "two")))
           (status (reply-status second)))
      (unless (member status '(200 204))
        (fail "second status ~d" status))
      (when (= status 200)
        (unless (string= (body-text second) "shelved")
          (fail "second body ~s" (body-text second)))))))

(defun http-tests (port)
  (check "rfc850 year is within 50 years"
    (let* ((now (encode-universal-time 0 0 0 21 10 2026 0))
           (ahead (pazuzu::parse-http-date "Sunday, 21-Oct-70 00:00:00 GMT" :now now))
           (behind (pazuzu::parse-http-date "Sunday, 06-Nov-94 08:49:37 GMT" :now now))
           (boundary (pazuzu::parse-http-date "Sunday, 06-Nov-76 00:00:00 GMT" :now now)))
      (unless (eql ahead (encode-universal-time 0 0 0 21 10 2070 0))
        (fail "70 -> ~a" ahead))
      (unless (eql behind (encode-universal-time 37 49 8 6 11 1994 0))
        (fail "94 -> ~a" behind))
      (unless (eql boundary (encode-universal-time 0 0 0 6 11 1976 0))
        (fail "76 -> ~a" boundary))))
  (check "HTTP-date is case-sensitive"
    (let ((now (encode-universal-time 0 0 0 21 10 2026 0)))
      (dolist (bad '("sun, 06 Nov 1994 08:49:37 GMT"
                     "Sun, 06 nov 1994 08:49:37 GMT"
                     "Sun, 06 Nov 1994 08:49:37 gmt"
                     "sunday, 06-Nov-94 08:49:37 GMT"
                     "Sunday, 06-nov-94 08:49:37 GMT"
                     "Sun, 06-Nov-94 08:49:37 GMT"
                     "sun Nov  6 08:49:37 1994"
                     "Sun nov  6 08:49:37 1994"))
        (when (pazuzu::parse-http-date bad :now now)
          (fail "accepted ~s" bad)))
      (unless (pazuzu::parse-http-date "Mon, 06 Nov 1994 08:49:37 GMT" :now now)
        (fail "Monday IMF"))
      (unless (pazuzu::parse-http-date "Monday, 06-Nov-94 08:49:37 GMT" :now now)
        (fail "Monday rfc850"))
      (unless (pazuzu::parse-http-date "Mon Nov  6 08:49:37 1994" :now now)
        (fail "Monday asctime"))
      (unless (pazuzu::parse-http-date "Sun, 06 Nov 1994 08:49:37 GMT" :now now)
        (fail "Sunday IMF"))
      (unless (pazuzu::parse-http-date "Sunday, 06-Nov-94 08:49:37 GMT" :now now)
        (fail "Sunday rfc850"))
      (unless (pazuzu::parse-http-date "Sun Nov  6 08:49:37 1994" :now now)
        (fail "Sunday asctime"))))
  (check "websocket accept vector"
    (unless (string= (pazuzu::websocket-accept "dGhlIHNhbXBsZSBub25jZQ==")
                     "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
      (fail "accept hash mismatch")))
  (check "non-ASCII method and field name are rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (concatenate '(simple-array (unsigned-byte 8) (*))
                                          #(71 233 84 32 47 32)
                                          (babel:string-to-octets
                                           (format nil "HTTP/1.1~c~cHost: 127.0.0.1~c~c~c~c"
                                                   #\Return #\Newline
                                                   #\Return #\Newline
                                                   #\Return #\Newline)
                                           :encoding :ascii))
                             stream)
             (finish-output stream)
             (sleep 0.5)
             (expect-status (read-reply stream) 400))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (concatenate '(simple-array (unsigned-byte 8) (*))
                                          (babel:string-to-octets
                                           (format nil "GET / HTTP/1.1~c~c" #\Return #\Newline)
                                           :encoding :ascii)
                                          #(88 45 233 58 32 49 13 10)
                                          (babel:string-to-octets
                                           (format nil "Host: 127.0.0.1~c~c~c~c"
                                                   #\Return #\Newline
                                                   #\Return #\Newline)
                                           :encoding :ascii))
                             stream)
             (finish-output stream)
             (expect-status (read-reply stream) 400))
        (ignore-errors (usocket:socket-close socket))))
    (let ((reply (exchange port (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "pazuzu")
        (fail "body ~s" (body-text reply)))))
  (check "HTTP/1 minor above 1 is answered as HTTP/1.1"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET / HTTP/1.2" "Host: 127.0.0.1")) stream)
             (finish-output stream)
             (let* ((reply (read-reply stream))
                    (text (latin1 (reply-body reply))))
               (expect-status reply 200)
               (unless (string= (reply-status-line reply) "HTTP/1.1 200 OK")
                 (fail "status line ~s" (reply-status-line reply)))
               (unless (string= text "pazuzu")
                 (fail "body ~s" text))))
        (ignore-errors (usocket:socket-close socket))))
    (expect-status (exchange port (request-text "GET / HTTP/2.0" "Host: 127.0.0.1")) 505))
  (check "GET date, length, keep-alive"
    (let ((reply (exchange port (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "pazuzu")
        (fail "body ~s" (body-text reply)))
      (unless (header reply "date")
        (fail "missing Date"))
      (unless (string= (header reply "content-length") "6")
        (fail "content-length ~s" (header reply "content-length")))
      (unless (string= (header reply "server") "pazuzu")
        (fail "server ~s" (header reply "server")))))
  (check "a future Last-Modified is the Date"
    ;; RFC 9110 §8.8.2.1. The handler's year 2099 is replaced by the
    ;; message origination time, which is the Date field.
    (let ((reply (exchange port (request-text "GET /future HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "future")
        (fail "future body ~s" (body-text reply)))
      (unless (string= (header reply "last-modified") (header reply "date"))
        (fail "last-modified ~s date ~s" (header reply "last-modified") (header reply "date")))
      (when (search "2099" (or (header reply "last-modified") ""))
        (fail "future year ~s" (header reply "last-modified")))))
  (check "Date is IMF-fixdate"
    ;; RFC 9110 §5.6.7. A generated HTTP-date is IMF-fixdate.
    (let ((reply (exchange port (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (imf-fixdate-p (header reply "date"))
        (fail "date ~s" (header reply "date")))))
  (status-line-space-test port)
  (check "HEAD"
    (let ((reply (exchange port (request-text "HEAD / HTTP/1.1" "Host: 127.0.0.1")
                           :headers-only t)))
      (expect-status reply 200)
      (unless (string= (header reply "content-length") "6")
        (fail "content-length ~s" (header reply "content-length")))))
  (check "HEAD sends no content"
    ;; RFC 9110 §9.3.2. Content-Length is the GET representation size.
    ;; The HEAD response carries none of that content, so the next
    ;; request on this connection is still the next message.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "HEAD / HTTP/1.1"
                                                                "Host: 127.0.0.1")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((head (read-reply-headers-only stream)))
               (expect-status head 200)
               (unless (string= (header head "content-length") "6")
                 (fail "content-length ~s" (header head "content-length"))))
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after HEAD ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "two requests one connection"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1")) stream)
             (finish-output stream)
             (let ((first (read-reply stream)))
               (expect-status first 200)
               (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1")) stream)
               (finish-output stream)
               (let ((second (read-reply stream)))
                 (expect-status second 200)
                 (unless (string= (body-text second) "pazuzu")
                   (fail "second body ~s" (body-text second))))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "pipelined requests"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "GET / HTTP/1.1" "Host: 127.0.0.1")
                                                  (request-text "GET /q?a=1&c=2 HTTP/1.1" "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (expect-status (read-reply stream) 200)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "a=1;c=2")
                 (fail "pipelined body ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "HTTP/1.0 closes"
    (let ((reply (exchange port (request-text "GET / HTTP/1.0"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "connection") "close")
        (fail "connection ~s" (header reply "connection")))))
  (check "close does not serve a later request"
    ;; RFC 9112 §9.6. The pipelined GET is already on the connection.
    ;; The server must not answer it after Connection: close.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Connection: close")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "pazuzu")
                 (fail "body ~s" (body-text reply)))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after close" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a close response does not serve a later request"
    ;; RFC 9112 §9.6. HTTP/1.0 sends Connection: close. The pipelined
    ;; request behind it is not processed.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "GET / HTTP/1.0")
                                                  (request-text "GET / HTTP/1.0")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "pazuzu")
                 (fail "body ~s" (body-text reply)))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after http/1.0 close" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "HTTP/1.0 keep-alive"
    (let ((reply (exchange port (request-text "GET / HTTP/1.0" "Connection: keep-alive"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "connection") "keep-alive")
        (fail "connection ~s" (header reply "connection")))))
  (check "HTTP/1.0 transfer-encoding is faulty framing"
    ;; RFC 9112 §6.1. The body is not read, and the connection closes.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.0"
                                                                "Transfer-Encoding: chunked"
                                                                "Connection: keep-alive")
                                                  (format nil "5~c~chello~c~c0~c~c~c~c"
                                                          #\Return #\Newline
                                                          #\Return #\Newline
                                                          #\Return #\Newline
                                                          #\Return #\Newline)
                                                  (request-text "GET / HTTP/1.0"
                                                                "Connection: keep-alive")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (string-equal (header reply "connection") "close")
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after HTTP/1.0 transfer-encoding"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "HTTP/1.0 does not receive 1xx"
    ;; RFC 9110 §15.2.
    (let ((reply (exchange port (request-text "GET /interim HTTP/1.0"))))
      (expect-status reply 500)
      (unless (search "HTTP/1.0" (reply-status-line reply))
        (fail "status line ~s" (reply-status-line reply)))))
  (check "a final response is never 1xx"
    ;; RFC 9110 §§10.1.1 and 15.2. The handler returns 100. That cannot
    ;; be the only status, and the connection stays usable.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /interim HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 500)
               (unless (search "HTTP/1.1" (reply-status-line reply))
                 (fail "status line ~s" (reply-status-line reply)))
               (unless (search "Internal Server Error" (body-text reply))
                 (fail "body ~s" (body-text reply))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after interim ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "cleartext http serves a host the certificate does not cover"
    ;; RFC 9110 §7.4 applies to an https target. Cleartext still returns
    ;; the representation for a host this listener's certificate would not.
    (let ((reply (exchange port (request-text "GET / HTTP/1.1"
                                              "Host: other.example"))))
      (expect-status reply 200)
      (unless (search "pazuzu" (body-text reply))
        (fail "body ~s" (body-text reply)))))
  (check "unknown method"
    (expect-status (exchange port (request-text "FOO / HTTP/1.1" "Host: 127.0.0.1")) 501)
    (expect-status (exchange port (request-text "get / HTTP/1.1" "Host: 127.0.0.1")) 501))
  (check "TRACE is not implemented"
    (expect-status (exchange port (request-text "TRACE / HTTP/1.1" "Host: 127.0.0.1")) 501))
  (check "a response field with CR is a single 500"
    (let ((reply (exchange port (request-text "GET /bad-header HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 500)
      (unless (and (reply-status-line reply)
                   (search "500" (reply-status-line reply)))
        (fail "status line ~s" (reply-status-line reply)))
      (unless (string= (body-text reply) "Internal Server Error")
        (fail "body ~s" (body-text reply)))
      (when (search "X-Injected" (body-text reply))
        (fail "injected ~s" (body-text reply)))
      (when (search "nope" (body-text reply))
        (fail "handler body ~s" (body-text reply)))))
  (response-nul-field-test port)
  (response-lf-field-test port)
  (check "HTTP/1 keeps a response field that ends with a space"
    ;; HTTP/1 field-line OWS is not the HTTP/2 field-value rule.
    (let ((reply (exchange port (request-text "GET /pad-header HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "nope")
        (fail "body ~s" (body-text reply)))))
  (check "rejected CONNECT closes the connection"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "CONNECT example.com:443 HTTP/1.1"
                                                                "Host: example.com:443")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 501)
               (unless (string-equal (header reply "connection") "close")
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after CONNECT" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "CONNECT without a valid port is rejected"
    ;; RFC 9110 §9.3.6. There is no default port. An empty or invalid
    ;; port is 400 and the connection closes. A port in 0..65535 stays 501.
    (dolist (target '("example.com" "example.com:" "example.com:65536"
                      "example.com:abc" "[::1]" "[::1]:"))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (write-sequence (octets (concatenate 'string
                                                    (request-text
                                                     (format nil "CONNECT ~a HTTP/1.1" target)
                                                     (format nil "Host: ~a" target))
                                                    (request-text "GET / HTTP/1.1"
                                                                  "Host: 127.0.0.1")))
                               stream)
               (finish-output stream)
               (let ((reply (read-reply stream)))
                 (unless (= (reply-status reply) 400)
                   (fail "CONNECT ~a status ~d" target (reply-status reply))))
               (let ((second (handler-case (read-reply stream)
                               (error () nil))))
                 (when second
                   (fail "answered ~s after CONNECT ~a" (reply-status second) target))))
          (ignore-errors (usocket:socket-close socket)))))
    (dolist (target '("example.com:443" "example.com:0" "example.com:0443" "[::1]:443"))
      (let ((reply (exchange port (request-text
                                   (format nil "CONNECT ~a HTTP/1.1" target)
                                   (format nil "Host: ~a" target)))))
        (unless (= (reply-status reply) 501)
          (fail "CONNECT ~a status ~d" target (reply-status reply))))))
  (check "POST on GET-only resource"
    (let ((reply (exchange port (request-text "POST / HTTP/1.1" "Host: 127.0.0.1"
                                              "Content-Length: 0"))))
      (expect-status reply 405)
      (unless (search "GET" (or (header reply "allow") ""))
        (fail "allow ~s" (header reply "allow")))))
  (check "the request body is read before the next request"
    ;; RFC 9112 §9.3. The origin reads the whole body or closes. A 405
    ;; leaves the connection open, so the five octets must not be parsed
    ;; as the next request line.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST / HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: 5")
                                                  "hello"
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 405)
               (unless (search "GET" (or (header reply "allow") ""))
                 (fail "allow ~s" (header reply "allow"))))
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after body ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "missing Host"
    (expect-status (exchange port (request-text "GET / HTTP/1.1")) 400))
  (check "duplicate Host"
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Host: 127.0.0.1"))
                   400))
  (check "a Host field with userinfo is rejected"
    ;; RFC 9110 §7.2. Host is uri-host [ ":" port ]. RFC 9112 §3.2. An
    ;; invalid field value is 400. userinfo is not part of uri-host.
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                "Host: user@127.0.0.1"))
                   400))
  (check "an empty host identifier is rejected"
    ;; RFC 9110 §4.2.1. An http URI with an empty host is invalid.
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                "Host:"))
                   400)
    (expect-status (exchange port (request-text "GET http:/// HTTP/1.1"
                                                "Host: 127.0.0.1"))
                   400))
  (field-value-whitespace-test port)
  (check "obs-fold"
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                " folded"))
                   400))
  (check "whitespace before the first header is rejected"
    ;; RFC 9112 §2.2. A space before the first field is not a header.
    ;; Skipping that line and keeping the next Host would answer 200.
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                " Host: ignored.example"
                                                "Host: 127.0.0.1"))
                   400))
  (check "whitespace is not sent before the first field"
    ;; RFC 9112 §2.2. The status line is followed by a field name, not
    ;; by SP, HTAB, or an empty line.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8)
                                       :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (let ((end (search #(13 10) head)))
                 (unless (and end (< (+ end 2) (length head)))
                   (fail "short head"))
                 (unless (pazuzu::token-char-p (code-char (aref head (+ end 2))))
                   (fail "octet after status ~d" (aref head (+ end 2)))))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a response is not line-folded"
    ;; RFC 9112 §5.2. No generated field line begins with SP or HTAB.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8)
                                       :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (dolist (line (uiop:split-string (latin1 head) :separator '(#\Newline)))
                 (let ((raw (string-right-trim '(#\Return) line)))
                   (unless (zerop (length raw))
                     (when (or (char= (char raw 0) #\Space)
                               (char= (char raw 0) #\Tab))
                       (fail "folded ~s" raw)))))))
        (ignore-errors (usocket:socket-close socket)))))
  (response-field-colon-test port)
  (check "whitespace before colon"
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                "Host : 127.0.0.1"))
                   400))
  (check "a bare CR is rejected"
    ;; RFC 9112 §2.2. CR in a field line is not followed by LF. Replacing
    ;; it with SP would leave a valid request for GET /.
    (expect-status (exchange port (format nil "GET / HTTP/1.1~c~cHost: 127.0.0.1~c~cX-Note: ab~ccd~c~c~c~c"
                                          #\Return #\Newline
                                          #\Return #\Newline
                                          #\Return
                                          #\Return #\Newline
                                          #\Return #\Newline))
                   400))
  (response-no-bare-cr-test port)
  (octet-message-test port)
  (check "a field value containing NUL is rejected"
    ;; RFC 9110 §5.5. NUL in a field value is invalid. The recipient
    ;; rejects the message rather than replacing that octet with SP.
    (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                (format nil "X-Note: a~cb" #\Nul)))
                   400))
  (too-many-fields-test port)
  (long-field-line-test port)
  (large-field-section-test port)
  (check "whitespace around a field value is excluded"
    ;; RFC 9110 §5.5. HTTP/1 allows OWS around a field value. It is
    ;; removed before the value is used.
    (let ((spaces (exchange port (request-text "GET /header-value HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               "X-Note:  ab  "))))
      (expect-status spaces 200)
      (unless (string= (body-text spaces) "ab")
        (fail "spaces ~s" (body-text spaces))))
    (let ((tabs (exchange port (request-text "GET /header-value HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             (format nil "X-Note:~cab~c" #\Tab #\Tab)))))
      (expect-status tabs 200)
      (unless (string= (body-text tabs) "ab")
        (fail "tabs ~s" (body-text tabs)))))
  (check "absolute-form"
    (let ((reply (exchange port (request-text
                                 (format nil "GET http://other.example:~d/q?a=z&c=w HTTP/1.1" port)
                                 "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "a=z;c=w")
        (fail "absolute-form body ~s" (body-text reply))))
    (let ((reply (exchange port (request-text
                                 (format nil "GET HtTp://other.example:~d/q?a=z&c=w HTTP/1.1" port)
                                 "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "a=z;c=w")
        (fail "scheme case ~s" (body-text reply)))))
  (check "absolute-form uses the request-target host"
    ;; RFC 9112 §3.2.2. The origin ignores Host and uses the target host.
    (let ((reply (exchange port (request-text
                                 (format nil "GET http://other.example:~d/who HTTP/1.1" port)
                                 "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) (format nil "other.example:~d" port))
        (fail "host ~s" (body-text reply)))))
  (check "https absolute-form on cleartext is 421"
    (expect-status (exchange port (request-text
                                   (format nil "GET https://other.example:~d/q HTTP/1.1" port)
                                   "Host: 127.0.0.1"))
                   421)
    (expect-status (exchange port (request-text
                                   (format nil "GET HTTPS://other.example:~d/q HTTP/1.1" port)
                                   "Host: 127.0.0.1"))
                   421))
  (check "a fragment in the request-target is rejected"
    (expect-status (exchange port (request-text "GET /etag#v HTTP/1.1"
                                                "Host: 127.0.0.1"))
                   400)
    (expect-status (exchange port (request-text "GET /etag?x=1#v HTTP/1.1"
                                                "Host: 127.0.0.1"))
                   400)
    (expect-status (exchange port (request-text
                                   (format nil "GET http://other.example:~d/etag#v HTTP/1.1" port)
                                   "Host: 127.0.0.1"))
                   400)
    (let ((reply (exchange port (request-text "GET /q?a=1%23&c=2 HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "a=1#;c=2")
        (fail "encoded hash ~s" (body-text reply)))))
  (check "query plus is space"
    (let ((reply (exchange port (request-text "GET /q?a=b&c=d+e HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "a=b;c=d e")
        (fail "query ~s" (body-text reply)))))
  (check "a chunked body without the last chunk is incomplete"
    ;; RFC 9112 §7.1 and §8. The zero-size chunk was not received, so the
    ;; request is not a complete message and is not echoed.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (format nil "~a5~c~chello~c~c"
                                             (request-text "POST /echo HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Transfer-Encoding: chunked")
                                             #\Return #\Newline
                                             #\Return #\Newline))
                             stream)
             (finish-output stream)
             (usocket:socket-shutdown socket :output)
             (let ((reply (handler-case (read-reply stream)
                            (error () nil))))
               (when (and reply (= (reply-status reply) 200))
                 (fail "accepted ~s" (ignore-errors (body-text reply))))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "chunked body"
    (let ((reply (exchange port (format nil "~a5~c~chello~c~c0~c~c~c~c"
                                        (request-text "POST /echo HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: chunked")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "chunked ~s" (body-text reply)))))
  (chunk-terminator-test port)
  (check "forbidden trailer fields are ignored"
    (let ((reply (exchange port (format nil "~a5~c~chello~c~c0~c~cContent-Length: 5~c~cX-Checksum: abc~c~c~c~c"
                                        (request-text "POST /trailers HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: chunked")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "x-checksum=abc")
        (fail "trailers ~s" (body-text reply)))))
  (check "a huge chunk-size does not wrap"
    ;; RFC 9112 §7.1. Twenty hex digits do not fit in 64 bits. The size
    ;; is rejected as larger than the body limit instead of wrapping.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (format nil "~aFFFFFFFFFFFFFFFFFFFF~c~c"
                                             (request-text "POST /echo HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Transfer-Encoding: chunked")
                                             #\Return #\Newline))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 413)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection")))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "chunk-size is hex without leading space"
    (expect-status (exchange port (format nil "~a ~c~c0~c~c~c~c"
                                          (request-text "POST /echo HTTP/1.1"
                                                        "Host: 127.0.0.1"
                                                        "Transfer-Encoding: chunked")
                                          #\Return #\Newline
                                          #\Return #\Newline #\Return #\Newline))
                   400)
    (let ((reply (exchange port (format nil "~a5 ;ext=1~c~chello~c~c0~c~c~c~c"
                                        (request-text "POST /echo HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: chunked")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "chunk-ext ~s" (body-text reply)))))
  (check "malformed chunk extension is rejected"
    (dolist (size-line '("5 ;" "5 ;ext=" "5 ;=1" "5 ;ext=\"ab" "5 "))
      (expect-status (exchange port (format nil "~a~a~c~chello~c~c0~c~c~c~c"
                                            (request-text "POST /echo HTTP/1.1"
                                                          "Host: 127.0.0.1"
                                                          "Transfer-Encoding: chunked")
                                            size-line
                                            #\Return #\Newline #\Return #\Newline
                                            #\Return #\Newline #\Return #\Newline))
                     400))
    (dolist (size-line `("5;ext=1" "5 ;ext=\"a;b\"" "5 ;ext=1;pad=2"
                         ,(format nil "5~c;ext=1" #\Tab)))
      (let ((reply (exchange port (format nil "~a~a~c~chello~c~c0~c~c~c~c"
                                          (request-text "POST /echo HTTP/1.1"
                                                        "Host: 127.0.0.1"
                                                        "Transfer-Encoding: chunked")
                                          size-line
                                          #\Return #\Newline #\Return #\Newline
                                          #\Return #\Newline #\Return #\Newline))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "hello")
          (fail "~a body ~s" size-line (ignore-errors (body-text reply)))))))
  (check "content-length and transfer-encoding"
    ;; RFC 9112 §6.1. Both fields are present, so the connection closes
    ;; after the response. A pipelined GET is not answered.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: 1"
                                                                "Transfer-Encoding: chunked")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after content-length and transfer-encoding"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "transfer-encoding must end in chunked"
    ;; RFC 9112 §6.1. chunked is not the final coding, so the length
    ;; cannot be known. The connection closes before the next request.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Transfer-Encoding: chunked, gzip")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after transfer-encoding" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "chunked transfer-coding parameters are rejected"
    (expect-status (exchange port (request-text "POST /echo HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Transfer-Encoding: chunked;foo=1"))
                   400)
    (let ((reply (exchange port (format nil "~a00000005~c~chello~c~c0~c~c~c~c"
                                        (request-text "POST /echo HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Transfer-Encoding: chunked")
                                        #\Return #\Newline #\Return #\Newline
                                        #\Return #\Newline #\Return #\Newline))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "leading-zero chunk ~s" (body-text reply)))))
  (check "conflicting content-length"
    (expect-status (exchange port (request-text "POST /echo HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 1"
                                                "Content-Length: 2"))
                   400))
  (check "identical content-length values are one length"
    ;; RFC 9112 §6.3 item 5. 5 and 05 are the same decimal, so the body
    ;; is that many octets and the request is served.
    (let ((reply (exchange port (concatenate 'string
                                             (request-text "POST /echo HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Content-Length: 5"
                                                           "Content-Length: 05")
                                             "hello"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "body ~s" (ignore-errors (body-text reply))))))
  (content-length-list-test port)
  (check "invalid content-length closes the connection"
    ;; RFC 9112 §6.3 item 5. A Content-Length that is not a decimal, and
    ;; is not a list of identical decimals, is unrecoverable framing.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: abc")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after bad content-length" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a short body is incomplete"
    ;; RFC 9112 §6.3 item 6. The sender closed before the Content-Length
    ;; octets arrived, so the request is not a complete message.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: 10")
                                                  "hi"))
                             stream)
             (finish-output stream)
             (usocket:socket-shutdown socket :output)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection")))
               (when (search "hi" (ignore-errors (body-text reply)))
                 (fail "partial body was accepted"))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a huge content-length does not wrap"
    ;; RFC 9110 §8.6. Nineteen digits do not fit in a signed 64-bit
    ;; integer. The same width with leading zeros is still the small value.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.1"
                                                                "Host: 127.0.0.1"
                                                                "Content-Length: 9999999999999999999")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 413)
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after huge content-length" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((reply (exchange port (concatenate 'string
                                             (request-text "POST /echo HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Content-Length: 0000000000000000005")
                                             "hello"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "padded length ~s" (ignore-errors (body-text reply))))))
  (check "path escapes root"
    (expect-status (exchange port (request-text "GET /../x HTTP/1.1" "Host: 127.0.0.1")) 400))
  (check "encoded dotdot escapes the root"
    (expect-status (exchange port (request-text "GET /%2e%2e/x HTTP/1.1" "Host: 127.0.0.1")) 400))
  (check "encoded slash"
    (expect-status (exchange port (request-text "GET /%2e%2e%2f HTTP/1.1" "Host: 127.0.0.1")) 400))
  (check "dotdot normalizes inside the root"
    (let ((reply (exchange port (request-text "GET /q/../q?a=1&c=2 HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "a=1;c=2")
        (fail "normalized ~s" (body-text reply)))))
  (check "expect 100-continue"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "POST /echo HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Content-Length: 4"
                                                   "Expect: 100-continue"))
                             stream)
             (finish-output stream)
             (let ((head (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
               (loop for byte = (read-byte stream)
                     do (vector-push-extend byte head)
                        (when (and (>= (length head) 4)
                                   (= (aref head (- (length head) 4)) 13)
                                   (= (aref head (- (length head) 3)) 10)
                                   (= (aref head (- (length head) 2)) 13)
                                   (= (aref head (- (length head) 1)) 10))
                          (return)))
               (unless (search "100" (latin1 head))
                 (fail "no 100 Continue: ~s" (latin1 head))))
             (write-sequence (octets "echo") stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "echo")
                 (fail "continue body ~s" (body-text reply)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a rejected 100-continue does not wait for the body"
    ;; RFC 9110 §10.1.1. The final status is known from the method and
    ;; target, or from Content-Length. The client does not send the body.
    (labels ((first-status (text)
               (let ((socket (connect port)))
                 (unwind-protect
                      (let ((stream (usocket:socket-stream socket)))
                        (write-sequence (octets text) stream)
                        (finish-output stream)
                        (let ((head (make-array 0 :element-type '(unsigned-byte 8)
                                                  :adjustable t :fill-pointer 0)))
                          (loop for byte = (read-byte stream)
                                do (vector-push-extend byte head)
                                   (when (and (>= (length head) 4)
                                              (= (aref head (- (length head) 4)) 13)
                                              (= (aref head (- (length head) 3)) 10)
                                              (= (aref head (- (length head) 2)) 13)
                                              (= (aref head (- (length head) 1)) 10))
                                     (return)))
                          (multiple-value-bind (status status-line headers)
                              (parse-headers (latin1 (subseq head 0 (- (length head) 4))))
                            (when (< status 200)
                              (fail "interim ~a" status-line))
                            (unless (string-equal (cdr (assoc "connection" headers :test #'string=))
                                                  "close")
                              (fail "connection ~s" headers))
                            (let ((length-text (cdr (assoc "content-length" headers :test #'string=))))
                              (when length-text
                                (read-n stream (parse-integer length-text))))
                            (values status headers))))
                   (ignore-errors (usocket:socket-close socket))))))
      (let ((status (first-status (request-text "POST /no-such-continue HTTP/1.1"
                                                 "Host: 127.0.0.1"
                                                 "Content-Length: 5"
                                                 "Expect: 100-continue"))))
        (unless (= status 404)
          (fail "missing ~d" status)))
      (multiple-value-bind (status headers)
          (first-status (request-text "POST / HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Content-Length: 5"
                                      "Expect: 100-continue"))
        (unless (= status 405)
          (fail "method ~d" status))
        (unless (search "GET" (cdr (assoc "allow" headers :test #'string=)))
          (fail "allow ~s" headers)))
      (let ((status (first-status (request-text "POST /echo HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 2000000"
                                                "Expect: 100-continue"))))
        (unless (= status 413)
          (fail "length ~d" status)))))
  (check "a header-decided rejection does not wait for the body"
    ;; RFC 9110 §10.1.1. Authorization, a failed precondition, and an
    ;; unknown content-coding are known from the header fields.
    (labels ((header-block (stream)
               (let ((head (make-array 0 :element-type '(unsigned-byte 8)
                                         :adjustable t :fill-pointer 0)))
                 (loop for byte = (read-byte stream)
                       do (vector-push-extend byte head)
                          (when (and (>= (length head) 4)
                                     (= (aref head (- (length head) 4)) 13)
                                     (= (aref head (- (length head) 3)) 10)
                                     (= (aref head (- (length head) 2)) 13)
                                     (= (aref head (- (length head) 1)) 10))
                            (return)))
                 (parse-headers (latin1 (subseq head 0 (- (length head) 4))))))
             (final-status (text)
               (let ((socket (connect port)))
                 (unwind-protect
                      (let ((stream (usocket:socket-stream socket)))
                        (write-sequence (octets text) stream)
                        (finish-output stream)
                        (multiple-value-bind (status status-line headers)
                            (header-block stream)
                          (when (< status 200)
                            (fail "interim ~a" status-line))
                          (unless (string-equal (cdr (assoc "connection" headers :test #'string=))
                                                "close")
                            (fail "connection ~s" headers))
                          (let ((length-text (cdr (assoc "content-length" headers :test #'string=))))
                            (when length-text
                              (read-n stream (parse-integer length-text))))
                          (values status headers)))
                   (ignore-errors (usocket:socket-close socket)))))
             (continued (text body)
               (let ((socket (connect port)))
                 (unwind-protect
                      (let ((stream (usocket:socket-stream socket)))
                        (write-sequence (octets text) stream)
                        (finish-output stream)
                        (multiple-value-bind (status status-line headers)
                            (header-block stream)
                          (declare (ignore headers))
                          (unless (= status 100)
                            (fail "continue ~a" status-line))
                          (write-sequence (octets body) stream)
                          (finish-output stream)
                          (read-reply stream)))
                   (ignore-errors (usocket:socket-close socket)))))
             (challenge ()
               (let ((reply (exchange port (request-text "GET /digest HTTP/1.1"
                                                         "Host: 127.0.0.1"))))
                 (expect-status reply 401)
                 (let ((www (or (header reply "www-authenticate") (fail "no challenge"))))
                   (values (ppcre-or-scan www "nonce=\"([^\"]+)\"")
                           (ppcre-or-scan www "opaque=\"([^\"]+)\"")))))
             (digest-auth (nonce opaque nc response &optional (uri "/digest-continue"))
               (format nil "Authorization: Digest username=\"ada\", realm=\"pazuzu\", nonce=\"~a\", uri=\"~a\", algorithm=SHA-256, response=\"~a\", qop=auth, nc=~a, cnonce=\"abcdef01\", opaque=\"~a\""
                       nonce uri response nc opaque))
             (post-digest (nonce nc &optional (method "POST") (uri "/digest-continue"))
               (let ((ha1 (sha256-hex "ada:pazuzu:secret"))
                     (ha2 (sha256-hex (format nil "~a:~a" method uri))))
                 (sha256-hex (format nil "~a:~a:~a:abcdef01:auth:~a" ha1 nonce nc ha2)))))
      (multiple-value-bind (status headers)
          (final-status (request-text "POST /basic-continue HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Content-Length: 4"
                                      "Expect: 100-continue"))
        (unless (= status 401)
          (fail "basic ~d" status))
        (unless (search "Basic" (or (cdr (assoc "www-authenticate" headers :test #'string=)) ""))
          (fail "basic challenge ~s" headers)))
      (let ((token (cl-base64:usb8-array-to-base64-string (octets "ada:secret"))))
        (let ((reply (continued (request-text "POST /basic-continue HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 4"
                                              "Expect: 100-continue"
                                              (format nil "Authorization: Basic ~a" token))
                                "ping")))
          (expect-status reply 200)
          (unless (string= (body-text reply) "ping")
            (fail "basic body ~s" (body-text reply)))))
      (multiple-value-bind (status headers)
          (final-status (request-text "POST /bearer-continue HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Content-Length: 4"
                                      "Expect: 100-continue"
                                      "Authorization: Bearer nope"))
        (unless (= status 401)
          (fail "bearer ~d" status))
        (unless (search "Bearer" (or (cdr (assoc "www-authenticate" headers :test #'string=)) ""))
          (fail "bearer challenge ~s" headers)))
      (multiple-value-bind (nonce opaque) (challenge)
        (multiple-value-bind (status headers)
            (final-status (request-text "POST /digest-continue HTTP/1.1"
                                        "Host: 127.0.0.1"
                                        "Content-Length: 4"
                                        "Expect: 100-continue"
                                        (digest-auth nonce opaque "00000001"
                                                     "0000000000000000000000000000000000000000000000000000000000000000")))
          (unless (= status 401)
            (fail "digest ~d" status))
          (when (search "stale=true" (or (cdr (assoc "www-authenticate" headers :test #'string=)) ""))
            (fail "stale on a bad digest ~s" headers)))
        (let ((reply (continued (request-text "POST /digest-continue HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 4"
                                              "Expect: 100-continue"
                                              (digest-auth nonce opaque "00000001"
                                                           (post-digest nonce "00000001")))
                                "ping")))
          (expect-status reply 200)
          (unless (string= (body-text reply) "digest-ok")
            (fail "digest body ~s" (body-text reply))))
        (multiple-value-bind (status headers)
            (final-status (request-text "POST /digest-continue HTTP/1.1"
                                        "Host: 127.0.0.1"
                                        "Content-Length: 4"
                                        "Expect: 100-continue"
                                        (digest-auth nonce opaque "00000001"
                                                     (post-digest nonce "00000001"))))
          (unless (= status 401)
            (fail "replay ~d" status))
          (when (search "stale=true" (or (cdr (assoc "www-authenticate" headers :test #'string=)) ""))
            (fail "stale on a replay ~s" headers))))
      (multiple-value-bind (nonce opaque) (challenge)
        (let ((record (gethash nonce pazuzu::*digest-nonces*)))
          (unless record
            (fail "nonce ~a is not stored" nonce))
          (setf (pazuzu::digest-nonce-expiry record) 1))
        (multiple-value-bind (status headers)
            (final-status (request-text "POST /digest-continue HTTP/1.1"
                                        "Host: 127.0.0.1"
                                        "Content-Length: 4"
                                        "Expect: 100-continue"
                                        (digest-auth nonce opaque "00000001"
                                                     (post-digest nonce "00000001"))))
          (unless (= status 401)
            (fail "stale ~d" status))
          (unless (search "stale=true" (or (cdr (assoc "www-authenticate" headers :test #'string=)) ""))
            (fail "missing stale ~s" headers))))
      (setf *put-calls* 0)
      (let ((status (final-status (request-text "PUT /item HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 4"
                                                "Expect: 100-continue"
                                                "If-Match: \"no\""))))
        (unless (= status 412)
          (fail "if-match ~d" status))
        (unless (zerop *put-calls*)
          (fail "handler ran ~d" *put-calls*)))
      (let ((reply (exchange port (request-text "PUT /item HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "Expect: 100-continue"
                                                "If-Match: \"v1\""))))
        (expect-status reply 200)
        (unless (= *put-calls* 1)
          (fail "handler ~d" *put-calls*)))
      (multiple-value-bind (status headers)
          (final-status (request-text "POST /echo HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Content-Length: 4"
                                      "Expect: 100-continue"
                                      "Content-Encoding: nosuch"))
        (unless (= status 415)
          (fail "coding ~d" status))
        (unless (string-equal (cdr (assoc "accept-encoding" headers :test #'string=))
                              "gzip, deflate, br, zstd")
          (fail "coding accept-encoding ~s" headers)))
      ;; A failed Authorization is not 2xx or 412, so If-Match is ignored
      ;; (RFC 9110 §13.2.1). A valid Digest that fails If-Match does not
      ;; consume nc, and the same nc is then accepted when If-Match matches.
      (setf *locked-calls* 0)
      (multiple-value-bind (status headers)
          (final-status (request-text "PUT /locked HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Content-Length: 4"
                                      "Expect: 100-continue"
                                      "If-Match: \"no\""))
        (unless (= status 401)
          (fail "locked early ~d" status))
        (unless (search "Basic" (or (cdr (assoc "www-authenticate" headers :test #'string=)) ""))
          (fail "locked challenge ~s" headers))
        (unless (zerop *locked-calls*)
          (fail "locked early handler ~d" *locked-calls*)))
      (setf *digest-item-calls* 0)
      (multiple-value-bind (nonce opaque) (challenge)
        (multiple-value-bind (status headers)
            (final-status (request-text "PUT /digest-item HTTP/1.1"
                                        "Host: 127.0.0.1"
                                        "Content-Length: 4"
                                        "Expect: 100-continue"
                                        "If-Match: \"no\""
                                        (digest-auth nonce opaque "00000001"
                                                     (post-digest nonce "00000001" "PUT" "/digest-item")
                                                     "/digest-item")))
          (declare (ignore headers))
          (unless (= status 412)
            (fail "digest precondition ~d" status))
          (unless (zerop *digest-item-calls*)
            (fail "digest precondition handler ~d" *digest-item-calls*))
          (let ((record (gethash nonce pazuzu::*digest-nonces*)))
            (when (and record
                       (gethash "00000001" (pazuzu::digest-nonce-seen record)))
              (fail "412 consumed nc"))))
        (let ((reply (continued (request-text "PUT /digest-item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 4"
                                              "Expect: 100-continue"
                                              "If-Match: \"v1\""
                                              (digest-auth nonce opaque "00000001"
                                                           (post-digest nonce "00000001" "PUT" "/digest-item")
                                                           "/digest-item"))
                                "ping")))
          (expect-status reply 200)
          (unless (string= (body-text reply) "digest-item")
            (fail "digest item body ~s" (body-text reply)))
          (unless (= *digest-item-calls* 1)
            (fail "digest item handler ~d" *digest-item-calls*))))))
  (unread-request-body-test port)
  (check "a failed authorization ignores preconditions"
    ;; RFC 9110 §13.2.1. 401 is known from Authorization. If-Match is
    ;; ignored. A matching credential is still subject to If-Match.
    (setf *locked-calls* 0)
    (let ((reply (exchange port (request-text "PUT /locked HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Match: \"no\""))))
      (expect-status reply 401)
      (unless (search "Basic" (or (header reply "www-authenticate") ""))
        (fail "locked www ~s" (header reply "www-authenticate")))
      (unless (zerop *locked-calls*)
        (fail "unauthenticated handler ~d" *locked-calls*)))
    (let ((reply (exchange port (request-text "PUT /locked HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Match: \"v1\""
                                              "Authorization: Basic nope"))))
      (expect-status reply 401)
      (unless (zerop *locked-calls*)
        (fail "bad credential handler ~d" *locked-calls*)))
    (let ((token (cl-base64:usb8-array-to-base64-string (octets "ada:secret"))))
      (let ((reply (exchange port (request-text "PUT /locked HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-Match: \"no\""
                                                (format nil "Authorization: Basic ~a" token)))))
        (expect-status reply 412)
        (unless (zerop *locked-calls*)
          (fail "precondition handler ~d" *locked-calls*)))
      (let ((reply (exchange port (request-text "PUT /locked HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-Match: \"v1\""
                                                (format nil "Authorization: Basic ~a" token)))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "locked")
          (fail "locked body ~s" (body-text reply)))
        (unless (= *locked-calls* 1)
          (fail "accepted handler ~d" *locked-calls*)))))
  (check "a 401 carries a challenge"
    ;; RFC 9110 §§11.6.1 and 15.5.2. A handler 401 with no challenge
    ;; still sends one. An existing Basic challenge is unchanged.
    (let ((bare (exchange port (request-text "GET /bare-401 HTTP/1.1"
                                             "Host: 127.0.0.1")))
          (basic (exchange port (request-text "PUT /locked HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"))))
      (expect-status bare 401)
      (let ((challenge (or (header bare "www-authenticate") "")))
        (when (zerop (length challenge))
          (fail "bare challenge ~s" challenge)))
      (expect-status basic 401)
      (let ((challenge (or (header basic "www-authenticate") "")))
        (unless (and (>= (length challenge) 5)
                     (string-equal challenge "Basic" :end1 5)
                     (search "realm=" challenge))
          (fail "basic challenge ~s" challenge)))))
  (check "a cleartext connection does not reuse credentials"
    ;; RFC 9110 §3.3. Requests on one connection are not the same user
    ;; agent unless the connection is secured and specific to that agent.
    ;; A successful Basic authentication does not authorize the next request.
    (setf *locked-calls* 0)
    (let ((socket (connect port))
          (token (cl-base64:usb8-array-to-base64-string (octets "ada:secret"))))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "PUT /locked HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Content-Length: 0"
                                                   "If-Match: \"v1\""
                                                   (format nil "Authorization: Basic ~a" token)))
                             stream)
             (finish-output stream)
             (let ((first (read-reply stream)))
               (expect-status first 200)
               (unless (string= (body-text first) "locked")
                 (fail "first locked ~s" (body-text first)))
               (unless (= *locked-calls* 1)
                 (fail "first handler ~d" *locked-calls*)))
             (write-sequence (octets (request-text "PUT /locked HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Content-Length: 0"
                                                   "If-Match: \"v1\""))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 401)
               (unless (search "Basic" (or (header second "www-authenticate") ""))
                 (fail "second www ~s" (header second "www-authenticate")))
               (unless (= *locked-calls* 1)
                 (fail "second handler ~d" *locked-calls*))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "one ETag line when the slot and the field both are set"
    (let ((reply (exchange port (request-text "GET /dual-etag HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (= 1 (count "etag" (reply-headers reply) :key #'car :test #'string-equal))
        (fail "etag lines ~s" (reply-headers reply)))
      (unless (string= (header reply "etag") "\"slot\"")
        (fail "etag ~s" (header reply "etag")))
      (unless (= 1 (count "last-modified" (reply-headers reply) :key #'car :test #'string-equal))
        (fail "last-modified lines ~s" (reply-headers reply)))
      (unless (string= (header reply "last-modified") "Mon, 01 Jan 1900 00:00:00 GMT")
        (fail "last-modified ~s" (header reply "last-modified")))))
  (check "expect rejection"
    (expect-status (exchange port (request-text "POST /echo HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "Expect: 102-processing"))
                   417)
    (expect-status (exchange port (request-text "POST /echo HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "Expect: 100-continue"
                                                "Expect: 102-processing"))
                   417))
  (check "HTTP/1.0 ignores 100-continue"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "POST /echo HTTP/1.0"
                                                                "Content-Length: 4"
                                                                "Expect: 100-continue")
                                                  "echo"))
                             stream)
             (finish-output stream)
             (let* ((text (latin1 (read-some stream)))
                    (end (or (position #\Return text) (length text))))
               (unless (search "HTTP/1.0 200" text :end2 end)
                 (fail "status ~s" (subseq text 0 end)))
               (unless (search "echo" text)
                 (fail "body ~s" text))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "204 has no content-length"
    (let ((reply (exchange port (request-text "GET /none HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 204)
      (when (header reply "content-length")
        (fail "204 content-length ~s" (header reply "content-length")))
      (when (header reply "transfer-encoding")
        (fail "204 transfer-encoding ~s" (header reply "transfer-encoding")))))
  (check "204 has no transfer-encoding"
    ;; RFC 9112 §6.1. The handler named chunked. A 204 must not send it.
    (let ((reply (exchange port (request-text "GET /none HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 204)
      (when (header reply "transfer-encoding")
        (fail "204 transfer-encoding ~s" (header reply "transfer-encoding")))
      (when (member "transfer-encoding" (connection-options reply) :test #'string=)
        (fail "204 connection ~s" (header reply "connection")))))
  (check "a 204 sends no content"
    ;; RFC 9112 §6.3 and RFC 9110 §15.3.5. The handler supplied a body.
    ;; The 204 ends at the empty line, so the next request is still the
    ;; next message.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (concatenate 'string
                                                  (request-text "GET /none-body HTTP/1.1"
                                                                "Host: 127.0.0.1")
                                                  (request-text "GET / HTTP/1.1"
                                                                "Host: 127.0.0.1")))
                             stream)
             (finish-output stream)
             (let ((none (read-reply-headers-only stream)))
               (expect-status none 204)
               (when (header none "content-length")
                 (fail "204 content-length ~s" (header none "content-length")))
               (when (header none "transfer-encoding")
                 (fail "204 transfer-encoding ~s" (header none "transfer-encoding"))))
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after 204 ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "rfc850 If-Modified-Since uses the near year"
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: Sunday, 21-Oct-70 00:00:00 GMT"))))
      (expect-status reply 304)))
  (check "invalid HTTP-date If-Modified-Since is ignored"
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: sunday, 21-Oct-70 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "dated")
        (fail "dated body ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Unmodified-Since: Sun, 01 jan 1990 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "dated")
        (fail "unmodified body ~s" (body-text reply)))))
  (check "repeated If-Modified-Since is ignored"
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: Sunday, 21-Oct-70 00:00:00 GMT"
                                              "If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "dated")
        (fail "dated body ~s" (body-text reply)))))
  (check "If-Modified-Since is ignored beside If-None-Match"
    ;; RFC 9110 §13.1.3. If-None-Match replaces If-Modified-Since. A
    ;; field value with more than one member, a method other than GET
    ;; or HEAD, and a representation with no modification date are
    ;; ignored as well.
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"no\""
                                              "If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "dated")
        (fail "replaced dated ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /dual-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"slot\""
                                              "If-Modified-Since: Sun, 31 Dec 1899 00:00:00 GMT"))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "replaced 304 sent a body")))
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT, Sun, 06 Nov 1994 08:49:37 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "dated")
        (fail "ims list ~s" (body-text reply))))
    (setf *unmodified-calls* 0)
    (let ((reply (exchange port (request-text "PUT /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "kept")
        (fail "ims put ~s" (body-text reply)))
      (unless (= *unmodified-calls* 1)
        (fail "ims put calls ~d" *unmodified-calls*)))
    (let ((reply (exchange port (request-text "GET /etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "tagged")
        (fail "ims no date ~s" (body-text reply)))))
  (check "If-None-Match"
    (let ((reply (exchange port (request-text "GET /etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"v1\""))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "304 sent a body")))
    (let ((reply (exchange port (request-text "GET /etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"no\""
                                              "If-None-Match: \"v1\""))))
      (expect-status reply 304)))
  (check "a comma inside a quoted etag is one tag"
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"a,b\""))))
      (expect-status reply 304))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"a,b\", \"no\""))))
      (expect-status reply 304))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: W/\"a,b\""))))
      (expect-status reply 304))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: w/\"a,b\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "comma")
        (fail "lowercase weak ~s" (ignore-errors (body-text reply)))))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"no\""
                                              "If-None-Match: \"a,b\""))))
      (expect-status reply 304))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Match: \"a\", \"b\""))))
      (expect-status reply 412))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Match: \"a,b\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "comma")
        (fail "comma body ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /comma-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"a,b\", *"))))
      (expect-status reply 400))
    (let ((reply (exchange port (request-text "GET /slash-etag HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              (concatenate 'string
                                                           "If-None-Match: "
                                                           "\"" "a\\" "\""
                                                           ", \"no\"")))))
      (expect-status reply 304))
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/html;note=\"keep,me\";q=0, text/plain"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "plain")
        (fail "quoted accept ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /noted HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain;note=\"x;q=0\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "noted")
        (fail "noted body ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /noted HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain;note=\"x;q=0\";q=0"))))
      (expect-status reply 406)))
  (check "a quoted-pair is the escaped octet"
    ;; RFC 9110 §5.6.4. note="a\b" is the value ab. note="a\\b" is a\b.
    (let ((reply (exchange port (request-text "GET /quoted HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain; note=\"a\\b\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "quoted")
        (fail "quoted-pair ~s" (body-text reply))))
    (expect-status (exchange port (request-text "GET /quoted HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept: text/plain; note=\"a\\\\b\""))
                   406))
  (check "If-Match on GET is decided before the handler"
    ;; RFC 9110 §13.1.1. Without Accept-Encoding the failed precondition
    ;; is final, so the handler does not run. An unacceptable coding is
    ;; 406 and If-Match is ignored (RFC 9110 §13.2.1).
    (setf *guard-calls* 0)
    (expect-status (exchange port (request-text "GET /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-Match: \"no\""))
                   412)
    (unless (zerop *guard-calls*)
      (fail "handler ran ~d" *guard-calls*))
    (let ((reply (exchange port (request-text "GET /guarded HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Match: \"g1\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "guarded")
        (fail "guarded ~s" (body-text reply)))
      (unless (= *guard-calls* 1)
        (fail "calls ~d" *guard-calls*)))
    (setf *guard-calls* 0)
    (expect-status (exchange port (request-text "GET /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Encoding: *;q=0"
                                                "If-Match: \"no\""))
                   406))
  (check "If-None-Match is decided before the method"
    ;; RFC 9110 §13.1.2. A false condition is 304 for GET and HEAD, and
    ;; 412 for PUT, and the handler does not run. Weak comparison is
    ;; used. * is false when a representation exists and true when it
    ;; does not. Accept-Encoding still selects first.
    (setf *guard-calls* 0)
    (let ((reply (exchange port (request-text "GET /guarded HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"g1\""))))
      (expect-status reply 304)
      (unless (string= (header reply "etag") "\"g1\"")
        (fail "early etag ~s" (header reply "etag")))
      (unless (header reply "date")
        (fail "early 304 without Date"))
      (when (header reply "content-type")
        (fail "early content-type ~s" (header reply "content-type"))))
    (unless (zerop *guard-calls*)
      (fail "get handler ran ~d" *guard-calls*))
    (let ((reply (exchange port (request-text "HEAD /guarded HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"g1\""))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "head 304 sent a body")))
    (unless (zerop *guard-calls*)
      (fail "head handler ran ~d" *guard-calls*))
    (expect-status (exchange port (request-text "GET /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-None-Match: W/\"g1\""))
                   304)
    (unless (zerop *guard-calls*)
      (fail "weak handler ran ~d" *guard-calls*))
    (expect-status (exchange port (request-text "GET /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-None-Match: *"))
                   304)
    (unless (zerop *guard-calls*)
      (fail "star handler ran ~d" *guard-calls*))
    (let ((reply (exchange port (request-text "GET /guarded HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"no\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "guarded")
        (fail "miss ~s" (body-text reply)))
      (unless (= *guard-calls* 1)
        (fail "miss calls ~d" *guard-calls*)))
    (setf *guard-calls* 0)
    (expect-status (exchange port (request-text "GET /guarded HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Encoding: *;q=0"
                                                "If-None-Match: \"g1\""))
                   406)
    (unless (= *guard-calls* 1)
      (fail "coding calls ~d" *guard-calls*))
    (setf *put-calls* 0)
    (expect-status (exchange port (request-text "PUT /item HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-None-Match: \"v1\""))
                   412)
    (expect-status (exchange port (request-text "PUT /item HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-None-Match: *"))
                   412)
    (unless (zerop *put-calls*)
      (fail "put handler ran ~d" *put-calls*))
    (let ((reply (exchange port (request-text "PUT /item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-None-Match: \"no\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "wrote")
        (fail "put miss ~s" (body-text reply)))
      (unless (= *put-calls* 1)
        (fail "put miss calls ~d" *put-calls*)))
    (setf *create-calls* 0)
    (let ((reply (exchange port (request-text "PUT /create HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-None-Match: *"))))
      (expect-status reply 201)
      (unless (string= (body-text reply) "created")
        (fail "create ~s" (body-text reply)))
      (unless (= *create-calls* 1)
        (fail "create calls ~d" *create-calls*))))
  (check "If-Unmodified-Since is decided before the method"
    ;; RFC 9110 §§13.1.4 and 13.2.2. The route date is 2000-01-01. A
    ;; false condition is 412 and the handler does not run. If-Match
    ;; replaces If-Unmodified-Since. A list of dates, a repeated field,
    ;; and a resource with no modification date are ignored.
    (setf *unmodified-calls* 0)
    (expect-status (exchange port (request-text "PUT /unmodified HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))
                   412)
    (unless (zerop *unmodified-calls*)
      (fail "put handler ran ~d" *unmodified-calls*))
    (expect-status (exchange port (request-text "GET /unmodified HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))
                   412)
    (unless (zerop *unmodified-calls*)
      (fail "get handler ran ~d" *unmodified-calls*))
    (let ((reply (exchange port (request-text "PUT /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "kept")
        (fail "equal put ~s" (body-text reply)))
      (unless (= *unmodified-calls* 1)
        (fail "equal put calls ~d" *unmodified-calls*)))
    (setf *unmodified-calls* 0)
    (let ((reply (exchange port (request-text "GET /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "kept")
        (fail "equal get ~s" (body-text reply)))
      (unless (= *unmodified-calls* 1)
        (fail "equal get calls ~d" *unmodified-calls*)))
    (setf *unmodified-calls* 0)
    (let ((reply (exchange port (request-text "PUT /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Match: \"u1\""
                                              "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "kept")
        (fail "if-match replaced ~s" (body-text reply)))
      (unless (= *unmodified-calls* 1)
        (fail "if-match calls ~d" *unmodified-calls*)))
    (setf *unmodified-calls* 0)
    (expect-status (exchange port (request-text "PUT /unmodified HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Content-Length: 0"
                                                "If-Match: \"no\""
                                                "If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT"))
                   412)
    (unless (zerop *unmodified-calls*)
      (fail "failed if-match ran ~d" *unmodified-calls*))
    (let ((reply (exchange port (request-text "GET /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT, Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "kept")
        (fail "date list ~s" (body-text reply)))
      (unless (= *unmodified-calls* 1)
        (fail "date list calls ~d" *unmodified-calls*)))
    (setf *unmodified-calls* 0)
    (let ((reply (exchange port (request-text "GET /unmodified HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"
                                              "If-Unmodified-Since: Tue, 02 Jan 1990 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "kept")
        (fail "repeated unmodified ~s" (body-text reply)))
      (unless (= *unmodified-calls* 1)
        (fail "repeated calls ~d" *unmodified-calls*)))
    (setf *put-calls* 0)
    (let ((reply (exchange port (request-text "PUT /item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "wrote")
        (fail "no date ~s" (body-text reply)))
      (unless (= *put-calls* 1)
        (fail "no date calls ~d" *put-calls*)))
    (let ((reply (exchange port (request-text "GET / HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "pazuzu")
        (fail "root unmodified ~s" (body-text reply))))
    (setf *unmodified-calls* 0)
    (expect-status (exchange port (request-text "GET /unmodified HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Encoding: *;q=0"
                                                "If-Unmodified-Since: Mon, 01 Jan 1990 00:00:00 GMT"))
                   406)
    (unless (= *unmodified-calls* 1)
      (fail "unacceptable coding calls ~d" *unmodified-calls*)))
  (check "PUT If-Match does not call the handler"
    (setf *put-calls* 0)
    (let ((reply (exchange port (request-text "PUT /item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Match: \"no\""))))
      (expect-status reply 412)
      (unless (zerop *put-calls*)
        (fail "handler ran"))))
  (put-create-test port)
  (put-existing-representation-test port)
  (put-store-then-modify-test port)
  (if-match-strong-test port)
  (if-match-case-test port)
  (check "If-Match star fails when there is no representation"
    (setf *create-calls* 0)
    (let ((reply (exchange port (request-text "PUT /create HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "If-Match: *"))))
      (expect-status reply 412)
      (unless (zerop *create-calls*)
        (fail "create handler ran"))))
  (check "Range"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-3"))))
      (expect-status reply 206)
      (unless (string= (body-text reply) "abcd")
        (fail "range ~s" (body-text reply)))))
  (check "205 has no content"
    (let ((reply (exchange port (request-text "GET /reset HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 205)
      (unless (string= (header reply "content-length") "0")
        (fail "205 content-length ~s" (header reply "content-length")))
      (unless (zerop (length (reply-body reply)))
        (fail "205 sent ~d octets" (length (reply-body reply))))))
  (check "206 keeps the 200 validators"
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-3"))))
      (expect-status reply 206)
      (unless (string= (body-text reply) "abcd")
        (fail "partial ~s" (body-text reply)))
      (unless (string= (header reply "etag") "\"p1\"")
        (fail "206 etag ~s" (header reply "etag")))
      (unless (string= (header reply "cache-control") "max-age=60")
        (fail "206 cache-control ~s" (header reply "cache-control")))
      (unless (string= (header reply "vary") "accept-encoding")
        (fail "206 vary ~s" (header reply "vary")))
      (unless (string= (header reply "expires") "Thu, 01 Jan 1970 00:00:00 GMT")
        (fail "206 expires ~s" (header reply "expires")))
      (unless (string= (header reply "content-location") "/partial/en")
        (fail "206 content-location ~s" (header reply "content-location")))
      (unless (string= (header reply "content-language") "en")
        (fail "206 content-language ~s" (header reply "content-language")))
      (unless (string= (header reply "content-type") "text/plain")
        (fail "206 content-type ~s" (header reply "content-type")))
      (unless (string= (header reply "content-range") "bytes 0-3/10")
        (fail "206 content-range ~s" (header reply "content-range")))
      (unless (header reply "date")
        (fail "206 missing date"))))
  (check "If-Range date is not a strong validator"
    (let ((reply (exchange port (request-text "GET /dated HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-2"
                                              "If-Range: Sat, 01 Jan 2000 00:00:00 GMT"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "dated")
        (fail "if-range date body ~s" (body-text reply)))))
  (check "a weak If-Range ignores Range"
    ;; RFC 9110 §§8.8.1 and 13.1.5. If-Range uses a strong comparison, so a
    ;; weak validator does not match and Range is ignored.
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-3"
                                              "If-Range: W/\"p1\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "abcdefghij")
        (fail "weak if-range body ~s" (body-text reply)))))
  (check "206 with If-Range omits representation fields"
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Range: \"p1\""
                                              "Range: bytes=0-3"))))
      (expect-status reply 206)
      (unless (string= (body-text reply) "abcd")
        (fail "if-range body ~s" (body-text reply)))
      (unless (string= (header reply "etag") "\"p1\"")
        (fail "if-range etag ~s" (header reply "etag")))
      (unless (string= (header reply "cache-control") "max-age=60")
        (fail "if-range cache-control ~s" (header reply "cache-control")))
      (unless (string= (header reply "content-location") "/partial/en")
        (fail "if-range content-location ~s" (header reply "content-location")))
      (when (header reply "content-type")
        (fail "if-range content-type ~s" (header reply "content-type")))
      (when (header reply "content-language")
        (fail "if-range content-language ~s" (header reply "content-language")))))
  (check "multipart parts use the representation type"
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-1,4-5"))))
      (expect-status reply 206)
      (unless (search "multipart/byteranges" (or (header reply "content-type") ""))
        (fail "multipart type ~s" (header reply "content-type")))
      (when (header reply "content-range")
        (fail "multipart content-range ~s" (header reply "content-range")))
      (unless (search "Content-Type: text/plain" (body-text reply))
        (fail "part type ~s" (body-text reply)))
      (unless (and (search "Content-Range: bytes 0-1/10" (body-text reply))
                   (search "Content-Range: bytes 4-5/10" (body-text reply)))
        (fail "part ranges ~s" (body-text reply)))
      (let* ((type (or (header reply "content-type") ""))
             (mark (search "boundary=" type)))
        (unless mark
          (fail "no boundary in ~s" type))
        (let ((boundary (subseq type (+ mark (length "boundary=")))))
          (when (search boundary "abcdefghij")
            (fail "boundary ~s occurs in the representation" boundary))
          (unless (search (format nil "--~a" boundary) (body-text reply))
            (fail "delimiter for ~s missing in ~s" boundary (body-text reply)))
          (let ((crlf (format nil "~c~c" #\Return #\Newline)))
            (unless (search (format nil "--~a~aContent-Type: text/plain~aContent-Range: bytes 0-1/10~a~aab~a"
                                    boundary crlf crlf crlf crlf crlf)
                            (body-text reply))
              (fail "part framing ~s" (body-text reply)))
            (unless (search (format nil "--~a--~a" boundary crlf) (body-text reply))
              (fail "close delimiter ~s" (body-text reply))))))))
  (check "multipart boundary does not occur in the body"
    (let* ((hay (pazuzu::ascii-octets "abcdefghij"))
           (boundary (pazuzu::multipart-boundary hay "text/plain")))
      (when (search (pazuzu::ascii-octets boundary) hay)
        (fail "boundary ~s is in the body" boundary))
      (when (search boundary "text/plain")
        (fail "boundary ~s is in the type" boundary))))
  (check "304 keeps cache validators and omits content-type"
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"p1\""))))
      (expect-status reply 304)
      (unless (zerop (length (reply-body reply)))
        (fail "304 sent a body"))
      (unless (string= (header reply "etag") "\"p1\"")
        (fail "304 etag ~s" (header reply "etag")))
      (unless (string= (header reply "cache-control") "max-age=60")
        (fail "304 cache-control ~s" (header reply "cache-control")))
      (unless (string= (header reply "vary") "accept-encoding")
        (fail "304 vary ~s" (header reply "vary")))
      (unless (string= (header reply "expires") "Thu, 01 Jan 1970 00:00:00 GMT")
        (fail "304 expires ~s" (header reply "expires")))
      (unless (string= (header reply "content-location") "/partial/en")
        (fail "304 content-location ~s" (header reply "content-location")))
      (when (header reply "content-type")
        (fail "304 content-type ~s" (header reply "content-type")))
      (when (header reply "content-language")
        (fail "304 content-language ~s" (header reply "content-language")))
      (when (header reply "content-length")
        (fail "304 content-length ~s" (header reply "content-length")))))
  (check "a 304 has a Date"
    ;; RFC 9110 §6.6.1. An origin with a clock sends Date on every 3xx.
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"p1\""))))
      (expect-status reply 304)
      (unless (header reply "date")
        (fail "304 without Date"))))
  (check "unknown range unit is ignored"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: widgets=0-1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "abcdefghij")
        (fail "unit ~s" (body-text reply)))))
  (range-unit-case-test port)
  (content-coding-case-test port)
  (media-type-case-test port)
  (language-tag-case-test port)
  (parameter-name-case-test port)
  (charset-case-test port)
  (transfer-coding-case-test port)
  (expect-case-test port)
  (connection-option-case-test port)
  (auth-scheme-case-test port)
  (challenge-parameter-once-test port)
  (auth-parameter-case-test port)
  (websocket-upgrade-case-test port)
  (websocket-connection-case-test port)
  (chunk-size-case-test port)
  (percent-hex-case-test port)
  (last-chunk-zeros-test port)
  (asctime-date-test port)
  (chunked-trailer-terminator-test port)
  (leap-second-date-test port)
  (if-none-match-before-range-test port)
  (if-match-before-none-test port)
  (if-unmodified-before-none-test port)
  (realm-quoted-token-test port)
  (switching-upgrade-test port)
  (websocket-post-handshake-test port)
  (websocket-absolute-target-test port)
  (no-content-date-test port)
  (if-match-list-test port)
  (if-match-star-test port)
  (range-method-test port)
  (accept-specificity-test port)
  (identity-q0-test port)
  (user-agent-semantics-test port)
  (handler-allow-test port)
  (via-members-test port)
  (qvalue-digits-test port)
  (product-identifier-test port)
  (empty-accept-encoding-test port)
  (coding-q0-test port)
  (coding-quality-test port)
  (if-none-match-continues-test port)
  (head-if-range-test port)
  (check "a huge range numeral does not overflow"
    ;; RFC 9110 §14.1.2. Forty nines is past any 128-bit unsigned
    ;; conversion. The first byte is past the representation, so the
    ;; range is unsatisfiable. A last-pos or suffix that long is the
    ;; whole representation.
    (let* ((huge (make-string 40 :initial-element #\9))
           (socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /range HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   (format nil "Range: bytes=~a-" huge)))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 416)
               (unless (string= (header reply "content-range") "bytes */10")
                 (fail "huge first ~s" (header reply "content-range")))
               (unless (string= (body-text reply) "Range Not Satisfiable")
                 (fail "huge first body ~s" (body-text reply))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after huge range ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket))))
    (let* ((huge (make-string 40 :initial-element #\9))
           (reply (exchange port (request-text "GET /range HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               (format nil "Range: bytes=0-~a" huge)))))
      (expect-status reply 206)
      (unless (string= (header reply "content-range") "bytes 0-9/10")
        (fail "huge last ~s" (header reply "content-range")))
      (unless (string= (body-text reply) "abcdefghij")
        (fail "huge last body ~s" (body-text reply))))
    (let* ((huge (make-string 40 :initial-element #\9))
           (reply (exchange port (request-text "GET /range HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               (format nil "Range: bytes=-~a" huge)))))
      (expect-status reply 206)
      (unless (string= (header reply "content-range") "bytes 0-9/10")
        (fail "huge suffix ~s" (header reply "content-range")))
      (unless (string= (body-text reply) "abcdefghij")
        (fail "huge suffix body ~s" (body-text reply)))))
  (check "a suffix range of an empty representation is satisfiable"
    ;; RFC 9110 §14.1.2. The only satisfiable bytes range of a
    ;; zero-length representation is a positive suffix. An int-range is
    ;; not. There is no inclusive byte position to put in a 206, so the
    ;; whole representation is sent.
    (let ((reply (exchange port (request-text "GET /empty HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=-1"))))
      (expect-status reply 200)
      (unless (zerop (length (reply-body reply)))
        (fail "empty suffix body ~d" (length (reply-body reply))))
      (unless (string= (header reply "content-length") "0")
        (fail "empty suffix length ~s" (header reply "content-length")))
      (when (header reply "content-range")
        (fail "empty suffix content-range ~s" (header reply "content-range"))))
    (let ((reply (exchange port (request-text "GET /empty HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-0,-1"))))
      (expect-status reply 200)
      (unless (string= (header reply "content-length") "0")
        (fail "mixed empty length ~s" (header reply "content-length"))))
    (let ((reply (exchange port (request-text "GET /empty HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-0"))))
      (expect-status reply 416)
      (unless (string= (header reply "content-range") "bytes */0")
        (fail "empty int-range ~s" (header reply "content-range"))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /empty HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Range: bytes=-1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after empty suffix ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "Range is ignored on POST"
    (let ((reply (exchange port (request-text "POST /post-range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "Range: bytes=0-3"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "abcdefghij")
        (fail "post range ~s" (body-text reply)))))
  (check "If-Range without Range is ignored"
    ;; RFC 9110 §13.1.5. If-Range is not a precondition unless Range is
    ;; present. A tag that does not match the representation still
    ;; returns that representation.
    (let ((reply (exchange port (request-text "GET /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-Range: \"no\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "abcdefghij")
        (fail "if-range alone ~s" (body-text reply)))
      (when (header reply "content-range")
        (fail "if-range content-range ~s" (header reply "content-range")))))
  (if-range-unsupported-test port)
  (check "Content-Range on a request is ignored"
    ;; RFC 9110 §14.4. POST has no Content-Range semantics, so the field
    ;; does not select a subrange of the received content.
    (let ((reply (exchange port (concatenate 'string
                                             (request-text "POST /echo HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Content-Length: 5"
                                                           "Content-Range: bytes 0-1/10")
                                             "hello"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "content-range body ~s" (body-text reply)))))
  (check "a request Content-Location does not change the target"
    ;; RFC 9110 §8.7. The field is transitory request context. It is not
    ;; saved as representation metadata, and it does not select another
    ;; resource.
    (let ((reply (exchange port (concatenate 'string
                                             (request-text "POST /echo HTTP/1.1"
                                                           "Host: 127.0.0.1"
                                                           "Content-Length: 5"
                                                           "Content-Location: http://source.example/original")
                                             "hello"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "hello")
        (fail "content-location body ~s" (body-text reply)))
      (when (header reply "content-location")
        (fail "content-location saved ~s" (header reply "content-location"))))
    (setf *put-calls* 0)
    (let ((reply (exchange port (request-text "PUT /item HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Length: 0"
                                              "Content-Location: http://source.example/original"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "wrote")
        (fail "content-location put ~s" (body-text reply)))
      (unless (= *put-calls* 1)
        (fail "content-location put calls ~d" *put-calls*))
      (when (header reply "content-location")
        (fail "content-location put saved ~s" (header reply "content-location")))))
  (check "HEAD ignores Range"
    ;; RFC 9110 §§8.6 and 14.2. A partial GET would send 4 octets. HEAD
    ;; does not apply Range, and it does not send that shorter length.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "HEAD /partial HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Range: bytes=0-3"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (expect-status reply 200)
               (when (header reply "content-length")
                 (fail "head range length ~s" (header reply "content-length")))
               (when (header reply "content-range")
                 (fail "head content-range ~s" (header reply "content-range"))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after head range ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((reply (exchange port (request-text "HEAD /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: widgets=0-1")
                           :headers-only t)))
      (expect-status reply 200)
      (unless (string= (header reply "content-length") "10")
        (fail "unknown unit length ~s" (header reply "content-length"))))
    (let ((reply (exchange port (request-text "HEAD /partial HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Range: bytes=0-9")
                           :headers-only t)))
      (expect-status reply 200)
      (unless (string= (header reply "content-length") "10")
        (fail "full range length ~s" (header reply "content-length")))))
  (check "Accept 406"
    (expect-status (exchange port (request-text "GET /neg HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept: application/json"))
                   406))
  (check "Accept parameter does not match a bare type"
    (expect-status (exchange port (request-text "GET /neg HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept: text/plain;format=flowed"))
                   406)
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain;format=flowed, text/html;q=0.2"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "html")
        (fail "accept body ~s" (body-text reply)))
      (unless (search "text/html" (or (header reply "content-type") ""))
        (fail "accept type ~s" (header reply "content-type")))))
  (check "Accept lines are one list"
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain;q=0"
                                              "Accept: text/html"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "html")
        (fail "split accept ~s" (body-text reply)))))
  (check "empty Accept is not acceptable"
    (expect-status (exchange port (request-text "GET /neg HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept:"))
                   406))
  (check "empty list elements are ignored"
    ;; RFC 9110 §5.6.1.2. A recipient accepts "foo , ,bar" and drops the
    ;; empty member. The remaining member still selects the representation.
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: text/plain;q=0, , text/html"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "html")
        (fail "accept ~s" (ignore-errors (body-text reply)))))
    (let ((reply (exchange port (request-text "GET /lang HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Language: , , da"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "da")
        (fail "language ~s" (ignore-errors (body-text reply))))))
  (check "a response list omits an empty member"
    ;; RFC 9110 §5.6.1.1. Empty members are not sent. A comma inside a
    ;; quoted directive stays. A field that is not a list is unchanged.
    ;; A list of only empty members is omitted.
    (let ((reply (exchange port (request-text "GET /list-field HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "listed")
        (fail "body ~s" (body-text reply)))
      (unless (string= (header reply "content-language") "en, da")
        (fail "language ~s" (header reply "content-language")))
      (unless (string= (header reply "vary") "accept, accept-language")
        (fail "vary ~s" (header reply "vary")))
      (unless (string= (header reply "cache-control")
                       "no-cache=\"a, b\", max-age=1")
        (fail "cache ~s" (header reply "cache-control")))
      (unless (string= (header reply "x-note") "a, , b")
        (fail "note ~s" (header reply "x-note")))
      (when (header reply "trailer")
        (fail "trailer ~s" (header reply "trailer")))))
  (check "a repeated content-language is one list"
    ;; RFC 9110 §5.2 and §8.5. Content-Language is a comma-separated
    ;; list. Each field line is part of that value, in order.
    (let ((reply (exchange port (request-text "GET /two-languages HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "langs")
        (fail "body ~s" (body-text reply)))
      (unless (string= (header reply "content-language") "en, da")
        (fail "language ~s" (header reply "content-language")))))
  (check "negotiation Vary is sent when the request omits the field"
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "vary") "accept")
        (fail "neg vary ~s" (header reply "vary"))))
    (let ((reply (exchange port (request-text "GET /lang HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "vary") "accept, accept-language")
        (fail "lang vary ~s" (header reply "vary"))))
    (let ((reply (exchange port (request-text "GET /neg HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept: application/json"))))
      (expect-status reply 406)
      (unless (string-equal (header reply "vary") "accept")
        (fail "406 vary ~s" (header reply "vary")))))
  (check "Accept-Language uses the longest range"
    (let ((rejected (exchange port (request-text "GET /lang HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Language: en;q=1, en-gb;q=0"))))
      (expect-status rejected 200)
      (unless (string= (body-text rejected) "en")
        (fail "rejected en-gb body ~s" (body-text rejected)))
      (unless (search "accept-language" (or (header rejected "vary") ""))
        (fail "vary ~s" (header rejected "vary"))))
    (let ((danish (exchange port (request-text "GET /lang HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Language: da, en-gb;q=0.8, en;q=0.7"))))
      (expect-status danish 200)
      (unless (string= (body-text danish) "da")
        (fail "danish body ~s" (body-text danish))))
    (expect-status (exchange port (request-text "GET /lang HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Language:"))
                   406)
    (expect-status (exchange port (request-text "GET /lang HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Language: *;q=0"))
                   406))
  (check "Accept-Encoding star excludes identity"
    (expect-status (exchange port (request-text "GET /range HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Encoding: *;q=0"))
                   406)
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: identity;q=0.5, *;q=0"))))
      (expect-status reply 200)
      (when (header reply "content-encoding")
        (fail "coded ~s" (header reply "content-encoding")))
      (unless (string= (body-text reply) "abcdefghij")
        (fail "identity body ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: gzip;q=1, *;q=0"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "content-encoding") "gzip")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (babel:octets-to-string (decode-coding (reply-body reply) "gzip")
                                               :encoding :utf-8)
                       "abcdefghij")
        (fail "gzip under star"))))
  (check "an unacceptable coding ignores preconditions"
    ;; RFC 9110 §13.2.1. The response without If-Match would be 406, so
    ;; the precondition is not evaluated. The same If-Match alone is 412.
    (expect-status (exchange port (request-text "GET /partial HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Encoding: *;q=0"
                                                "If-Match: \"no\""))
                   406)
    (expect-status (exchange port (request-text "GET /partial HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "If-Match: \"no\""))
                   412))
  (missing-target-precondition-test port)
  (check "a coded representation has its own etag"
    ;; RFC 9110 §8.8.1. gzip is a different representation from identity,
    ;; so it does not reuse the strong tag "r1".
    (let ((plain (exchange port (request-text "GET /range HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status plain 200)
      (unless (string= (header plain "etag") "\"r1\"")
        (fail "identity etag ~s" (header plain "etag")))
      (expect-status (exchange port (request-text "GET /range HTTP/1.1"
                                                  "Host: 127.0.0.1"
                                                  "If-Match: \"r1\""))
                     200)
      (let ((coded (exchange port (request-text "GET /range HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Accept-Encoding: gzip"))))
        (expect-status coded 200)
        (unless (string-equal (header coded "content-encoding") "gzip")
          (fail "coding ~s" (header coded "content-encoding")))
        (let ((etag (or (header coded "etag") (fail "no coded etag"))))
          (when (or (string= etag "\"r1\"")
                    (and (>= (length etag) 2)
                         (char= (char etag 0) #\W)
                         (char= (char etag 1) #\/)))
            (fail "coded etag ~s" etag))
          (let ((again (exchange port (request-text "GET /range HTTP/1.1"
                                                    "Host: 127.0.0.1"
                                                    "Accept-Encoding: gzip"
                                                    (format nil "If-None-Match: ~a" etag)))))
            (expect-status again 304)
            (unless (string= (header again "etag") etag)
              (fail "304 etag ~s" (header again "etag")))
            (unless (search "accept-encoding" (or (header again "vary") ""))
              (fail "304 vary ~s" (header again "vary"))))
          (let ((miss (exchange port (request-text "GET /range HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Accept-Encoding: gzip"
                                                   "If-None-Match: \"r1\""))))
            (expect-status miss 200)
            (unless (string= (header miss "etag") etag)
              (fail "miss etag ~s" (header miss "etag"))))))))
  (check "Accept-Encoding lines are one list"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: identity;q=0"
                                              "Accept-Encoding: gzip"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "content-encoding") "gzip")
        (fail "split coding ~s" (header reply "content-encoding")))))
  (check "Content-Encoding lines decode from the outside"
    (let* ((raw (octets "layered"))
           (once (salza2:compress-data raw 'salza2:gzip-compressor))
           (twice (salza2:compress-data once 'salza2:gzip-compressor)))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (write-sequence
                (octets (request-text "POST /echo HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      (format nil "Content-Length: ~d" (length twice))
                                      "Content-Encoding: gzip"
                                      "Content-Encoding: gzip"))
                stream)
               (write-sequence twice stream)
               (finish-output stream)
               (let ((reply (read-reply stream)))
                 (expect-status reply 200)
                 (unless (equalp (reply-body reply) raw)
                   (fail "split coding body ~s" (ignore-errors (body-text reply))))))
          (ignore-errors (usocket:socket-close socket))))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (write-sequence
                (octets (request-text "POST /echo HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      (format nil "Content-Length: ~d" (length twice))
                                      "Content-Encoding: gzip, gzip"))
                stream)
               (write-sequence twice stream)
               (finish-output stream)
               (let ((reply (read-reply stream)))
                 (expect-status reply 200)
                 (unless (equalp (reply-body reply) raw)
                   (fail "joined coding body ~s" (ignore-errors (body-text reply))))))
          (ignore-errors (usocket:socket-close socket))))
      (let ((reply (exchange port (concatenate 'string
                                                 (request-text "POST /echo HTTP/1.1"
                                                               "Host: 127.0.0.1"
                                                               "Content-Length: 2"
                                                               "Content-Encoding: gzip, nosuch")
                                                 "hi"))))
        (expect-status reply 415)
        (unless (string-equal (header reply "accept-encoding")
                              "gzip, deflate, br, zstd")
          (fail "joined coding accept-encoding ~s" (header reply "accept-encoding"))))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (write-sequence
                (octets (request-text "POST /echo HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      (format nil "Content-Length: ~d" (length once))
                                      "Content-Encoding: x-gzip"))
                stream)
               (write-sequence once stream)
               (finish-output stream)
               (let ((reply (read-reply stream)))
                 (expect-status reply 200)
                 (unless (equalp (reply-body reply) raw)
                   (fail "x-gzip body ~s" (ignore-errors (body-text reply))))))
          (ignore-errors (usocket:socket-close socket))))))
  (check "a 415 unrelated to content coding omits Accept-Encoding"
    ;; RFC 9110 §12.5.3. This 415 is a media type the resource rejects.
    ;; Accept-Encoding is only for a content-coding failure.
    (let ((reply (exchange port (request-text "POST /media HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Content-Type: application/xml"
                                              "Content-Length: 0"))))
      (expect-status reply 415)
      (unless (string= (body-text reply) "Unsupported Media Type")
        (fail "media body ~s" (body-text reply)))
      (when (header reply "accept-encoding")
        (fail "unrelated accept-encoding ~s" (header reply "accept-encoding")))))
  (check "PUT omits validators after content-coding"
    (let* ((raw (octets "note"))
           (coded (salza2:compress-data raw 'salza2:gzip-compressor))
           (plain (exchange port (concatenate 'string
                                              (request-text "PUT /store HTTP/1.1"
                                                            "Host: 127.0.0.1"
                                                            "Content-Length: 4")
                                              "note"))))
      (expect-status plain 201)
      (unless (search "\"s1\"" (or (header plain "etag") ""))
        (fail "plain etag ~s" (header plain "etag")))
      (unless (header plain "last-modified")
        (fail "plain last-modified missing"))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (write-sequence
                (octets (request-text "PUT /store HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      (format nil "Content-Length: ~d" (length coded))
                                      "Content-Encoding: gzip"))
                stream)
               (write-sequence coded stream)
               (finish-output stream)
               (let ((reply (read-reply stream)))
                 (expect-status reply 201)
                 (when (header reply "etag")
                   (fail "coded etag ~s" (header reply "etag")))
                 (when (header reply "last-modified")
                   (fail "coded last-modified ~s" (header reply "last-modified")))))
          (ignore-errors (usocket:socket-close socket))))))
  (check "gzip roundtrip"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: gzip"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "content-encoding") "gzip")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (babel:octets-to-string (decode-coding (reply-body reply) "gzip")
                                               :encoding :utf-8)
                       "abcdefghij")
        (fail "gzip body"))))
  (check "deflate roundtrip"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: deflate"))))
      (expect-status reply 200)
      (unless (string= (babel:octets-to-string (decode-coding (reply-body reply) "deflate")
                                               :encoding :utf-8)
                       "abcdefghij")
        (fail "deflate body"))))
  (check "brotli roundtrip"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: br"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "content-encoding") "br")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (babel:octets-to-string (decode-coding (reply-body reply) "br")
                                               :encoding :utf-8)
                       "abcdefghij")
        (fail "br body"))))
  (check "zstd roundtrip"
    (let ((reply (exchange port (request-text "GET /range HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: zstd"))))
      (expect-status reply 200)
      (unless (string-equal (header reply "content-encoding") "zstd")
        (fail "coding ~s" (header reply "content-encoding")))
      (unless (string= (babel:octets-to-string (decode-coding (reply-body reply) "zstd")
                                               :encoding :utf-8)
                       "abcdefghij")
        (fail "zstd body"))))
  (check "HSTS is absent on cleartext"
    (let ((reply (exchange port (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
      (when (header reply "strict-transport-security")
        (fail "cleartext HSTS ~s" (header reply "strict-transport-security")))
      (when (header reply "alt-svc")
        (fail "cleartext Alt-Svc ~s" (header reply "alt-svc")))))
  (check "Date on 404"
    (let ((reply (exchange port (request-text "GET /missing HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 404)
      (unless (header reply "date")
        (fail "404 without Date"))))
  (check "OPTIONS *"
    (let ((reply (exchange port (request-text "OPTIONS * HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (search "GET" (or (header reply "allow") ""))
        (fail "allow ~s" (header reply "allow")))))
  (get-asterisk-test port)
  (authority-form-method-test port)
  (check "OPTIONS ignores conditionals"
    (let ((reply (exchange port (request-text "OPTIONS /opt HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "If-None-Match: \"o1\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "opt")
        (fail "options body ~s" (body-text reply)))))
  (check "cookie"
    (let ((reply (exchange port (request-text "GET /cookie HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Cookie: sid=abc"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "abc")
        (fail "cookie body ~s" (body-text reply)))
      (unless (search "HttpOnly" (or (header reply "set-cookie") ""))
        (fail "set-cookie ~s" (header reply "set-cookie")))))
  (check "cookie octet grammar"
    (let ((reply (exchange port (request-text "GET /cookie HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Cookie: sid=\"abc\""))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "abc")
        (fail "quoted cookie ~s" (body-text reply))))
    (let ((reply (exchange port (request-text "GET /cookie HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Cookie: sid=ab\"c"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "")
        (fail "bad cookie ~s" (body-text reply))))
    (unless (handler-case (progn (pazuzu:set-cookie "sid" "a\"b") nil)
              (error () t))
      (fail "set-cookie accepted a quote"))
    (unless (handler-case (progn (pazuzu:set-cookie "sid" "abc" :path "/;x") nil)
              (error () t))
      (fail "set-cookie accepted a semicolon path")))
  (check "a repeated content-type is one line"
    ;; RFC 9110 §5.2. Content-Type is not a list, so one line is sent.
    (let ((reply (exchange port (request-text "GET /dup-type HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "one")
        (fail "body ~s" (body-text reply)))
      (let ((types (loop for pair in (reply-headers reply)
                         when (string= (car pair) "content-type")
                           collect (cdr pair))))
        (unless (equal types '("text/html"))
          (fail "types ~s" types)))))
  (check "set-cookie stays on two lines"
    (let ((reply (exchange port (request-text "GET /two-cookies HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (let ((cookies (loop for pair in (reply-headers reply)
                           when (string= (car pair) "set-cookie")
                             collect (cdr pair))))
        (unless (and (= (length cookies) 2)
                     (some (lambda (value) (search "sid=abc" value)) cookies)
                     (some (lambda (value) (search "theme=dark" value)) cookies))
          (fail "cookies ~s" cookies)))))
  (check "realm quotes DQUOTE and backslash"
    ;; RFC 9110 §§5.6.4 and 11.5. The challenge is a quoted-string.
    (let ((reply (exchange port (request-text "GET /realm HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 401)
      (unless (string= (header reply "www-authenticate") "Basic realm=\"a\\\"b\\\\c\"")
        (fail "realm ~s" (header reply "www-authenticate")))))
  (check "basic auth"
    (expect-status (exchange port (request-text "GET /basic HTTP/1.1" "Host: 127.0.0.1")) 401)
    (let* ((token (cl-base64:usb8-array-to-base64-string (octets "ada:secret")))
           (reply (exchange port (request-text "GET /basic HTTP/1.1"
                                               "Host: 127.0.0.1"
                                               (format nil "Authorization: Basic ~a" token)))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "welcome")
        (fail "basic ~s" (body-text reply)))))
  (separate-user-agent-test port)
  (check "bearer auth"
    (let ((reply (exchange port (request-text "GET /bearer HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Authorization: Bearer tok_9"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "bearer-ok")
        (fail "bearer ~s" (body-text reply)))))
  (check "digest auth"
    (let ((challenge (exchange port (request-text "GET /digest HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status challenge 401)
      (let* ((www (or (header challenge "www-authenticate") (fail "no challenge")))
             (nonce (ppcre-or-scan www "nonce=\"([^\"]+)\""))
             (opaque (ppcre-or-scan www "opaque=\"([^\"]+)\""))
             (nc "00000001")
             (cnonce "abcdef01")
             (ha1 (sha256-hex "ada:pazuzu:secret"))
             (ha2 (sha256-hex "GET:/digest"))
             (response (sha256-hex (format nil "~a:~a:~a:~a:auth:~a" ha1 nonce nc cnonce ha2)))
             (reply (exchange port
                              (request-text
                               "GET /digest HTTP/1.1"
                               "Host: 127.0.0.1"
                               (format nil "Authorization: Digest username=\"ada\", realm=\"pazuzu\", nonce=\"~a\", uri=\"/digest\", algorithm=SHA-256, response=\"~a\", qop=auth, nc=~a, cnonce=\"~a\", opaque=\"~a\""
                                       nonce response nc cnonce opaque)))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "digest-ok")
          (fail "digest ~s" (body-text reply))))))
  (check "bad whitespace around equals is excluded"
    ;; RFC 9110 §5.6.3. A sender does not generate BWS. A recipient
    ;; removes it before the auth-param or chunk-ext is used.
    (labels ((bws-p (text)
               (loop for index below (length text)
                     thereis (and (char= (char text index) #\=)
                                  (or (and (plusp index)
                                           (member (char text (1- index))
                                                   '(#\Space #\Tab)))
                                      (and (< (1+ index) (length text))
                                           (member (char text (1+ index))
                                                   '(#\Space #\Tab))))))))
      (dolist (target '("/basic" "/bearer" "/digest"))
        (let ((challenge (exchange port (request-text
                                         (format nil "GET ~a HTTP/1.1" target)
                                         "Host: 127.0.0.1"))))
          (expect-status challenge 401)
          (let ((www (or (header challenge "www-authenticate")
                         (fail "no challenge"))))
            (when (bws-p www)
              (fail "generated BWS ~s" www)))))
      (let* ((www (header (exchange port (request-text "GET /digest HTTP/1.1"
                                                       "Host: 127.0.0.1"))
                          "www-authenticate"))
             (nonce (ppcre-or-scan www "nonce=\"([^\"]+)\""))
             (opaque (ppcre-or-scan www "opaque=\"([^\"]+)\""))
             (nc "00000001")
             (cnonce "abcdef01")
             (ha1 (sha256-hex "ada:pazuzu:secret"))
             (ha2 (sha256-hex "GET:/digest"))
             (response (sha256-hex (format nil "~a:~a:~a:~a:auth:~a"
                                           ha1 nonce nc cnonce ha2)))
             (reply (exchange port
                              (request-text
                               "GET /digest HTTP/1.1"
                               "Host: 127.0.0.1"
                               (format nil "Authorization: Digest username = \"ada\", realm = \"pazuzu\", nonce = \"~a\", uri = \"/digest\", algorithm = SHA-256, response = \"~a\", qop~c=~cauth, nc = ~a, cnonce = \"~a\", opaque = \"~a\""
                                       nonce response #\Tab #\Tab nc cnonce opaque)))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "digest-ok")
          (fail "bws digest ~s" (body-text reply))))
      (dolist (size-line `("5;ext = 1"
                           ,(format nil "5;ext~c=~c1" #\Tab #\Tab)))
        (let ((reply (exchange port (format nil "~a~a~c~chello~c~c0~c~c~c~c"
                                            (request-text "POST /echo HTTP/1.1"
                                                          "Host: 127.0.0.1"
                                                          "Transfer-Encoding: chunked")
                                            size-line
                                            #\Return #\Newline #\Return #\Newline
                                            #\Return #\Newline #\Return #\Newline))))
          (expect-status reply 200)
          (unless (string= (body-text reply) "hello")
            (fail "~a body ~s" size-line (ignore-errors (body-text reply))))))))
  (check "digest nonce count is not consumed by a bad response"
    ;; RFC 7616 §§3.3 and 3.4. A wrong response leaves nc usable. The same
    ;; nc is then a replay. An expired nonce with a valid digest is stale.
    (labels ((challenge ()
               (let ((reply (exchange port (request-text "GET /digest HTTP/1.1"
                                                         "Host: 127.0.0.1"))))
                 (expect-status reply 401)
                 (let ((www (or (header reply "www-authenticate") (fail "no challenge"))))
                   (values (ppcre-or-scan www "nonce=\"([^\"]+)\"")
                           (ppcre-or-scan www "opaque=\"([^\"]+)\"")
                           www))))
             (authorization (nonce opaque nc response)
               (format nil "Authorization: Digest username=\"ada\", realm=\"pazuzu\", nonce=\"~a\", uri=\"/digest\", algorithm=SHA-256, response=\"~a\", qop=auth, nc=~a, cnonce=\"abcdef01\", opaque=\"~a\""
                       nonce response nc opaque))
             (digest (nonce nc)
               (let ((ha1 (sha256-hex "ada:pazuzu:secret"))
                     (ha2 (sha256-hex "GET:/digest")))
                 (sha256-hex (format nil "~a:~a:~a:abcdef01:auth:~a" ha1 nonce nc ha2)))))
      (multiple-value-bind (nonce opaque www) (challenge)
        (declare (ignore www))
        (let ((bad (exchange port (request-text "GET /digest HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                (authorization nonce opaque "00000001" "0000000000000000000000000000000000000000000000000000000000000000")))))
          (expect-status bad 401)
          (when (search "stale=true" (or (header bad "www-authenticate") ""))
            (fail "stale on a bad digest ~s" (header bad "www-authenticate"))))
        (let ((good (exchange port (request-text "GET /digest HTTP/1.1"
                                                 "Host: 127.0.0.1"
                                                 (authorization nonce opaque "00000001"
                                                                (digest nonce "00000001"))))))
          (expect-status good 200)
          (unless (string= (body-text good) "digest-ok")
            (fail "retry ~s" (body-text good))))
        (let ((replay (exchange port (request-text "GET /digest HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   (authorization nonce opaque "00000001"
                                                                  (digest nonce "00000001"))))))
          (expect-status replay 401)
          (when (search "stale=true" (or (header replay "www-authenticate") ""))
            (fail "stale on a replay ~s" (header replay "www-authenticate")))))
      (multiple-value-bind (nonce opaque www) (challenge)
        (declare (ignore www))
        (let ((record (gethash nonce pazuzu::*digest-nonces*)))
          (unless record
            (fail "nonce ~a is not stored" nonce))
          (setf (pazuzu::digest-nonce-expiry record) 1))
        (let ((stale (exchange port (request-text "GET /digest HTTP/1.1"
                                                  "Host: 127.0.0.1"
                                                  (authorization nonce opaque "00000001"
                                                                 (digest nonce "00000001"))))))
          (expect-status stale 401)
          (unless (search "stale=true" (or (header stale "www-authenticate") ""))
            (fail "missing stale ~s" (header stale "www-authenticate")))))))
  (check "static file and If-None-Match"
    (let ((reply (exchange port (request-text "GET /files/hello.txt HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "static-hello")
        (fail "static ~s" (body-text reply)))
      (let* ((etag (or (header reply "etag") (fail "no etag")))
             (again (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                                 "Host: 127.0.0.1"
                                                 (format nil "If-None-Match: ~a" etag)))))
        (expect-status again 304))))
  (check "a file etag is weak"
    ;; RFC 9110 §§8.8.1 and 8.8.3. Length and a one-second mtime are not
    ;; unique for every representation, so strong comparison fails.
    (let ((reply (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (let ((etag (or (header reply "etag") (fail "no etag"))))
        (unless (and (>= (length etag) 4)
                     (char= (char etag 0) #\W)
                     (char= (char etag 1) #\/)
                     (char= (char etag 2) #\"))
          (fail "file etag ~s" etag))
        (let ((ranged (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   (format nil "If-Range: ~a" etag)
                                                   "Range: bytes=0-3"))))
          (expect-status ranged 200)
          (unless (string= (body-text ranged) "static-hello")
            (fail "if-range ~s" (body-text ranged))))
        (let ((matched (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"
                                                    (format nil "If-Match: ~a" etag)))))
          (expect-status matched 412))
        (let ((partial (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"
                                                    "Range: bytes=0-3"))))
          (expect-status partial 206)
          (unless (string= (body-text partial) "stat")
            (fail "range ~s" (body-text partial)))))))
  (check "a static file is streamed with its length"
    ;; The body is larger than one read. Content-Length is the file size,
    ;; so the response is not chunked, and a range that crosses a read
    ;; boundary is those bytes only.
    (let ((reply (exchange port (request-text "GET /files/wide.txt HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (header reply "content-length") "200000")
        (fail "content-length ~s" (header reply "content-length")))
      (when (header reply "transfer-encoding")
        (fail "transfer-encoding ~s" (header reply "transfer-encoding")))
      (unless (string= (header reply "accept-ranges") "bytes")
        (fail "accept-ranges ~s" (header reply "accept-ranges")))
      (let ((etag (or (header reply "etag") (fail "no etag"))))
        (unless (and (>= (length etag) 2)
                     (char= (char etag 0) #\W)
                     (char= (char etag 1) #\/))
          (fail "etag ~s" etag)))
      (unless (header reply "last-modified")
        (fail "no last-modified"))
      (let ((body (body-text reply)))
        (unless (= (length body) 200000)
          (fail "body length ~d" (length body)))
        (unless (string= (subseq body 16380 16400) "cdef0123456789abcdef")
          (fail "span ~s" (subseq body 16380 16400)))))
    (let ((head (exchange port (request-text "HEAD /files/wide.txt HTTP/1.1"
                                             "Host: 127.0.0.1")
                          :headers-only t)))
      (expect-status head 200)
      (unless (string= (header head "content-length") "200000")
        (fail "head length ~s" (header head "content-length"))))
    (let ((partial (exchange port (request-text "GET /files/wide.txt HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                "Range: bytes=16380-16399"))))
      (expect-status partial 206)
      (unless (string= (header partial "content-range") "bytes 16380-16399/200000")
        (fail "content-range ~s" (header partial "content-range")))
      (unless (string= (header partial "content-length") "20")
        (fail "range length ~s" (header partial "content-length")))
      (unless (string= (body-text partial) "cdef0123456789abcdef")
        (fail "range ~s" (body-text partial))))
    (let ((many (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Range: bytes=0-3,10-11"))))
      (expect-status many 206)
      (unless (search "multipart/byteranges" (or (header many "content-type") ""))
        (fail "type ~s" (header many "content-type")))
      (let ((body (body-text many)))
        (unless (and (search "stat" body) (search "lo" body)
                     (search (format nil "bytes 0-3/12~c~c" #\Return #\Newline) body)
                     (search (format nil "bytes 10-11/12~c~c" #\Return #\Newline) body))
          (fail "multipart ~s" body))))
    (let ((miss (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                             "Host: 127.0.0.1"
                                             "Range: bytes=100-110"))))
      (expect-status miss 416)
      (unless (string= (header miss "content-range") "bytes */12")
        (fail "416 ~s" (header miss "content-range"))))
    (let ((coded (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Accept-Encoding: gzip"))))
      (expect-status coded 200)
      (unless (string-equal (header coded "content-encoding") "gzip")
        (fail "coding ~s" (header coded "content-encoding")))
      (unless (search "accept-encoding" (or (header coded "vary") "")
                      :test #'char-equal)
        (fail "vary ~s" (header coded "vary")))
      (let ((etag (or (header coded "etag") (fail "no coded etag"))))
        (unless (char= (char etag 0) #\")
          (fail "coded etag ~s" etag)))
      (unless (string= (babel:octets-to-string
                        (decode-coding (reply-body coded) "gzip")
                        :encoding :utf-8)
                       "static-hello")
        (fail "gzip body")))
    (dolist (pair '(("br" "br") ("zstd" "zstd") ("deflate" "deflate")))
      (let ((reply (exchange port (request-text "GET /files/hello.txt HTTP/1.1"
                                                "Host: 127.0.0.1"
                                                (format nil "Accept-Encoding: ~a" (first pair))))))
        (expect-status reply 200)
        (unless (string-equal (header reply "content-encoding") (second pair))
          (fail "~a coding ~s" (first pair) (header reply "content-encoding")))
        (unless (string= (babel:octets-to-string
                          (decode-coding (reply-body reply) (second pair))
                          :encoding :utf-8)
                         "static-hello")
          (fail "~a body" (first pair)))))
    (multiple-value-bind (version body)
        (curl-version (format nil "http://127.0.0.1:~d/files/wide.txt" port)
                      "--http2-prior-knowledge")
      (unless (string= version "2")
        (fail "http2 version ~s body-prefix ~s" version
              (subseq (or body "") 0 (min 40 (length (or body ""))))))
      (unless (and body (= (length body) 200000)
                   (string= (subseq body 16380 16400) "cdef0123456789abcdef"))
        (fail "http2 static length ~d" (length (or body ""))))))
  (check "static traversal"
    (expect-status (exchange port (request-text "GET /files/../../etc/passwd HTTP/1.1"
                                                "Host: 127.0.0.1"))
                   400))
  (check "connection-specific fields are named"
    ;; RFC 9110 §7.6.1. Fields this response actually sends are listed.
    ;; Fields the origin strips are not sent. The connection stays open.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /hop HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "clean")
                 (fail "body ~s" (body-text reply)))
               (unless (string-equal (header reply "upgrade") "websocket")
                 (fail "upgrade ~s" (header reply "upgrade")))
               (unless (string-equal (header reply "te") "trailers")
                 (fail "te ~s" (header reply "te")))
               (when (header reply "keep-alive")
                 (fail "keep-alive ~s" (header reply "keep-alive")))
               (when (header reply "proxy-connection")
                 (fail "proxy-connection ~s" (header reply "proxy-connection")))
               (when (header reply "transfer-encoding")
                 (fail "transfer-encoding ~s" (header reply "transfer-encoding")))
               (let ((options (connection-options reply)))
                 (unless (and (member "upgrade" options :test #'string=)
                              (member "te" options :test #'string=))
                   (fail "connection ~s" (header reply "connection")))
                 (when (member "close" options :test #'string=)
                   (fail "closed ~s" (header reply "connection")))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after hop ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a connection option is not an end-to-end field"
    ;; RFC 9110 §7.6.1. Fields meant for every recipient are not
    ;; connection options. Cache-Control is the example in that section.
    (let ((reply (exchange port (request-text "GET /hop HTTP/1.1"
                                              "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (string= (body-text reply) "clean")
        (fail "body ~s" (body-text reply)))
      (let ((options (connection-options reply)))
        (unless options
          (fail "no connection field"))
        (dolist (name '("content-type" "content-length" "date" "server"
                        "cache-control" "etag"))
          (when (member name options :test #'string=)
            (fail "~a listed in ~s" name (header reply "connection")))))))
  (check "sse"
    (let ((reply (exchange port (request-text "GET /events HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (search "text/event-stream" (or (header reply "content-type") ""))
        (fail "sse type ~s" (header reply "content-type")))
      (unless (search "hello" (body-text reply))
        (fail "sse ~s" (body-text reply)))))
  (check "a chunked response lists transfer-encoding"
    ;; RFC 9110 §7.6.1. Transfer-Encoding is named in Connection.
    ;; That option is not close, so the next request is answered.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /events HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (search "chunked" (or (header reply "transfer-encoding") "")
                               :test #'char-equal)
                 (fail "transfer-encoding ~s" (header reply "transfer-encoding")))
               (unless (search "hello" (body-text reply))
                 (fail "sse ~s" (body-text reply)))
               (let ((options (connection-options reply)))
                 (unless (member "transfer-encoding" options :test #'string=)
                   (fail "connection ~s" (header reply "connection")))
                 (when (member "close" options :test #'string=)
                   (fail "closed ~s" (header reply "connection")))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after chunked ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /events HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Connection: close"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (let ((options (connection-options reply)))
                 (unless (and (member "close" options :test #'string=)
                              (member "transfer-encoding" options :test #'string=))
                   (fail "connection ~s" (header reply "connection")))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after chunked close" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a chunked response omits content-length"
    ;; RFC 9112 §6.2. Transfer-Encoding and Content-Length are not both sent.
    (let ((reply (exchange port (request-text "GET /events HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (search "chunked" (or (header reply "transfer-encoding") "")
                      :test #'char-equal)
        (fail "transfer-encoding ~s" (header reply "transfer-encoding")))
      (when (header reply "content-length")
        (fail "content-length ~s" (header reply "content-length")))))
  (check "chunked is applied once"
    ;; RFC 9112 §6.1. The chunked transfer coding is applied once, and
    ;; it is the final coding when any transfer coding is applied.
    (let ((reply (exchange port (request-text "GET /events HTTP/1.1" "Host: 127.0.0.1"))))
      (expect-status reply 200)
      (unless (search "hello" (body-text reply))
        (fail "body ~s" (body-text reply)))
      (let ((codings (loop for part in (uiop:split-string
                                        (or (header reply "transfer-encoding") "")
                                        :separator '(#\,))
                           for token = (string-downcase (string-trim '(#\Space #\Tab) part))
                           for semi = (position #\; token)
                           for name = (string-trim '(#\Space #\Tab)
                                                   (if semi (subseq token 0 semi) token))
                           unless (zerop (length name))
                             collect name)))
        (unless (and codings
                     (= (count "chunked" codings :test #'string=) 1)
                     (string= (car (last codings)) "chunked"))
          (fail "transfer-encoding ~s" (header reply "transfer-encoding"))))))
  (response-chunk-size-test port)
  (chunked-no-trailer-test port)
  (check "HTTP/1.0 does not send transfer-encoding"
    ;; RFC 9112 §6.1. The same streaming body is chunked on HTTP/1.1.
    (let ((reply (exchange port (request-text "GET /events HTTP/1.0"))))
      (expect-status reply 200)
      (unless (search "hello" (body-text reply))
        (fail "sse ~s" (body-text reply)))
      (when (header reply "transfer-encoding")
        (fail "transfer-encoding ~s" (header reply "transfer-encoding")))
      (unless (member "close" (connection-options reply) :test #'string=)
        (fail "connection ~s" (header reply "connection")))))
  (check "a 100 response has no message framing fields"
    ;; RFC 9110 §8.6 and RFC 9112 §6.1. 1xx carries neither field.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "POST /echo HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Content-Length: 4"
                                                   "Expect: 100-continue"))
                             stream)
             (finish-output stream)
             (let ((interim (read-reply-headers-only stream)))
               (unless (= (reply-status interim) 100)
                 (fail "status ~d" (reply-status interim)))
               (when (header interim "content-length")
                 (fail "100 content-length ~s" (header interim "content-length")))
               (when (header interim "transfer-encoding")
                 (fail "100 transfer-encoding ~s" (header interim "transfer-encoding"))))
             (write-sequence (octets "echo") stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 200)
               (unless (string= (body-text reply) "echo")
                 (fail "body ~s" (body-text reply)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "an unselected WebSocket subprotocol is omitted"
    ;; RFC 6455 §4.2.2. The server does not agree to chat or mux, so
    ;; neither field is sent. The handshake still completes.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"
                                      "Sec-WebSocket-Protocol: chat"
                                      "Sec-WebSocket-Extensions: mux"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-protocol")
                 (fail "protocol ~s" (header reply "sec-websocket-protocol")))
               (when (header reply "sec-websocket-extensions")
                 (fail "extensions ~s" (header reply "sec-websocket-extensions")))))
        (ignore-errors (usocket:socket-close socket)))))
  (websocket-bad-extension-test port)
  (websocket-empty-extension-test port)
  (websocket-repeated-protocol-test port)
  (websocket-protocol-token-test port)
  (websocket-empty-protocol-test port)
  (check "a 101 response has no message framing fields"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (when (header reply "content-length")
                 (fail "101 content-length ~s" (header reply "content-length")))
               (when (header reply "transfer-encoding")
                 (fail "101 transfer-encoding ~s" (header reply "transfer-encoding")))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a 426 lists upgrade"
    ;; RFC 9110 §§7.6.1 and 15.6.15. Upgrade is named in Connection.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text "GET /ws HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 426)
               (unless (string-equal (header reply "upgrade") "websocket")
                 (fail "upgrade ~s" (header reply "upgrade")))
               (let ((options (connection-options reply)))
                 (unless (member "upgrade" options :test #'string=)
                   (fail "connection ~s" (header reply "connection")))
                 (when (member "close" options :test #'string=)
                   (fail "closed ~s" (header reply "connection")))))
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((second (read-reply stream)))
               (expect-status second 200)
               (unless (string= (body-text second) "pazuzu")
                 (fail "after 426 ~s" (body-text second)))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((reply (exchange port (request-text "GET /ws HTTP/1.0"))))
      (expect-status reply 426)
      (unless (string-equal (header reply "upgrade") "websocket")
        (fail "upgrade ~s" (header reply "upgrade")))
      (let ((options (connection-options reply)))
        (unless (and (member "close" options :test #'string=)
                     (member "upgrade" options :test #'string=))
          (fail "connection ~s" (header reply "connection"))))))
  (check "an unoffered upgrade is not selected"
    ;; RFC 9110 §7.8. The server does not switch to a protocol the
    ;; client did not name. The 426 still offers websocket.
    (let ((reply (exchange port (request-text "GET /ws HTTP/1.1"
                                              "Host: 127.0.0.1"
                                              "Upgrade: IRC/6.9"
                                              "Connection: Upgrade"))))
      (expect-status reply 426)
      (unless (string-equal (header reply "upgrade") "websocket")
        (fail "upgrade ~s" (header reply "upgrade")))
      (when (search "101" (or (reply-status-line reply) ""))
        (fail "switched ~s" (reply-status-line reply)))))
  (check "100-continue precedes 101"
    ;; RFC 9110 §7.8. Expect: 100-continue is a 100 before the 101.
    ;; The 101 names upgrade in Connection. A declared body is not read
    ;; before the 100.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"
                                      "Expect: 100-continue"))
                             stream)
             (finish-output stream)
             (let ((interim (read-reply-headers-only stream)))
               (unless (= (reply-status interim) 100)
                 (fail "interim ~d" (reply-status interim))))
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string-equal (header reply "upgrade") "websocket")
                 (fail "upgrade ~s" (header reply "upgrade")))
               (unless (member "upgrade" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (write-masked-text stream "hi")
             (let ((echo (read-server-text stream)))
               (unless (string= echo "hi")
                 (fail "echo ~s" echo))))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"
                                      "Content-Length: 4"
                                      "Expect: 100-continue"))
                             stream)
             (finish-output stream)
             (let ((interim (read-reply-headers-only stream)))
               (unless (= (reply-status interim) 100)
                 (fail "interim ~d" (reply-status interim))))
             (write-sequence (octets "ping") stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply))))
             (write-masked-text stream "yo")
             (let ((echo (read-server-text stream)))
               (unless (string= echo "yo")
                 (fail "echo ~s" echo))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket echo"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "websocket status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "accept ~s" (header reply "sec-websocket-accept"))))
             (write-masked-text stream "hi")
             (let ((payload (read-server-text stream)))
               (unless (string= payload "hi")
                 (fail "echo ~s" payload))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a repeated WebSocket version is rejected"
    (let ((reply (exchange port (request-text
                                 "GET /ws HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Version: 13"
                                 "Sec-WebSocket-Version: 13"))))
      (expect-status reply 400)
      (unless (string= (header reply "sec-websocket-version") "13")
        (fail "version header ~s" (header reply "sec-websocket-version"))))
    (let ((reply (exchange port (request-text
                                 "GET /ws HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Version: 8"))))
      (expect-status reply 400)
      (unless (string= (header reply "sec-websocket-version") "13")
        (fail "offered version ~s" (header reply "sec-websocket-version")))))
  (check "a WebSocket key must decode to 16 bytes"
    ;; RFC 6455 §4.2.1. A key that is not 16 octets after base64
    ;; decoding is not a handshake, so the server answers 400 and does
    ;; not switch protocols.
    (let ((reply (exchange port (request-text
                                 "GET /ws HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: AAAA"
                                 "Sec-WebSocket-Version: 13"))))
      (expect-status reply 400)
      (when (header reply "sec-websocket-accept")
        (fail "short key accept ~s" (header reply "sec-websocket-accept")))
      (when (string-equal (header reply "upgrade") "websocket")
        (fail "short key upgraded")))
    (let ((reply (exchange port (request-text
                                 "GET /ws HTTP/1.1"
                                 "Host: 127.0.0.1"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                 "Sec-WebSocket-Version: 13"))))
      (expect-status reply 400)
      (when (header reply "sec-websocket-accept")
        (fail "long key accept ~s" (header reply "sec-websocket-accept"))))
    (expect-status (exchange port (request-text
                                   "GET /ws HTTP/1.1"
                                   "Host: 127.0.0.1"
                                   "Upgrade: websocket"
                                   "Connection: Upgrade"
                                   "Sec-WebSocket-Key: ****"
                                   "Sec-WebSocket-Version: 13"))
                   400))
  (websocket-key-grammar-test port)
  (websocket-repeated-key-test port)
  (websocket-accept-once-test port)
  (websocket-missing-service-test port)
  (check "HTTP/1.0 ignores Upgrade"
    (let ((reply (exchange port (request-text
                                 "GET /ws HTTP/1.0"
                                 "Upgrade: websocket"
                                 "Connection: Upgrade"
                                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                                 "Sec-WebSocket-Version: 13"))))
      (unless (= (reply-status reply) 426)
        (fail "upgrade status ~d" (reply-status reply)))))
  (check "websocket ping inside a fragment"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 "ab" :fin nil)
             (write-masked-frame stream 10 "zz")
             (write-masked-frame stream 9 "xy")
             (write-masked-frame stream 0 "cd")
             (multiple-value-bind (opcode payload) (read-server-frame stream)
               (unless (= opcode 10)
                 (fail "pong opcode ~d" opcode))
               (unless (equalp payload (octets "xy"))
                 (fail "pong ~s" payload)))
             (multiple-value-bind (opcode payload) (read-server-frame stream)
               (unless (= opcode 1)
                 (fail "echo opcode ~d" opcode))
               (unless (string= (babel:octets-to-string payload :encoding :utf-8) "abcd")
                 (fail "echo ~s" payload)))
             (expect-ws-close stream 1000))
        (ignore-errors (usocket:socket-close socket)))))
  (websocket-second-message-test port)
  (websocket-pong-frame-test port)
  (websocket-ping-after-close-test port)
  (websocket-binary-opcode-test port)
  (websocket-binary-fragment-test port)
  (check "websocket non-minimal length is 1002"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 "Q" :length-form :16)
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket)))))
  (websocket-minimal-length-test port)
  (websocket-length64-test port)
  (websocket-tcp-close-test port)
  (check "websocket 64-bit length is 1002"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 "Q" :length-form :64)
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket))))
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-length64-high stream 1)
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket)))))
  (websocket-oversized-frame-test port)
  (check "a server close frame is one frame of at most 125 bytes"
    ;; RFC 6455 §5.5. The largest close this server sends is one frame.
    ;; FIN is set, the frame is not masked, and the payload is 125 bytes.
    (multiple-value-bind (socket stream) (ws-open port "/ws-close")
      (unwind-protect
           (let* ((first (read-byte stream))
                  (second (read-byte stream))
                  (nbytes (logand second #x7f)))
             (unless (= (logand first #x80) #x80)
               (fail "fin ~d" first))
             (unless (zerop (logand first #x70))
               (fail "rsv ~d" first))
             (unless (= (logand first #x0f) 8)
               (fail "opcode ~d" first))
             (unless (zerop (logand second #x80))
               (fail "server frame was masked"))
             (unless (= nbytes 125)
               (fail "length ~d" nbytes))
             (let ((payload (read-n stream nbytes)))
               (unless (= (logior (ash (aref payload 0) 8) (aref payload 1)) 1000)
                 (fail "code"))
               (unless (every (lambda (byte) (= byte (char-code #\a)))
                              (subseq payload 2))
                 (fail "reason"))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a server close does not use code 1005"
    ;; RFC 6455 §7.4.1. 1005 is not a status code on a Close frame.
    (multiple-value-bind (socket stream) (ws-open port "/ws-1005")
      (unwind-protect
           (let ((first (read-byte stream nil :eof)))
             (unless (eq first :eof)
               (let ((second (read-byte stream nil :eof)))
                 (unless (or (eq second :eof) (< (logand second #x7f) 2))
                   (let* ((nbytes (logand second #x7f))
                          (payload (if (>= nbytes 126) #() (read-n stream nbytes))))
                     (when (and (= (logand first #x0f) 8)
                                (>= (length payload) 2)
                                (= (logior (ash (aref payload 0) 8)
                                           (aref payload 1))
                                   1005))
                       (fail "sent 1005")))))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a server close does not use code 1006"
    ;; RFC 6455 §7.4.1. 1006 is not a status code on a Close frame.
    (multiple-value-bind (socket stream) (ws-open port "/ws-1006")
      (unwind-protect
           (let ((first (read-byte stream nil :eof)))
             (unless (eq first :eof)
               (let ((second (read-byte stream nil :eof)))
                 (unless (or (eq second :eof) (< (logand second #x7f) 2))
                   (let* ((nbytes (logand second #x7f))
                          (payload (if (>= nbytes 126) #() (read-n stream nbytes))))
                     (when (and (= (logand first #x0f) 8)
                                (>= (length payload) 2)
                                (= (logior (ash (aref payload 0) 8)
                                           (aref payload 1))
                                   1006))
                       (fail "sent 1006")))))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a server close does not use code 1015"
    ;; RFC 6455 §7.4.1. 1015 is not a status code on a Close frame.
    (multiple-value-bind (socket stream) (ws-open port "/ws-1015")
      (unwind-protect
           (let ((first (read-byte stream nil :eof)))
             (unless (eq first :eof)
               (let ((second (read-byte stream nil :eof)))
                 (unless (or (eq second :eof) (< (logand second #x7f) 2))
                   (let* ((nbytes (logand second #x7f))
                          (payload (if (>= nbytes 126) #() (read-n stream nbytes))))
                     (when (and (= (logand first #x0f) 8)
                                (>= (length payload) 2)
                                (= (logior (ash (aref payload 0) 8)
                                           (aref payload 1))
                                   1015))
                       (fail "sent 1015")))))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a server sends no data frame after close"
    ;; RFC 6455 §5.5.1. A Close frame is the last data the application sends.
    (multiple-value-bind (socket stream) (ws-open port "/ws-after-close")
      (unwind-protect
           (progn
             (multiple-value-bind (opcode payload) (read-server-frame stream)
               (declare (ignore payload))
               (unless (= opcode 8)
                 (fail "opcode ~d" opcode)))
             (let ((next (handler-case
                             (sb-sys:with-deadline (:seconds 2)
                               (read-byte stream nil :eof))
                           (sb-sys:deadline-timeout () :open)
                           (error () :eof))))
               (when (and (integerp next)
                          (member (logand next #x0f) '(1 2)))
                 (fail "data opcode ~d" (logand next #x0f)))))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket bad control frame is 1002"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 9
                                 (make-array 126 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                                 :length-form :16)
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket))))
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 9 "" :fin nil)
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket one-byte close is 1002"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 8 #(9))
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket non-utf-8 close reason is 1007"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 8 #(3 #xE8 #xFF))
             (expect-ws-close stream 1007))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a WebSocket text message must be UTF-8"
    ;; RFC 6455 §§5.6 and 8.1. One fragment may hold a partial sequence.
    ;; The reassembled message must be UTF-8, or the connection fails.
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 #(#xFF))
             (expect-ws-close stream 1007)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "connection stayed open")))
        (ignore-errors (usocket:socket-close socket))))
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 #(#xC3) :fin nil)
             (write-masked-frame stream 0 #(#xA9))
             (unless (string= (read-server-text stream)
                              (string (code-char #xE9)))
               (fail "split utf-8 was not echoed")))
        (ignore-errors (usocket:socket-close socket))))
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 #(#xC3) :fin nil)
             (write-masked-frame stream 0 #(#x20))
             (expect-ws-close stream 1007)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "split connection stayed open")))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket forbidden close code is 1002"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 8 #(3 #xED))
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket echoes a close code"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 8 (concatenate '(vector (unsigned-byte 8))
                                                       #(3 #xE9) (octets "bye")))
             (expect-ws-close stream 1001)
             ;; RFC 6455 §7.1.1. After the closing handshake, TCP ends.
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "connection stayed open")))
        (ignore-errors (usocket:socket-close socket)))))
  (check "websocket interleaved message is 1002"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 "a" :fin nil)
             (write-masked-frame stream 1 "b")
             (expect-ws-close stream 1002))
        (ignore-errors (usocket:socket-close socket)))))
  (check "an unmasked client frame closes the connection"
    ;; RFC 6455 §5.1. A client frame without the mask bit is a close.
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-byte #x81 stream)
             (write-byte 2 stream)
             (write-sequence (octets "hi") stream)
             (finish-output stream)
             (expect-ws-close stream 1002)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "connection stayed open")))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a failed WebSocket does not answer a later close"
    ;; RFC 6455 §7.1.7. Fail the WebSocket Connection stops processing,
    ;; including a Close frame that follows the failing frame. Code 4000
    ;; would be echoed if that Close were handled.
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-sequence (concatenate '(simple-array (unsigned-byte 8) (*))
                                             #(#x81 2) (octets "hi")
                                             #(#x88 #x82 1 2 3 4 #x0E #xA2))
                             stream)
             (finish-output stream)
             (expect-ws-close stream 1002)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "answered the close after failure")))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a reserved WebSocket bit closes the connection"
    ;; RFC 6455 §5.2. RSV1 with no extension fails the connection.
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-byte #xC1 stream)
             (write-byte (logior #x80 1) stream)
             (write-sequence #(1 2 3 4) stream)
             (write-byte (logxor (char-code #\Q) 1) stream)
             (finish-output stream)
             (expect-ws-close stream 1002)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "connection stayed open")))
        (ignore-errors (usocket:socket-close socket)))))
  (check "an unknown WebSocket opcode closes the connection"
    ;; RFC 6455 §5.2. Opcode 3 is reserved for a future data frame.
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 3 "Q")
             (expect-ws-close stream 1002)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "connection stayed open")))
        (ignore-errors (usocket:socket-close socket)))))
  (check "a reserved WebSocket control opcode closes the connection"
    ;; RFC 6455 §5.2. Opcode 0xB is reserved for a future control frame.
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream #xB "Q")
             (expect-ws-close stream 1002)
             (unless (eq (read-byte stream nil :eof) :eof)
               (fail "connection stayed open")))
        (ignore-errors (usocket:socket-close socket))))))

(defclass byte-source (sb-gray:fundamental-binary-input-stream)
  ((data :initarg :data :reader byte-source-data)
   (pos :initform 0 :accessor byte-source-pos)
   (fills :initform 0 :accessor byte-source-fills)))

(defmethod stream-element-type ((stream byte-source))
  '(unsigned-byte 8))

(defmethod sb-gray:stream-read-byte ((stream byte-source))
  (incf (byte-source-fills stream))
  (if (< (byte-source-pos stream) (length (byte-source-data stream)))
      (prog1 (aref (byte-source-data stream) (byte-source-pos stream))
        (incf (byte-source-pos stream)))
      :eof))

(defmethod sb-gray:stream-listen ((stream byte-source))
  (< (byte-source-pos stream) (length (byte-source-data stream))))

(defmethod sb-gray:stream-read-sequence ((stream byte-source) sequence
                                         &optional (start 0) end)
  (incf (byte-source-fills stream))
  (let ((end (or end (length sequence)))
        (data (byte-source-data stream)))
    (loop while (and (< start end)
                     (< (byte-source-pos stream) (length data)))
          do (setf (aref sequence start) (aref data (byte-source-pos stream)))
             (incf start)
             (incf (byte-source-pos stream)))
    start))

(defun request-path-tests (server)
  "TCP_NODELAY, one static stat per dispatch, and header bytes that cross a read buffer."
  (check "header bytes that cross the read buffer stay in order"
    (let* ((line-2 (make-string 250 :initial-element #\b))
           ;; 7990 octets, CRLF, then a line that begins in the first
           ;; 8192-octet refill and ends in the next one.
           (mark (+ 7990 2))
           (data (make-array (+ mark (length line-2) 2 3)
                             :element-type '(unsigned-byte 8)
                             :initial-element 65))
           (source (make-instance 'byte-source :data data))
           (pazuzu::*read-ahead* (pazuzu::make-read-ahead))
           (stream source))
      (setf (aref data 7990) 13
            (aref data 7991) 10)
      (replace data (pazuzu::ascii-octets (format nil "~a~c~c" line-2 #\Return #\Newline))
               :start1 mark)
      (replace data (pazuzu::ascii-octets "xyz")
               :start1 (+ mark (length line-2) 2))
      (let ((first (pazuzu::read-crlf-line stream 8000)))
        (unless (= (length first) 7990)
          (fail "first line length ~d" (length first))))
      (let ((second (pazuzu::read-crlf-line stream 8000)))
        (unless (string= second line-2)
          (fail "second line ~s" second)))
      (let ((body (pazuzu::read-exact stream 3)))
        (unless (equalp body (pazuzu::ascii-octets "xyz"))
          (fail "body ~s" body)))
      ;; listen is true for the whole vector, so each refill drains it
      ;; and every octet is read once.
      (unless (= (byte-source-fills source) (length data))
        (fail "inner reads ~d" (byte-source-fills source)))))
  (check "one open for a static file in one dispatch"
    (let ((pazuzu::*static-stat-calls* 0)
          (pazuzu::*file-stat-cache* (make-hash-table :test #'equal))
          (request (pazuzu::make-request :method "GET"
                                         :path "/files/hello.txt"
                                         :target "/files/hello.txt")))
      (pazuzu::static-validator #p"/tmp/pazuzu-static/" "/files" request)
      (let ((response (pazuzu::static-response #p"/tmp/pazuzu-static/" "/files" request)))
        (unless (= (pazuzu:response-status response) 200)
          (fail "status ~d" (pazuzu:response-status response))))
      (unless (= pazuzu::*static-stat-calls* 1)
        (fail "stat calls ~d" pazuzu::*static-stat-calls*))))
  (let ((port (pazuzu::server-port server)))
    (check "accepted HTTP/1 socket sets TCP_NODELAY"
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                               stream)
               (finish-output stream)
               (expect-status (read-reply stream) 200)
               (let ((clients (bt:with-lock-held ((pazuzu::server-lock server))
                                (copy-list (pazuzu::server-clients server)))))
                 (unless clients
                   (fail "no accepted client"))
                 (unless (every (lambda (client)
                                  (pazuzu::tcp-nodelay-p (pazuzu::usocket-fd client)))
                                clients)
                   (fail "TCP_NODELAY is off"))))
          (ignore-errors (usocket:socket-close socket)))))))

