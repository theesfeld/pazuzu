(in-package #:pazuzu)

(defun header-value (headers name)
  (cdr (assoc name headers :test #'string-equal)))

(defun header-values (headers name)
  (loop for (key . value) in headers
        when (string-equal key name)
          collect value))

(defun collapse-cookie-fields (headers)
  "RFC 9113 §8.2.3 and RFC 9114 §4.2.1. Several Cookie lines become one
field. The pairs stay in the order they arrived and are joined by \"; \"."
  (let ((cookies (loop for pair in headers
                       when (string-equal (car pair) "cookie")
                         collect (cdr pair))))
    (if (null (rest cookies))
        headers
        (let ((emitted nil)
              (joined (format nil "~{~a~^; ~}" cookies))
              (out nil))
          (dolist (pair headers)
            (cond ((string-equal (car pair) "cookie")
                   (unless emitted
                     (setf emitted t)
                     (push (cons "cookie" joined) out)))
                  (t (push pair out))))
          (nreverse out)))))

(defparameter *forbidden-trailer-fields*
  '("transfer-encoding" "content-length" "host" "cache-control" "max-forwards"
    "te" "authorization" "set-cookie" "age" "expires" "location"
    "content-encoding" "content-type" "content-range" "trailer")
  "RFC 9110 §6.5. These fields are ignored when they arrive as trailers.")

(defun retain-trailer-fields (trailers)
  "Drop trailer fields the recipient must ignore (RFC 9110 §6.5)."
  (remove-if (lambda (pair)
               (member (car pair) *forbidden-trailer-fields* :test #'string-equal))
             trailers))

(defun header-list-value (headers name)
  "Join every line of a list-based field with a comma, in list order
(RFC 9110 §5.2). NIL when the field is absent."
  (let ((values (header-values headers name)))
    (when values
      (format nil "~{~a~^, ~}" values))))

(defun single-date-field (headers name)
  "The sole line of a single-date field, or NIL when it is absent or
repeated. If-Modified-Since and If-Unmodified-Since are not lists
(RFC 9110 §§13.1.3 and 13.1.4)."
  (let ((values (header-values headers name)))
    (when (and values (null (rest values)))
      (first values))))

(defparameter *singleton-response-fields*
  '("age" "content-length"
    "content-location" "content-range" "content-type" "date" "etag"
    "expires" "last-modified" "location" "retry-after" "server")
  "Fields that are not comma-separated lists. One line is sent.
Set-Cookie is the exception that stays on multiple lines (RFC 9110 §5.2).
Content-Encoding and Content-Language are lists and are joined instead.")

(defun collapse-singleton-fields (headers)
  "RFC 9110 §5.2. A field that is not a list keeps its first line.
A list field keeps every line, joined by comma SP in the order received."
  (let ((seen nil)
        (out nil))
    (dolist (pair headers)
      (let ((name (car pair)))
        (cond ((and (stringp name)
                    (member name *list-response-fields* :test #'string-equal))
               (unless (member name seen :test #'string-equal)
                 (push name seen)
                 (push (cons name
                             (format nil "~{~a~^, ~}"
                                     (loop for (key . value) in headers
                                           when (and (stringp key)
                                                     (string-equal key name)
                                                     (stringp value))
                                             collect value)))
                       out)))
              ((and (stringp name)
                    (member name *singleton-response-fields* :test #'string-equal))
               (unless (member name seen :test #'string-equal)
                 (push name seen)
                 (push pair out)))
              (t (push pair out)))))
    (nreverse out)))

(defun add-header (headers name value)
  (acons name value headers))

(defun remove-headers (headers &rest names)
  (remove-if (lambda (pair) (member (car pair) names :test #'string-equal))
             headers))

(defun field-value-ok-p (value)
  (every (lambda (character)
           (let ((code (char-code character)))
             (or (eql character #\Tab)
                 (<= 32 code 126)
                 (<= 128 code 255))))
         value))

(defun http-field-value-malformed-p (value)
  "RFC 9113 §8.2.1, which RFC 9114 also requires. CR, LF, NUL, or a value
that starts or ends with SP or HTAB."
  (when (and (plusp (length value))
             (let ((first (char value 0))
                   (last (char value (1- (length value)))))
               (or (eql first #\Space) (eql first #\Tab)
                   (eql last #\Space) (eql last #\Tab))))
    (return-from http-field-value-malformed-p t))
  (find-if (lambda (character)
             (let ((code (char-code character)))
               (or (zerop code) (= code 10) (= code 13))))
           value))

(defun parse-field-line (line)
  (when (or (zerop (length line))
            (char= (char line 0) #\Space)
            (char= (char line 0) #\Tab))
    (protocol-error 400 :detail "obsolete line folding"))
  (let ((colon (position #\: line)))
    (unless colon
      (protocol-error 400 :detail "header without colon"))
    (let ((name (subseq line 0 colon)))
      (when (or (zerop (length name))
                (find #\Space name)
                (find #\Tab name))
        ;; Whitespace before the colon is a request-smuggling vector.
        (protocol-error 400 :detail "whitespace in field name"))
      (unless (token-string-p name)
        (protocol-error 400 :detail "bad field name"))
      (let ((value (string-trim '(#\Space #\Tab) (subseq line (1+ colon)))))
        (unless (field-value-ok-p value)
          (protocol-error 400 :detail "bad field value"))
        (cons (string-downcase name) value)))))

(defun read-header-section (stream)
  (let ((headers nil)
        (bytes 0)
        (count 0))
    (loop for line = (read-crlf-line stream +max-request-line+)
          until (zerop (length line))
          do (incf bytes (+ (length line) 2))
             (incf count)
             (when (or (> count +max-header-fields+)
                       (> bytes +max-header-bytes+))
               (protocol-error 431 :detail "headers too large"))
             (push (parse-field-line line) headers))
    (nreverse headers)))

(defun split-list-elements (value &key escape (separator #\,))
  "Split on SEPARATOR when it is not inside a double-quoted string.
Empty members are dropped. The second value is how many empty members
were dropped. ESCAPE is for quoted-string list fields: a backslash
inside quotes is a quoted-pair, and parentheses outside quotes are
comments (RFC 9110 §§5.6.1, 5.6.4, and 5.6.5). Entity-tags have no
quoted-pair, so they pass ESCAPE nil (RFC 9110 §8.8.3)."
  (let ((elements nil)
        (empty 0)
        (start 0)
        (index 0)
        (end (length value))
        (in-quote nil)
        (comment 0))
    (loop while (< index end)
          do (let ((character (char value index)))
               (cond
                 ((and escape (not in-quote) (char= character #\())
                  (incf comment)
                  (incf index))
                 ((and escape (not in-quote) (plusp comment) (char= character #\)))
                  (decf comment)
                  (incf index))
                 ((and escape
                       (or in-quote (plusp comment))
                       (char= character #\\))
                  (incf index (if (< (1+ index) end) 2 1)))
                 ((and (zerop comment) (char= character #\"))
                  (setf in-quote (not in-quote))
                  (incf index))
                 ((and (not in-quote) (zerop comment) (char= character separator))
                  (let ((piece (string-trim '(#\Space #\Tab)
                                            (subseq value start index))))
                    (if (zerop (length piece))
                        (incf empty)
                        (push piece elements)))
                  (incf index)
                  (setf start index))
                 (t (incf index)))))
    (let ((piece (string-trim '(#\Space #\Tab) (subseq value start))))
      (if (zerop (length piece))
          (incf empty)
          (push piece elements)))
    (values (nreverse elements) empty)))

(defun split-commas (value)
  "RFC 9110 §5.6.1. Empty members are ignored. A comma inside a
quoted-string or a comment is not a separator. The second value is how
many empty members were dropped."
  (split-list-elements value :escape t))

(defparameter *list-response-fields*
  '("accept-encoding" "accept-language" "accept-ranges" "allow"
    "cache-control" "connection" "content-encoding" "content-language"
    "proxy-authenticate" "te" "trailer" "transfer-encoding" "upgrade"
    "vary" "via" "www-authenticate")
  "List fields this origin sends. RFC 9110 §5.6.1.1.")

(defun limit-qvalue-digits (value)
  "RFC 9110 §12.4.2. A weight is \";\" OWS \"q=\" qvalue, and a sender
emits at most three digits after the decimal point. A qvalue inside a
quoted-string is left unchanged. Further fraction digits are dropped."
  (unless (and (stringp value) (position #\q value :test #'char-equal))
    (return-from limit-qvalue-digits value))
  (with-output-to-string (out)
    (let ((quoted nil)
          (index 0)
          (length (length value)))
      (loop while (< index length)
            do (let ((ch (char value index)))
                 (cond ((and quoted (char= ch #\\) (< (1+ index) length))
                        (write-char ch out)
                        (write-char (char value (1+ index)) out)
                        (incf index 2))
                       ((char= ch #\")
                        (write-char ch out)
                        (setf quoted (not quoted))
                        (incf index))
                       (quoted
                        (write-char ch out)
                        (incf index))
                       ((char= ch #\;)
                        (write-char ch out)
                        (incf index)
                        (let ((scan index))
                          (loop while (and (< scan length)
                                           (or (char= (char value scan) #\Space)
                                               (char= (char value scan) #\Tab)))
                                do (incf scan))
                          (when (and (< (+ scan 2) length)
                                     (char-equal (char value scan) #\q)
                                     (char= (char value (1+ scan)) #\=)
                                     (or (char= (char value (+ scan 2)) #\0)
                                         (char= (char value (+ scan 2)) #\1)))
                            (loop while (< index scan)
                                  do (write-char (char value index) out)
                                     (incf index))
                            (write-char (char value index) out)
                            (write-char #\= out)
                            (incf index 2)
                            (write-char (char value index) out)
                            (incf index)
                            (when (and (< index length)
                                       (char= (char value index) #\.))
                              (write-char #\. out)
                              (incf index)
                              (let ((digits 0))
                                (loop while (and (< index length)
                                                 (digit-char-p (char value index)))
                                      do (when (< digits 3)
                                           (write-char (char value index) out))
                                         (incf digits)
                                         (incf index)))))))
                       (t
                        (write-char ch out)
                        (incf index))))))))

(defun limit-qvalue-fields (headers)
  (loop for pair in headers
        collect (if (stringp (cdr pair))
                    (cons (car pair) (limit-qvalue-digits (cdr pair)))
                    pair)))

(defun omit-empty-list-members (headers)
  "RFC 9110 §5.6.1.1. A list field is not sent with an empty member.
A comma inside a quoted-string or a comment stays. A value with no
empty member is left unchanged. A list that is only empty members is
omitted. A field that is not a list is unchanged."
  (let ((out nil))
    (dolist (pair headers)
      (let ((name (car pair))
            (value (cdr pair)))
        (cond ((and (stringp name) (stringp value)
                    (member name *list-response-fields* :test #'string-equal))
               (multiple-value-bind (members empty) (split-commas value)
                 (cond ((zerop empty) (push pair out))
                       (members
                        (push (cons name (format nil "~{~a~^, ~}" members)) out)))))
              (t (push pair out)))))
    (nreverse out)))

(defun reason-phrase (status)
  (case status
    (100 "Continue")
    (101 "Switching Protocols")
    (200 "OK")
    (201 "Created")
    (202 "Accepted")
    (204 "No Content")
    (205 "Reset Content")
    (206 "Partial Content")
    (301 "Moved Permanently")
    (302 "Found")
    (303 "See Other")
    (304 "Not Modified")
    (307 "Temporary Redirect")
    (308 "Permanent Redirect")
    (400 "Bad Request")
    (401 "Unauthorized")
    (403 "Forbidden")
    (404 "Not Found")
    (405 "Method Not Allowed")
    (406 "Not Acceptable")
    (408 "Request Timeout")
    (409 "Conflict")
    (411 "Length Required")
    (412 "Precondition Failed")
    (413 "Content Too Large")
    (414 "URI Too Long")
    (415 "Unsupported Media Type")
    (416 "Range Not Satisfiable")
    (417 "Expectation Failed")
    (421 "Misdirected Request")
    (426 "Upgrade Required")
    (428 "Precondition Required")
    (431 "Request Header Fields Too Large")
    (500 "Internal Server Error")
    (501 "Not Implemented")
    (502 "Bad Gateway")
    (503 "Service Unavailable")
    (505 "HTTP Version Not Supported")
    (t (cond ((<= 100 status 199) "Informational")
             ((<= 200 status 299) "OK")
             ((<= 300 status 399) "Redirect")
             ((<= 400 status 499) "Client Error")
             ((<= 500 status 599) "Server Error")
             (t "Status")))))

(defparameter *recognized-methods*
  '("GET" "HEAD" "POST" "PUT" "DELETE" "CONNECT" "OPTIONS" "TRACE" "PATCH")
  "Methods this origin recognizes. Unlisted tokens are answered with 501.")

(defparameter *implemented-methods*
  '("GET" "HEAD" "POST" "PUT" "DELETE" "OPTIONS" "PATCH")
  "Methods this origin can perform. CONNECT and TRACE are recognized but not implemented.")

(defun recognized-method-p (method)
  (member method *recognized-methods* :test #'string=))

(defun implemented-method-p (method)
  (member method *implemented-methods* :test #'string=))

(defun continue-expectation (headers)
  "RFC 9110 §10.1.1. T when every Expect member is 100-continue.
NIL when the field is absent. Any other member is 417."
  (let ((expect (header-list-value headers "expect")))
    (when expect
      (let ((parts (split-commas expect)))
        (unless (and parts
                     (every (lambda (part) (string-equal part "100-continue")) parts))
          (protocol-error 417 :detail "expect"))
        t))))
