(in-package #:pazuzu)

(defstruct request
  method
  target
  path
  query
  (http-version 11)
  headers
  trailers
  body
  host
  (scheme "http")
  (peer "")
  transformed)

(defun request-header (request name)
  (header-value (request-headers request) name))

(defstruct (response (:copier nil))
  (status 200)
  headers
  body
  content-type
  etag
  last-modified
  cache-control
  representations
  language)

(defun text-response (text &key (status 200) (content-type "text/plain; charset=utf-8") headers etag)
  (make-response :status status :body text :content-type content-type
                 :headers headers :etag etag))

(defun octet-response (octets &key (status 200) (content-type "application/octet-stream") headers etag)
  (make-response :status status :body octets :content-type content-type
                 :headers headers :etag etag))

(defun empty-response (status &key headers)
  (make-response :status status :headers headers :body nil))

(defun redirect-response (location &key (status 302))
  (make-response :status status :headers `(("location" . ,location)) :body nil))

(defun copy-response (response)
  (make-response :status (response-status response)
                 :headers (copy-tree (response-headers response))
                 :body (response-body response)
                 :content-type (response-content-type response)
                 :etag (response-etag response)
                 :last-modified (response-last-modified response)
                 :cache-control (response-cache-control response)
                 :representations (response-representations response)
                 :language (response-language response)))

(defun http-version-token-p (text)
  "RFC 9112 HTTP-version: HTTP/ digit \".\" digit. The name is case-sensitive."
  (and (= (length text) 8)
       (string= text "HTTP/" :end1 5)
       (digit-char-p (char text 5))
       (char= (char text 6) #\.)
       (digit-char-p (char text 7))))

(defun parse-version (text)
  "Return 10 or 11. A higher HTTP/1 minor is served as HTTP/1.1.
Another major version is 505. A version that is not HTTP/x.y is 400
(RFC 9112 §2.3)."
  (cond ((not (http-version-token-p text))
         (if (and (>= (length text) 5) (string= text "HTTP/" :end1 5))
             (protocol-error 505 :detail text)
             (protocol-error 400 :detail "bad version")))
        ((char/= (char text 5) #\1)
         (protocol-error 505 :detail text))
        ((char= (char text 7) #\0) 10)
        (t 11)))

(defun split-request-line (line)
  (let* ((first-space (position #\Space line))
         (last-space (position #\Space line :from-end t)))
    (unless (and first-space last-space (> last-space first-space)
                 (not (find #\Space line :start (1+ first-space) :end last-space)))
      (protocol-error 400 :detail "bad request line"))
    (values (subseq line 0 first-space)
            (subseq line (1+ first-space) last-space)
            (subseq line (1+ last-space)))))

(defun ascii-alpha-p (character)
  (or (char<= #\A character #\Z)
      (char<= #\a character #\z)))

(defun h16-p (text)
  (and (<= 1 (length text) 4)
       (every (lambda (character) (digit-char-p character 16)) text)))

(defun dec-octet-p (text)
  "RFC 3986 dec-octet. A leading zero is only the single digit 0."
  (and (<= 1 (length text) 3)
       (every #'digit-char-p text)
       (or (= (length text) 1)
           (char/= (char text 0) #\0))
       (<= (parse-integer text) 255)))

(defun ipv4-address-p (text)
  (let ((pieces (uiop:split-string text :separator '(#\.))))
    (and (= (length pieces) 4)
         (every #'dec-octet-p pieces))))

(defun count-h16s (text)
  "h16 pieces separated by one colon, or NIL. Empty TEXT is zero pieces."
  (if (zerop (length text))
      0
      (let ((pieces (uiop:split-string text :separator '(#\:))))
        (when (every #'h16-p pieces)
          (length pieces)))))

(defun count-ipv6-groups (text)
  "16-bit groups in one side of an IPv6 address, or NIL.
The last piece may be an IPv4 address, which counts as two groups."
  (if (zerop (length text))
      0
      (let ((pieces (uiop:split-string text :separator '(#\:))))
        (unless (some (lambda (piece) (zerop (length piece))) pieces)
          (let ((last (car (last pieces)))
                (heads (butlast pieces)))
            (when (every #'h16-p heads)
              (cond ((find #\. last)
                     (when (ipv4-address-p last)
                       (+ (length heads) 2)))
                    ((h16-p last)
                     (1+ (length heads))))))))))

(defun ipv6-address-p (text)
  "RFC 3986 IPv6address. A '::' stands for one or more 16-bit groups."
  (let ((mark (search "::" text)))
    (cond ((null mark)
           (eql (count-ipv6-groups text) 8))
          ((search "::" text :start2 (+ mark 2))
           nil)
          (t
           (let ((left (count-h16s (subseq text 0 mark)))
                 (right (count-ipv6-groups (subseq text (+ mark 2)))))
             (and left right (< (+ left right) 8)))))))

(defun ipv-future-tail-p (character)
  (or (ascii-alpha-p character)
      (digit-char-p character)
      (find character "-._~!$&'()*+,;=:" :test #'char=)))

(defun ipv-future-p (text)
  "RFC 3986 IPvFuture. The version marker is case-insensitive."
  (and (>= (length text) 4)
       (char-equal (char text 0) #\v)
       (let ((dot (position #\. text :start 1)))
         (and dot
              (> dot 1)
              (every (lambda (character) (digit-char-p character 16))
                     (subseq text 1 dot))
              (< (1+ dot) (length text))
              (every #'ipv-future-tail-p (subseq text (1+ dot)))))))

(defun ip-literal-p (text)
  (or (ipv6-address-p text) (ipv-future-p text)))

(defun reg-name-char-p (character)
  (or (ascii-alpha-p character)
      (digit-char-p character)
      (find character "-._~!$&'()*+,;=" :test #'char=)))

(defun reg-name-p (text)
  "RFC 3986 reg-name. A percent starts a two-digit hex encoding."
  (when (zerop (length text))
    (return-from reg-name-p nil))
  (loop for index = 0 then next
        while (< index (length text))
        for next = (let ((character (char text index)))
                     (cond ((char= character #\%)
                            (unless (and (<= (+ index 3) (length text))
                                         (digit-char-p (char text (+ index 1)) 16)
                                         (digit-char-p (char text (+ index 2)) 16))
                              (return-from reg-name-p nil))
                            (+ index 3))
                           ((reg-name-char-p character)
                            (1+ index))
                           (t (return-from reg-name-p nil))))
        finally (return t)))

(defun valid-port-p (text)
  "RFC 3986 port: digits, at most 65535. An empty port is allowed."
  (or (zerop (length text))
      (and (<= (length text) 5)
           (every #'digit-char-p text)
           (<= (parse-integer text) 65535))))

(defun valid-host-p (host)
  "uri-host and an optional port (RFC 3986 §3.2.2, RFC 9110 §7.2).
No userinfo. A bracketed host is an IPv6 address or an IPvFuture."
  (when (or (zerop (length host)) (find #\@ host) (find #\Space host))
    (return-from valid-host-p nil))
  (if (char= (char host 0) #\[)
      (let ((close (position #\] host)))
        (and close
             (> close 1)
             (ip-literal-p (subseq host 1 close))
             (or (= close (1- (length host)))
                 (and (< (1+ close) (length host))
                      (char= (char host (1+ close)) #\:)
                      (valid-port-p (subseq host (+ close 2)))))))
      (let ((colon (position #\: host :from-end t)))
        (if (and colon (not (find #\: host :end colon)))
            (and (valid-port-p (subseq host (1+ colon)))
                 (reg-name-p (subseq host 0 colon)))
            (reg-name-p host)))))

(defun split-authority (authority)
  "Return (values host port-text). HOST is downcased and keeps IPv6 brackets.
PORT-TEXT is NIL when the authority omits the port."
  (let ((text (string-trim '(#\Space #\Tab) (or authority ""))))
    (when (zerop (length text))
      (return-from split-authority (values nil nil)))
    (if (char= (char text 0) #\[)
        (let ((close (position #\] text)))
          (unless (and close (< close (length text)))
            (return-from split-authority (values nil nil)))
          (let ((host (string-downcase (subseq text 0 (1+ close))))
                (rest (subseq text (1+ close))))
            (cond ((zerop (length rest)) (values host nil))
                  ((char= (char rest 0) #\:)
                   (values host (subseq rest 1)))
                  (t (values nil nil)))))
        (let ((colon (position #\: text)))
          (if (and colon (not (find #\: text :start (1+ colon))))
              (values (string-downcase (subseq text 0 colon))
                      (subseq text (1+ colon)))
              (values (string-downcase text) nil))))))

(defun connect-authority-ok-p (authority)
  "RFC 9110 §9.3.6. A CONNECT target is a host and a port. The port is
present and is a decimal from 0 through 65535. There is no default."
  (when (stringp authority)
    (multiple-value-bind (host port) (split-authority authority)
      (and host (plusp (length host))
           (stringp port) (plusp (length port))
           (valid-port-p port)))))

(defun authority-port (port scheme)
  "Numeric port, or the scheme default when PORT is omitted or empty."
  (cond ((or (null port) (zerop (length port)))
         (cond ((string-equal scheme "http") 80)
               ((string-equal scheme "https") 443)))
        ((and (plusp (length port))
              (<= (length port) 5)
              (every #'digit-char-p port))
         (let ((number (parse-integer port)))
           (when (<= 0 number 65535) number)))))

(defun authorities-match-p (left right scheme)
  "RFC 9113 §8.3.1. The same entity after host case-folding and default-port
elision. An explicit port and an omitted port match when the number is the
scheme default."
  (multiple-value-bind (host-a port-a) (split-authority left)
    (multiple-value-bind (host-b port-b) (split-authority right)
      (let ((a (authority-port port-a scheme))
            (b (authority-port port-b scheme)))
        (and host-a host-b (plusp (length host-a)) (plusp (length host-b))
             (string= host-a host-b)
             a b (= a b))))))

(defun reject-authority-host (authority headers scheme)
  "RFC 9113 §8.3.1. :authority selects the target. A Host field is malformed
when it is repeated or names a different entity."
  (let ((hosts (header-values headers "host")))
    (when (rest hosts)
      (protocol-error 400 :detail "duplicate host"))
    (when (and hosts
               (or (not (valid-host-p (first hosts)))
                   (not (authorities-match-p authority (first hosts) scheme))))
      (protocol-error 400 :detail "host"))))

(defun parse-absolute-form (target)
  "Return (values scheme host path query) or signal 400."
  (let* ((marker (search "://" target))
         (scheme (and marker (>= marker 1) (subseq target 0 marker))))
    (unless (and scheme (member scheme '("http" "https") :test #'string-equal))
      (protocol-error 400 :detail "bad absolute-form"))
    (let* ((rest (subseq target (+ marker 3)))
           (slash (position #\/ rest))
           (authority (if slash (subseq rest 0 slash) rest))
           (path-and-query (if slash (subseq rest slash) "/"))
           (qmark (position #\? path-and-query)))
      (when (or (zerop (length authority)) (find #\@ authority))
        (protocol-error 400 :detail "bad authority"))
      (unless (valid-host-p authority)
        (protocol-error 400 :detail "bad absolute-form host"))
      (values (string-downcase scheme)
              authority
              (if qmark (subseq path-and-query 0 qmark) path-and-query)
              (and qmark (subseq path-and-query (1+ qmark)))))))

(defun decode-percent (text)
  (let ((out (make-array (length text) :element-type 'character :fill-pointer 0)))
    (loop for index = 0 then next
          while (< index (length text))
          for next = (1+ index)
          do (let ((character (char text index)))
               (cond ((char= character #\%)
                      (unless (<= (+ index 2) (1- (length text)))
                        (protocol-error 400 :detail "bad percent-encoding"))
                      (let ((hi (digit-char-p (char text (1+ index)) 16))
                            (lo (digit-char-p (char text (+ index 2)) 16)))
                        (unless (and hi lo)
                          (protocol-error 400 :detail "bad percent-encoding"))
                        (let ((code (+ (* hi 16) lo)))
                          (when (zerop code)
                            (protocol-error 400 :detail "encoded NUL"))
                          (vector-push (code-char code) out)
                          (incf next 2))))
                     ((or (char= character #\Nul) (char= character #\Return) (char= character #\Newline))
                      (protocol-error 400 :detail "illegal path character"))
                     (t (vector-push character out)))))
    out))

(defun normalize-path (raw-path)
  "Decode each segment. Reject encoded slashes, backslashes, and paths that climb above the root."
  (unless (and (plusp (length raw-path)) (char= (char raw-path 0) #\/))
    (protocol-error 400 :detail "path must be origin-form"))
  (let ((segments nil))
    (dolist (piece (uiop:split-string raw-path :separator '(#\/)))
      (let ((decoded (decode-percent piece)))
        (cond ((or (string= decoded "") (string= decoded "."))
               nil)
              ((string= decoded "..")
               (if segments
                   (pop segments)
                   (protocol-error 400 :detail "path escapes root")))
              (t
               (when (or (find #\/ decoded) (find #\\ decoded) (find #\Nul decoded))
                 (protocol-error 400 :detail "encoded separator"))
               (push decoded segments)))))
    (if segments
        (with-output-to-string (out)
          (dolist (segment (nreverse segments))
            (write-char #\/ out)
            (write-string segment out)))
        "/")))

(defun reject-fragment (target)
  "origin-form and :path are absolute-path and an optional query.
A fragment delimiter is not part of either (RFC 9112 §3.2, RFC 9113 §8.3.1)."
  (when (and target (find #\# target))
    (protocol-error 400 :detail "fragment")))

(defun classify-target (method target)
  "Return (values form path query absolute-host absolute-scheme).
FORM is :origin, :absolute, :authority, or :asterisk."
  (reject-fragment target)
  (cond ((string= target "*")
         (unless (string= method "OPTIONS")
           (protocol-error 400 :detail "asterisk-form is only valid for OPTIONS"))
         (values :asterisk "/" nil nil nil))
        ((and (>= (length target) 1) (char= (char target 0) #\/))
         (let ((qmark (position #\? target)))
           (values :origin
                   (if qmark (subseq target 0 qmark) target)
                   (and qmark (subseq target (1+ qmark)))
                   nil nil)))
        ((search "://" target)
         (multiple-value-bind (scheme host path query) (parse-absolute-form target)
           (values :absolute path query host scheme)))
        ((string= method "CONNECT")
         ;; RFC 9110 §9.3.6. No default port. An empty or invalid port is 400.
         (unless (and (valid-host-p target)
                      (connect-authority-ok-p target))
           (protocol-error 400 :detail "bad authority-form"))
         (values :authority "/" nil target nil))
        (t (protocol-error 400 :detail "bad request-target"))))

(defun parse-decimal-length (value max-body)
  ;; RFC 9110 §8.6. Content-Length is 1*DIGIT with no upper bound. The
  ;; header line limit bounds the numeral, so the integer cannot wrap.
  ;; A value above the body limit is 413.
  (when (or (zerop (length value))
            (notevery #'digit-char-p value))
    (protocol-error 400 :detail "bad content-length"))
  (let ((number (parse-integer value)))
    (when (> number max-body)
      (protocol-error 413 :detail "content-length"))
    number))

(defun content-length-members (value)
  "RFC 9112 §6.3 item 5. One decimal, or a comma-separated list of
decimals (RFC 9110 §5.6.1). Empty members are ignored. A value with no
member is kept so a bare comma stays an invalid length."
  (or (split-commas value) (list value)))

(defun content-length-of (headers max-body)
  (let ((values (header-values headers "content-length")))
    (when values
      (let ((lengths nil))
        (dolist (value values)
          (dolist (member (content-length-members value))
            (push (parse-decimal-length member max-body) lengths)))
        (unless (every (lambda (length) (= length (first lengths))) lengths)
          (protocol-error 400 :detail "conflicting content-length"))
        (first lengths)))))

(defun transfer-codings (headers)
  (loop for value in (header-values headers "transfer-encoding")
        nconc (mapcar #'string-downcase (split-commas value))))

(defun coding-name (coding)
  (let ((semi (position #\; coding)))
    (string-trim '(#\Space #\Tab) (if semi (subseq coding 0 semi) coding))))

(defun bws-end (text start)
  (loop for index = start then (1+ index)
        while (and (< index (length text))
                   (or (char= (char text index) #\Space)
                       (char= (char text index) #\Tab)))
        finally (return index)))

(defun token-end (text start)
  (loop for index = start then (1+ index)
        while (and (< index (length text))
                   (token-char-p (char text index)))
        finally (return index)))

(defun qdtext-p (character)
  (let ((code (char-code character)))
    (or (char= character #\Tab)
        (char= character #\Space)
        (= code 33)
        (<= 35 code 91)
        (<= 93 code 126)
        (<= 128 code 255))))

(defun quoted-string-end (text start)
  "Index after a quoted-string that begins at START, or NIL."
  (when (or (>= start (length text)) (char/= (char text start) #\"))
    (return-from quoted-string-end nil))
  (loop with index = (1+ start)
        while (< index (length text))
        do (let ((character (char text index)))
             (cond ((char= character #\")
                    (return-from quoted-string-end (1+ index)))
                   ((char= character #\\)
                    (incf index)
                    (when (or (>= index (length text))
                              (not (or (char= (char text index) #\Tab)
                                       (char= (char text index) #\Space)
                                       (<= 33 (char-code (char text index)) 126)
                                       (<= 128 (char-code (char text index)) 255))))
                      (return-from quoted-string-end nil))
                    (incf index))
                   ((qdtext-p character)
                    (incf index))
                   (t (return-from quoted-string-end nil)))))
  nil)

(defun chunk-ext-value-end (text start)
  (when (>= start (length text))
    (return-from chunk-ext-value-end nil))
  (if (char= (char text start) #\")
      (quoted-string-end text start)
      (let ((end (token-end text start)))
        (when (> end start) end))))

(defun chunk-extensions-p (text start)
  "RFC 9112 §7.1.1. Each extension is BWS \";\" BWS name [ BWS \"=\" BWS value ].
Trailing whitespace that is not the BWS before a semicolon is rejected."
  (loop
    (let ((after-bws (bws-end text start)))
      (cond ((= after-bws (length text))
             (return (= after-bws start)))
            ((char/= (char text after-bws) #\;)
             (return nil))
            (t
             (setf start (bws-end text (1+ after-bws)))
             (let ((name-end (token-end text start)))
               (when (= name-end start)
                 (return nil))
               (setf start (bws-end text name-end))
               (when (and (< start (length text)) (char= (char text start) #\=))
                 (let ((value-end (chunk-ext-value-end text (bws-end text (1+ start)))))
                   (unless value-end
                     (return nil))
                   (setf start value-end)))))))))

(defun chunk-size-text (line)
  "RFC 9112 §7.1. Return the hex chunk-size, or NIL when the line is not
chunk-size [ chunk-ext ]. Whitespace before the size is rejected. BWS is
allowed only where the chunk-ext grammar puts it."
  (unless (and line (plusp (length line)) (digit-char-p (char line 0) 16))
    (return-from chunk-size-text nil))
  (let ((end (or (position-if-not (lambda (character) (digit-char-p character 16)) line)
                 (length line))))
    (when (and (plusp end) (chunk-extensions-p line end))
      (subseq line 0 end))))

(defun read-chunked-body (stream max-body)
  (let ((body (make-array 256 :element-type '(unsigned-byte 8)
                              :adjustable t :fill-pointer 0)))
    (loop
      (let* ((line (read-crlf-line stream 4096))
             (size-text (chunk-size-text line)))
        (unless size-text
          (protocol-error 400 :detail "bad chunk size"))
        (let ((size (parse-integer size-text :radix 16)))
          (when (zerop size)
            (return (values (simple-octets body) (read-header-section stream))))
          (when (> (+ (length body) size) max-body)
            (protocol-error 413 :detail "chunked body"))
          (append-octets body (read-exact stream size))
          (let ((terminator (read-exact stream 2)))
            (unless (and (= (aref terminator 0) 13) (= (aref terminator 1) 10))
              (protocol-error 400 :detail "bad chunk terminator"))))))))

(defun classify-message-body (headers max-body)
  "RFC 9112 §§6.3 and 7. Return NIL when there is no body, :chunked, or a
byte length. Framing errors in the header fields are signaled here, before
any body byte is read."
  (let* ((raw (transfer-codings headers))
         (codings (mapcar #'coding-name raw)))
    (when (some (lambda (coding) (find #\; coding)) raw)
      (protocol-error 400 :detail "transfer-coding parameters"))
    (when (and codings (header-values headers "content-length"))
      (protocol-error 400 :detail "content-length and transfer-encoding"))
    (cond
      ((null codings) (content-length-of headers max-body))
      ((not (string= (car (last codings)) "chunked"))
       (protocol-error 400 :detail "transfer-encoding must end in chunked"))
      ((not (every (lambda (coding) (string= coding "chunked")) codings))
       (protocol-error 501 :detail "unsupported transfer-coding"))
      ((rest codings)
       (protocol-error 400 :detail "repeated chunked coding"))
      (t :chunked))))

(defun read-message-body (stream headers max-body)
  (let ((framed (classify-message-body headers max-body)))
    (cond ((eq framed :chunked) (read-chunked-body stream max-body))
          ((null framed) (ascii-octets ""))
          (t (read-exact stream framed)))))

(defun expect-continue-p (headers version)
  "RFC 9110 §10.1.1. A 100-continue expectation on HTTP/1.0 is ignored.
HTTP/1.1 is true only when every member, on every field line, is 100-continue."
  (when (= version 11)
    (continue-expectation headers)))

(defun send-continue (stream)
  (write-ascii stream "HTTP/1.1 100 Continue")
  (write-crlf stream)
  (write-crlf stream)
  (finish-output stream))

(defun connection-close-p (headers version)
  (let ((tokens (mapcar #'string-downcase
                        (loop for value in (header-values headers "connection")
                              nconc (split-commas value)))))
    (or (member "close" tokens :test #'string=)
        (and (= version 10)
             (not (member "keep-alive" tokens :test #'string=))))))

(defun read-request (stream &key (scheme "http") (peer "") (max-body (* 1024 1024))
                              early-response)
  "Read one HTTP/1.0 or HTTP/1.1 request from the binary STREAM.
Signals END-OF-REQUEST on a clean EOF between requests.
Signals PROTOCOL-ERROR for a message this origin refuses.
EARLY-RESPONSE, when supplied, is called with the header-only request
once Expect is 100-continue and content is declared. A response from
that function is the final status and the content is not read
(RFC 9110 §10.1.1)."
  (let ((line nil))
    (loop repeat 32
          for candidate = (read-crlf-line stream +max-request-line+ :on-too-long 414)
          do (unless (zerop (length candidate))
               (setf line candidate)
               (return)))
    (unless line
      (protocol-error 400 :detail "empty request"))
    (multiple-value-bind (method target version-text) (split-request-line line)
      (unless (token-string-p method)
        (protocol-error 400 :detail "bad method"))
      (let ((version (parse-version version-text)))
        (multiple-value-bind (form raw-path query absolute-host absolute-scheme)
            (classify-target method target)
          ;; RFC 9110 §7.4. An https target needs a secured connection.
          ;; This listener has no certificate, so the request is misdirected.
          (when (and absolute-scheme
                     (string= absolute-scheme "https")
                     (not (string= scheme "https")))
            (protocol-error 421 :detail "https target"))
          (let ((headers (read-header-section stream)))
            (let ((host-values (header-values headers "host")))
              (when (> (length host-values) 1)
                (protocol-error 400 :detail "duplicate host"))
              (when (and (= version 11) (null host-values))
                (protocol-error 400 :detail "missing host"))
              (when (and host-values (not (valid-host-p (first host-values))))
                ;; Absolute-form still requires a syntactically valid Host field
                ;; on the wire; the origin ignores its value below.
                (when (or (null absolute-host) (plusp (length (first host-values))))
                  (unless (valid-host-p (first host-values))
                    (protocol-error 400 :detail "bad host"))))
              (when (and host-values
                         (zerop (length (first host-values)))
                         (not absolute-host)
                         (= version 11)
                         (not (eq form :asterisk)))
                (protocol-error 400 :detail "empty host"))
              (let ((effective-host (or absolute-host
                                        (and host-values (first host-values))
                                        "")))
                (unless (or absolute-host (eq form :authority) (valid-host-p effective-host)
                            (and (= version 10) (zerop (length effective-host))))
                  (protocol-error 400 :detail "bad host"))
                (let ((path (if (eq form :authority)
                                "/"
                                (normalize-path raw-path)))
                      (continue (expect-continue-p headers version)))
                  (when (and continue
                             (or (transfer-codings headers)
                                 (header-value headers "content-length")))
                    ;; Reject a framing error before 100, then send the
                    ;; final status when the method and target already
                    ;; decide it. Otherwise 100, then the content.
                    (classify-message-body headers max-body)
                    (let* ((partial (make-request :method method
                                                  :target target
                                                  :path path
                                                  :query query
                                                  :http-version version
                                                  :headers headers
                                                  :body (ascii-octets "")
                                                  :host effective-host
                                                  :scheme (or absolute-scheme scheme)
                                                  :peer peer))
                           (early (and early-response (funcall early-response partial))))
                      (when early
                        (error 'final-before-content :request partial :response early)))
                    (send-continue stream))
                  ;; RFC 9112 §6.1. Transfer-Encoding did not exist in HTTP/1.0.
                  ;; A message that carries it has faulty framing even when a
                  ;; Content-Length is also present. Do not read the body.
                  (when (and (= version 10) (transfer-codings headers))
                    (protocol-error 400 :detail "http/1.0 transfer-encoding"))
                  (multiple-value-bind (body trailers)
                      (read-message-body stream headers max-body)
                    (make-request :method method
                                  :target target
                                  :path path
                                  :query query
                                  :http-version version
                                  :headers headers
                                  :trailers (retain-trailer-fields trailers)
                                  :body (or body (ascii-octets ""))
                                  :host effective-host
                                  :scheme (or absolute-scheme scheme)
                                  :peer peer)))))))))))

(defun status-has-body-p (status)
  (not (or (< status 200) (= status 204) (= status 304))))

(defun emitted-body (response)
  "Body octets this response generates. A 205 has no content (RFC 9110 §15.3.6).
HTTP/1.1 still frames that empty content with Content-Length: 0."
  (if (= (response-status response) 205)
      (ascii-octets "")
      (response-body response)))

(defun malformed-field-p (pair)
  (let ((name (car pair))
        (value (cdr pair)))
    (not (and (stringp name) (stringp value)
              (token-string-p name) (field-value-ok-p value)
              (not (find #\Return value)) (not (find #\Newline value))))))

(defun write-header-fields (stream headers)
  (dolist (pair headers)
    (when (malformed-field-p pair)
      (error "Refusing to send a malformed header ~a" (car pair)))
    (let ((name (car pair))
          (value (cdr pair)))
      (write-ascii stream name)
      (write-ascii stream ": ")
      (write-ascii stream value)
      (write-crlf stream))))

(defstruct file-body
  "Bytes of one file, from START inclusive to END exclusive.
END nil means the length observed when the span is read. The send path
reads the span in chunks instead of holding the file."
  pathname
  (start 0)
  (end nil))

(defparameter *file-read-chunk* 16384
  "Octets read from a file body at one time.")

(defun file-body-limit (body)
  (or (file-body-end body)
      (with-open-file (in (file-body-pathname body)
                          :element-type '(unsigned-byte 8))
        (file-length in))))

(defun file-body-count (body)
  "Length of the span. A stored END does not open the file."
  (max 0 (- (file-body-limit body) (file-body-start body))))

(defun call-with-file-chunks (body function)
  "Call FUNCTION with successive chunks covering BODY.
A short read is an error: Content-Length was taken from this span."
  (with-open-file (in (file-body-pathname body)
                      :element-type '(unsigned-byte 8))
    (let ((limit (or (file-body-end body) (file-length in)))
          (pos (file-body-start body)))
      (file-position in pos)
      (loop while (< pos limit)
            for want = (min *file-read-chunk* (- limit pos))
            for chunk = (make-array want :element-type '(unsigned-byte 8))
            for got = (read-sequence chunk in)
            do (when (zerop got)
                 (error "short read of ~a" (file-body-pathname body)))
               (let ((piece (if (= got want) chunk (subseq chunk 0 got))))
                 (funcall function piece)
                 (incf pos (length piece))))
      (unless (= pos limit)
        (error "short read of ~a" (file-body-pathname body))))))

(defun write-file-body (body stream)
  (call-with-file-chunks body (lambda (chunk) (write-sequence chunk stream))))

(defun read-file-span (body)
  "The span as one vector. Multipart ranges and similar framing need the
selected bytes; the identity send path does not call this."
  (let ((chunks nil)
        (size 0))
    (call-with-file-chunks body
                           (lambda (chunk)
                             (incf size (length chunk))
                             (push chunk chunks)))
    (let ((out (make-array size :element-type '(unsigned-byte 8)))
          (start 0))
      (dolist (chunk (nreverse chunks))
        (replace out chunk :start1 start)
        (incf start (length chunk)))
      out)))

(defun response-octets (body)
  (cond ((null body) (ascii-octets ""))
        ((stringp body) (utf8-octets body))
        ((typep body '(vector (unsigned-byte 8))) (simple-octets body))
        ((pathnamep body)
         (with-open-file (in body :element-type '(unsigned-byte 8))
           (let ((buffer (make-array (file-length in) :element-type '(unsigned-byte 8))))
             (read-sequence buffer in)
             buffer)))
        (t nil)))

(defun known-body-length (body)
  "Octet length of a buffered body or a file span. NIL for a stream function."
  (cond ((functionp body) nil)
        ((file-body-p body) (file-body-count body))
        (t (let ((octets (response-octets body)))
             (and octets (length octets))))))

(defun write-chunk (stream octets)
  (write-ascii stream (format nil "~X" (length octets)))
  (write-crlf stream)
  (write-sequence octets stream)
  (write-crlf stream))

(defun write-response (stream request response &key suppress-body close-connection (date (get-universal-time)))
  "Write one HTTP/1.1 (or HTTP/1.0) response. Returns T when the connection must close."
  ;; A 1xx cannot be the whole response (RFC 9110 §§10.1.1 and 15.2).
  ;; HTTP/1.0 has no 1xx status codes at all.
  (when (< (response-status response) 200)
    (setf response (make-response :status 500
                                  :content-type "text/plain; charset=utf-8"
                                  :body (reason-phrase 500))))
  (let* ((status (response-status response))
         (version (if (and request (= (request-http-version request) 10)) 10 11))
         (omit-length (header-value (response-headers response) "pazuzu-omit-length"))
         ;; Copy the spine. Handlers may reuse a literal field list, and the
         ;; write below reverses that spine.
         (headers (copy-list (remove-headers (response-headers response)
                                             "connection" "transfer-encoding" "keep-alive"
                                             "proxy-connection" "content-length"
                                             "pazuzu-omit-length" "pazuzu-mixed")))
         (body (emitted-body response))
         (streaming (functionp body))
         (file (and (file-body-p body) body))
         (known (unless (or streaming file) (response-octets body)))
         (body-length (cond (file (file-body-count file))
                            (known (length known))))
         (send-body (and (status-has-body-p status) (not suppress-body))))
    (when (response-content-type response)
      (unless (header-value headers "content-type")
        (push (cons "content-type" (response-content-type response)) headers)))
    ;; ETag and Last-Modified are not list fields (RFC 9110 §5.2). The
    ;; slot is the validator, so it replaces a field the handler also set.
    (when (response-etag response)
      (setf headers (acons "etag" (response-etag response)
                           (remove-headers headers "etag"))))
    (when (response-last-modified response)
      ;; RFC 9110 §8.8.2.1. A future modification time is the Date of
      ;; this message, which is the same origination timestamp.
      (setf headers (acons "last-modified"
                           (format-imf-fixdate (min (response-last-modified response) date))
                           (remove-headers headers "last-modified"))))
    (when (response-cache-control response)
      (push (cons "cache-control" (response-cache-control response)) headers))
    (when (and (response-language response)
               (not (header-value headers "content-language")))
      (push (cons "content-language" (response-language response)) headers))
    (unless (header-value headers "server")
      (push (cons "server" "pazuzu") headers))
    (when (and (>= status 200) (<= status 599)
               (not (header-value headers "date")))
      (push (cons "date" (format-imf-fixdate date)) headers))
    (let ((use-chunked (and send-body streaming (= version 11) (not close-connection))))
      (when (and (numberp body-length) (not streaming) (not omit-length)
                 (status-has-body-p status)
                 (or send-body suppress-body)
                 (not (header-value headers "content-length")))
        (push (cons "content-length" (princ-to-string body-length)) headers))
      (when use-chunked
        (push (cons "transfer-encoding" "chunked") headers))
      (let ((must-close (or close-connection
                           (and streaming (not use-chunked))
                           (and request (connection-close-p (request-headers request) version)))))
        ;; RFC 9110 §7.6.1. A field other than Connection that describes
        ;; this connection is named here. close and keep-alive are options.
        (let ((options nil))
          (when must-close
            (push "close" options))
          (when (and (= version 10) (not must-close))
            (push "keep-alive" options))
          ;; Any connection-specific field still in the section is named.
          ;; close and the HTTP/1.0 keep-alive option are not fields.
          (dolist (name '("transfer-encoding" "upgrade" "te"
                          "keep-alive" "proxy-connection"))
            (when (and (header-value headers name)
                       (not (member name options :test #'string=)))
              (push name options)))
          (when options
            (push (cons "connection"
                        (format nil "~{~a~^, ~}" (nreverse options)))
                  headers)))
        ;; Reject a bad field before the status line. A later 500 must be
        ;; the only response on the wire (RFC 9112 §2.2, response splitting).
        (setf headers (limit-qvalue-fields
                       (omit-empty-list-members (collapse-singleton-fields headers))))
        (let ((bad (find-if #'malformed-field-p headers)))
          (when bad
            (error "Refusing to send a malformed header ~a" (car bad))))
        (write-ascii stream (if (= version 10) "HTTP/1.0 " "HTTP/1.1 "))
        (write-ascii stream (princ-to-string status))
        (write-byte 32 stream)
        (write-ascii stream (reason-phrase status))
        (write-crlf stream)
        (write-header-fields stream (nreverse headers))
        (write-crlf stream)
        (when send-body
          (cond (use-chunked
                 (funcall body
                          (lambda (octets)
                            (let ((octets (simple-octets octets)))
                              (when (plusp (length octets))
                                (write-chunk stream octets)
                                (finish-output stream)))))
                 (write-chunk stream (ascii-octets ""))
                 (finish-output stream))
                (streaming
                 (funcall body
                          (lambda (octets)
                            (write-sequence (simple-octets octets) stream)
                            (finish-output stream))))
                (file
                 (write-file-body file stream))
                (t
                 (write-sequence known stream))))
        (finish-output stream)
        must-close))))

(defparameter *hop-by-hop-headers*
  '("connection" "keep-alive" "proxy-connection" "transfer-encoding"
    "upgrade" "te" "host" "http2-settings" "content-length"
    "proxy-authenticate" "proxy-authorization" "pazuzu-omit-length"
    "pazuzu-mixed"))

(defun response-wire-fields (response &key (date (get-universal-time)))
  "Field alist for an HTTP/2 or HTTP/3 response. :status is first and carries
only the status code. Content-Length is omitted on 1xx and 204."
  (let* ((status (response-status response))
         (omit-length (header-value (response-headers response) "pazuzu-omit-length"))
         (headers (apply #'remove-headers (response-headers response) *hop-by-hop-headers*))
         (body (emitted-body response))
         (body-length (known-body-length body)))
    (when (response-content-type response)
      (unless (header-value headers "content-type")
        (push (cons "content-type" (response-content-type response)) headers)))
    (when (response-etag response)
      (setf headers (acons "etag" (response-etag response)
                           (remove-headers headers "etag"))))
    (when (response-last-modified response)
      ;; RFC 9110 §8.8.2.1. The same origination timestamp as Date.
      (setf headers (acons "last-modified"
                           (format-imf-fixdate (min (response-last-modified response) date))
                           (remove-headers headers "last-modified"))))
    (when (response-cache-control response)
      (push (cons "cache-control" (response-cache-control response)) headers))
    (when (and (response-language response)
               (not (header-value headers "content-language")))
      (push (cons "content-language" (response-language response)) headers))
    (unless (header-value headers "server")
      (push (cons "server" "pazuzu") headers))
    (when (and (<= 200 status 599) (not (header-value headers "date")))
      (push (cons "date" (format-imf-fixdate date)) headers))
    (when (and (numberp body-length) (status-has-body-p status) (not omit-length)
               (not (header-value headers "content-length")))
      (push (cons "content-length" (princ-to-string body-length)) headers))
    (cons (cons ":status" (princ-to-string status))
          (nreverse
           (loop for (name . value) in (limit-qvalue-fields
                                         (omit-empty-list-members
                                          (collapse-singleton-fields headers)))
                 for down = (string-downcase name)
                 ;; RFC 9113 §8.2.1 and RFC 9114 §10.3. A value that starts or
                 ;; ends with SP or HTAB, or that contains CR, LF, or NUL,
                 ;; is not a field value this response may send.
                 do (unless (and (token-string-p down) (field-value-ok-p value)
                                 (not (http-field-value-malformed-p value)))
                      (error "Refusing to send a malformed header ~a" down))
                 unless (char= (char down 0) #\:)
                   collect (cons down value))))))
