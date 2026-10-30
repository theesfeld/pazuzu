(in-package #:pazuzu/tests)

(defvar *failures* nil)

(defun fail (control &rest args)
  (apply #'error control args))

(defmacro check (name &body body)
  `(handler-case
       (progn
         (sb-sys:with-deadline (:seconds 10)
           ,@body)
         (format t "ok   ~a~%" ,name)
         (finish-output t))
     (error (condition)
       (format t "FAIL ~a: ~a~%" ,name condition)
       (finish-output t)
       (push ,name *failures*))
     (sb-sys:deadline-timeout (condition)
       (format t "FAIL ~a: ~a~%" ,name condition)
       (finish-output t)
       (push ,name *failures*))))

(defun octets (string)
  (babel:string-to-octets string :encoding :utf-8))

(defun latin1 (octets)
  (babel:octets-to-string octets :encoding :iso-8859-1))

(defun request-text (&rest lines)
  (with-output-to-string (out)
    (dolist (line lines)
      (write-string line out)
      (write-char #\Return out)
      (write-char #\Newline out))
    (write-char #\Return out)
    (write-char #\Newline out)))

(defun read-n (stream count)
  (let ((buffer (make-array count :element-type '(unsigned-byte 8))))
    (loop for got = 0 then (+ got n)
          while (< got count)
          for n = (read-sequence buffer stream :start got)
          when (zerop n)
            do (fail "short read, got ~d of ~d" got count))
    buffer))

(defun read-some (stream)
  (loop for byte = (read-byte stream nil :eof)
          until (eq byte :eof)
          collect byte into bytes
          finally (return (coerce bytes '(simple-array (unsigned-byte 8) (*))))))

(defstruct reply status status-line headers body)

(defun header (reply name)
  (cdr (assoc name (reply-headers reply) :test #'string-equal)))

(defun connection-options (reply)
  (loop for part in (uiop:split-string (or (header reply "connection") "")
                                       :separator '(#\,))
        for token = (string-downcase (string-trim '(#\Space #\Tab) part))
        unless (zerop (length token))
          collect token))

(defun parse-headers (text)
  (let ((lines (uiop:split-string text :separator '(#\Newline))))
    (unless lines
      (fail "empty response"))
    (let* ((status-line (string-right-trim '(#\Return) (first lines)))
           (sp1 (position #\Space status-line))
           (sp2 (and sp1 (position #\Space status-line :start (1+ sp1))))
           (status (and sp1 (parse-integer status-line :start (1+ sp1)
                                           :end (or sp2 (length status-line))
                                           :junk-allowed t))))
      (unless (and sp1 status)
        (fail "bad status line ~s" status-line))
      (values status status-line
              (loop for line in (rest lines)
                    for trimmed = (string-right-trim '(#\Return) line)
                    unless (zerop (length trimmed))
                      collect (let ((colon (position #\: trimmed)))
                                (unless colon
                                  (fail "bad header ~s" trimmed))
                                (cons (string-downcase (subseq trimmed 0 colon))
                                      (string-trim '(#\Space #\Tab)
                                                   (subseq trimmed (1+ colon))))))))))

(defun read-reply (stream)
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
      (when (< status 200)
        (return-from read-reply (read-reply stream)))
      (let* ((length-text (cdr (assoc "content-length" headers :test #'string=)))
             (chunked (let ((te (cdr (assoc "transfer-encoding" headers :test #'string=))))
                        (and te (search "chunked" te :test #'char-equal))))
             (body (cond ((member status '(204 304))
                          (make-array 0 :element-type '(unsigned-byte 8)))
                         (length-text
                          (read-n stream (parse-integer length-text)))
                         (chunked
                          (read-chunks stream))
                         (t (read-some stream)))))
        (make-reply :status status :status-line status-line :headers headers :body body)))))

(defun read-chunks (stream)
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop
      (let* ((line (read-crlf-line stream))
             (semi (position #\; line))
             (size (parse-integer (if semi (subseq line 0 semi) line) :radix 16)))
        (when (zerop size)
          (loop for trailer = (read-crlf-line stream)
                until (zerop (length trailer)))
          (return (coerce out '(simple-array (unsigned-byte 8) (*)))))
        (let ((chunk (read-n stream size)))
          (loop for byte across chunk do (vector-push-extend byte out))
          (let ((end (read-n stream 2)))
            (unless (and (= (aref end 0) 13) (= (aref end 1) 10))
              (fail "bad chunk trailer"))))))))

(defun read-crlf-line (stream)
  (let ((out (make-array 0 :element-type 'character :adjustable t :fill-pointer 0)))
    (loop for byte = (read-byte stream)
          do (cond ((= byte 13)
                    (unless (= (read-byte stream) 10)
                      (fail "bare CR"))
                    (return out))
                   (t (vector-push-extend (code-char byte) out))))))

(defun connect (port)
  (loop repeat 50
        for socket = (handler-case
                         (usocket:socket-connect "127.0.0.1" port
                                                 :element-type '(unsigned-byte 8))
                       (error () nil))
        when socket
          do (return socket)
        do (sleep 0.02)
        finally (fail "port ~d is not accepting" port)))

(defun exchange (port text &key headers-only)
  (let ((socket (connect port)))
    (unwind-protect
         (let ((stream (usocket:socket-stream socket)))
           (write-sequence (octets text) stream)
           (finish-output stream)
           (if headers-only
               (read-reply-headers-only stream)
               (read-reply stream)))
      (ignore-errors (usocket:socket-close socket)))))

(defun body-text (reply)
  (babel:octets-to-string (reply-body reply) :encoding :utf-8))

(defun expect-status (reply status)
  (unless (= (reply-status reply) status)
    (fail "status ~d, body ~s" (reply-status reply) (ignore-errors (body-text reply)))))

(defun imf-fixdate-p (text)
  "RFC 9110 §5.6.7. Fixed-length IMF-fixdate, no extra whitespace."
  (and (stringp text)
       (= (length text) 29)
       (pazuzu::weekday-short-p (subseq text 0 3))
       (string= (subseq text 3 5) ", ")
       (every #'digit-char-p (subseq text 5 7))
       (char= (char text 7) #\Space)
       (pazuzu::month-number (subseq text 8 11))
       (char= (char text 11) #\Space)
       (every #'digit-char-p (subseq text 12 16))
       (char= (char text 16) #\Space)
       (every #'digit-char-p (subseq text 17 19))
       (char= (char text 19) #\:)
       (every #'digit-char-p (subseq text 20 22))
       (char= (char text 22) #\:)
       (every #'digit-char-p (subseq text 23 25))
       (string= (subseq text 25) " GMT")
       (pazuzu::parse-http-date text)))

(defun sha256-hex (text)
  (string-downcase
   (ironclad:byte-array-to-hex-string
    (ironclad:digest-sequence :sha256 (octets text)))))

(defun decode-coding (octets coding)
  (pazuzu::decode-content-encoding octets coding (* 1024 1024)))

(defvar *put-calls* 0)
(defvar *create-calls* 0)
(defvar *shelf* nil)
(defvar *locked-calls* 0)
(defvar *digest-item-calls* 0)
(defvar *guard-calls* 0)
(defvar *unmodified-calls* 0)
(defvar *header-applies* 0)

(defun install-routes (server)
  (setf *put-calls* 0
        *locked-calls* 0
        *digest-item-calls* 0
        *shelf* nil)
  (pazuzu:add-route server :get "/"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "pazuzu")))
  (pazuzu:add-route server :get "/applied"
                    (lambda (request)
                      (declare (ignore request))
                      (incf *header-applies*)
                      (pazuzu:text-response "applied")))
  (pazuzu:add-route server :get "/flow-body"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response (make-string 4096 :initial-element #\x))))
  (pazuzu:add-route server :get "/wide"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response (make-string 20000 :initial-element #\w))))
  (pazuzu:add-route server :get "/flow-conn"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response (make-string 65536 :initial-element #\y))))
  (pazuzu:add-route server :post "/echo"
                    (lambda (request)
                      (pazuzu:octet-response (pazuzu:request-body request)
                                             :content-type "text/plain; charset=utf-8")))
  (pazuzu:add-route server :post "/media"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 415
                                            :content-type "text/plain; charset=utf-8"
                                            :body "Unsupported Media Type")))
  (pazuzu:add-route server :get "/q"
                    (lambda (request)
                      (let ((params (pazuzu:query-parameters request)))
                        (pazuzu:text-response
                         (format nil "a=~a;c=~a"
                                 (cdr (assoc "a" params :test #'string=))
                                 (cdr (assoc "c" params :test #'string=)))))))
  (pazuzu:add-route server :get "/who"
                    (lambda (request)
                      (pazuzu:text-response (pazuzu:request-host request))))
  (pazuzu:add-route server :get "/none"
                    (lambda (request)
                      (declare (ignore request))
                      ;; RFC 9112 §6.1 and RFC 9110 §8.6. These fields must
                      ;; not appear on a 204, even when the handler names them.
                      (pazuzu:make-response
                       :status 204
                       :headers '(("transfer-encoding" . "chunked")
                                  ("content-length" . "5")))))
  (pazuzu:add-route server :get "/none-body"
                    (lambda (request)
                      (declare (ignore request))
                      ;; RFC 9112 §6.3 and RFC 9110 §15.3.5. A 204 cannot
                      ;; contain this content. The next request is the
                      ;; next message.
                      (pazuzu:make-response
                       :status 204
                       :content-type "text/plain"
                       :body "nope")))
  (pazuzu:add-route server :get "/interim"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 100 :body nil)))
  (pazuzu:add-route server :get "/etag"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "tagged" :etag "\"v1\"")))
  (pazuzu:add-route server :get "/dual-etag"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "one"
                       :content-type "text/plain; charset=utf-8"
                       :etag "\"slot\""
                       :last-modified 0
                       :headers '(("etag" . "\"header\"")
                                  ("last-modified" . "Sun, 06 Nov 1994 08:49:37 GMT")))))
  (pazuzu:add-route server :get "/noted"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :representations
                       (list (pazuzu:make-representation
                              :content-type "text/plain;note=\"x;q=0\""
                              :body "noted")))))
  (pazuzu:add-route server :get "/charset"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :representations
                       (list (pazuzu:make-representation
                              :content-type "text/plain;charset=utf-8"
                              :body "utf8")))))
  (pazuzu:add-route server :get "/quoted"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :representations
                       (list (pazuzu:make-representation
                              :content-type "text/plain; note=\"ab\""
                              :body "quoted")))))
  (pazuzu:add-route server :get "/comma-etag"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "comma" :etag "\"a,b\"")))
  (pazuzu:add-route server :get "/slash-etag"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "slash"
                                            :etag (concatenate 'string "\"" "a\\" "\""))))
  (pazuzu:add-route server :get "/dated"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :content-type "text/plain; charset=utf-8"
                       :body "dated"
                       :last-modified (encode-universal-time 0 0 0 1 1 2000 0))))
  (pazuzu:add-route server :get "/future"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :content-type "text/plain; charset=utf-8"
                       :body "future"
                       :last-modified (encode-universal-time 0 0 0 1 1 2099 0))))
  (pazuzu:add-route server :options "/opt"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "opt" :etag "\"o1\"")))
  (pazuzu:add-route server :put "/store"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 201
                       :content-type "text/plain; charset=utf-8"
                       :body "stored"
                       :etag "\"s1\""
                       :last-modified (encode-universal-time 0 0 0 1 1 2000 0))))
  (pazuzu:add-route server :put "/item"
                    (lambda (request)
                      (declare (ignore request))
                      (incf *put-calls*)
                      (pazuzu:text-response "wrote"))
                    :etag (lambda (request)
                            (declare (ignore request))
                            "\"v1\""))
  (pazuzu:add-route server :get "/guarded"
                    (lambda (request)
                      (declare (ignore request))
                      (incf *guard-calls*)
                      (pazuzu:text-response "guarded" :etag "\"g1\""))
                    :etag (lambda (request)
                            (declare (ignore request))
                            "\"g1\""))
  (pazuzu:add-route server '(:get :put) "/unmodified"
                    (lambda (request)
                      (declare (ignore request))
                      (incf *unmodified-calls*)
                      (pazuzu:text-response "kept"))
                    :etag (lambda (request)
                            (declare (ignore request))
                            "\"u1\"")
                    :last-modified (lambda (request)
                                     (declare (ignore request))
                                     (encode-universal-time 0 0 0 1 1 2000 0)))
  (pazuzu:add-route server :put "/locked"
                    (pazuzu:require-basic
                     (lambda (request)
                       (declare (ignore request))
                       (incf *locked-calls*)
                       (pazuzu:text-response "locked"))
                     :user "ada" :password "secret")
                    :etag (lambda (request)
                            (declare (ignore request))
                            "\"v1\""))
  (pazuzu:add-route server :put "/digest-item"
                    (pazuzu:require-digest
                     (lambda (request)
                       (declare (ignore request))
                       (incf *digest-item-calls*)
                       (pazuzu:text-response "digest-item"))
                     :user "ada" :password "secret")
                    :etag (lambda (request)
                            (declare (ignore request))
                            "\"v1\""))
  (pazuzu:add-route server :put "/create"
                    (lambda (request)
                      (declare (ignore request))
                      (incf *create-calls*)
                      (pazuzu:text-response "created"))
                    :etag (lambda (request)
                            (declare (ignore request))
                            nil))
  (pazuzu:add-route server :put "/shelf"
                    (lambda (request)
                      (declare (ignore request))
                      (setf *shelf* "kept")
                      (pazuzu:text-response "shelved"))
                    :etag (lambda (request)
                            (declare (ignore request))
                            (and *shelf* "\"shelf\"")))
  (pazuzu:add-route server :get "/bare-401"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "hidden" :status 401)))
  (pazuzu:add-route server '(:get :post) "/method-no"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 405
                                            :content-type "text/plain; charset=utf-8"
                                            :body "no")))
  (pazuzu:add-route server '(:get :post) "/method-own"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 405
                                            :headers '(("allow" . "GET"))
                                            :content-type "text/plain; charset=utf-8"
                                            :body "own")))
  (pazuzu:add-route server :get "/via"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :headers '(("via" . "1.0 fred")
                                  ("via" . "1.1 p.example.net"))
                       :content-type "text/plain; charset=utf-8"
                       :body "via")))
  (pazuzu:add-route server :get "/long-q"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :headers '(("accept-encoding" . "gzip;q=0.0001, br;q=1.0000")
                                  ("x-note" . "q=0.0001")
                                  ("x-quoted" . "\"q=0.0001\""))
                       :content-type "text/plain; charset=utf-8"
                       :body "q")))
  (pazuzu:add-route server :get "/qpack-a"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 200
                                            :content-type "a"
                                            :body "a")))
  (pazuzu:add-route server :get "/qpack-b"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 200
                                            :content-type "bb"
                                            :body "b")))
  (pazuzu:add-route server :get "/range"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "abcdefghij" :etag "\"r1\"")))
  (pazuzu:add-route server :get "/empty"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "")))
  (pazuzu:add-route server :get "/partial"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :content-type "text/plain"
                       :body "abcdefghij"
                       :etag "\"p1\""
                       :language "en"
                       :cache-control "max-age=60"
                       :headers '(("vary" . "accept-encoding")
                                  ("expires" . "Thu, 01 Jan 1970 00:00:00 GMT")
                                  ("content-location" . "/partial/en")))))
  (pazuzu:add-route server :get "/reset"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response :status 205
                                            :content-type "text/plain"
                                            :body "nope")))
  (pazuzu:add-route server :post "/post-range"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "abcdefghij")))
  (pazuzu:add-route server :get "/neg"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :representations
                       (list (pazuzu:make-representation
                              :content-type "text/plain"
                              :body "plain")
                             (pazuzu:make-representation
                              :content-type "text/html"
                              :body "html")))))
  (pazuzu:add-route server :get "/lang"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :representations
                       (list (pazuzu:make-representation
                              :content-type "text/plain"
                              :language "en-gb"
                              :body "en-gb")
                             (pazuzu:make-representation
                              :content-type "text/plain"
                              :language "en"
                              :body "en")
                             (pazuzu:make-representation
                              :content-type "text/plain"
                              :language "da"
                              :body "da")))))
  (pazuzu:add-route server :get "/cookie"
                    (lambda (request)
                      (let ((sid (cdr (assoc "sid" (pazuzu:cookies request) :test #'string=))))
                        (pazuzu:text-response (or sid "")
                                              :headers (list (pazuzu:set-cookie "sid" "abc"
                                                                                :http-only t
                                                                                :path "/"
                                                                                :same-site "Lax"))))))
  (pazuzu:add-route server :get "/cookie-header"
                    (lambda (request)
                      (pazuzu:text-response (or (pazuzu:request-header request "cookie") ""))))
  (pazuzu:add-route server :get "/header-value"
                    (lambda (request)
                      (pazuzu:text-response (or (pazuzu:request-header request "x-note") ""))))
  (pazuzu:add-route server :get "/list-field"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "listed"
                       :content-type "text/plain"
                       :headers '(("content-language" . "en, , da")
                                  ("vary" . "accept, , accept-language")
                                  ("cache-control" . "no-cache=\"a, b\", , max-age=1")
                                  ("trailer" . ", ,")
                                  ("x-note" . "a, , b")))))
  (pazuzu:add-route server :get "/two-languages"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "langs"
                       :content-type "text/plain"
                       :headers '(("content-language" . "en")
                                  ("content-language" . "da")))))
  (pazuzu:add-route server :get "/dup-type"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "one"
                       :headers '(("content-type" . "text/html")
                                  ("content-type" . "text/plain")))))
  (pazuzu:add-route server :get "/two-cookies"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "cookies"
                       :content-type "text/plain"
                       :headers (list (pazuzu:set-cookie "sid" "abc")
                                      (pazuzu:set-cookie "theme" "dark")))))
  (pazuzu:add-route server :get "/bad-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers (list (cons "x-evil"
                                            (format nil "a~c~cX-Injected: b"
                                                    #\Return #\Newline))))))
  (pazuzu:add-route server :get "/nul-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers (list (cons "x-pad" (format nil "a~cb" #\Nul))))))
  (pazuzu:add-route server :get "/lf-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers (list (cons "x-pad" (format nil "a~cb" #\Newline))))))
  (pazuzu:add-route server :get "/pad-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers '(("x-pad" . "trail ")))))
  (pazuzu:add-route server :get "/lead-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers '(("x-pad" . " lead")))))
  (pazuzu:add-route server :get "/tab-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers (list (cons "x-pad" (format nil "trail~c" #\Tab))))))
  (pazuzu:add-route server :get "/tab-lead-header"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :body "nope"
                       :headers (list (cons "x-pad" (format nil "~ctrail" #\Tab))))))
  ;; 30000 "a" octets. HPACK Huffman encodes that letter in 6 bits, so the
  ;; field block is still larger than the default 16384-octet frame.
  (pazuzu:add-route server :get "/wide-field"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response
                       "split"
                       :headers `(("x-wide" . ,(make-string 30000
                                                           :initial-element #\a))))))
  ;; More than two default frames, and still under the 64KiB send limit.
  (pazuzu:add-route server :get "/wider-field"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response
                       "wider"
                       :headers `(("x-wider" . ,(make-string 54000
                                                            :initial-element #\a))))))
  (pazuzu:add-route server :get "/mixed-case"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response "case" :headers '(("X-Note" . "Yes")))))
  (pazuzu:add-route server :post "/trailers"
                    (lambda (request)
                      ;; RFC 9110 §6.5.1. A trailer merged into the header
                      ;; section is visible to request-header.
                      (pazuzu:text-response
                       (if (pazuzu:request-header request "x-checksum")
                           "merged"
                           (format nil "~{~a=~a~^;~}"
                                   (loop for pair in (pazuzu:request-trailers request)
                                         collect (car pair)
                                         collect (cdr pair)))))))
  (pazuzu:add-route server :get "/basic"
                    (pazuzu:require-basic
                     (lambda (request)
                       (declare (ignore request))
                       (pazuzu:text-response "welcome"))
                     :user "ada" :password "secret"))
  (pazuzu:add-route server :get "/realm"
                    (pazuzu:require-basic
                     (lambda (request)
                       (declare (ignore request))
                       (pazuzu:text-response "welcome"))
                     :user "ada" :password "secret" :realm "a\"b\\c"))
  (pazuzu:add-route server :get "/digest"
                    (pazuzu:require-digest
                     (lambda (request)
                       (declare (ignore request))
                       (pazuzu:text-response "digest-ok"))
                     :user "ada" :password "secret"))
  (pazuzu:add-route server :get "/bearer"
                    (pazuzu:require-bearer
                     (lambda (request)
                       (declare (ignore request))
                       (pazuzu:text-response "bearer-ok"))
                     :token "tok_9"))
  (pazuzu:add-route server :post "/basic-continue"
                    (pazuzu:require-basic
                     (lambda (request)
                       (pazuzu:text-response
                        (if (plusp (length (pazuzu:request-body request)))
                            (babel:octets-to-string (pazuzu:request-body request)
                                                    :encoding :utf-8)
                            "")))
                     :user "ada" :password "secret"))
  (pazuzu:add-route server :post "/bearer-continue"
                    (pazuzu:require-bearer
                     (lambda (request)
                       (declare (ignore request))
                       (pazuzu:text-response "bearer-ok"))
                     :token "tok_9"))
  (pazuzu:add-route server :post "/digest-continue"
                    (pazuzu:require-digest
                     (lambda (request)
                       (declare (ignore request))
                       (pazuzu:text-response "digest-ok"))
                     :user "ada" :password "secret"))
  (pazuzu:add-route server :get "/horder"
                    (lambda (request)
                      (pazuzu:text-response
                       (format nil "~{~a~^,~}"
                               (map 'list #'car
                                    (remove-if-not
                                     (lambda (pair)
                                       (let ((name (car pair)))
                                         (and (stringp name)
                                              (>= (length name) 2)
                                              (string= (subseq name 0 2) "x-"))))
                                     (pazuzu:request-headers request)))))))
  (pazuzu:add-websocket-route
   server "/ws"
   (lambda (socket)
     (let ((message (pazuzu:websocket-receive socket)))
       (when message
         (pazuzu:websocket-send socket message))
       (pazuzu:websocket-close socket))))
  (pazuzu:add-websocket-route
   server "/ws-two"
   (lambda (socket)
     ;; RFC 6455 §6.2. Each finished data frame is its own message.
     (let ((first (pazuzu:websocket-receive socket))
           (second (pazuzu:websocket-receive socket)))
       (when first
         (pazuzu:websocket-send socket first))
       (when second
         (pazuzu:websocket-send socket second))
       (pazuzu:websocket-close socket))))
  (pazuzu:add-websocket-route
   server "/ws-close"
   (lambda (socket)
     (pazuzu:websocket-close socket :code 1000
                             :reason (make-string 123 :initial-element #\a))))
  (pazuzu:add-websocket-route
   server "/ws-1005"
   (lambda (socket)
     (pazuzu:websocket-close socket :code 1005)))
  (pazuzu:add-websocket-route
   server "/ws-1006"
   (lambda (socket)
     (pazuzu:websocket-close socket :code 1006)))
  (pazuzu:add-websocket-route
   server "/ws-1015"
   (lambda (socket)
     (pazuzu:websocket-close socket :code 1015)))
  (pazuzu:add-websocket-route
   server "/ws-after-close"
   (lambda (socket)
     (pazuzu:websocket-close socket :code 1000)
     (pazuzu:websocket-send socket "nope")))
  (pazuzu:add-route server :get "/events"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:sse-response
                       (lambda (emit)
                         (funcall emit "hello" :event "ping" :id "1")))))
  (pazuzu:add-route server :get "/hop"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:make-response
                       :status 200
                       :content-type "text/plain; charset=utf-8"
                       :body "clean"
                       :headers '(("connection" . "close")
                                  ("keep-alive" . "timeout=5")
                                  ("proxy-connection" . "keep-alive")
                                  ("transfer-encoding" . "chunked")
                                  ("upgrade" . "websocket")
                                  ("te" . "trailers")))))
  (let ((dir (ensure-directories-exist #p"/tmp/pazuzu-static/")))
    (with-open-file (out (merge-pathnames "hello.txt" dir)
                         :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-string "static-hello" out))
    ;; Larger than one read chunk, so a correct body crossed a read boundary.
    (with-open-file (out (merge-pathnames "wide.txt" dir)
                         :direction :output :if-exists :supersede :if-does-not-exist :create)
      (loop repeat 12500
            do (write-string "0123456789abcdef" out)))
    (pazuzu:serve-directory server "/files" dir)))

