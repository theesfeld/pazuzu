;;; HTTP/3 response checks and the shared server fixture.

(in-package #:pazuzu/tests)

(defun h3-empty-list-test (port)
  "RFC 9110 §5.6.1.1. An HTTP/3 response omits an empty list member.
A comma inside a quoted cache directive stays. A field that is not a
list is unchanged. A list of only empty members is omitted."
  (check "an HTTP/3 response list omits an empty member"
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "-D" "-" "--http3-only" "--max-time" "8"
                      (format nil "https://127.0.0.1:~d/list-field" port))
      (unless (and code (zerop code) (search "listed" text) (search "HTTP/3" text))
        (fail "http3 list ~s exit ~s" text code))
      (unless (search "content-language: en, da" text)
        (fail "http3 language ~s" text))
      (unless (search "vary: accept, accept-language" text)
        (fail "http3 vary ~s" text))
      (unless (search "cache-control: no-cache=\"a, b\", max-age=1" text)
        (fail "http3 cache ~s" text))
      (unless (search "x-note: a, , b" text)
        (fail "http3 note ~s" text))
      (when (search (format nil "~%trailer:") text :test #'char-equal)
        (fail "http3 trailer ~s" text)))))

(defun h3-too-many-fields-test (port)
  "RFC 9110 §5.4. HTTP/3 counts every field line, including the
pseudo-header fields. More than 100 is 431, and GET / is not returned."
  (check "too many HTTP/3 header fields is 431"
    (let ((script "/tmp/pazuzu-h3-fields.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._waiter = None"
                     "        self._status = None"
                     "        self._data = b''"
                     ""
                     "    def quic_event_received(self, event):"
                     "        for http_event in self._http.handle_event(event):"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        self._status = int(value)"
                     "                if http_event.stream_ended and self._waiter and not self._waiter.done():"
                     "                    self._waiter.set_result(True)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                self._data += http_event.data"
                     "                if http_event.stream_ended and self._waiter and not self._waiter.done():"
                     "                    self._waiter.set_result(True)"
                     ""
                     "    async def get(self, authority):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        self._waiter = self._loop.create_future()"
                     "        headers = ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':path', b'/'),"
                     "            (b':authority', authority.encode()),"
                     "        ]"
                     "        for index in range(100):"
                     "            headers.append((f'x-extra-{index}'.encode(), b'v'))"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(self._waiter, 5)"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    try:"
                     "        async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "            await client.get(f'127.0.0.1:{port}')"
                     "            print(f'RESULT status={client._status} body={client._data.decode()}')"
                     "            client.close()"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=431 body=Request Header Fields Too Large" out)
                     (not (search "body=pazuzu" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun tls-protocol-tests (port)
  (check "HTTP/2 over TLS"
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/" port)
                      "--http2" "-k")
      (unless (string= version "2")
        (fail "version ~s body ~s" version body))
      (unless (and body (search "pazuzu" body))
        (fail "body ~s" body))))
  (check "HTTP/3"
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/" port)
                      "--http3-only" "-k")
      (unless (string= version "3")
        (fail "version ~s body ~s" version body))
      (unless (and body (search "pazuzu" body))
        (fail "body ~s" body))))
  (check "HTTP/3 POST"
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/echo" port)
                      "--http3-only" "-k" "-d" "hello-h3")
      (unless (string= version "3")
        (fail "version ~s body ~s" version body))
      (unless (and body (search "hello-h3" body))
        (fail "body ~s" body))))
  (check "HTTP/3 HEAD and 404"
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/" port)
                      "--http3-only" "-k" "-I")
      (declare (ignore body))
      (unless (string= version "3")
        (fail "HEAD version ~s" version)))
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "--http3-only" "--max-time" "8"
                      "-o" "/dev/null" "-w" "%{http_code} %{http_version}"
                      (format nil "https://127.0.0.1:~d/missing" port))
      (unless (and code (zerop code) (search "404" text) (search "3" text))
        (fail "404 ~s exit ~s" text code))))
  (check "HTTP/3 HEAD sends no content"
    ;; RFC 9110 §9.3.2. The HEAD response is HTTP/3 and has no body.
    ;; The next GET still returns the resource.
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/" port)
                      "--http3-only" "-k" "-X" "HEAD")
      (unless (string= version "3")
        (fail "version ~s body ~s" version body))
      (when (and body (plusp (length (string-trim '(#\Newline #\Return #\Space) body))))
        (fail "HEAD body ~s" body)))
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/" port)
                      "--http3-only" "-k")
      (unless (and (string= version "3") body (search "pazuzu" body))
        (fail "later ~s ~s" version body))))
  (check "HTTP/3 does not end on 1xx"
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "--http3-only" "--max-time" "8"
                      "-w" (format nil "~c%{http_code} %{http_version}" #\Newline)
                      (format nil "https://127.0.0.1:~d/interim" port))
      (unless (and code (zerop code)
                   (search "Internal Server Error" text)
                   (search "500" text)
                   (search "3" text))
        (fail "http3 interim ~s exit ~s" text code)))
  (check "HTTP/3 omits connection-specific fields"
    ;; RFC 9114 §4.2. The handler named them. The wire does not.
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "-D" "-" "--http3-only" "--max-time" "8"
                      (format nil "https://127.0.0.1:~d/hop" port))
      (unless (and code (zerop code) (search "clean" text) (search "HTTP/3" text))
        (fail "http3 hop ~s exit ~s" text code))
      (dolist (name '("connection" "keep-alive" "proxy-connection"
                      "transfer-encoding" "upgrade" "te"))
        (when (search (format nil "~%~a:" name) text :test #'char-equal)
          (fail "http3 sent ~a in ~s" name text))))))
  (check "an HTTP/3 response field name is lowercase"
    ;; RFC 9114 §4.2. The handler spells the name X-Note.
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "-D" "-" "--http3-only" "--max-time" "8"
                      (format nil "https://127.0.0.1:~d/mixed-case" port))
      (unless (and code (zerop code) (search "case" text) (search "HTTP/3" text))
        (fail "http3 case ~s exit ~s" text code))
      (unless (search "x-note: Yes" text)
        (fail "missing lowercase name in ~s" text))
      (when (search "X-Note:" text)
        (fail "uppercase name in ~s" text))))
  (h3-empty-list-test port)
  (h3-too-many-fields-test port)
  (check "HTTP/3 malformed response field is a 500"
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "--http3-only" "--max-time" "8"
                      "-w" (format nil "~c%{http_code} %{http_version}" #\Newline)
                      (format nil "https://127.0.0.1:~d/bad-header" port))
      (unless (and code (zerop code)
                   (search "Internal Server Error" text)
                   (search "500" text)
                   (search "3" text))
        (fail "http3 bad field ~s exit ~s" text code))))
  (check "HTTP/3 rejects a response field that ends with a space"
    ;; RFC 9114 §10.3. field-content does not end with SP.
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-k" "--http3-only" "--max-time" "8"
                      "-w" (format nil "~c%{http_code} %{http_version}" #\Newline)
                      (format nil "https://127.0.0.1:~d/pad-header" port))
      (unless (and code (zerop code)
                   (search "Internal Server Error" text)
                   (search "500" text)
                   (search "3" text))
        (fail "http3 padded field ~s exit ~s" text code))))
  (check "HTTP/3 query"
    (multiple-value-bind (version body)
        (curl-version (format nil "https://127.0.0.1:~d/q?a=1&c=2" port)
                      "--http3-only" "-k")
      (unless (string= version "3")
        (fail "version ~s body ~s" version body))
      (unless (and body (search "a=1;c=2" body))
        (fail "body ~s" body))))
  (check "aioquic HTTP/3 GET, POST, and concurrent streams"
    (aioquic-http3 port))
  (check "HTTP/3 100-continue"
    (aioquic-continue port))
  (h3-informational-length-test port)
  (check "Alt-Svc and HSTS on HTTPS"
    (multiple-value-bind (headers code)
        (command-text "curl" "-sS" "-k" "-D" "-" "-o" "/dev/null" "--http1.1"
                      "--max-time" "8"
                      (format nil "https://127.0.0.1:~d/" port))
      (declare (ignore code))
      (unless (search "alt-svc:" headers :test #'char-equal)
        (fail "no Alt-Svc in ~s" headers))
      (unless (search "h3=" headers)
        (fail "Alt-Svc ~s" headers))
      (unless (search "strict-transport-security:" headers :test #'char-equal)
        (fail "no HSTS in ~s" headers))))
  (check "ALPN prefers h2"
    (multiple-value-bind (text code)
        (command-text "timeout" "3" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-alpn" "h2,http/1.1")
      (declare (ignore code))
      (unless (search "ALPN protocol: h2" text)
        (fail "alpn ~s" text))))
  (h2c-alpn-test port)
  (check "TLS 1.1 is rejected"
    (multiple-value-bind (text code)
        (command-text "timeout" "5" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-tls1_1")
      (when (search "unknown option" text)
        (fail "openssl rejected the flag: ~s" text))
      (unless (and code (plusp code))
        (fail "tls 1.1 exit ~s text ~s" code text))))
  (check "TLS 1.2 HTTP/2 accepts ECDHE-RSA-AES128-GCM-SHA256"
    ;; RFC 9113 §9.2.2. The only offered suite is the mandatory one,
    ;; on P-256, and ALPN selects h2.
    (multiple-value-bind (text code)
        (command-text "timeout" "3" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-tls1_2"
                      "-cipher" "ECDHE-RSA-AES128-GCM-SHA256"
                      "-groups" "prime256v1"
                      "-alpn" "h2")
      (declare (ignore code))
      (unless (and (search "ECDHE-RSA-AES128-GCM-SHA256" text)
                   (search "ALPN protocol: h2" text)
                   (search "prime256v1" text))
        (fail "cipher ~s" text))))
  (tls-compression-test port)
  (tls-post-handshake-auth-test port)
  (tls-renegotiation-test port)
  (tls-close-notify-test port))

(defun call-with-server (function &key (address "127.0.0.1")
                                     certificate private-key hsts-max-age cors
                                     (max-connections nil max-connections-p)
                                     (max-connections-per-peer nil per-peer-p)
                                     (read-timeout nil read-timeout-p)
                                     (workers nil workers-p)
                                     access-log error-log
                                     (metrics-port nil metrics-port-p)
                                     (metrics-token nil metrics-token-p)
                                     (request-rate nil request-rate-p)
                                     (redirect-port nil redirect-port-p)
                                     (user nil user-p))
  (let ((server (apply #'pazuzu:start
                       :address address :port 0
                       :certificate certificate
                       :private-key private-key
                       :hsts-max-age hsts-max-age
                       :cors cors
                       :max-connections (if max-connections-p max-connections 128)
                       :max-connections-per-peer (if per-peer-p max-connections-per-peer 32)
                       :read-timeout (if read-timeout-p read-timeout 30)
                       :workers (if workers-p workers 2)
                       :access-log access-log
                       :error-log error-log
                       :metrics-port (if metrics-port-p metrics-port nil)
                       :metrics-token (if metrics-token-p metrics-token nil)
                       (append (when request-rate-p (list :request-rate request-rate))
                               (when redirect-port-p (list :redirect-port redirect-port))
                               (when user-p (list :user user))))))
    (unwind-protect
         (funcall function server)
      (ignore-errors (pazuzu:stop server)))))

(defun make-cert (dir &optional (cn "127.0.0.1"))
  (ensure-directories-exist dir)
  (let ((key (merge-pathnames "key.pem" dir))
        (cert (merge-pathnames "cert.pem" dir)))
    (uiop:run-program
     (list "openssl" "req" "-x509" "-newkey" "rsa:2048"
           "-keyout" (namestring key)
           "-out" (namestring cert)
           "-days" "1" "-nodes"
           "-subj" (format nil "/CN=~a" cn)
           ;; The suite requests 127.0.0.1 and ::1. CN stays the label
           ;; the reload check searches for.
           "-addext" "subjectAltName=IP:127.0.0.1,IP:::1,DNS:example.com")
     :output :string :error-output :string)
    (values cert key)))

(defun frame-types (octets)
  (loop with index = 0
        with types = nil
        while (and (<= (+ index 9) (length octets))
                   (<= (+ index 9
                          (logior (ash (aref octets index) 16)
                                  (ash (aref octets (+ index 1)) 8)
                                  (aref octets (+ index 2))))
                       (length octets)))
        for type = (aref octets (+ index 3))
        for length = (logior (ash (aref octets index) 16)
                             (ash (aref octets (+ index 1)) 8)
                             (aref octets (+ index 2)))
        do (push type types)
           (incf index (+ 9 length))
        finally (return (nreverse types))))

(defun goaway-last-stream (octets)
  "Last-stream-id of the first complete GOAWAY frame, or NIL."
  (let ((index 0))
    (loop
      (unless (<= (+ index 9) (length octets))
        (return nil))
      (let* ((length (logior (ash (aref octets index) 16)
                             (ash (aref octets (+ index 1)) 8)
                             (aref octets (+ index 2))))
             (type (aref octets (+ index 3))))
        (unless (<= (+ index 9 length) (length octets))
          (return nil))
        (when (and (= type 7) (>= length 8))
          (return (logand #x7fffffff
                          (logior (ash (aref octets (+ index 9)) 24)
                                  (ash (aref octets (+ index 10)) 16)
                                  (ash (aref octets (+ index 11)) 8)
                                  (aref octets (+ index 12))))))
        (incf index (+ 9 length))))))

(defun goaway-test (server)
  (check "HTTP/2 GOAWAY on stop"
    ;; RFC 9113 §8.7. Stream 1 was passed to the application. The GOAWAY
    ;; last-stream-id has to name that stream or a later one.
    (let ((socket (usocket:socket-connect "127.0.0.1" (pazuzu::server-port server)
                                          :element-type '(unsigned-byte 8)))
          (port (pazuzu::server-port server)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu")
             (pazuzu:stop server)
             (let ((last (goaway-last-stream (read-some stream))))
               (unless (and last (>= last 1))
                 (fail "goaway last stream ~s" last))))
        (ignore-errors (usocket:socket-close socket))))))

(defun capacity-and-timeout-tests ()
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "connection cap answers 503"
       (let ((reply (exchange (pazuzu::server-port server)
                              (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
         (expect-status reply 503))))
   :max-connections 0)
  (call-with-server
   (lambda (server)
     (check "partial request times out"
       (let ((socket (usocket:socket-connect "127.0.0.1" (pazuzu::server-port server)
                                             :element-type '(unsigned-byte 8))))
         (unwind-protect
              (let ((stream (usocket:socket-stream socket)))
                (write-byte (char-code #\G) stream)
                (finish-output stream)
                (expect-status (read-reply stream) 408))
           (ignore-errors (usocket:socket-close socket))))))
   :read-timeout 1)
  (call-with-server
   (lambda (server)
     (check "invalid connection preface is a GOAWAY"
       (let ((socket (usocket:socket-connect "127.0.0.1" (pazuzu:server-port server)
                                             :element-type '(unsigned-byte 8))))
         (unwind-protect
              (let ((stream (usocket:socket-stream socket)))
                (write-sequence (babel:string-to-octets "INVALID CONNECTION PREFACE"
                                                        :encoding :ascii)
                                stream)
                (write-sequence #(13 10 13 10) stream)
                (finish-output stream)
                (let ((buf (read-some stream)))
                  (unless (and (>= (length buf) 17)
                               (equalp (subseq buf 0 17)
                                       #(0 0 8 7 0 0 0 0 0 0 0 0 0 0 0 0 1)))
                    (fail "preface reply ~s" buf))))
           (ignore-errors (usocket:socket-close socket))))))))

