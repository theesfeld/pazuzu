;;; HTTP/2 checks.

(in-package #:pazuzu/tests)

(defun extended-connect-test (port)
  "RFC 8441: CONNECT without :protocol is not a tunnel, and :protocol websocket
echoes one masked text frame. Node's HTTP/2 client sends the extended CONNECT."
  (check "HTTP/2 extended CONNECT"
    (let ((script "/tmp/pazuzu-h2-ws.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const authority = `127.0.0.1:${port}`;"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  client.close();"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 3000);"
                     "function request(headers, payload) {"
                     "  return new Promise((resolve, reject) => {"
                     "    const req = client.request(headers);"
                     "    const chunks = [];"
                     "    let response;"
                     "    req.on('response', (received) => { response = received; });"
                     "    req.on('data', (chunk) => chunks.push(chunk));"
                     "    req.on('end', () => resolve({ headers: response, body: Buffer.concat(chunks) }));"
                     "    req.on('error', reject);"
                     "    if (payload) req.write(payload);"
                     "    req.end();"
                     "  });"
                     "}"
                     "const masked = Buffer.from([0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 0x69, 0x6b]);"
                     "try {"
                     "  const plain = await request({ ':method': 'CONNECT', ':authority': authority });"
                     "  if (Number(plain.headers[':status']) !== 501) fail(`plain CONNECT ${plain.headers[':status']}`);"
                     "  const getws = await request({"
                     "    ':method': 'GET',"
                     "    ':path': '/ws',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  if (Number(getws.headers[':status']) !== 400) fail(`GET ws ${getws.headers[':status']}`);"
                     "  if (getws.headers['upgrade']) fail(`upgrade ${getws.headers['upgrade']}`);"
                     "  const other = await request({"
                     "    ':method': 'CONNECT',"
                     "    ':protocol': 'mqtt',"
                     "    ':scheme': 'http',"
                     "    ':path': '/ws',"
                     "    ':authority': authority,"
                     "  });"
                     "  if (Number(other.headers[':status']) !== 501) fail(`mqtt CONNECT ${other.headers[':status']}`);"
                     "  const socket = await request({"
                     "    ':method': 'CONNECT',"
                     "    ':protocol': 'websocket',"
                     "    ':scheme': 'http',"
                     "    ':path': '/ws',"
                     "    ':authority': authority,"
                     "    'sec-websocket-version': '13',"
                     "    'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',"
                     "  }, masked);"
                     "  if (Number(socket.headers[':status']) !== 200) fail(`websocket ${socket.headers[':status']}`);"
                     "  if (socket.headers['sec-websocket-accept'] !== 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=') {"
                     "    fail(`accept ${socket.headers['sec-websocket-accept']}`);"
                     "  }"
                     "  if (socket.headers['content-length'] !== undefined) {"
                     "    fail(`content-length ${socket.headers['content-length']}`);"
                     "  }"
                     "  if (socket.headers['transfer-encoding'] !== undefined) {"
                     "    fail(`transfer-encoding ${socket.headers['transfer-encoding']}`);"
                     "  }"
                     "  const body = socket.body;"
                     "  if (body.length < 4 || body[0] !== 0x81 || body[1] !== 2 || body[2] !== 0x68 || body[3] !== 0x69) {"
                     "    fail(`echo ${body.toString('hex')}`);"
                     "  }"
                     "  console.log('ok');"
                     "  clearTimeout(timer);"
                     "  client.close();"
                     "  process.exit(0);"
                     "} catch (error) {"
                     "  fail(error.message);"
                     "}"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code) (search "ok" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun http2-continue-test (port)
  "RFC 9110 §10.1.1 on HTTP/2. 100 is sent before the body. A missing
target is 404 without the body. Any other expectation is 417.
A failed Authorization, If-Match, or content-coding is final and the
body is not sent."
  (check "HTTP/2 100-continue"
    (let ((script "/tmp/pazuzu-h2-continue.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const authority = `127.0.0.1:${port}`;"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  client.close();"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "function statusOf(req) {"
                     "  return new Promise((resolve, reject) => {"
                     "    req.on('response', (headers) => resolve(Number(headers[':status'])));"
                     "    req.on('error', reject);"
                     "  });"
                     "}"
                     "const missing = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/no-such-continue',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "});"
                     "const missingStatus = await statusOf(missing);"
                     "if (missingStatus !== 404) fail(`missing ${missingStatus}`);"
                     "missing.close();"
                     "const rejected = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/echo',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '0',"
                     "  'expect': '102-processing',"
                     "});"
                     "const rejectedStatus = await statusOf(rejected);"
                     "if (rejectedStatus !== 417) fail(`expect ${rejectedStatus}`);"
                     "rejected.close();"
                     "const unauth = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/basic-continue',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "});"
                     "const unauthHeaders = await new Promise((resolve, reject) => {"
                     "  unauth.on('response', (headers) => resolve(headers));"
                     "  unauth.on('error', reject);"
                     "});"
                     "if (Number(unauthHeaders[':status']) !== 401) fail(`auth ${unauthHeaders[':status']}`);"
                     "const www = String(unauthHeaders['www-authenticate'] || '');"
                     "if (!www.includes('Basic')) fail(`www ${www}`);"
                     "unauth.close();"
                     "const matched = client.request({"
                     "  ':method': 'PUT',"
                     "  ':path': '/item',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "  'if-match': '\"no\"',"
                     "});"
                     "const matchedStatus = await statusOf(matched);"
                     "if (matchedStatus !== 412) fail(`match ${matchedStatus}`);"
                     "matched.close();"
                     "const coded = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/echo',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "  'content-encoding': 'nosuch',"
                     "});"
                     "const codedStatus = await statusOf(coded);"
                     "if (codedStatus !== 415) fail(`coding ${codedStatus}`);"
                     "coded.close();"
                     "const authed = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/basic-continue',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "  'authorization': 'Basic YWRhOnNlY3JldA==',"
                     "});"
                     "let authed100 = false;"
                     "let authedStatus = 0;"
                     "const authedChunks = [];"
                     "const authedDone = new Promise((resolve, reject) => {"
                     "  authed.on('headers', (headers) => {"
                     "    if (Number(headers[':status']) === 100) {"
                     "      authed100 = true;"
                     "      authed.end('ping');"
                     "    }"
                     "  });"
                     "  authed.on('response', (headers) => { authedStatus = Number(headers[':status']); });"
                     "  authed.on('data', (chunk) => authedChunks.push(chunk));"
                     "  authed.on('end', resolve);"
                     "  authed.on('error', reject);"
                     "});"
                     "await authedDone;"
                     "if (!authed100) fail('no auth 100');"
                     "if (authedStatus !== 200) fail(`auth echo ${authedStatus}`);"
                     "if (Buffer.concat(authedChunks).toString() !== 'ping') fail(`auth body ${Buffer.concat(authedChunks).toString()}`);"
                     "const req = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/echo',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "});"
                     "const chunks = [];"
                     "let finalStatus = 0;"
                     "let saw100 = false;"
                     "const done = new Promise((resolve, reject) => {"
                     "  req.on('headers', (headers) => {"
                     "    if (Number(headers[':status']) === 100) {"
                     "      saw100 = true;"
                     "      req.end('echo');"
                     "    }"
                     "  });"
                     "  req.on('response', (headers) => { finalStatus = Number(headers[':status']); });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', resolve);"
                     "  req.on('error', reject);"
                     "});"
                     "await done;"
                     "if (!saw100) fail('no 100');"
                     "if (finalStatus !== 200) fail(`echo ${finalStatus}`);"
                     "const body = Buffer.concat(chunks).toString();"
                     "if (body !== 'echo') fail(`body ${body}`);"
                     "console.log('ok');"
                     "clearTimeout(timer);"
                     "client.close();"
                     "process.exit(0);"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code) (search "ok" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun prior-knowledge-test (port)
  (check "HTTP/2 prior knowledge"
    (multiple-value-bind (version body)
        (curl-version (format nil "http://127.0.0.1:~d/" port)
                      "--http2-prior-knowledge")
      (unless (string= version "2")
        (fail "version ~s body ~s" version body))
      (unless (and body (search "pazuzu" body))
        (fail "body ~s" body))))
  (check "HTTP/2 POST"
    (multiple-value-bind (version body)
        (curl-version (format nil "http://127.0.0.1:~d/echo" port)
                      "--http2-prior-knowledge" "-d" "hello-h2")
      (unless (string= version "2")
        (fail "version ~s body ~s" version body))
      (unless (and body (search "hello-h2" body))
        (fail "body ~s" body))))
  (check "HTTP/2 does not end on 1xx"
    ;; RFC 9113 §8.1. A HEADERS frame that carries 1xx must not set
    ;; END_STREAM. The handler's 100 is a final 500 instead.
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "--http2-prior-knowledge" "--max-time" "8"
                      "-w" (format nil "~c%{http_code} %{http_version}" #\Newline)
                      (format nil "http://127.0.0.1:~d/interim" port))
      (unless (and code (zerop code)
                   (search "Internal Server Error" text)
                   (search "500" text)
                   (search "2" text))
        (fail "http2 interim ~s exit ~s" text code))))
  (check "HTTP/2 omits connection-specific fields"
    ;; RFC 9113 §8.2.2. The handler named them. The wire does not.
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-D" "-" "--http2-prior-knowledge" "--max-time" "8"
                      (format nil "http://127.0.0.1:~d/hop" port))
      (unless (and code (zerop code) (search "clean" text))
        (fail "http2 hop ~s exit ~s" text code))
      (dolist (name '("connection" "keep-alive" "proxy-connection"
                      "transfer-encoding" "upgrade" "te"))
        (when (search (format nil "~%~a:" name) text :test #'char-equal)
          (fail "http2 sent ~a in ~s" name text)))))
  (check "an HTTP/2 response list omits an empty member"
    ;; RFC 9110 §5.6.1.1. The same list fields are sent on HTTP/2.
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-D" "-" "--http2-prior-knowledge" "--max-time" "8"
                      (format nil "http://127.0.0.1:~d/list-field" port))
      (unless (and code (zerop code) (search "listed" text))
        (fail "http2 list ~s exit ~s" text code))
      (unless (search "content-language: en, da" text)
        (fail "http2 language ~s" text))
      (unless (search "vary: accept, accept-language" text)
        (fail "http2 vary ~s" text))
      (unless (search "cache-control: no-cache=\"a, b\", max-age=1" text)
        (fail "http2 cache ~s" text))
      (unless (search "x-note: a, , b" text)
        (fail "http2 note ~s" text))
      (when (search (format nil "~%trailer:") text :test #'char-equal)
        (fail "http2 trailer ~s" text)))))

(defun h2-lowercase-field-test (port)
  "RFC 9113 §8.2. A field name MUST be converted to lowercase when
constructing an HTTP/2 message. The handler spells the name X-Note."
  (check "an HTTP/2 response field name is lowercase"
    (multiple-value-bind (text code)
        (command-text "curl" "-sS" "-D" "-" "--http2-prior-knowledge" "--max-time" "8"
                      (format nil "http://127.0.0.1:~d/mixed-case" port))
      (unless (and code (zerop code) (search "case" text))
        (fail "http2 case ~s exit ~s" text code))
      (unless (search "x-note: Yes" text)
        (fail "missing lowercase name in ~s" text))
      (when (search "X-Note:" text)
        (fail "uppercase name in ~s" text)))))

(defun h2-response-status-test (port)
  "RFC 9113 §8.3. A response carries one :status pseudo-header before the
regular fields and does not carry a request pseudo-header. GET / still
returns pazuzu. Node reports the header names in the order it received them."
  (check "an HTTP/2 response carries only :status"
    (let ((script "/tmp/pazuzu-h2-pseudo.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const req = client.request({"
                     "  ':method': 'GET',"
                     "  ':path': '/',"
                     "  ':scheme': 'http',"
                     "  ':authority': `127.0.0.1:${port}`,"
                     "});"
                     "const chunks = [];"
                     "let names = [];"
                     "let status = '';"
                     "req.on('response', (headers) => {"
                     "  names = Object.keys(headers);"
                     "  status = String(headers[':status']);"
                     "});"
                     "req.on('data', (chunk) => chunks.push(chunk));"
                     "req.on('end', () => {"
                     "  const body = Buffer.concat(chunks).toString();"
                     "  const pseudos = names.filter((name) => name.startsWith(':'));"
                     "  console.log(`RESULT status=${status} body=${body} names=${names.join(',')} pseudos=${pseudos.join(',')} first=${names[0]}`);"
                     "  clearTimeout(timer);"
                     "  client.close();"
                     "  process.exit(0);"
                     "});"
                     "req.on('error', (error) => fail(error.message));"
                     "req.end();"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu " out)
                     (search "pseudos=:status " out)
                     (search "first=:status" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h2-too-many-fields-test (port)
  "RFC 9110 §5.4. HTTP/2 counts every field line, including the
pseudo-header fields. More than 100 is 431, and GET / is not returned."
  (check "too many HTTP/2 header fields is 431"
    (let ((script "/tmp/pazuzu-h2-fields.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const headers = {"
                     "  ':method': 'GET',"
                     "  ':path': '/',"
                     "  ':scheme': 'http',"
                     "  ':authority': `127.0.0.1:${port}`,"
                     "};"
                     "for (let index = 0; index < 100; index += 1) headers[`x-extra-${index}`] = 'v';"
                     "const req = client.request(headers);"
                     "const chunks = [];"
                     "let status = '';"
                     "req.on('response', (headers) => { status = String(headers[':status']); });"
                     "req.on('data', (chunk) => chunks.push(chunk));"
                     "req.on('end', () => {"
                     "  const body = Buffer.concat(chunks).toString();"
                     "  console.log(`RESULT status=${status} body=${body}`);"
                     "  clearTimeout(timer);"
                     "  client.close();"
                     "  process.exit(0);"
                     "});"
                     "req.on('error', (error) => fail(error.message));"
                     "req.end();"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=431 body=Request Header Fields Too Large" out)
                     (not (search "body=pazuzu" out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h2-write-header-block (stream stream-id block)
  "HEADERS plus CONTINUATION. END_STREAM is on HEADERS. END_HEADERS is
on the last frame. Each payload stays within 16384 octets."
  (let ((start 0)
        (total (length block)))
    (loop for first = t then nil
          while (< start total)
          do (let* ((end (min total (+ start 16384)))
                    (last (>= end total))
                    (flags (logior (if first #x01 0) (if last #x04 0))))
               (h2-write stream (h2-frame (if first 1 9) flags stream-id
                                          (subseq block start end)))
               (setf start end)))))

(defun h2-oversized-field-block-test (port)
  "RFC 9113 §10.5.1. A field block larger than the server will handle is
431. The block is still processed, so the dynamic-table entry it inserts
is usable on the next request, which returns pazuzu."
  (check "an oversized field block still updates compression state"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (value (make-array 7000 :element-type '(unsigned-byte 8)
                                          :initial-element 98)))
             (h2-handshake stream)
             (labels ((hpack-bytes (octets)
                        (let ((n (length octets))
                              (out (make-array 0 :element-type '(unsigned-byte 8)
                                               :adjustable t :fill-pointer 0)))
                          (if (< n 127)
                              (vector-push-extend n out)
                              (let ((rest (- n 127)))
                                (vector-push-extend 127 out)
                                (loop while (>= rest 128)
                                      do (vector-push-extend
                                          (logior 128 (logand rest 127)) out)
                                         (setf rest (ash rest -7)))
                                (vector-push-extend rest out)))
                          (loop for byte across octets
                                do (vector-push-extend byte out))
                          out)))
               (let ((block (octets-cat
                             (h2-request-block port)
                             (hpack-incremental "x-a" "z")
                             (apply #'octets-cat
                                    (loop repeat 10
                                          collect (octets-cat #(0)
                                                              (hpack-string "x-big")
                                                              (hpack-bytes value)))))))
                 (h2-write-header-block stream 1 block)))
             (let ((got (make-array 0 :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer 0)))
               (dotimes (ignored 24
                         (fail "body ~s"
                               (ignore-errors
                                (babel:octets-to-string got :encoding :utf-8))))
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 0) (= sid 1))
                          (loop for byte across payload
                                do (vector-push-extend byte got))
                          (when (search (ascii "Request Header Fields Too Large") got)
                            (return))))))
               (when (search (ascii "pazuzu") got)
                 (fail "resource body")))
             ;; Static table length 61. x-a is the first dynamic entry.
             (h2-write stream (h2-frame 1 #x05 3
                                        (octets-cat (h2-request-block port)
                                                    #(#xbe))))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-continued-field-block-test (port)
  "RFC 9113 §6.2. A HEADERS frame without END_HEADERS is followed by a
CONTINUATION frame on the same stream, and by nothing else, until
END_HEADERS. GET /wide-field returns the resource body."
  (check "a continued field block is followed by CONTINUATION"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (phase :before)
                 (got (make-array 0 :element-type '(unsigned-byte 8)
                                  :adjustable t :fill-pointer 0))
                 (want (ascii "split")))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/wide-field")))
             (dotimes (ignored 40
                       (fail "phase ~a body ~s" phase
                             (ignore-errors (babel:octets-to-string got))))
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (ecase phase
                   (:before
                    (cond ((= type 7)
                           (fail "GOAWAY ~d" (h2-u32 payload 4)))
                          ((and (= type 1) (= sid 1))
                           (when (logtest flags #x04)
                             (fail "END_HEADERS on the first fragment"))
                           (setf phase :block))))
                   (:block
                    (unless (and (= type 9) (= sid 1))
                      (fail "frame ~d on stream ~d interrupted the field block"
                            type sid))
                    (when (logtest flags #x04)
                      (setf phase :body)))
                   (:body
                    (cond ((= type 7)
                           (fail "GOAWAY ~d" (h2-u32 payload 4)))
                          ((and (= type 3) (= sid 1))
                           (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                          ((and (= type 0) (= sid 1))
                           (loop for byte across payload
                                 do (vector-push-extend byte got))
                           (when (search want got)
                             (return)))))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-continuation-chain-test (port)
  "RFC 9113 §6.10. A CONTINUATION frame without END_HEADERS is followed
by another CONTINUATION frame on the same stream. GET /wider-field
returns the resource body."
  (check "a CONTINUATION without END_HEADERS is followed by CONTINUATION"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (phase :before)
                 (open-cont nil)
                 (got (make-array 0 :element-type '(unsigned-byte 8)
                                  :adjustable t :fill-pointer 0))
                 (want (ascii "wider")))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/wider-field")))
             (dotimes (ignored 48
                       (fail "phase ~a open ~a body ~s" phase open-cont
                             (ignore-errors (babel:octets-to-string got))))
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (ecase phase
                   (:before
                    (cond ((= type 7)
                           (fail "GOAWAY ~d" (h2-u32 payload 4)))
                          ((and (= type 1) (= sid 1))
                           (when (logtest flags #x04)
                             (fail "END_HEADERS on the first fragment"))
                           (setf phase :block))))
                   (:block
                    (unless (and (= type 9) (= sid 1))
                      (fail "frame ~d on stream ~d interrupted the field block"
                            type sid))
                    (cond ((logtest flags #x04)
                           (unless open-cont
                             (fail "no CONTINUATION lacked END_HEADERS"))
                           (setf phase :body))
                          (t
                           (setf open-cont t))))
                   (:body
                    (cond ((= type 7)
                           (fail "GOAWAY ~d" (h2-u32 payload 4)))
                          ((and (= type 3) (= sid 1))
                           (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                          ((and (= type 0) (= sid 1))
                           (loop for byte across payload
                                 do (vector-push-extend byte got))
                           (when (search want got)
                             (return)))))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun octets-cat (&rest parts)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) parts))

(defun ascii (string)
  (babel:string-to-octets string :encoding :ascii))

(defun hpack-string (string)
  "HPACK string literal without Huffman coding (RFC 7541 §5.2)."
  (let ((raw (ascii string)))
    (when (> (length raw) 126)
      (fail "header too long"))
    (octets-cat (vector (length raw)) raw)))

(defun hpack-indexed-name (index value)
  "Literal header field without indexing, indexed name (RFC 7541 §6.2.2)."
  (octets-cat (if (< index 15)
                  (vector index)
                  (vector 15 (- index 15)))
              (hpack-string value)))

(defun hpack-new-name (name value)
  "Literal header field without indexing, new name (RFC 7541 §6.2.2)."
  (octets-cat #(0) (hpack-string name) (hpack-string value)))

(defun hpack-incremental (name value)
  "Literal header field with incremental indexing, new name (RFC 7541 §6.2.1)."
  (octets-cat #(#x40) (hpack-string name) (hpack-string value)))

(defun h2-frame (type flags stream-id payload)
  (let ((length (length payload)))
    (octets-cat (vector (ldb (byte 8 16) length)
                        (ldb (byte 8 8) length)
                        (ldb (byte 8 0) length)
                        type
                        flags
                        (ldb (byte 8 24) stream-id)
                        (ldb (byte 8 16) stream-id)
                        (ldb (byte 8 8) stream-id)
                        (ldb (byte 8 0) stream-id))
                payload)))

(defun h2-read-frame-within (stream seconds)
  "One HTTP/2 frame, or NIL when none arrives within SECONDS."
  (handler-case
      (sb-sys:with-deadline (:seconds seconds)
        (read-h2-frame stream))
    (sb-sys:deadline-timeout ()
      nil)))

(defun read-h2-frame (stream)
  "Returns type, flags, stream id, payload, and the reserved bit (0 or 1)."
  (let* ((head (read-n stream 9))
         (nbytes (logior (ash (aref head 0) 16)
                         (ash (aref head 1) 8)
                         (aref head 2))))
    (when (> nbytes 65535)
      (fail "frame length ~d" nbytes))
    (values (aref head 3)
            (aref head 4)
            (logand #x7fffffff
                    (logior (ash (aref head 5) 24)
                            (ash (aref head 6) 16)
                            (ash (aref head 7) 8)
                            (aref head 8)))
            (if (plusp nbytes)
                (read-n stream nbytes)
                (make-array 0 :element-type '(unsigned-byte 8)))
            (ldb (byte 1 7) (aref head 5)))))

(defun h2-u32 (payload start)
  (unless (<= (+ start 4) (length payload))
    (fail "short payload ~d" (length payload)))
  (logior (ash (aref payload start) 24)
          (ash (aref payload (+ start 1)) 16)
          (ash (aref payload (+ start 2)) 8)
          (aref payload (+ start 3))))

(defun h2-write (stream octets)
  (write-sequence octets stream)
  (finish-output stream))

(defun h2-request-block (port &key (method "GET") (path "/") content-length extra
                              authority host scheme fields)
  "Request header block. Pseudo-fields come first. No dynamic-table updates.
EXTRA is one (name . value) regular field. FIELDS is a list of those pairs.
HOST is a host field."
  (octets-cat (vector (if (string= method "POST") #x83 #x82))
              (if scheme
                  (hpack-indexed-name 6 scheme)
                  #(#x86))
              (if (string= path "/")
                  #(#x84)
                  (hpack-indexed-name 4 path))
              (hpack-indexed-name 1 (or authority (format nil "127.0.0.1:~d" port)))
              (if content-length
                  (hpack-indexed-name 28 content-length)
                  #())
              (if host
                  (hpack-new-name "host" host)
                  #())
              (if extra
                  (hpack-new-name (car extra) (cdr extra))
                  #())
              (if fields
                  (apply #'octets-cat
                         (mapcar (lambda (pair)
                                   (hpack-new-name (car pair) (cdr pair)))
                                 fields))
                  #())))

(defun h2-settings-pairs (payload)
  (unless (zerop (mod (length payload) 6))
    (fail "SETTINGS length ~d" (length payload)))
  (loop for start from 0 below (length payload) by 6
        collect (cons (logior (ash (aref payload start) 8)
                              (aref payload (1+ start)))
                      (h2-u32 payload (+ start 2)))))

(defun h2-read-server-settings (stream)
  "First non-ACK SETTINGS frame on stream 0. Returns (id . value) pairs."
  (dotimes (ignored 16)
    (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
      (when (and (= type 4) (zerop (logand flags 1)) (zerop sid))
        (return-from h2-read-server-settings (h2-settings-pairs payload)))))
  (fail "no SETTINGS"))

(defun server-preface-test (port)
  "RFC 9113 §3.4 and §6.5.3. The first server frame is SETTINGS, and the
client's preface SETTINGS is acknowledged after that frame."
  (check "the server preface is SETTINGS"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   #(0 0 0 4 0 0 0 0 0)))
             (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
               (unless (and (= type 4) (zerop (logand flags 1)) (zerop sid))
                 (fail "first frame type ~d flags ~d stream ~d" type flags sid))
               (unless (zerop (mod (length payload) 6))
                 (fail "settings length ~d" (length payload))))
             (let ((acked nil))
               (dotimes (ignored 8)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (when (and (= type 4)
                              (not (zerop (logand flags 1)))
                              (zerop sid))
                     (unless (zerop (length payload))
                       (fail "ack payload ~d" (length payload)))
                     (setf acked t)
                     (return))))
               (unless acked
                 (fail "no SETTINGS acknowledgement"))))
        (ignore-errors (usocket:socket-close socket))))))

(defun initial-window-unchanged-test (port)
  "RFC 9113 §6.9.3. This origin does not send SETTINGS_INITIAL_WINDOW_SIZE.
A smaller value would require accepting DATA that still fit the previous
window. The preface SETTINGS has no identifier 4, so that reduction
does not occur."
  (check "the server does not reduce the initial flow-control window"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   #(0 0 0 4 0 0 0 0 0)))
             (when (assoc 4 (h2-read-server-settings stream))
               (fail "settings include initial window")))
        (ignore-errors (usocket:socket-close socket))))))

(defun preface-followed-by-settings-test (port)
  "RFC 9113 §3.4. The 24-octet client preface is followed by a SETTINGS
frame. A PING in that position is an invalid preface, a connection
error of type PROTOCOL_ERROR."
  (check "the client preface is followed by SETTINGS"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (code nil))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   (h2-frame 6 0 0 #(1 2 3 4 5 6 7 8))))
             (handler-case
                 (dotimes (ignored 8)
                   (multiple-value-bind (type flags sid payload)
                       (read-h2-frame stream)
                     (declare (ignore flags sid))
                     (when (eql type 7)
                       (setf code (h2-u32 payload 4))
                       (return))))
               (error ()
                 nil))
             (unless (eql code 1)
               (fail "GOAWAY ~s" code)))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-stream-test (port)
  "RFC 9113 §6.5. A SETTINGS frame on a non-zero stream is a connection
error of type PROTOCOL_ERROR."
  (check "SETTINGS on a stream is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 0 1 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-ack-test (port)
  "RFC 9113 §6.5. A SETTINGS acknowledgement with a payload is
FRAME_SIZE_ERROR."
  (check "a SETTINGS acknowledgement carries no payload"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 1 0 #(0 1 0 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-length-test (port)
  "RFC 9113 §6.5. A SETTINGS payload whose length is not a multiple of 6
is FRAME_SIZE_ERROR."
  (check "a SETTINGS length is a multiple of six"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 0 0 #(0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-window-test (port)
  "RFC 9113 §6.5.2. SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1 is
FLOW_CONTROL_ERROR."
  (check "an initial window above 2^31-1 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 0 0 #(0 4 128 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 3)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-frame-size-test (port)
  "RFC 9113 §6.5.2. SETTINGS_MAX_FRAME_SIZE below 16384 is PROTOCOL_ERROR."
  (check "a max frame size below 16384 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 0 0 #(0 5 0 0 63 255)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-frame-size-upper-test (port)
  "RFC 9113 §6.5.2. SETTINGS_MAX_FRAME_SIZE above 2^24-1 is a connection
error of type PROTOCOL_ERROR."
  (check "a max frame size above 2^24-1 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Identifier 5, value 2^24.
             (h2-write stream (h2-frame 4 0 0 #(0 5 1 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-frame-size-max-test (port)
  "RFC 9113 §6.5.2. SETTINGS_MAX_FRAME_SIZE of 2^24-1 is the largest
allowed value. The connection still answers GET /."
  (check "a max frame size of 2^24-1 is accepted"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Identifier 5, value 16,777,215.
             (h2-write stream (h2-frame 4 0 0 #(0 5 0 255 255 255)))
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-push-value-test (port)
  "RFC 9113 §6.5.2. SETTINGS_ENABLE_PUSH other than 0 or 1 is
PROTOCOL_ERROR."
  (check "ENABLE_PUSH other than 0 or 1 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 0 0 #(0 2 0 0 0 2)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun unknown-setting-test (port)
  "RFC 9113 §6.5.2. An unknown setting identifier is ignored. The
connection still serves the next request."
  (check "an unknown setting is ignored"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 4 0 0 #(0 255 0 0 0 1)))
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun data-on-stream-zero-test (port)
  "RFC 9113 §6.1. DATA on stream 0 is a connection error of type
PROTOCOL_ERROR."
  (check "DATA on stream 0 is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 0 0 0 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun goaway-closes-connection-test (port)
  "RFC 9113 §5.4.1. After GOAWAY for a connection error, the TCP
connection closes. DATA on stream 0 is that error."
  (check "a connection error closes the TCP connection"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 0 0 0 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code)))
             (let ((end (handler-case
                            (sb-sys:with-deadline (:seconds 2)
                              (loop for byte = (read-byte stream nil :eof)
                                    until (eq byte :eof)
                                    finally (return :eof)))
                          (sb-sys:deadline-timeout () :open))))
               (unless (eq end :eof)
                 (fail "still open ~s" end))))
        (ignore-errors (usocket:socket-close socket))))))

(defun data-padding-test (port)
  "RFC 9113 §6.1. Pad Length at least as large as the DATA payload is
a connection error of type PROTOCOL_ERROR."
  (check "DATA padding covers the whole payload"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST")))
             ;; PADDED. The one payload octet is the pad length, so the
             ;; padding is not shorter than the payload.
             (h2-write stream (h2-frame 0 #x08 1 #(1)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun headers-on-stream-zero-test (port)
  "RFC 9113 §6.2. A HEADERS frame on stream 0 is a connection error of
type PROTOCOL_ERROR."
  (check "HEADERS on stream 0 is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 0 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun headers-padding-test (port)
  "RFC 9113 §6.2. Pad Length at least as large as the HEADERS payload
is a connection error of type PROTOCOL_ERROR."
  (check "HEADERS padding covers the whole payload"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; PADDED on stream 1. The one payload octet is the pad
             ;; length, so the padding is not shorter than the payload.
             (h2-write stream (h2-frame 1 #x08 1 #(1)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun headers-continuation-test (port)
  "RFC 9113 §6.2. A HEADERS frame without END_HEADERS must be followed
by CONTINUATION on the same stream. Any other frame is a connection
error of type PROTOCOL_ERROR."
  (check "HEADERS without END_HEADERS needs CONTINUATION"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 0 1 #()))
             (h2-write stream (h2-frame 0 0 1 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun headers-other-stream-test (port)
  "RFC 9113 §6.2. A HEADERS frame without END_HEADERS followed by a
frame on a different stream is a connection error of type PROTOCOL_ERROR."
  (check "a header block cannot continue on another stream"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 0 1 #()))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun continuation-other-stream-test (port)
  "RFC 9113 §6.10. A CONTINUATION frame without END_HEADERS followed by
a frame on a different stream is a connection error of type
PROTOCOL_ERROR."
  (check "a CONTINUATION block cannot continue on another stream"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 0 1 #()))
             (h2-write stream (h2-frame 9 0 1 #()))
             ;; Same frame type, different stream.
             (h2-write stream (h2-frame 9 #x04 3 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun continuation-other-type-test (port)
  "RFC 9113 §6.10. A CONTINUATION frame without END_HEADERS followed by
any other frame type is a connection error of type PROTOCOL_ERROR.
PING would otherwise be legal on stream 0."
  (check "a CONTINUATION block cannot be interrupted"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 0 1 #()))
             (h2-write stream (h2-frame 9 0 1 #()))
             (h2-write stream (h2-frame 6 0 0 #(1 2 3 4 5 6 7 8)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun rst-on-stream-zero-test (port)
  "RFC 9113 §6.4. RST_STREAM on stream 0 is a connection error of type
PROTOCOL_ERROR."
  (check "RST_STREAM on stream 0 is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Error code PROTOCOL_ERROR. The stream identifier is 0.
             (h2-write stream (h2-frame 3 0 0 #(0 0 0 1)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun rst-idle-test (port)
  "RFC 9113 §6.4. RST_STREAM for an idle stream is a connection error
of type PROTOCOL_ERROR."
  (check "RST_STREAM on an idle stream is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Stream 1 was never opened. Four octets is a legal length.
             (h2-write stream (h2-frame 3 0 1 #(0 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun rst-length-test (port)
  "RFC 9113 §6.4. A RST_STREAM whose length is not 4 octets is a
connection error of type FRAME_SIZE_ERROR."
  (check "RST_STREAM length is four octets"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Open the stream so the failure is the length, not idle.
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST")))
             (h2-write stream (h2-frame 3 0 1 #()))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun even-stream-test (port)
  "RFC 9113 §5.1.1. A client stream identifier is odd. HEADERS on an
even stream is a connection error of type PROTOCOL_ERROR."
  (check "an even stream identifier is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 2 (h2-request-block port)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun decreasing-stream-test (port)
  "RFC 9113 §5.1.1. A new stream identifier must be greater than every
stream the client has already opened. A smaller identifier is a
connection error of type PROTOCOL_ERROR."
  (check "a decreasing stream identifier is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 5 (h2-request-block port)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun ping-stream-test (port)
  "RFC 9113 §6.7. A PING frame on a stream other than 0 is a connection
error of type PROTOCOL_ERROR."
  (check "PING on a stream is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 6 0 1 #(1 2 3 4 5 6 7 8)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun ping-length-test (port)
  "RFC 9113 §6.7. A PING frame whose length is not 8 octets is a
connection error of type FRAME_SIZE_ERROR."
  (check "PING length is eight octets"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 6 0 0 #(1)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun ping-ack-test (port)
  "RFC 9113 §6.7. A PING without ACK is answered by a PING with ACK and
the same payload. A PING that already has ACK is not answered."
  (check "PING is acknowledged with the same payload"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (opaque #(9 8 7 6 5 4 3 2)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 6 0 0 opaque))
             (let ((acked nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (when (and (= type 6) (= sid 0) (logtest flags 1)
                              (equalp payload opaque))
                     (setf acked t)
                     (return))))
               (unless acked
                 (fail "no PING ACK")))
             (let ((again #(1 1 1 1 1 1 1 1)))
               (h2-write stream (h2-frame 6 1 0 again))
               (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
               (let ((got (make-array 0 :element-type '(unsigned-byte 8)
                                      :adjustable t :fill-pointer 0))
                     (want (ascii "pazuzu")))
                 (dotimes (ignored 16
                           (fail "body ~s" (ignore-errors
                                            (babel:octets-to-string got))))
                   (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                     (declare (ignore flags))
                     (cond ((and (= type 6) (equalp payload again))
                            (fail "answered an ACK PING"))
                           ((= type 7)
                            (fail "GOAWAY ~d" (h2-u32 payload 4)))
                           ((and (= type 0) (= sid 1))
                            (loop for byte across payload
                                  do (vector-push-extend byte got))
                            (when (search want got)
                              (return)))))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun ping-after-goaway-test (port)
  "RFC 9113 §6.7. A PING that does not carry ACK is acknowledged with
the same payload after the client has sent GOAWAY. nghttp2 skips that
acknowledgement once the peer has sent GOAWAY."
  (check "a PING after a client GOAWAY is acknowledged"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (opaque #(9 8 7 6 5 4 3 2))
                 (acked nil))
             (h2-handshake stream)
             (h2-write stream
                       (octets-cat (h2-frame 7 0 0 #(0 0 0 0 0 0 0 0))
                                   (h2-frame 6 0 0 opaque)))
             (handler-case
                 (dotimes (ignored 12)
                   (multiple-value-bind (type flags sid payload)
                       (read-h2-frame stream)
                     (declare (ignore sid))
                     (when (and (= type 6) (logtest flags 1)
                                (equalp payload opaque))
                       (setf acked t)
                       (return))
                     (when (and (= type 7) payload
                                (not (eql (h2-u32 payload 4) 0)))
                       (fail "GOAWAY ~d" (h2-u32 payload 4)))))
               (error ()
                 nil))
             (unless acked
               (fail "no PING ACK")))
        (ignore-errors (usocket:socket-close socket))))))

(defun goaway-stream-test (port)
  "RFC 9113 §6.8. A GOAWAY frame on a stream other than 0 is a
connection error of type PROTOCOL_ERROR."
  (check "GOAWAY on a stream is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Last-Stream-ID 0 and NO_ERROR. The stream identifier is 1.
             (h2-write stream (h2-frame 7 0 1 #(0 0 0 0 0 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun priority-length-test (port)
  "RFC 9113 §6.3. A PRIORITY frame whose length is not 5 octets is a
stream error of type FRAME_SIZE_ERROR. Section 5.4.1 allows that to be
reported as a connection error of the same type."
  (check "a PRIORITY frame of the wrong length is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 2 0 1 #(0)))
             (let ((rst nil)
                   (goaway nil))
               (loop for ignored below 12
                     do (multiple-value-bind (type flags sid payload)
                            (h2-read-frame-within stream 0.4)
                          (declare (ignore flags))
                          (cond ((null type)
                                 (return))
                                ((and (= type 3) (= sid 1))
                                 (setf rst (h2-u32 payload 0))
                                 (return))
                                ((= type 7)
                                 (setf goaway (h2-u32 payload 4))
                                 (return)))))
               (unless (or (eql rst 6) (eql goaway 6))
                 (fail "RST ~s GOAWAY ~s" rst goaway))))
        (ignore-errors (usocket:socket-close socket))))))

(defun rst-then-data-test (port)
  "RFC 9113 §5.1. After this endpoint receives RST_STREAM, a DATA frame
on that stream is a stream error of type STREAM_CLOSED. Section 5.4.2
allows the same code as a connection error. DATA that follows a reset
this endpoint sent is still discarded."
  (check "DATA after a received RST_STREAM is STREAM_CLOSED"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 3 0 1 #(0 0 0 8)))
             (h2-write stream (h2-frame 0 1 1 #(116 101 115 116)))
             (let ((code nil))
               (loop for ignored below 12
                     do (multiple-value-bind (type flags sid payload)
                            (h2-read-frame-within stream 0.4)
                          (declare (ignore flags))
                          (cond ((null type) (return))
                                ((and (= type 3) (= sid 1))
                                 (setf code (h2-u32 payload 0))
                                 (return))
                                ((= type 7)
                                 (setf code (h2-u32 payload 4))
                                 (return)))))
               (unless (eql code 5)
                 (fail "RST/GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun rst-then-headers-test (port)
  "RFC 9113 §5.1. After this endpoint receives RST_STREAM, a HEADERS
frame on that stream is STREAM_CLOSED."
  (check "HEADERS after a received RST_STREAM is STREAM_CLOSED"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 3 0 1 #(0 0 0 8)))
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (let ((code nil))
               (loop for ignored below 12
                     do (multiple-value-bind (type flags sid payload)
                            (h2-read-frame-within stream 0.4)
                          (declare (ignore flags))
                          (cond ((null type) (return))
                                ((and (= type 3) (= sid 1))
                                 (setf code (h2-u32 payload 0))
                                 (return))
                                ((= type 7)
                                 (setf code (h2-u32 payload 4))
                                 (return)))))
               (unless (eql code 5)
                 (fail "RST/GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun priority-stream-zero-test (port)
  "RFC 9113 §6.3. A PRIORITY frame on stream 0 is a connection error of
type PROTOCOL_ERROR. nghttp2 discards a 5-octet PRIORITY frame."
  (check "a PRIORITY frame on stream 0 is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 2 0 0 #(0 0 0 0 255)))
             (let ((code nil))
               (loop for ignored below 12
                     do (multiple-value-bind (type flags sid payload)
                            (h2-read-frame-within stream 0.4)
                          (declare (ignore flags sid))
                          (cond ((null type) (return))
                                ((= type 7)
                                 (setf code (h2-u32 payload 4))
                                 (return)))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun priority-self-test (port)
  "RFC 7540 §5.3.1, the rule h2spec 5.3.1/2 executes. A PRIORITY frame
whose dependency is its own stream is PROTOCOL_ERROR. RFC 9113 removed
the dependency semantics and nghttp2 drops the frame, so the connection
error carries that code."
  (check "a self-dependent PRIORITY frame is PROTOCOL_ERROR"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 2 0 1 #(0 0 0 1 255)))
             (let ((code nil))
               (loop for ignored below 12
                     do (multiple-value-bind (type flags sid payload)
                            (h2-read-frame-within stream 0.4)
                          (declare (ignore flags))
                          (cond ((null type) (return))
                                ((and (= type 3) (= sid 1))
                                 (setf code (h2-u32 payload 0))
                                 (return))
                                ((= type 7)
                                 (setf code (h2-u32 payload 4))
                                 (return)))))
               (unless (eql code 1)
                 (fail "RST/GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun goaway-length-test (port)
  "RFC 9113 §4.2 and §6.8. A GOAWAY frame must carry a last stream
identifier and an error code. Fewer than 8 octets is too small, which
is a connection error of type FRAME_SIZE_ERROR."
  (check "a short GOAWAY is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 7 0 0 #(0 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-zero-test (port)
  "RFC 9113 §6.9. A WINDOW_UPDATE that increases the connection
flow-control window by 0 is a connection error of type PROTOCOL_ERROR."
  (check "a zero connection window increment is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 8 0 0 #(0 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-length-test (port)
  "RFC 9113 §6.9. A WINDOW_UPDATE whose length is not 4 octets is a
connection error of type FRAME_SIZE_ERROR."
  (check "WINDOW_UPDATE length is four octets"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 8 0 0 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-overflow-test (port)
  "RFC 9113 §6.9.1. A WINDOW_UPDATE that makes the connection
flow-control window exceed 2^31-1 is a connection error of type
FLOW_CONTROL_ERROR."
  (check "a connection window above 2^31-1 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Increment 2^31-1. The connection window starts at 65535.
             (h2-write stream (h2-frame 8 0 0 #(127 255 255 255)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 3)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun continuation-stream-zero-test (port)
  "RFC 9113 §6.10. A CONTINUATION frame on stream 0 is a connection
error of type PROTOCOL_ERROR."
  (check "CONTINUATION on stream 0 is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 9 #x04 0 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun continuation-unexpected-test (port)
  "RFC 9113 §6.10. A CONTINUATION that is not preceded by a HEADERS,
PUSH_PROMISE, or CONTINUATION without END_HEADERS is a connection
error of type PROTOCOL_ERROR."
  (check "a CONTINUATION without a header block is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 9 #x04 1 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun client-push-test (port)
  "RFC 9113 §8.4. A server treats a PUSH_PROMISE from the client as a
connection error of type PROTOCOL_ERROR."
  (check "a client PUSH_PROMISE is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST")))
             ;; Promised stream 2, END_HEADERS, empty field block.
             (h2-write stream (h2-frame 5 #x04 1 #(0 0 0 2)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun unknown-frame-test (port)
  "RFC 9113 §4.1 and §5.5. A frame of unknown type is discarded. The
connection still serves the next request."
  (check "an unknown frame type is ignored"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 10 0 0 #(1 2 3)))
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun unused-flag-test (port)
  "RFC 9113 §4.1. An unused flag on HEADERS is ignored."
  (check "an unused HEADERS flag is ignored"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; 0x01 END_STREAM, 0x02 unused, 0x04 END_HEADERS.
             (h2-write stream (h2-frame 1 #x07 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-unused-flag-mask (type)
  "Flag bits RFC 9113 does not define for TYPE. Those bits must be unset
on a frame this endpoint sends. A type with no defined flags uses every bit."
  (case type
    (0 #xF6)                            ; DATA: END_STREAM, PADDED
    (1 #xD2)                            ; HEADERS: END_STREAM, END_HEADERS, PADDED, PRIORITY
    (4 #xFE)                            ; SETTINGS: ACK
    (5 #xF3)                            ; PUSH_PROMISE: END_HEADERS, PADDED
    (6 #xFE)                            ; PING: ACK
    (9 #xFB)                            ; CONTINUATION: END_HEADERS
    (otherwise #xFF)))

(defun server-unused-flags-test (port)
  "RFC 9113 §4.1. Unused flags are left unset on frames the server sends."
  (check "the server leaves unused HTTP/2 flags unset"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (saw-settings nil)
                 (saw-headers nil)
                 (saw-data nil)
                 (body (make-array 0 :element-type '(unsigned-byte 8)
                                   :adjustable t :fill-pointer 0)))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   #(0 0 0 4 0 0 0 0 0)))
             (labels ((check-flags (type flags)
                        (let ((bad (logand flags (h2-unused-flag-mask type))))
                          (unless (zerop bad)
                            (fail "type ~d flags ~d unused ~d" type flags bad)))))
               (let ((acked nil))
                 (dotimes (ignored 8)
                   (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                     (declare (ignore sid payload))
                     (check-flags type flags)
                     (when (and (= type 4) (zerop (logand flags 1)))
                       (setf saw-settings t)
                       (h2-write stream #(0 0 0 4 1 0 0 0 0))
                       (setf acked t)
                       (return))))
                 (unless acked
                   (fail "no SETTINGS")))
               (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
               (dotimes (ignored 24)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (check-flags type flags)
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 1) (= sid 1))
                          (setf saw-headers t))
                         ((and (= type 0) (= sid 1))
                          (setf saw-data t)
                          (loop for byte across payload
                                do (vector-push-extend byte body)))))
                 (when (and saw-data (search (ascii "pazuzu") body))
                   (return))))
             (unless (and saw-settings saw-headers saw-data)
               (fail "frames settings ~a headers ~a data ~a"
                     saw-settings saw-headers saw-data))
             (unless (search (ascii "pazuzu") body)
               (fail "body ~s"
                     (ignore-errors (babel:octets-to-string body :encoding :utf-8)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun server-reserved-bit-test (port)
  "RFC 9113 §4.1. The reserved bit stays unset on frames the server sends."
  (check "the server leaves the HTTP/2 reserved bit unset"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (saw-settings nil)
                 (saw-headers nil)
                 (saw-data nil)
                 (body (make-array 0 :element-type '(unsigned-byte 8)
                                   :adjustable t :fill-pointer 0)))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   #(0 0 0 4 0 0 0 0 0)))
             (labels ((check-reserved (type reserved)
                        (unless (zerop reserved)
                          (fail "type ~d reserved ~d" type reserved))))
               (let ((acked nil))
                 (dotimes (ignored 8)
                   (multiple-value-bind (type flags sid payload reserved)
                       (read-h2-frame stream)
                     (declare (ignore sid payload))
                     (check-reserved type reserved)
                     (when (and (= type 4) (zerop (logand flags 1)))
                       (setf saw-settings t)
                       (h2-write stream #(0 0 0 4 1 0 0 0 0))
                       (setf acked t)
                       (return))))
                 (unless acked
                   (fail "no SETTINGS")))
               (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
               (dotimes (ignored 24)
                 (multiple-value-bind (type flags sid payload reserved)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (check-reserved type reserved)
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 1) (= sid 1))
                          (setf saw-headers t))
                         ((and (= type 0) (= sid 1))
                          (setf saw-data t)
                          (loop for byte across payload
                                do (vector-push-extend byte body)))))
                 (when (and saw-data (search (ascii "pazuzu") body))
                   (return))))
             (unless (and saw-settings saw-headers saw-data)
               (fail "frames settings ~a headers ~a data ~a"
                     saw-settings saw-headers saw-data))
             (unless (search (ascii "pazuzu") body)
               (fail "body ~s"
                     (ignore-errors (babel:octets-to-string body :encoding :utf-8)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun server-padding-zero-test (port)
  "RFC 9113 §§6.1 and 6.2. Padding octets are zero on frames the server
sends. GET / is 200 with body pazuzu, and every DATA, HEADERS, and
PUSH_PROMISE frame leaves those octets at zero."
  (check "server HTTP/2 padding octets are zero"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (saw-settings nil)
                 (saw-headers nil)
                 (saw-data nil)
                 (nonzero 0)
                 (body (make-array 0 :element-type '(unsigned-byte 8)
                                   :adjustable t :fill-pointer 0)))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   #(0 0 0 4 0 0 0 0 0)))
             (labels ((note (type flags payload)
                        (when (and (member type '(0 1 5))
                                   (plusp (logand flags #x08)))
                          (cond ((zerop (length payload))
                                 (incf nonzero))
                                (t
                                 (let* ((pad (aref payload 0))
                                        (prefix (cond ((and (= type 1)
                                                            (plusp (logand flags #x20)))
                                                       6)
                                                      ((= type 5) 5)
                                                      (t 1))))
                                   (cond ((> pad (- (length payload) prefix))
                                          (incf nonzero))
                                         (t
                                          (loop for index from (- (length payload) pad)
                                                  below (length payload)
                                                do (unless (zerop (aref payload index))
                                                     (incf nonzero)))))))))))
               (let ((acked nil))
                 (dotimes (ignored 8)
                   (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                     (declare (ignore sid))
                     (note type flags payload)
                     (when (and (= type 4) (zerop (logand flags 1)))
                       (setf saw-settings t)
                       (h2-write stream #(0 0 0 4 1 0 0 0 0))
                       (setf acked t)
                       (return))))
                 (unless acked
                   (fail "no SETTINGS")))
               (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
               (dotimes (ignored 24)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (note type flags payload)
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 1) (= sid 1))
                          (setf saw-headers t))
                         ((and (= type 0) (= sid 1))
                          (setf saw-data t)
                          (loop for byte across payload
                                do (vector-push-extend byte body)))))
                 (when (and saw-data (search (ascii "pazuzu") body))
                   (return))))
             (unless (and saw-settings saw-headers saw-data)
               (fail "frames settings ~a headers ~a data ~a"
                     saw-settings saw-headers saw-data))
             (unless (zerop nonzero)
               (fail "nonzero padding ~d" nonzero))
             (unless (search (ascii "pazuzu") body)
               (fail "body ~s"
                     (ignore-errors (babel:octets-to-string body :encoding :utf-8)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun server-frame-limit-test (port)
  "RFC 9113 §4.1. A frame larger than 2^14 is not sent unless the peer
raised SETTINGS_MAX_FRAME_SIZE. The client leaves that setting at 16384.
GET /wide is 20000 octets, so the body occupies more than one DATA frame."
  (check "a response frame stays within the default max frame size"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (data-frames 0)
                 (body (make-array 0 :element-type '(unsigned-byte 8)
                                   :adjustable t :fill-pointer 0))
                 (want (make-array 20000 :element-type '(unsigned-byte 8)
                                   :initial-element (char-code #\w))))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/wide")))
             (dotimes (ignored 24)
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (declare (ignore flags))
                 (when (> (length payload) 16384)
                   (fail "type ~d length ~d" type (length payload)))
                 (cond ((= type 7)
                        (fail "GOAWAY ~d" (h2-u32 payload 4)))
                       ((and (= type 3) (= sid 1))
                        (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                       ((and (= type 0) (= sid 1))
                        (incf data-frames)
                        (loop for byte across payload
                              do (vector-push-extend byte body)))))
               (when (and (>= data-frames 2) (= (length body) 20000))
                 (return)))
             (unless (>= data-frames 2)
               (fail "DATA frames ~d" data-frames))
             (unless (= (length body) 20000)
               (fail "body length ~d" (length body)))
             (unless (equalp body want)
               (fail "body mismatch")))
        (ignore-errors (usocket:socket-close socket))))))

(defun server-flow-window-test (port)
  "RFC 9113 §6.9.1. The sender does not send a DATA frame longer than
the space left in the receiver's flow-control window. The client leaves
both windows at the default 65535 and does not send WINDOW_UPDATE.
GET /flow-conn is 65536 octets, one past that window."
  (check "a response stays within the default flow-control window"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (got 0)
                 (quiet 0))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/flow-conn")))
             (loop repeat 40
                   do (multiple-value-bind (type flags sid payload)
                          (h2-read-frame-within stream 0.25)
                        (declare (ignore flags))
                        (cond ((null type)
                               (incf quiet)
                               (when (and (plusp got) (>= quiet 2))
                                 (return)))
                              (t
                               (setf quiet 0)
                               (cond ((= type 7)
                                      (fail "GOAWAY ~d" (h2-u32 payload 4)))
                                     ((and (= type 3) (= sid 1))
                                      (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                                     ((and (= type 0) (= sid 1))
                                      (incf got (length payload))))))))
             (unless (<= got 65535)
               (fail "sent ~d octets past the window" got))
             (unless (= got 65535)
               (fail "stopped at ~d octets" got)))
        (ignore-errors (usocket:socket-close socket))))))

(defun server-negative-window-test (port)
  "RFC 9113 §6.9.2. A SETTINGS_INITIAL_WINDOW_SIZE change that makes the
send window negative stops DATA. A WINDOW_UPDATE that leaves the window
negative does not release more data. One that makes it positive releases
only the positive credit. The client sets the initial stream window to
1000, reads that much of GET /wide, then lowers the setting to 0."
  (check "a negative flow-control window sends no data"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (labels ((read-one (&optional (pause 0.25))
                        (h2-read-frame-within stream pause))
                      (note-frame (type sid payload)
                        (cond ((= type 7)
                               (fail "GOAWAY ~d" (h2-u32 payload 4)))
                              ((and (= type 3) (= sid 1))
                               (fail "RST_STREAM ~d" (h2-u32 payload 0)))))
                      (drain (&key (pause 0.25) (limit 40))
                        (let ((got 0)
                              (quiet 0))
                          (loop repeat limit
                                do (multiple-value-bind (type flags sid payload)
                                       (read-one pause)
                                     (declare (ignore flags))
                                     (cond ((null type)
                                            (incf quiet)
                                            (when (>= quiet 2)
                                              (return)))
                                           (t
                                            (setf quiet 0)
                                            (note-frame type sid payload)
                                            (when (and (= type 0) (= sid 1))
                                              (incf got (length payload)))))))
                          got))
                      (await-ack ()
                        (loop repeat 12
                              do (multiple-value-bind (type flags sid payload)
                                     (read-one 0.5)
                                   (cond ((null type)
                                          (fail "no SETTINGS acknowledgement"))
                                         (t
                                          (note-frame type sid payload)
                                          (when (and (= type 0) (= sid 1))
                                            (fail "DATA of ~d during settings"
                                                  (length payload)))
                                          (when (and (= type 4)
                                                     (not (zerop (logand flags 1))))
                                            (return))))))))
               ;; Drop the preface acknowledgement before the next SETTINGS.
               (drain :pause 0.1 :limit 8)
               (h2-write stream (h2-frame 4 0 0 #(0 4 0 0 3 232)))
               (await-ack)
               (h2-write stream (h2-frame 1 #x05 1
                                          (h2-request-block port :path "/wide")))
               (let ((got (drain)))
                 (unless (= got 1000)
                   (fail "initial window delivered ~d" got)))
               (h2-write stream (h2-frame 4 0 0 #(0 4 0 0 0 0)))
               (await-ack)
               ;; Window is -1000. An increment of 500 leaves it negative.
               (h2-write stream (h2-frame 8 0 1 #(0 0 1 244)))
               (let ((extra (drain)))
                 (unless (zerop extra)
                   (fail "negative window delivered ~d" extra)))
               ;; -500 + 1500 = 1000 octets of credit.
               (h2-write stream (h2-frame 8 0 1 #(0 0 5 220)))
               (let ((extra (drain)))
                 (unless (= extra 1000)
                   (fail "restored window delivered ~d" extra)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun reserved-bit-test (port)
  "RFC 9113 §4.1. The reserved bit in the stream identifier is ignored."
  (check "the reserved stream bit is ignored"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 (logior 1 (ash 1 31))
                                        (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun oversized-frame-test (port)
  "RFC 9113 §4.2. A frame larger than SETTINGS_MAX_FRAME_SIZE, which
starts at 16384, is a connection error of type FRAME_SIZE_ERROR.
An unknown type is used so the size is the only fault, and stream 0
makes that fault a connection error."
  (check "a frame larger than 16384 octets is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 10 0 0
                                 (make-array 16385
                                             :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 6)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun data-on-idle-test (port)
  "RFC 9113 §5.1. DATA on an idle stream is a connection error of type
PROTOCOL_ERROR."
  (check "DATA on an idle stream is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 0 0 1 #()))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-on-idle-test (port)
  "RFC 9113 §5.1. A WINDOW_UPDATE on an idle stream is a connection
error of type PROTOCOL_ERROR. The increment is 1, so the fault is the
idle state and not a zero increment."
  (check "WINDOW_UPDATE on an idle stream is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 8 0 1 #(0 0 0 1)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun unknown-frame-in-block-test (port)
  "RFC 9113 §5.5. An unknown frame between the frames of one field
block is a connection error of type PROTOCOL_ERROR."
  (check "an unknown frame inside a header block is a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 0 1 #()))
             (h2-write stream (h2-frame 10 0 1 #(0)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-stream-zero-test (port)
  "RFC 9113 §6.9. A WINDOW_UPDATE of 0 on a stream is an error of type
PROTOCOL_ERROR. Section 5.4.2 allows that stream error to be reported
as a connection error."
  (check "a zero stream window increment is PROTOCOL_ERROR"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST")))
             (h2-write stream (h2-frame 8 0 1 #(0 0 0 0)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun max-frame-test (port)
  "RFC 9113 §4.2. A recipient must accept a frame payload of 2^14
octets, the initial maximum frame size."
  (check "a frame of 16384 octets is accepted"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (body (make-array 16384 :element-type '(unsigned-byte 8)
                                   :initial-element 97)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST"
                                                          :path "/echo"
                                                          :content-length "16384")))
             (h2-write stream (h2-frame 0 #x01 1 body))
             (let ((got (make-array 0 :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer 0)))
               (dotimes (ignored 24
                         (fail "body length ~d" (length got)))
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 0) (= sid 1))
                          (loop for byte across payload
                                do (vector-push-extend byte got))
                          (when (= (length got) 16384)
                            (unless (every (lambda (byte) (= byte 97)) got)
                              (fail "echo mismatch"))
                            (return))))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun data-half-closed-test (port)
  "RFC 9113 §5.1. DATA after the request has ended is a stream error of
type STREAM_CLOSED. Section 5.4.2 allows that to be a connection error
of the same type."
  (check "DATA after END_STREAM is STREAM_CLOSED"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-write stream (h2-frame 0 0 1 #(1)))
             (let ((rst nil)
                   (goaway nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (setf goaway (h2-u32 payload 4))
                          (return))
                         ((and (= type 3) (= sid 1))
                          (setf rst (h2-u32 payload 0))
                          (return)))))
               (unless (or (eql rst 5) (eql goaway 5))
                 (fail "RST ~s GOAWAY ~s" rst goaway))
               (when rst
                 (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
                 (h2-expect-body stream 3 "pazuzu"))))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-closed-stream-sender-test (port)
  "RFC 9113 §5.1. After both peers end a stream, the server sends no frame
on it other than PRIORITY. GET / returns pazuzu, and a following PING is
acknowledged without another frame on that stream."
  (check "a closed stream draws no further server frames"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (ended nil)
                 (got (make-array 0 :element-type '(unsigned-byte 8)
                                  :adjustable t :fill-pointer 0))
                 (want (ascii "pazuzu"))
                 (opaque #(4 4 4 4 4 4 4 4)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (dotimes (ignored 24 (fail "ended ~a body ~s" ended
                                        (ignore-errors (babel:octets-to-string got))))
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (cond ((= type 7)
                        (fail "GOAWAY ~d" (h2-u32 payload 4)))
                       ((and (= sid 1) (= type 3))
                        (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                       ((and (= sid 1) ended (/= type 2))
                        (fail "frame ~d after the stream closed" type))
                       ((and (= sid 1) (or (= type 0) (= type 1)))
                        (when (= type 0)
                          (loop for byte across payload
                                do (vector-push-extend byte got)))
                        (when (logtest flags 1)
                          (unless (search want got)
                            (fail "body ~s" (ignore-errors
                                             (babel:octets-to-string got))))
                          (setf ended t)
                          (return))))))
             (h2-write stream (h2-frame 6 0 0 opaque))
             (let ((acked nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= sid 1) (/= type 2))
                          (fail "frame ~d on the closed stream" type))
                         ((and (= type 6) (zerop sid) (logtest flags 1)
                               (equalp payload opaque))
                          (setf acked t)
                          (return)))))
               (unless acked
                 (fail "no PING acknowledgement"))))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-half-closed-sender-test (port)
  "RFC 9113 §5.1. A stream that is half-closed (local) sends only
WINDOW_UPDATE, PRIORITY, or RST_STREAM. POST /no-such-continue with
Expect: 100-continue and no END_STREAM is answered 404, and a following
PING arrives with no further HEADERS or DATA on that stream."
  (check "a half-closed response sends no further HEADERS or DATA"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (ended nil)
                 (got (make-array 0 :element-type '(unsigned-byte 8)
                                  :adjustable t :fill-pointer 0))
                 (want (ascii "Not Found"))
                 (opaque #(5 5 5 5 5 5 5 5)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x04 1
                                 (h2-request-block port :method "POST"
                                                   :path "/no-such-continue"
                                                   :content-length "4"
                                                   :fields '(("expect" . "100-continue")))))
             (dotimes (ignored 24 (fail "ended ~a body ~s" ended
                                        (ignore-errors (babel:octets-to-string got))))
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (cond ((= type 7)
                        (fail "GOAWAY ~d" (h2-u32 payload 4)))
                       ((and (= sid 1) ended (not (member type '(2 3 8))))
                        (fail "frame ~d after the response ended" type))
                       ((and (= sid 1) (= type 0))
                        (loop for byte across payload
                              do (vector-push-extend byte got))
                        (when (logtest flags 1)
                          (unless (search want got)
                            (fail "body ~s" (ignore-errors
                                             (babel:octets-to-string got))))
                          (setf ended t)
                          (return)))
                       ((and (= sid 1) (= type 1) (logtest flags 1))
                        (unless (search want got)
                          (fail "body ~s" (ignore-errors
                                           (babel:octets-to-string got))))
                        (setf ended t)
                        (return)))))
             (h2-write stream (h2-frame 6 0 0 opaque))
             (let ((acked nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= sid 1) (not (member type '(2 3 8))))
                          (fail "frame ~d on the half-closed stream" type))
                         ((and (= type 6) (zerop sid) (logtest flags 1)
                               (equalp payload opaque))
                          (setf acked t)
                          (return)))))
               (unless acked
                 (fail "no PING acknowledgement"))))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-refused-stream-test (port)
  "RFC 9113 §8.7. Once a request has reached the application, the server
does not reset that stream with REFUSED_STREAM. GET / returns pazuzu,
and no RST_STREAM on the stream carries error code 7."
  (check "a processed request is not REFUSED_STREAM"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (got (make-array 0 :element-type '(unsigned-byte 8)
                                  :adjustable t :fill-pointer 0))
                 (want (ascii "pazuzu"))
                 (opaque #(6 6 6 6 6 6 6 6))
                 (ended nil))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (dotimes (ignored 24 (fail "response did not end"))
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (cond ((and (= type 3) (= sid 1) (= (h2-u32 payload 0) 7))
                        (fail "REFUSED_STREAM"))
                       ((and (= sid 1) (= type 0))
                        (loop for byte across payload
                              do (vector-push-extend byte got))
                        (when (and (logtest flags 1) (search want got))
                          (setf ended t)
                          (return))))))
             (unless ended
               (fail "body ~s" (ignore-errors (babel:octets-to-string got))))
             (h2-write stream (h2-frame 6 0 0 opaque))
             (let ((acked nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (cond ((and (= type 3) (= sid 1) (= (h2-u32 payload 0) 7))
                          (fail "REFUSED_STREAM"))
                         ((and (= type 6) (zerop sid) (logtest flags 1)
                               (equalp payload opaque))
                          (setf acked t)
                          (return)))))
               (unless acked
                 (fail "no PING acknowledgement"))))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-stream-overflow-test (port)
  "RFC 9113 §6.9.1. A WINDOW_UPDATE that makes a stream flow-control
window exceed 2^31-1 is FLOW_CONTROL_ERROR."
  (check "a stream window above 2^31-1 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST")))
             (h2-write stream (h2-frame 8 0 1 #(127 255 255 255)))
             (let ((rst nil)
                   (goaway nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (setf goaway (h2-u32 payload 4))
                          (return))
                         ((and (= type 3) (= sid 1))
                          (setf rst (h2-u32 payload 0))
                          (return)))))
               (unless (or (eql rst 3) (eql goaway 3))
                 (fail "RST ~s GOAWAY ~s" rst goaway))))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-rst-inflight-test (port)
  "RFC 9113 §5.1. RST_STREAM sent while the stream is open can be followed
by DATA the peer already sent. That DATA is discarded. It is not a
connection error. The next request on the connection still completes."
  (check "DATA after a server reset is discarded"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; A second header block on an open stream is malformed.
             ;; The server resets that stream and leaves the connection up.
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (let ((rst nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf rst (h2-u32 payload 0))
                          (return)))))
               (unless (eql rst 1)
                 (fail "RST ~s" rst)))
             (h2-write stream (h2-frame 0 0 1 #(1)))
             (dotimes (ignored 4)
               (multiple-value-bind (type flags sid payload)
                   (h2-read-frame-within stream 0.2)
                 (declare (ignore flags sid))
                 (cond ((null type)
                        (return))
                       ((= type 7)
                        (fail "GOAWAY ~d after the reset" (h2-u32 payload 4)))
                       ((= type 3)
                        (fail "RST ~d after the reset" (h2-u32 payload 0))))))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-rst-window-test (port)
  "RFC 9113 §5.1. DATA discarded after a server RST_STREAM still counts
toward the connection flow-control window. Two 16384-octet frames cross
half of the 65535-octet window, so the server sends a connection
WINDOW_UPDATE. The next request on the connection still completes."
  (check "discarded DATA counts toward the connection window"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (payload (make-array 16384 :element-type '(unsigned-byte 8)
                                              :initial-element 1)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (let ((rst nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf rst (h2-u32 payload 0))
                          (return)))))
               (unless (eql rst 1)
                 (fail "RST ~s" rst)))
             (h2-write stream (h2-frame 0 0 1 payload))
             (h2-write stream (h2-frame 0 0 1 payload))
             (let ((credit 0))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 8) (zerop sid))
                          (incf credit (logand (h2-u32 payload 0) #x7fffffff))
                          (when (>= credit 32768)
                            (return))))))
               (unless (>= credit 32768)
                 (fail "window ~s" credit)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-rst-hpack-test (port)
  "RFC 9113 §5.1. A HEADERS block that arrives after this endpoint has
reset an open stream is discarded, but its header compression state is
still applied. The block inserts one dynamic-table entry. The next
request refers to that entry and still returns pazuzu."
  (check "a header block after a server reset updates compression state"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (let ((rst nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf rst (h2-u32 payload 0))
                          (return)))))
               (unless (eql rst 1)
                 (fail "RST ~s" rst)))
             ;; Static table length 61. This is the first dynamic entry,
             ;; so a later block addresses it as index 62 (#xBE).
             (h2-write stream (h2-frame 1 #x04 1 (hpack-incremental "x-a" "z")))
             (h2-write stream (h2-frame 1 #x05 3
                                        (octets-cat (h2-request-block port)
                                                    #(#xbe))))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-pad-window-test (port)
  "RFC 9113 §6.1. The entire DATA frame payload counts toward flow
control, including the Pad Length field and the padding. Two
16384-octet frames with 255 padding octets each carry 32256 octets of
data, below half of the 65535-octet window. The full payloads are
32768 octets, so the server sends a connection WINDOW_UPDATE. The next
request on the connection still completes."
  (check "DATA padding counts toward the connection window"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (body (make-array 16384 :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
             (setf (aref body 0) 255)
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 0 #x08 1 body))
             (h2-write stream (h2-frame 0 #x08 1 body))
             (let ((credit 0))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 8) (zerop sid))
                          (incf credit (logand (h2-u32 payload 0) #x7fffffff))
                          (when (>= credit 32768)
                            (return))))))
               (unless (>= credit 32768)
                 (fail "window ~s" credit)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-error-window-test (port)
  "RFC 9113 §6.9. A flow-controlled frame counts toward the connection
window even when the frame is in error. POST /echo declares five octets
and then sends two 16384-octet DATA frames. That mismatch is a stream
error, and the payloads still produce a connection WINDOW_UPDATE. The
next request on the connection completes."
  (check "a malformed DATA frame counts toward the connection window"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (body (make-array 16384 :element-type '(unsigned-byte 8)
                                           :initial-element 1)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST"
                                                          :path "/echo"
                                                          :content-length "5")))
             (h2-write stream (h2-frame 0 0 1 body))
             (h2-write stream (h2-frame 0 0 1 body))
             (let ((credit 0)
                   (rst nil))
               (dotimes (ignored 24)
                 (multiple-value-bind (type flags sid payload)
                     (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf rst (h2-u32 payload 0)))
                         ((and (= type 8) (zerop sid))
                          (incf credit (logand (h2-u32 payload 0) #x7fffffff)))))
                 (when (and (eql rst 1) (>= credit 32768))
                   (return)))
               (unless (eql rst 1)
                 (fail "RST ~s" rst))
               (unless (>= credit 32768)
                 (fail "window ~s" credit)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun settings-window-overflow-test (port)
  "RFC 9113 §6.9.2. A SETTINGS_INITIAL_WINDOW_SIZE change that makes an
open stream's flow-control window exceed 2^31-1 is a connection error
of type FLOW_CONTROL_ERROR."
  (check "a settings window change above 2^31-1 is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST")))
             ;; Raise the stream window by 1000, then set the initial
             ;; window to 2^31-1. The stream window would pass the max.
             (h2-write stream (h2-frame 8 0 1 #(0 0 3 232)))
             (h2-write stream (h2-frame 4 0 0 #(0 4 127 255 255 255)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 3)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun concurrent-stream-test (port)
  "RFC 9113 §5.1.2 and §5.4.1. The server advertises
SETTINGS_MAX_CONCURRENT_STREAMS of 100. One hundred open streams stay
up. HEADERS that would open a 101st stream is refused. The library
reports that excess as a connection error of type PROTOCOL_ERROR, which
the specification allows in place of the stream error."
  (check "a stream beyond the concurrent limit is refused"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (block (h2-request-block port)))
             (h2-handshake stream)
             ;; END_HEADERS and no END_STREAM, so each stream stays open
             ;; and counts toward the advertised limit.
             (loop for n from 0 below 100
                   do (h2-write stream (h2-frame 1 #x04 (1+ (* n 2)) block)))
             (loop for ignored below 8
                   do (multiple-value-bind (type flags sid payload)
                          (h2-read-frame-within stream 0.2)
                        (declare (ignore sid))
                        (cond ((null type)
                               (return))
                              ((= type 7)
                               (fail "GOAWAY ~d before the extra stream"
                                     (h2-u32 payload 4)))
                              ((or (and (= type 4) (logtest flags 1))
                                   (= type 8)))
                              (t
                               (fail "frame ~d before the extra stream" type)))))
             (h2-write stream (h2-frame 1 #x04 201 block))
             (let ((code nil))
               (loop for ignored below 8
                     do (multiple-value-bind (type flags sid payload)
                            (h2-read-frame-within stream 0.5)
                          (declare (ignore sid))
                          (cond ((null type)
                                 (return))
                                ((= type 7)
                                 (setf code (h2-u32 payload 4))
                                 (return))
                                ((or (and (= type 4) (logtest flags 1))
                                     (= type 8)))
                                (t
                                 (fail "frame ~d flags ~d" type flags)))))
               (unless (eql code 1)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun rst-no-reply-test (port)
  "RFC 9113 §6.4 and §5.4.2. After a RST_STREAM, the server sends no
further frame on that stream. It does not answer the reset with another
RST_STREAM. A later request on the connection still completes."
  (check "a reset stream draws no further frames"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             ;; CANCEL. The request never reached END_STREAM.
             (h2-write stream (h2-frame 3 0 1 #(0 0 0 8)))
             (loop for ignored below 8
                   do (multiple-value-bind (type flags sid payload)
                          (h2-read-frame-within stream 0.25)
                        (declare (ignore flags))
                        (cond ((null type)
                               (return))
                              ((= type 7)
                               (fail "GOAWAY ~d" (h2-u32 payload 4)))
                              ((and (= sid 1) payload)
                               (fail "frame ~d on the reset stream" type)))))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-unknown-error-code-test (port)
  "RFC 9113 §7. An error code outside the defined set MUST NOT trigger
special behavior. RST_STREAM with code 255 resets that stream only. The
next request on the connection still completes."
  (check "an unknown HTTP/2 error code is not a connection error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 3 0 1 #(0 0 0 255)))
             (loop for ignored below 8
                   do (multiple-value-bind (type flags sid payload)
                          (h2-read-frame-within stream 0.25)
                        (declare (ignore flags))
                        (cond ((null type)
                               (return))
                              ((= type 7)
                               (fail "GOAWAY ~d" (h2-u32 payload 4)))
                              ((and (= sid 1) payload)
                               (fail "frame ~d on the reset stream" type)))))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun window-on-closed-test (port)
  "RFC 9113 §6.9. A WINDOW_UPDATE on a stream the peer has already
finished is not an error, including after both sides have ended the
stream. The next request still completes."
  (check "a window update on a closed stream is not an error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu")
             (h2-write stream (h2-frame 8 0 1 #(0 0 0 1)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun second-headers-test (port)
  "RFC 9113 §8.1 and §8.1.1. A HEADERS frame without END_STREAM after
the frame that opened the request is malformed. That is a stream error
of type PROTOCOL_ERROR."
  (check "a second header block without END_STREAM is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (h2-write stream (h2-frame 1 #x04 1 (h2-request-block port)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun trailer-pseudo-test (port)
  "RFC 9113 §8.1. Trailers must not include a pseudo-header field. A
request that does is malformed, a stream error of type PROTOCOL_ERROR
(§8.1.1)."
  (check "a pseudo-header in trailers is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x04 1
                                        (h2-request-block port :method "POST"
                                                          :path "/echo"
                                                          :content-length "2")))
             (h2-write stream (h2-frame 0 0 1 (ascii "hi")))
             ;; END_STREAM and END_HEADERS. Indexed :method GET.
             (h2-write stream (h2-frame 1 #x05 1 #(#x82)))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-trailer-test (port)
  "RFC 9110 §6.5.1. A recipient MUST NOT merge a trailer field into the
header section. The trailer is returned from request-trailers, and the
header field sent with the request is not."
  (check "an HTTP/2 trailer is not merged into the header section"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x04 1
                                 (h2-request-block port :method "POST"
                                                   :path "/trailers"
                                                   :content-length "5"
                                                   :fields '(("x-note" . "head")))))
             (h2-write stream (h2-frame 0 0 1 (ascii "hello")))
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (hpack-new-name "x-checksum" "abc")))
             (let ((got (h2-expect-body stream 1 "x-checksum=abc")))
               (unless (equalp got (ascii "x-checksum=abc"))
                 (fail "trailers ~s"
                       (ignore-errors (babel:octets-to-string got :encoding :utf-8)))))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun uppercase-field-test (port)
  "RFC 9113 §8.2. A field name that contains an uppercase letter is
malformed. That is a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an uppercase field name is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             (hpack-new-name "Accept" "text/plain"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-pseudo-after-regular-test (port)
  "RFC 9113 §8.3. A pseudo-header after a regular field line is
malformed. That is a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 pseudo-header after a regular field is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (hpack-new-name "x-a" "1")
                                             (h2-request-block port))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-repeated-pseudo-test (port)
  "RFC 9113 §8.3. The same pseudo-header field name must not appear more
than once. A repeated :method is malformed, a stream error of type
PROTOCOL_ERROR (§8.1.1)."
  (check "a repeated HTTP/2 pseudo-header is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; A second indexed :method GET (#x82) follows a complete request.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port) #(#x82))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-response-pseudo-test (port)
  "RFC 9113 §8.3. :status is defined for responses. A request that
carries it is malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 response pseudo-header on a request is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed :status 200 is static index 8, the octet #x88.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port) #(#x88))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-empty-path-test (port)
  "RFC 9113 §8.3.1. :path must not be empty for an https URI. That
request is malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an empty HTTP/2 :path is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x87)
                                             (hpack-indexed-name 4 "")
                                             (hpack-indexed-name 1
                                                                 (format nil "127.0.0.1:~d" port)))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-empty-authority-test (port)
  "RFC 9113 §8.3.1. :authority must not be empty when it is present.
That request is malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an empty HTTP/2 :authority is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x87 #x84)
                                             (hpack-indexed-name 1 ""))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-relative-path-test (port)
  "RFC 9113 §8.3.1. :path for https is path-absolute or *. A value
with no leading slash is malformed, a stream error of type
PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 :path without a leading slash is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x87)
                                             (hpack-indexed-name 4 "noslash")
                                             (hpack-indexed-name 1
                                                                 (format nil "127.0.0.1:~d" port)))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-asterisk-path-test (port)
  "RFC 9113 §8.3.1. An OPTIONS request whose target has no path uses
:path *. That request applies to the server, so Allow lists the methods
the origin implements, including PUT. A later GET / still returns pazuzu."
  (check "HTTP/2 accepts an OPTIONS asterisk path"
    (let ((script "/tmp/pazuzu-h2-asterisk.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "const req = client.request({"
                     "  ':method': 'OPTIONS',"
                     "  ':path': '*',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "});"
                     "const chunks = [];"
                     "let status = '';"
                     "let allow = '';"
                     "req.on('response', (headers) => {"
                     "  status = String(headers[':status']);"
                     "  allow = String(headers.allow ?? '');"
                     "});"
                     "req.on('data', (chunk) => chunks.push(chunk));"
                     "req.on('end', () => {"
                     "  const body = Buffer.concat(chunks);"
                     "  const next = client.request({"
                     "    ':method': 'GET',"
                     "    ':path': '/',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  const nextChunks = [];"
                     "  let nextStatus = '';"
                     "  next.on('response', (headers) => { nextStatus = String(headers[':status']); });"
                     "  next.on('data', (chunk) => nextChunks.push(chunk));"
                     "  next.on('end', () => {"
                     "    const nextBody = Buffer.concat(nextChunks).toString();"
                     "    console.log(`RESULT status=${status} bodylen=${body.length} allow=${allow} next=${nextStatus} nextbody=${nextBody}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "    process.exit(0);"
                     "  });"
                     "  next.on('error', (error) => fail(error.message));"
                     "  next.end();"
                     "});"
                     "req.on('error', (error) => fail(error.message));"
                     "req.end();"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 bodylen=0 allow=" out)
                     (search " next=200 nextbody=pazuzu" out))
          (fail "exit ~s out ~s err ~s" code out err))
        (let* ((mark (search "allow=" out))
               (tail (and mark (subseq out (+ mark 6))))
               (stop (and tail (search " next=" tail)))
               (allow (and stop (subseq tail 0 stop))))
          (unless (and allow (search "PUT" allow) (search "DELETE" allow))
            (fail "allow ~s out ~s" allow out)))))))

(defun h2-get-asterisk-path-test (port)
  "RFC 9110 §7.1 and RFC 9113 §8.1.1. Asterisk-form is only for OPTIONS.
GET with :path * is malformed, a stream error of type PROTOCOL_ERROR.
A later GET / still returns pazuzu."
  (check "HTTP/2 rejects GET with an asterisk path"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x86)
                                             (hpack-indexed-name 4 "*")
                                             (hpack-indexed-name 1
                                                                 (format nil "127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-expect-stream-error (stream stream-id)
  "Read until RST_STREAM on STREAM-ID. A connection GOAWAY fails the check.
Return the error code, or NIL when none arrives."
  (let ((code nil))
    (dotimes (ignored 16)
      (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
        (declare (ignore flags))
        (cond ((= type 7)
               (fail "GOAWAY ~d" (h2-u32 payload 4)))
              ((and (= type 3) (= sid stream-id))
               (setf code (h2-u32 payload 0))
               (return)))))
    code))

(defun h2-missing-method-test (port)
  "RFC 9113 §8.3.1. A request includes exactly one :method. Omitting it
is malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 request without :method is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed :scheme http (#x86) and :path / (#x84), then :authority.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x86 #x84)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-missing-scheme-test (port)
  "RFC 9113 §8.3.1. A non-CONNECT request includes exactly one :scheme.
Omitting it is malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 request without :scheme is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed :method GET (#x82) and :path / (#x84), then :authority.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x84)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-missing-path-test (port)
  "RFC 9113 §8.3.1. A non-CONNECT request includes exactly one :path.
Omitting it is malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 request without :path is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed :method GET (#x82) and :scheme http (#x86), then :authority.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x86)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-connect-path-test (port)
  "RFC 9113 §8.5. A CONNECT request omits :path. Including it is
malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 CONNECT request with :path is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Literal :method CONNECT, indexed :path /, then :authority.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (hpack-indexed-name 2 "CONNECT")
                                             #(#x84)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-connect-scheme-test (port)
  "RFC 9113 §8.5. A CONNECT request omits :scheme. Including it is
malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 CONNECT request with :scheme is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Literal :method CONNECT, indexed :scheme http, then :authority.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (hpack-indexed-name 2 "CONNECT")
                                             #(#x86)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-connect-authority-test (port)
  "RFC 9113 §8.5. A CONNECT request includes :authority. Omitting it is
malformed, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 CONNECT request without :authority is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Literal :method CONNECT and no other pseudo-header.
             (h2-write stream
                       (h2-frame 1 #x05 1 (hpack-indexed-name 2 "CONNECT")))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-connect-port-test (port)
  "RFC 9110 §9.3.6. A CONNECT target with an empty or invalid port is 400.
A port in 0..65535 is the unimplemented tunnel, 501, and the next request
still returns the resource."
  (check "an HTTP/2 CONNECT request without a valid port is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (stream-id 1))
             (h2-handshake stream)
             (dolist (authority '("example.com" "example.com:" "example.com:65536"
                                  "example.com:abc" "[::1]" "[::1]:"))
               (h2-write stream
                         (h2-frame 1 #x05 stream-id
                                   (octets-cat (hpack-indexed-name 2 "CONNECT")
                                               (hpack-indexed-name 1 authority))))
               (handler-case (h2-expect-body stream stream-id "Bad Request")
                 (error (condition)
                   (fail "CONNECT ~a: ~a" authority condition)))
               (incf stream-id 2))
             (dolist (authority '("example.com:443" "example.com:0" "[::1]:443"))
               (h2-write stream
                         (h2-frame 1 #x05 stream-id
                                   (octets-cat (hpack-indexed-name 2 "CONNECT")
                                               (hpack-indexed-name 1 authority))))
               (handler-case (h2-expect-body stream stream-id "Not Implemented")
                 (error (condition)
                   (fail "CONNECT ~a: ~a" authority condition)))
               (incf stream-id 2))
             (h2-write stream (h2-frame 1 #x05 stream-id (h2-request-block port)))
             (h2-expect-body stream stream-id "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-userinfo-authority-test (port)
  "RFC 9113 §8.3.1. :authority for an http or https URI excludes userinfo.
That value is invalid, so the request is malformed, a stream error of
type PROTOCOL_ERROR (§8.1.1)."
  (check "an HTTP/2 :authority with userinfo is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed :method GET, :scheme http, :path /, then :authority
             ;; user@host:port.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x82 #x86 #x84)
                                             (hpack-indexed-name
                                              1 (format nil "user@127.0.0.1:~d" port)))))
             (let ((code (h2-expect-stream-error stream 1)))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-head-no-content-test (port)
  "RFC 9110 §9.3.2. HEAD does not send the representation. The header
block ends the stream, and the next request still returns the resource."
  (check "an HTTP/2 HEAD response sends no content"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (hpack-indexed-name 2 "HEAD")
                                             #(#x86 #x84)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (let ((ended nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 0) (= sid 1) (plusp (length payload)))
                          (fail "HEAD content ~s"
                                (babel:octets-to-string payload :encoding :utf-8)))
                         ((and (= sid 1) (logtest flags 1) (member type '(0 1 9)))
                          (setf ended t)
                          (return)))))
               (unless ended
                 (fail "HEAD did not end the stream")))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-head-length-test (port)
  "RFC 9110 §8.6. A HEAD response may send Content-Length only when that
value is the number of octets GET would have sent. HTTP/2 writes that
field through the HTTP/2 field section, sends no content, and the
following GET / still returns pazuzu."
  (check "an HTTP/2 HEAD content-length equals the GET size"
    (let ((script "/tmp/pazuzu-h2-head-length.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(method, done) {"
                     "  const req = client.request({"
                     "    ':method': method,"
                     "    ':path': '/',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let length = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    length = headers['content-length'] == null ? '' : String(headers['content-length']);"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, length, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request('HEAD', (status, length, body) => {"
                     "  request('GET', (getStatus, getLength, getBody) => {"
                     "    console.log(`RESULT head=${status} hlen=${length} hbody=${body.length} get=${getStatus} glen=${getLength} gbody=${getBody.length} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let ((hlen (let ((mark (search "hlen=" out)))
                      (and mark (parse-integer out :start (+ mark 5) :junk-allowed t))))
              (hbody (let ((mark (search "hbody=" out)))
                       (and mark (parse-integer out :start (+ mark 6) :junk-allowed t))))
              (glen (let ((mark (search "glen=" out)))
                      (and mark (parse-integer out :start (+ mark 5) :junk-allowed t))))
              (gbody (let ((mark (search "gbody=" out)))
                       (and mark (parse-integer out :start (+ mark 6) :junk-allowed t)))))
          (unless (and code (zerop code)
                       (search "RESULT head=200 " out)
                       (search " get=200 " out)
                       (search " gtext=pazuzu" out)
                       hlen hbody glen gbody
                       (zerop hbody)
                       (= hlen gbody glen)
                       (plusp gbody))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-not-modified-length-test (port)
  "RFC 9110 §8.6. A 304 may send Content-Length only when that value is
the size of the 200 for the same request. The HTTP/2 field section
omits it, sends no content, and the following GET still returns the
representation."
  (check "an HTTP/2 304 omits content-length"
    (let ((script "/tmp/pazuzu-h2-304-length.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(headers, done) {"
                     "  const req = client.request(headers);"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let length = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    length = headers['content-length'] == null ? '' : String(headers['content-length']);"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, length, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request({"
                     "  ':method': 'GET',"
                     "  ':path': '/partial',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'if-none-match': '\"p1\"',"
                     "}, (status, length, body) => {"
                     "  request({"
                     "    ':method': 'GET',"
                     "    ':path': '/partial',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  }, (getStatus, getLength, getBody) => {"
                     "    console.log(`RESULT status=${status} hlen=${length} hbody=${body.length} get=${getStatus} glen=${getLength} gbody=${getBody.length} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let ((mark (search "hlen=" out))
              (hbody (let ((at (search "hbody=" out)))
                       (and at (parse-integer out :start (+ at 6) :junk-allowed t))))
              (glen (let ((at (search "glen=" out)))
                      (and at (parse-integer out :start (+ at 5) :junk-allowed t))))
              (gbody (let ((at (search "gbody=" out)))
                       (and at (parse-integer out :start (+ at 6) :junk-allowed t)))))
          (unless (and code (zerop code)
                       (search "RESULT status=304 " out)
                       (search " get=200 " out)
                       (search " gtext=abcdefghij" out)
                       mark
                       (< (+ mark 5) (length out))
                       (char= (char out (+ mark 5)) #\Space)
                       hbody glen gbody
                       (zerop hbody)
                       (= glen gbody)
                       (plusp gbody))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-no-content-length-test (port)
  "RFC 9110 §8.6. A 204 must not send Content-Length. The handler names
one anyway. The HTTP/2 field section omits it, sends no content, and
the following GET / still returns pazuzu."
  (check "an HTTP/2 204 omits content-length"
    (let ((script "/tmp/pazuzu-h2-204-length.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(path, done) {"
                     "  const req = client.request({"
                     "    ':method': 'GET',"
                     "    ':path': path,"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let length = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    length = headers['content-length'] == null ? '' : String(headers['content-length']);"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, length, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request('/none', (status, length, body) => {"
                     "  request('/', (getStatus, getLength, getBody) => {"
                     "    console.log(`RESULT status=${status} hlen=${length} hbody=${body.length} get=${getStatus} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let ((mark (search "hlen=" out))
              (hbody (let ((at (search "hbody=" out)))
                       (and at (parse-integer out :start (+ at 6) :junk-allowed t)))))
          (unless (and code (zerop code)
                       (search "RESULT status=204 " out)
                       (search " get=200 " out)
                       (search " gtext=pazuzu" out)
                       mark
                       (< (+ mark 5) (length out))
                       (char= (char out (+ mark 5)) #\Space)
                       hbody
                       (zerop hbody))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-informational-length-test (port)
  "RFC 9110 §8.6. An informational response must not send Content-Length.
The HTTP/2 100 for Expect: 100-continue omits it. The client sends the
body only after that 100, and the final response returns the content."
  (check "an HTTP/2 100 omits content-length"
    (let ((script "/tmp/pazuzu-h2-100-length.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(path, done) {"
                     "  const req = client.request({"
                     "    ':method': 'GET',"
                     "    ':path': path,"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  req.on('response', (headers) => { status = String(headers[':status']); });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "const req = client.request({"
                     "  ':method': 'POST',"
                     "  ':path': '/echo',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'content-length': '4',"
                     "  'expect': '100-continue',"
                     "});"
                     "const chunks = [];"
                     "let saw = false;"
                     "let length = '';"
                     "let status = '';"
                     "req.on('headers', (headers) => {"
                     "  if (Number(headers[':status']) === 100) {"
                     "    saw = true;"
                     "    length = headers['content-length'] == null ? '' : String(headers['content-length']);"
                     "    req.end('echo');"
                     "  }"
                     "});"
                     "req.on('response', (headers) => { status = String(headers[':status']); });"
                     "req.on('data', (chunk) => chunks.push(chunk));"
                     "req.on('error', (error) => fail(error.message));"
                     "req.on('end', () => {"
                     "  const body = Buffer.concat(chunks).toString();"
                     "  request('/', (getStatus, getBody) => {"
                     "    console.log(`RESULT saw=${saw ? 1 : 0} ilen=${length} status=${status} body=${body} get=${getStatus} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let ((mark (search "ilen=" out)))
          (unless (and code (zerop code)
                       (search "RESULT saw=1 " out)
                       (search " status=200 " out)
                       (search " body=echo " out)
                       (search " get=200 " out)
                       (search " gtext=pazuzu" out)
                       mark
                       (< (+ mark 5) (length out))
                       (char= (char out (+ mark 5)) #\Space))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-future-last-modified-test (port)
  "RFC 9110 §8.8.2.1. A Last-Modified time in the future is replaced by
the message origination time. On HTTP/2 that value is the Date field.
The handler's year 2099 is not sent."
  (check "an HTTP/2 future Last-Modified is the Date"
    (let ((script "/tmp/pazuzu-h2-future-lm.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(method, path, done) {"
                     "  const req = client.request({"
                     "    ':method': method,"
                     "    ':path': path,"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let modified = '';"
                     "  let date = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    modified = headers['last-modified'] == null ? '' : String(headers['last-modified']);"
                     "    date = headers['date'] == null ? '' : String(headers['date']);"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, modified, date, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request('GET', '/future', (status, modified, date, body) => {"
                     "  request('GET', '/', (getStatus, getModified, getDate, getBody) => {"
                     "    console.log(`RESULT status=${status} body=${body.toString()} lm=${modified} date=${date} get=${getStatus} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let* ((lm-at (search " lm=" out))
               (date-at (and lm-at (search " date=" out :start2 lm-at)))
               (get-at (and date-at (search " get=" out :start2 date-at)))
               (modified (and lm-at date-at (subseq out (+ lm-at 4) date-at)))
               (date (and date-at get-at (subseq out (+ date-at 6) get-at))))
          (unless (and code (zerop code)
                       (search "RESULT status=200 " out)
                       (search " body=future " out)
                       (search " get=200 " out)
                       (search " gtext=pazuzu" out)
                       modified
                       date
                       (plusp (length modified))
                       (string= modified date)
                       (not (search "2099" modified))
                       (imf-fixdate-p modified))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-not-modified-validators-test (port)
  "RFC 9110 §15.4.5. A 304 sends the validators a 200 for the same
target would have sent: Content-Location, Date, ETag, Vary,
Cache-Control, and Expires. Content-Type is not among them. The
following GET still returns the representation."
  (check "an HTTP/2 304 keeps the 200 validators"
    (let ((script "/tmp/pazuzu-h2-304-validators.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function field(headers, name) {"
                     "  return headers[name] == null ? '' : String(headers[name]);"
                     "}"
                     "function request(headers, done) {"
                     "  const req = client.request(headers);"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let etag = '';"
                     "  let cache = '';"
                     "  let vary = '';"
                     "  let expires = '';"
                     "  let location = '';"
                     "  let date = '';"
                     "  let type = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    etag = field(headers, 'etag');"
                     "    cache = field(headers, 'cache-control');"
                     "    vary = field(headers, 'vary');"
                     "    expires = field(headers, 'expires');"
                     "    location = field(headers, 'content-location');"
                     "    date = field(headers, 'date');"
                     "    type = field(headers, 'content-type');"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, etag, cache, vary, expires, location, date, type, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request({"
                     "  ':method': 'GET',"
                     "  ':path': '/partial',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'if-none-match': '\"p1\"',"
                     "}, (status, etag, cache, vary, expires, location, date, type, body) => {"
                     "  request({"
                     "    ':method': 'GET',"
                     "    ':path': '/partial',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  }, (getStatus, getEtag, getCache, getVary, getExpires, getLocation, getDate, getType, getBody) => {"
                     "    console.log(`RESULT status=${status} etag=${etag} cc=${cache} vary=${vary} exp=${expires} cloc=${location} date=${date} type=${type} hbody=${body.length} get=${getStatus} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let* ((date-at (search " date=" out))
               (type-at (and date-at (search " type=" out :start2 date-at)))
               (date (and date-at type-at (subseq out (+ date-at 6) type-at))))
          (unless (and code (zerop code)
                       (search "RESULT status=304 " out)
                       (search " etag=\"p1\" " out)
                       (search " cc=max-age=60 " out)
                       (search " vary=accept-encoding " out)
                       (search " exp=Thu, 01 Jan 1970 00:00:00 GMT " out)
                       (search " cloc=/partial/en " out)
                       (search " type= " out)
                       (search " hbody=0 " out)
                       (search " get=200 " out)
                       (search " gtext=abcdefghij" out)
                       date
                       (imf-fixdate-p date))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-partial-validators-test (port)
  "RFC 9110 §15.3.7. A 206 sends Date, Cache-Control, ETag, Expires,
Content-Location, and Vary when the 200 would have sent them, plus
Content-Range for the enclosed part. The following GET still returns
the whole representation."
  (check "an HTTP/2 206 keeps the 200 validators"
    (let ((script "/tmp/pazuzu-h2-206-validators.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function field(headers, name) {"
                     "  return headers[name] == null ? '' : String(headers[name]);"
                     "}"
                     "function request(headers, done) {"
                     "  const req = client.request(headers);"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let etag = '';"
                     "  let cache = '';"
                     "  let vary = '';"
                     "  let expires = '';"
                     "  let location = '';"
                     "  let language = '';"
                     "  let type = '';"
                     "  let range = '';"
                     "  let date = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    etag = field(headers, 'etag');"
                     "    cache = field(headers, 'cache-control');"
                     "    vary = field(headers, 'vary');"
                     "    expires = field(headers, 'expires');"
                     "    location = field(headers, 'content-location');"
                     "    language = field(headers, 'content-language');"
                     "    type = field(headers, 'content-type');"
                     "    range = field(headers, 'content-range');"
                     "    date = field(headers, 'date');"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, etag, cache, vary, expires, location, language, type, range, date, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request({"
                     "  ':method': 'GET',"
                     "  ':path': '/partial',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'range': 'bytes=0-3',"
                     "}, (status, etag, cache, vary, expires, location, language, type, range, date, body) => {"
                     "  request({"
                     "    ':method': 'GET',"
                     "    ':path': '/partial',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  }, (getStatus, getEtag, getCache, getVary, getExpires, getLocation, getLanguage, getType, getRange, getDate, getBody) => {"
                     "    console.log(`RESULT status=${status} etag=${etag} cc=${cache} vary=${vary} exp=${expires} cloc=${location} lang=${language} type=${type} crange=${range} date=${date} body=${body.toString()} get=${getStatus} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let* ((date-at (search " date=" out))
               (body-at (and date-at (search " body=" out :start2 date-at)))
               (date (and date-at body-at (subseq out (+ date-at 6) body-at))))
          (unless (and code (zerop code)
                       (search "RESULT status=206 " out)
                       (search " etag=\"p1\" " out)
                       (search " cc=max-age=60 " out)
                       (search " vary=accept-encoding " out)
                       (search " exp=Thu, 01 Jan 1970 00:00:00 GMT " out)
                       (search " cloc=/partial/en " out)
                       (search " lang=en " out)
                       (search " type=text/plain " out)
                       (search " crange=bytes 0-3/10 " out)
                       (search " body=abcd " out)
                       (search " get=200 " out)
                       (search " gtext=abcdefghij" out)
                       date
                       (imf-fixdate-p date))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-reset-content-test (port)
  "RFC 9110 §15.3.6. A 205 must not generate content. The handler
supplies a body anyway. The HTTP/2 response is 205 with Content-Length
0, no content octets, and the following GET / still returns pazuzu."
  (check "an HTTP/2 205 sends no content"
    (let ((script "/tmp/pazuzu-h2-205-content.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(path, done) {"
                     "  const req = client.request({"
                     "    ':method': 'GET',"
                     "    ':path': path,"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let length = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    length = headers['content-length'] == null ? '' : String(headers['content-length']);"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, length, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request('/reset', (status, length, body) => {"
                     "  request('/', (getStatus, getLength, getBody) => {"
                     "    console.log(`RESULT status=${status} hlen=${length} hbody=${body.length} btext=${body.toString()} get=${getStatus} gtext=${getBody.toString()}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=205 " out)
                     (search " hlen=0 " out)
                     (search " hbody=0 " out)
                     (search " btext= get=" out)
                     (search " get=200 " out)
                     (search " gtext=pazuzu" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h2-no-content-date-test (port)
  "RFC 9110 §6.6.1. An origin with a clock sends Date on every 2xx.
An HTTP/2 204 and an HTTP/2 205 still send that field as IMF-fixdate."
  (check "an HTTP/2 204 and 205 send Date"
    (let ((script "/tmp/pazuzu-h2-204-date.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function request(path, done) {"
                     "  const req = client.request({"
                     "    ':method': 'GET',"
                     "    ':path': path,"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  });"
                     "  let status = '';"
                     "  let date = '';"
                     "  const chunks = [];"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    date = headers['date'] == null ? '' : String(headers['date']);"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, date, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request('/none', (nstatus, ndate) => {"
                     "  request('/reset', (rstatus, rdate) => {"
                     "    request('/', (getStatus, getDate, getBody) => {"
                     "      console.log(`RESULT none=${nstatus} ndate=${ndate} reset=${rstatus} rdate=${rdate} get=${getStatus} gtext=${getBody.toString()}`);"
                     "      clearTimeout(timer);"
                     "      client.close();"
                     "    });"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let* ((ndate-at (search " ndate=" out))
               (reset-at (and ndate-at (search " reset=" out :start2 ndate-at)))
               (rdate-at (and reset-at (search " rdate=" out :start2 reset-at)))
               (get-at (and rdate-at (search " get=" out :start2 rdate-at)))
               (ndate (and ndate-at reset-at (subseq out (+ ndate-at 7) reset-at)))
               (rdate (and rdate-at get-at (subseq out (+ rdate-at 7) get-at))))
          (unless (and code (zerop code)
                       (search "RESULT none=204 " out)
                       (search " reset=205 " out)
                       (search " get=200 " out)
                       (search " gtext=pazuzu" out)
                       ndate rdate
                       (imf-fixdate-p ndate)
                       (imf-fixdate-p rdate))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h2-multipart-range-test (port)
  "RFC 9110 §§15.3.7.2 and 8.3.3. Multiple ranges are multipart/byteranges.
The message has no Content-Range. Each part is delimited with CRLF, and
the following GET still returns the whole representation."
  (check "an HTTP/2 multipart range uses CRLF between parts"
    (let ((script "/tmp/pazuzu-h2-multipart.mjs"))
      (write-lines script
                   '("import http2 from 'node:http2';"
                     "const port = process.argv[2];"
                     "const client = http2.connect(`http://127.0.0.1:${port}`);"
                     "function fail(message) {"
                     "  console.error(message);"
                     "  try { client.close(); } catch {}"
                     "  process.exit(1);"
                     "}"
                     "client.on('error', (error) => fail(error.message));"
                     "const timer = setTimeout(() => fail('timeout'), 4000);"
                     "const authority = `127.0.0.1:${port}`;"
                     "function field(headers, name) {"
                     "  return headers[name] == null ? '' : String(headers[name]);"
                     "}"
                     "function request(headers, done) {"
                     "  const req = client.request(headers);"
                     "  const chunks = [];"
                     "  let status = '';"
                     "  let type = '';"
                     "  let range = '';"
                     "  req.on('response', (headers) => {"
                     "    status = String(headers[':status']);"
                     "    type = field(headers, 'content-type');"
                     "    range = field(headers, 'content-range');"
                     "  });"
                     "  req.on('data', (chunk) => chunks.push(chunk));"
                     "  req.on('end', () => done(status, type, range, Buffer.concat(chunks)));"
                     "  req.on('error', (error) => fail(error.message));"
                     "  req.end();"
                     "}"
                     "request({"
                     "  ':method': 'GET',"
                     "  ':path': '/partial',"
                     "  ':scheme': 'http',"
                     "  ':authority': authority,"
                     "  'range': 'bytes=0-1,4-5',"
                     "}, (status, type, range, body) => {"
                     "  request({"
                     "    ':method': 'GET',"
                     "    ':path': '/partial',"
                     "    ':scheme': 'http',"
                     "    ':authority': authority,"
                     "  }, (getStatus, getType, getRange, getBody) => {"
                     "    console.log(`RESULT status=${status} type=${type} crange=${range} body=${body.toString('latin1')} get=${getStatus} gtext=${getBody.toString('latin1')}`);"
                     "    clearTimeout(timer);"
                     "    client.close();"
                     "  });"
                     "});"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list "node" script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let* ((type-at (search " type=" out))
               (crange-at (and type-at (search " crange=" out :start2 type-at)))
               (body-at (and crange-at (search " body=" out :start2 crange-at)))
               (get-at (and body-at (search " get=" out :start2 body-at)))
               (type (and type-at crange-at (subseq out (+ type-at 6) crange-at)))
               (crange (and crange-at body-at (subseq out (+ crange-at 8) body-at)))
               (body (and body-at get-at (subseq out (+ body-at 6) get-at)))
               (bmark (and type (search "boundary=" type)))
               (boundary (and bmark (subseq type (+ bmark 9))))
               (crlf (format nil "~c~c" #\Return #\Newline)))
          (unless (and code (zerop code)
                       (search "RESULT status=206 " out)
                       (search " get=200 " out)
                       (search " gtext=abcdefghij" out)
                       type
                       (search "multipart/byteranges" type)
                       boundary
                       (plusp (length boundary))
                       (not (search boundary "abcdefghij"))
                       crange
                       (string= crange "")
                       body
                       (search (format nil "--~a~aContent-Type: text/plain~aContent-Range: bytes 0-1/10~a~aab~a"
                                       boundary crlf crlf crlf crlf crlf)
                               body)
                       (search (format nil "Content-Range: bytes 4-5/10~a~aef~a" crlf crlf crlf) body)
                       (search (format nil "--~a--~a" boundary crlf) body))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun colon-field-name-test (port)
  "RFC 9113 §8.2. A field name other than a pseudo-header must not
contain a colon. That request is malformed, a stream error of type
PROTOCOL_ERROR (§8.1.1)."
  (check "a colon in a field name is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             (hpack-new-name "x:y" "z"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun nul-field-value-test (port)
  "RFC 9113 §8.2. A field value that contains NUL is malformed. That is
a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field value with NUL is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name x-nul, value a NUL b. No Huffman.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0)
                                             (hpack-string "x-nul")
                                             #(3 97 0 98))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun lf-field-value-test (port)
  "RFC 9113 §8.2. A field value that contains LF is malformed. That is
a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field value with LF is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name x-lf, value a LF b. No Huffman.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0)
                                             (hpack-string "x-lf")
                                             #(3 97 10 98))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun cr-field-value-test (port)
  "RFC 9113 §8.2. A field value that contains CR is malformed. That is
a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field value with CR is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name x-cr, value a CR b. No Huffman.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0)
                                             (hpack-string "x-cr")
                                             #(3 97 13 98))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun leading-sp-field-value-test (port)
  "RFC 9113 §8.2.1. A field value that starts with SP is malformed. That
is a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field value with a leading space is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name x-lsp, value SP a. No Huffman.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0)
                                             (hpack-string "x-lsp")
                                             #(2 32 97))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun leading-htab-field-value-test (port)
  "RFC 9113 §8.2.1. A field value that starts with HTAB is malformed.
That is a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field value with a leading tab is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name x-lht, value HTAB a. No Huffman.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0)
                                             (hpack-string "x-lht")
                                             #(2 9 97))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun trailing-htab-field-value-test (port)
  "RFC 9113 §8.2.1. A field value that ends with HTAB is malformed. That
is a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field value with a trailing tab is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name x-tht, value a HTAB. No Huffman.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0)
                                             (hpack-string "x-tht")
                                             #(2 97 9))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun space-field-name-test (port)
  "RFC 9113 §8.2.1. A field name MUST NOT contain SP (0x20). That is a
malformed request, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a space in a field name is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             (hpack-new-name "x y" "z"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun del-field-name-test (port)
  "RFC 9113 §8.2.1. A field name MUST NOT contain DEL (0x7f). That is a
malformed request, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field name with DEL is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name is one DEL octet, value z.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0 1 127)
                                             (hpack-string "z"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun high-field-name-test (port)
  "RFC 9113 §8.2.1. A field name MUST NOT contain an octet in 0x80-0xff.
That is a malformed request, a stream error of type PROTOCOL_ERROR
(§8.1.1)."
  (check "a field name with a non-ASCII octet is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name is octet 0xff, value z.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0 1 255)
                                             (hpack-string "z"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun nul-field-name-test (port)
  "RFC 9113 §8.2.1. A field name MUST NOT contain NUL (0x00). That is a
malformed request, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field name with NUL is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name is one NUL octet, value z.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0 1 0)
                                             (hpack-string "z"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun htab-field-name-test (port)
  "RFC 9113 §8.2.1. A field name MUST NOT contain HTAB (0x09). That is a
malformed request, a stream error of type PROTOCOL_ERROR (§8.1.1)."
  (check "a field name with HTAB is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; HPACK literal, new name is one HTAB octet, value z.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0 1 9)
                                             (hpack-string "z"))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (setf code (h2-u32 payload 0))
                          (return)))))
               (unless (eql code 1)
                 (fail "RST_STREAM ~s" code)))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-index-zero-test (port)
  "RFC 9113 §4.3 and RFC 7541 §6.1. An indexed field whose index is 0 is
a decoding error. A decoding error in a field block MUST be a connection
error of type COMPRESSION_ERROR (0x09)."
  (check "an HPACK index of zero is a compression error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed Header Field Representation, index 0.
             (h2-write stream (h2-frame 1 #x05 1 #(#x80)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-index-past-table-test (port)
  "RFC 7541 §2.3.3 and RFC 9113 §4.3. The static table ends at 61. With
an empty dynamic table, index 62 is past both tables. That is a decoding
error, COMPRESSION_ERROR."
  (check "an HPACK index past the tables is a compression error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Indexed representation of 62 is one byte, 0xBE.
             (h2-write stream (h2-frame 1 #x05 1 #(#xbe)))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-table-limit-test (port)
  "RFC 7541 §6.3 and RFC 9113 §4.3. The initial header table size is
4096. A dynamic table size update of that maximum is accepted. One
octet above it is a decoding error, COMPRESSION_ERROR."
  (check "a header table size above the limit is a compression error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; 001xxxxx, 5-bit prefix integer 4096: 0x3f 0xe1 0x1f.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x3f #xe1 #x1f)
                                             (h2-request-block port))))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; The same encoding of 4097.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(#x3f #xe2 #x1f)
                                             (h2-request-block port))))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-huffman-padding-test (port)
  "RFC 7541 §5.2 and RFC 9113 §4.3. The symbol 0 is the five bits 00000.
Padding to an octet must be the most significant bits of EOS, 111, so
the encoded octet is 0x07. Padding 000 is a decoding error. That error
is GOAWAY with COMPRESSION_ERROR. The EOS padding still returns pazuzu."
  (check "Huffman padding that is not the EOS prefix is a compression error"
    (let ((name (ascii "x-a")))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (h2-handshake stream)
               ;; Literal without indexing, new name, Huffman value 0x07.
               (h2-write stream
                         (h2-frame 1 #x05 1
                                   (octets-cat (h2-request-block port)
                                               #(0 3)
                                               name
                                               #(#x81 #x07))))
               (h2-expect-body stream 1 "pazuzu"))
          (ignore-errors (usocket:socket-close socket))))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (h2-handshake stream)
               (h2-write stream
                         (h2-frame 1 #x05 1
                                   (octets-cat (h2-request-block port)
                                               #(0 3)
                                               name
                                               #(#x81 #x00))))
               (let ((code nil))
                 (dotimes (ignored 12)
                   (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                     (declare (ignore flags sid))
                     (when (= type 7)
                       (setf code (h2-u32 payload 4))
                       (return))))
                 (unless (eql code 9)
                   (fail "GOAWAY ~s" code))))
          (ignore-errors (usocket:socket-close socket)))))))

(defun hpack-integer-limit-test (port)
  "RFC 7541 §5.1 and RFC 9113 §4.3. An integer encoding whose shift
passes 32 bits exceeds the decoder limit and is a decoding error.
A two-octet length of 127 stays inside that limit and GET / returns
pazuzu. The error is GOAWAY with COMPRESSION_ERROR."
  (check "an HPACK integer past the implementation limit is a compression error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (name (make-array 127 :element-type '(unsigned-byte 8)
                                       :initial-element 97)))
             (h2-handshake stream)
             ;; 7-bit prefix 127, one continuation octet 0: length 127.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0 #x7f 0)
                                             name
                                             #(1 #x7a))))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             ;; Six continuation octets: the shift reaches 35.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             #(0 #x7f #x80 #x80 #x80 #x80 #x80 0))))
             (let ((code nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-huffman-eos-test (port)
  "RFC 7541 §5.2 and RFC 9113 §4.3. The EOS symbol is thirty 1 bits.
Four octets of 0xff are that symbol plus two bits of padding, so the
string contains EOS. That is a decoding error, GOAWAY with
COMPRESSION_ERROR. The one-octet encoding of 0, 0x07, still returns
pazuzu."
  (check "a Huffman string that contains the EOS symbol is a compression error"
    (let ((name (ascii "x-a")))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (h2-handshake stream)
               (h2-write stream
                         (h2-frame 1 #x05 1
                                   (octets-cat (h2-request-block port)
                                               #(0 3)
                                               name
                                               #(#x81 #x07))))
               (h2-expect-body stream 1 "pazuzu"))
          (ignore-errors (usocket:socket-close socket))))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (h2-handshake stream)
               (h2-write stream
                         (h2-frame 1 #x05 1
                                   (octets-cat (h2-request-block port)
                                               #(0 3)
                                               name
                                               #(#x84 #xff #xff #xff #xff))))
               (let ((code nil))
                 (dotimes (ignored 12)
                   (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                     (declare (ignore flags sid))
                     (when (= type 7)
                       (setf code (h2-u32 payload 4))
                       (return))))
                 (unless (eql code 9)
                   (fail "GOAWAY ~s" code))))
          (ignore-errors (usocket:socket-close socket)))))))

(defun hpack-huffman-overlong-test (port)
  "RFC 7541 §5.2 and RFC 9113 §4.3. One Huffman octet of 0xff is eight
1 bits and no symbol. Padding longer than seven bits is a decoding
error, GOAWAY with COMPRESSION_ERROR. The octet 0x07 still returns
pazuzu."
  (check "Huffman padding longer than seven bits is a compression error"
    (let ((name (ascii "x-a")))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (h2-handshake stream)
               (h2-write stream
                         (h2-frame 1 #x05 1
                                   (octets-cat (h2-request-block port)
                                               #(0 3)
                                               name
                                               #(#x81 #x07))))
               (h2-expect-body stream 1 "pazuzu"))
          (ignore-errors (usocket:socket-close socket))))
      (let ((socket (connect port)))
        (unwind-protect
             (let ((stream (usocket:socket-stream socket)))
               (h2-handshake stream)
               (h2-write stream
                         (h2-frame 1 #x05 1
                                   (octets-cat (h2-request-block port)
                                               #(0 3)
                                               name
                                               #(#x81 #xff))))
               (let ((code nil))
                 (dotimes (ignored 12)
                   (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                     (declare (ignore flags sid))
                     (when (= type 7)
                       (setf code (h2-u32 payload 4))
                       (return))))
                 (unless (eql code 9)
                   (fail "GOAWAY ~s" code))))
          (ignore-errors (usocket:socket-close socket)))))))

(defun hpack-duplicate-entry-test (port)
  "RFC 7541 §2.3.2. Two indexed copies of one field are two dynamic
table entries. The decoder must not treat that duplication as an
error. The newer entry is index 62 and the older is index 63, and
GET / still returns pazuzu."
  (check "a duplicate dynamic table entry is not an error"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (insert (hpack-incremental "x-d" "v")))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             insert
                                             insert)))
             (h2-expect-body stream 1 "pazuzu")
             ;; Indexed 62 is 0xBE. Indexed 63 is 0xBF.
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat (h2-request-block port)
                                             #(#xbe #xbf))))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-two-table-sizes-test (port)
  "RFC 7541 §4.2. Two maximum-size changes between header blocks signal
the smallest maximum and then the final maximum. 0 then 100 starts the
next response block with those updates. GET / still returns pazuzu."
  (check "two header table size changes signal the minimum and the final size"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (flet ((wait-ack ()
                      (dotimes (ignored 12 (fail "no SETTINGS ack"))
                        (multiple-value-bind (type flags sid payload)
                            (read-h2-frame stream)
                          (declare (ignore sid))
                          (cond ((and (= type 4) (= (logand flags 1) 1))
                                 (return))
                                ((= type 1)
                                 (fail "header block ~s" payload))
                                ((= type 7)
                                 (fail "GOAWAY ~d" (h2-u32 payload 4))))))))
               ;; SETTINGS_HEADER_TABLE_SIZE = 0, then 100.
               (h2-write stream (h2-frame 4 0 0 #(0 1 0 0 0 0)))
               (wait-ack)
               (h2-write stream (h2-frame 4 0 0 #(0 1 0 0 0 100)))
               (wait-ack))
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (let ((prefix nil)
                   (got (make-array 0 :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer 0))
                   (want (ascii "pazuzu")))
               (dotimes (ignored 16 (fail "body"))
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 1) (= sid 1) (plusp (length payload)))
                          (setf prefix (subseq payload 0 (min 3 (length payload)))))
                         ((and (= type 0) (= sid 1))
                          (loop for byte across payload
                                do (vector-push-extend byte got))
                          (when (search want got)
                            (return))))))
               (unless (equalp prefix #(#x20 #x3f #x45))
                 (fail "header block ~s" prefix))
               (unless (search want got)
                 (fail "body"))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-field-order-test (port)
  "RFC 7541 §2.1. The decoder orders header fields as they appear in the
header block. GET /horder with x-b, x-a, and x-c returns that order."
  (check "HPACK field lines keep their encoded order"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (h2-request-block
                                  port :path "/horder"
                                  :fields '(("x-b" . "2")
                                            ("x-a" . "1")
                                            ("x-c" . "3")))))
             (h2-expect-body stream 1 "x-b,x-a,x-c"))
        (ignore-errors (usocket:socket-close socket))))))

(defparameter *hpack-static-names*
  #("" ":authority" ":method" ":method" ":path" ":path" ":scheme" ":scheme"
    ":status" ":status" ":status" ":status" ":status" ":status" ":status"
    "accept-charset" "accept-encoding" "accept-language" "accept-ranges"
    "accept" "access-control-allow-origin" "age" "allow" "authorization"
    "cache-control" "content-disposition" "content-encoding" "content-language"
    "content-length" "content-location" "content-range" "content-type"
    "cookie" "date" "etag" "expect" "expires" "from" "host" "if-match"
    "if-modified-since" "if-none-match" "if-range" "if-unmodified-since"
    "last-modified" "link" "location" "max-forwards" "proxy-authenticate"
    "proxy-authorization" "range" "referer" "refresh" "retry-after" "server"
    "set-cookie" "strict-transport-security" "transfer-encoding" "user-agent"
    "vary" "via" "www-authenticate")
  "RFC 7541 Appendix A. Index 0 is unused.")

(defun hpack-read-int (payload index bits)
  (let* ((mask (1- (ash 1 bits)))
         (value (logand (aref payload index) mask)))
    (incf index)
    (if (< value mask)
        (values value index)
        (let ((shift 0))
          (loop
            (let ((next (aref payload index)))
              (incf index)
              (incf value (ash (logand next 127) shift))
              (incf shift 7)
              (when (zerop (logand next 128))
                (return (values value index)))))))))

(defun hpack-skip-string (payload index)
  (multiple-value-bind (length next) (hpack-read-int payload index 7)
    (+ next length)))

(defun hpack-raw-string (payload index)
  "A non-Huffman HPACK string, and the index after it."
  (when (plusp (logand (aref payload index) 128))
    (fail "huffman name"))
  (multiple-value-bind (length next) (hpack-read-int payload index 7)
    (values (babel:octets-to-string (subseq payload next (+ next length))
                                    :encoding :ascii)
            (+ next length))))

(defun hpack-name-at (payload index name-index)
  (if (zerop name-index)
      (hpack-raw-string payload index)
      (values (if (< name-index (length *hpack-static-names*))
                  (aref *hpack-static-names* name-index)
                  (format nil "dynamic-~d" name-index))
              index)))

(defun hpack-block-names (payload)
  "Field names in one HPACK header block, in block order (RFC 7541 §2.1)."
  (let ((index 0)
        (names nil))
    (loop while (< index (length payload))
          do (let ((byte (aref payload index)))
               (cond ((plusp (logand byte #x80))
                      (multiple-value-bind (name-index next)
                          (hpack-read-int payload index 7)
                        (multiple-value-bind (name after)
                            (hpack-name-at payload next name-index)
                          (declare (ignore after))
                          (push name names)
                          (setf index next))))
                     ((plusp (logand byte #x40))
                      (multiple-value-bind (name-index next)
                          (hpack-read-int payload index 6)
                        (multiple-value-bind (name after)
                            (hpack-name-at payload next name-index)
                          (push name names)
                          (setf index (hpack-skip-string payload after)))))
                     ((plusp (logand byte #x20))
                      (multiple-value-bind (ignored next)
                          (hpack-read-int payload index 5)
                        (declare (ignore ignored))
                        (setf index next)))
                     (t
                      (multiple-value-bind (name-index next)
                          (hpack-read-int payload index 4)
                        (multiple-value-bind (name after)
                            (hpack-name-at payload next name-index)
                          (push name names)
                          (setf index (hpack-skip-string payload after))))))))
    (nreverse names)))

(defun hpack-response-order-test (port)
  "RFC 7541 §2.1. The encoder orders header field representations as they
appear in the response field list. GET / returns pazuzu. The block names
:status, accept-ranges, content-type, server, date, and content-length."
  (check "HPACK response fields keep their input order"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (names nil))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (dotimes (ignored 16 (fail "no headers"))
               (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                 (declare (ignore flags))
                 (cond ((= type 7)
                        (fail "GOAWAY ~d" (h2-u32 payload 4)))
                       ((and (= type 1) (= sid 1) (plusp (length payload)))
                        (setf names (hpack-block-names payload))
                        (return)))))
             (unless (equal names
                            '(":status" "accept-ranges" "content-type" "server"
                              "date" "content-length"))
               (fail "names ~s" names))
             (h2-expect-body stream 1 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-oversized-entry-test (port)
  "RFC 7541 §4.4. Adding an entry larger than the dynamic table is not an
error. The table is emptied and that entry is not inserted. GET /horder
still returns x-big. Index 62, which named x-d before that literal, is
then a compression error."
  (check "an HPACK entry larger than the table empties the table"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 (value (make-array 4060 :element-type '(unsigned-byte 8)
                                    :initial-element 97)))
             (h2-handshake stream)
             ;; x-d: v fits. Index 62 is that entry.
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat (h2-request-block port)
                                             (hpack-incremental "x-d" "v"))))
             (h2-expect-body stream 1 "pazuzu")
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat (h2-request-block port) #(#xbe))))
             (h2-expect-body stream 3 "pazuzu")
             ;; Name 5 + value 4060 + 32 = 4097, one past the 4096 maximum.
             (h2-write stream
                       (h2-frame 1 #x05 5
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  #(#x40 5 #x78 #x2d #x62 #x69 #x67 #x7f #xdd #x1e)
                                  value)))
             (h2-expect-body stream 5 "x-big")
             (h2-write stream
                       (h2-frame 1 #x05 7
                                 (octets-cat (h2-request-block port) #(#xbe))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-evict-entry-test (port)
  "RFC 7541 §3.2 and §4.4. A decoder inserts a literal that fits. An entry
whose size equals the 4096 maximum is added, so index 62 on GET /horder
returns x-a. The next literal evicts that entry from the end of the table.
Index 62 then returns x-b, and index 63 is a compression error."
  (check "an HPACK entry that fills the table is evicted from the end"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket))
                 ;; Name 3 + value 4061 + 32 = 4096, the table maximum.
                 (value (make-array 4061 :element-type '(unsigned-byte 8)
                                    :initial-element 97)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  #(#x40 3 #x78 #x2d #x61 #x7f #xde #x1e)
                                  value)))
             (h2-expect-body stream 1 "x-a")
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  #(#xbe))))
             (h2-expect-body stream 3 "x-a")
             (h2-write stream
                       (h2-frame 1 #x05 5
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  (hpack-incremental "x-b" "v"))))
             (h2-expect-body stream 5 "x-b")
             (h2-write stream
                       (h2-frame 1 #x05 7
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  #(#xbe))))
             (h2-expect-body stream 7 "x-b")
             (h2-write stream
                       (h2-frame 1 #x05 9
                                 (octets-cat (h2-request-block port) #(#xbf))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-without-indexing-test (port)
  "RFC 7541 §3.2 and §6.2.2. A literal that is not added is appended to
the header list and leaves the dynamic table empty. GET /horder returns
x-a. Index 62 is then a compression error."
  (check "a literal header field without indexing is not inserted"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  (hpack-new-name "x-a" "v"))))
             (h2-expect-body stream 1 "x-a")
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat (h2-request-block port) #(#xbe))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-shrink-table-test (port)
  "RFC 7541 §4.3. A smaller dynamic table maximum evicts entries from the
end until the table fits. x-a and x-b are both indexed, so index 62 is
x-b and index 63 is x-a. A size update of 36 keeps x-b and makes index
63 a compression error."
  (check "a smaller header table size evicts the oldest entry"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  (hpack-incremental "x-a" "v")
                                  (hpack-incremental "x-b" "w"))))
             (h2-expect-body stream 1 "x-a,x-b")
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat
                                  (h2-request-block port :path "/horder")
                                  #(#xbe #xbf))))
             (h2-expect-body stream 3 "x-b,x-a")
             ;; 5-bit prefix integer 36: 0x3f 0x05. Each entry is 36 octets.
             (h2-write stream
                       (h2-frame 1 #x05 5
                                 (octets-cat
                                  #(#x3f #x05)
                                  (h2-request-block port :path "/horder")
                                  #(#xbe))))
             (h2-expect-body stream 5 "x-b")
             (h2-write stream
                       (h2-frame 1 #x05 7
                                 (octets-cat (h2-request-block port) #(#xbf))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-indexed-name-test (port)
  "RFC 7541 §6.2.1. Incremental indexing can name an existing entry.
Index 62 is x-note: v. The next literal uses that index and the value w,
so GET /header-value returns w, index 62 returns w, and index 63 returns v."
  (check "an indexed HPACK name is inserted with its new value"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  (hpack-incremental "x-note" "v"))))
             (h2-expect-body stream 1 "v")
             ;; 01 plus a 6-bit index of 62, then the value w.
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  #(#x7e)
                                  (hpack-string "w"))))
             (h2-expect-body stream 3 "w")
             (h2-write stream
                       (h2-frame 1 #x05 5
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  #(#xbe))))
             (h2-expect-body stream 5 "w")
             (h2-write stream
                       (h2-frame 1 #x05 7
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  #(#xbf))))
             (h2-expect-body stream 7 "v"))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-indexed-name-unchanged-test (port)
  "RFC 7541 §6.2.2. A literal without indexing can name an existing entry
and still leave the dynamic table unchanged. GET /header-value returns w.
Index 62 still returns v, and index 63 is a compression error."
  (check "an indexed HPACK name without indexing is not inserted"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  (hpack-incremental "x-note" "v"))))
             (h2-expect-body stream 1 "v")
             (h2-write stream
                       (h2-frame 1 #x05 3
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  (hpack-indexed-name 62 "w"))))
             (h2-expect-body stream 3 "w")
             (h2-write stream
                       (h2-frame 1 #x05 5
                                 (octets-cat
                                  (h2-request-block port :path "/header-value")
                                  #(#xbe))))
             (h2-expect-body stream 5 "v")
             (h2-write stream
                       (h2-frame 1 #x05 7
                                 (octets-cat (h2-request-block port) #(#xbf))))
             (let ((code nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags sid))
                   (when (= type 7)
                     (setf code (h2-u32 payload 4))
                     (return))))
               (unless (eql code 9)
                 (fail "GOAWAY ~s" code))))
        (ignore-errors (usocket:socket-close socket))))))

(defun hpack-table-size-test (port)
  "RFC 9113 §4.3.1. Once the server acknowledges SETTINGS_HEADER_TABLE_SIZE
of 0, the next response field block MUST start with a Dynamic Table Size
Update no larger than that maximum. Size 0 is the single octet 0x20."
  (check "a reduced header table size starts the next header block"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (h2-expect-body stream 1 "pazuzu")
             ;; SETTINGS_HEADER_TABLE_SIZE = 0.
             (h2-write stream (h2-frame 4 0 0 #(0 1 0 0 0 0)))
             (let ((acked nil))
               (dotimes (ignored 12)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore sid payload))
                   (when (and (= type 4) (= (logand flags 1) 1))
                     (setf acked t)
                     (return))))
               (unless acked
                 (fail "no SETTINGS ack")))
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (let ((first nil))
               (dotimes (ignored 16)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 3))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 1) (= sid 3) (plusp (length payload)))
                          (setf first (aref payload 0))
                          (return)))))
               (unless (eql first #x20)
                 (fail "header block ~s" first)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun push-settings-test (port)
  "RFC 9113 §6.5.2. The server does not set ENABLE_PUSH to 1. After the
client sets it to 0, a response carries no PUSH_PROMISE."
  (check "HTTP/2 does not enable push"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-write stream
                       (octets-cat (ascii "PRI * HTTP/2.0")
                                   #(13 10 13 10 83 77 13 10 13 10)
                                   (h2-frame 4 0 0 #(0 2 0 0 0 0))))
             (let ((pairs (h2-read-server-settings stream)))
               (unless (equal (cdr (assoc 3 pairs)) 100)
                 (fail "settings ~s" pairs))
               (let ((push (assoc 2 pairs)))
                 (when (and push (/= (cdr push) 0))
                   (fail "ENABLE_PUSH ~s" pairs))))
             (h2-write stream #(0 0 0 4 1 0 0 0 0))
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port)))
             (let ((want (ascii "pazuzu"))
                   (got (make-array 0 :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer 0)))
               (dotimes (ignored 24)
                 (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
                   (declare (ignore flags))
                   (cond ((= type 5)
                          (fail "PUSH_PROMISE"))
                         ((= type 7)
                          (fail "GOAWAY ~d" (h2-u32 payload 4)))
                         ((and (= type 3) (= sid 1))
                          (fail "RST_STREAM ~d" (h2-u32 payload 0)))
                         ((and (= type 0) (= sid 1))
                          (loop for byte across payload
                                do (vector-push-extend byte got))
                          (when (search want got)
                            (return))))))
               (unless (search want got)
                 (fail "body ~s" (ignore-errors
                                  (babel:octets-to-string got :encoding :utf-8))))))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-handshake (stream)
  (h2-write stream
            (octets-cat (ascii "PRI * HTTP/2.0")
                        #(13 10 13 10 83 77 13 10 13 10)
                        #(0 0 0 4 0 0 0 0 0)))
  (dotimes (ignored 16)
    (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
      (declare (ignore sid payload))
      (when (and (= type 4) (zerop (logand flags 1)))
        (h2-write stream #(0 0 0 4 1 0 0 0 0))
        (return-from h2-handshake t))))
  (fail "no SETTINGS"))

(defun h2-expect-rst (stream stream-id)
  "RST_STREAM PROTOCOL_ERROR, and no response and no GOAWAY."
  (dotimes (ignored 24)
    (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
      (declare (ignore flags))
      (cond ((= type 7)
             (fail "GOAWAY ~d" (h2-u32 payload 4)))
            ((and (= type 1) (= sid stream-id))
             (fail "response headers on stream ~d" stream-id))
            ((and (= type 3) (= sid stream-id))
             (let ((code (h2-u32 payload 0)))
               (unless (= code 1)
                 (fail "RST_STREAM ~d on stream ~d" code stream-id))
               (return-from h2-expect-rst code))))))
  (fail "no RST_STREAM on stream ~d" stream-id))

(defun h2-expect-body (stream stream-id text)
  (let ((want (ascii text))
        (got (make-array 0 :element-type '(unsigned-byte 8)
                         :adjustable t :fill-pointer 0)))
    (dotimes (ignored 24)
      (multiple-value-bind (type flags sid payload) (read-h2-frame stream)
        (declare (ignore flags))
        (cond ((= type 7)
               (fail "GOAWAY ~d" (h2-u32 payload 4)))
              ((and (= type 3) (= sid stream-id))
               (fail "RST_STREAM ~d on stream ~d" (h2-u32 payload 0) stream-id))
              ((and (= type 0) (= sid stream-id))
               (loop for byte across payload do (vector-push-extend byte got))
               (when (search want got)
                 (return-from h2-expect-body got))))))
    (fail "body ~s" (ignore-errors (babel:octets-to-string got :encoding :utf-8)))))

(defun malformed-http2-test (port)
  "RFC 9113 §8.2.2 and §8.1.1: connection-specific fields, and te other than
trailers, and a content-length that does not match the body, are stream
errors of type PROTOCOL_ERROR. te: trailers is allowed. The connection
stays up. curl and Node will not send the forbidden field, so the frames
are written directly."
  (check "HTTP/2 malformed message is a stream error"
    (let ((socket (connect port))
          (stream-id 1))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (dolist (field '(("connection" . "close")
                              ("keep-alive" . "timeout=5")
                              ("proxy-connection" . "keep-alive")
                              ("transfer-encoding" . "chunked")
                              ("upgrade" . "websocket")
                              ("te" . "gzip")
                              ("x-pad" . "value ")))
               (h2-write stream (h2-frame 1 #x05 stream-id
                                          (h2-request-block port :extra field)))
               (h2-expect-rst stream stream-id)
               (incf stream-id 2))
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port :extra '("te" . "trailers"))))
             (h2-expect-body stream stream-id "pazuzu")
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x04 stream-id
                                        (h2-request-block port :method "POST"
                                                          :path "/echo"
                                                          :content-length "5")))
             (h2-write stream (h2-frame 0 #x01 stream-id (ascii "ab")))
             (h2-expect-rst stream stream-id)
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id (h2-request-block port)))
             (h2-expect-body stream stream-id "pazuzu")
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port :path "/#f")))
             (h2-expect-rst stream stream-id)
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id (h2-request-block port)))
             (h2-expect-body stream stream-id "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun split-cookie-h2-test (port)
  "RFC 9113 §8.2.3. Split Cookie fields are one field joined by \"; \"."
  (check "HTTP/2 split Cookie fields are one field"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (h2-request-block port :path "/cookie-header"
                                                   :fields '(("cookie" . "a=b")
                                                             ("cookie" . "c=d")))))
             (h2-expect-body stream 1 "a=b; c=d"))
        (ignore-errors (usocket:socket-close socket))))))

(defun bad-header-h2-test (port)
  "A response field containing CR is one 500. The connection stays up."
  (check "HTTP/2 malformed response field is a 500"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/bad-header")))
             (h2-expect-body stream 1 "Internal Server Error")
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket)))))
  (check "HTTP/2 rejects a response field that ends with a space"
    ;; RFC 9113 §8.2.1. The handler value ends with SP. One 500, then the
    ;; next stream still returns the resource.
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/pad-header")))
             (h2-expect-body stream 1 "Internal Server Error")
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-leading-space-response-test (port)
  "RFC 9113 §8.2.1. A field value that starts with SP is not sent.
The handler value starts with SP. One 500, then the next stream still
returns the resource."
  (check "HTTP/2 rejects a response field that starts with a space"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/lead-header")))
             (h2-expect-body stream 1 "Internal Server Error")
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-trailing-tab-response-test (port)
  "RFC 9113 §8.2.1. A field value that ends with HTAB is not sent.
The handler value ends with HTAB. One 500, then the next stream still
returns the resource."
  (check "HTTP/2 rejects a response field that ends with a tab"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/tab-header")))
             (h2-expect-body stream 1 "Internal Server Error")
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-leading-tab-response-test (port)
  "RFC 9113 §8.2.1. A field value that starts with HTAB is not sent.
The handler value starts with HTAB. One 500, then the next stream still
returns the resource."
  (check "HTTP/2 rejects a response field that starts with a tab"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :path "/tab-lead-header")))
             (h2-expect-body stream 1 "Internal Server Error")
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun scheme-case-h2-test (port)
  "RFC 3986 scheme is case-insensitive. HTTP matches the cleartext listener.
https does not."
  (check "HTTP/2 scheme comparison ignores case"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1
                                        (h2-request-block port :scheme "HTTP")))
             (h2-expect-body stream 1 "pazuzu")
             (h2-write stream (h2-frame 1 #x05 3
                                        (h2-request-block port :scheme "https")))
             (h2-expect-body stream 3 "Bad Request")
             (h2-write stream (h2-frame 1 #x05 5 (h2-request-block port)))
             (h2-expect-body stream 5 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-fragment-path-test (port)
  "RFC 9113 §8.3.1. :path is absolute-path and an optional query. A
fragment delimiter is not a valid value, so the request is malformed."
  (check "an HTTP/2 :path with a fragment is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port :path "/#")))
             (h2-expect-rst stream 1)
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-invalid-scheme-test (port)
  "RFC 3986 §3.1 and RFC 9113 §8.3.1. :scheme is a URI scheme. A value
that is not a scheme is malformed, a stream error of type PROTOCOL_ERROR."
  (check "an HTTP/2 :scheme that is not a URI scheme is malformed"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 1 (h2-request-block port :scheme "9")))
             (h2-expect-rst stream 1)
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun non-token-h2-method-test (port)
  "A :method that is not a token is a malformed HTTP/2 request.
nghttp2 rejects it as RST_STREAM PROTOCOL_ERROR. The connection stays up."
  (check "HTTP/2 non-token method is rejected"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream
                       (h2-frame 1 #x05 1
                                 (octets-cat #(2 3 71 233 84)
                                             #(#x86)
                                             #(#x84)
                                             (hpack-indexed-name
                                              1 (format nil "127.0.0.1:~d" port)))))
             (h2-expect-rst stream 1)
             (h2-write stream (h2-frame 1 #x05 3 (h2-request-block port)))
             (h2-expect-body stream 3 "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun authority-host-test (port)
  "RFC 9113 §8.3.1. :authority selects the target. Host may name the same
entity with different case or the default port, and otherwise the request
is malformed. A repeated Host is malformed. The connection stays up."
  (check "Host that differs from :authority is rejected"
    (let ((socket (connect port))
          (stream-id 1))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port :host "other.example")))
             (h2-expect-body stream stream-id "Bad Request")
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port
                                                          :authority "Example.COM"
                                                          :host "example.com:80")))
             (h2-expect-body stream stream-id "pazuzu")
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port
                                                          :authority "example.com"
                                                          :host "example.com"
                                                          :extra '("host" . "example.com"))))
             (h2-expect-rst stream stream-id)
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id (h2-request-block port)))
             (h2-expect-body stream stream-id "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun h2-authority-selects-host-test (port)
  "RFC 9113 §8.3.1. When :authority is present, that field selects the
target. Host may name the same entity with different case and the
scheme's default port. GET /who returns the :authority value."
  (check "an HTTP/2 :authority selects the target host"
    (let ((socket (connect port))
          (stream-id 1))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port
                                                          :path "/who"
                                                          :authority "Example.COM"
                                                          :host "example.com:80")))
             (h2-expect-body stream stream-id "Example.COM"))
        (ignore-errors (usocket:socket-close socket))))))

(defun ip-literal-test (port)
  "RFC 3986 §3.2.2 and RFC 9110 §7.2. A bracketed host is an IPv6 address or
an IPvFuture. A reg-name percent-encoding is two hex digits. An empty port
is the scheme default."
  (check "invalid IP-literal host is rejected"
    (dolist (host '("::1" "::" "1::" "2001:db8::1" "1:2:3:4:5:6:7:8"
                    "0:0:0:0:0:0:0:1" "::ffff:192.0.2.1" "::192.0.2.1"
                    "1:2:3:4:5:6:192.0.2.1" "AbCd::1" "1:2:3:4:5:6:7::"))
      (unless (pazuzu::valid-host-p (format nil "[~a]" host))
        (fail "rejected [~a]" host))
      (unless (pazuzu::valid-host-p (format nil "[~a]:80" host))
        (fail "rejected [~a]:80" host)))
    (dolist (host '("[v1.example]" "[V1.Z]" "[vF.a:b!$&'()*+,;=._~-]"
                    "example.com" "example.com:" "example.com:80" "foo%2ecom"
                    "a!b" "127.0.0.1" "[::1]:"))
      (unless (pazuzu::valid-host-p host)
        (fail "rejected ~a" host)))
    (dolist (host '("[::::]" "[1]" "[1:2:3:4:5:6:7:8:9]" "[1::2::3]" "[:::]"
                    "[::ffff:192.0.2.01]" "[::ffff:192.0.2.256]" "[12345::]"
                    "[:1]" "[1:]" "[1:2:3:4:5:6:7:8::]" "[v1.]" "[v.a]"
                    "[::1%25eth0]" "[]" "[::1]:99999" "[::1]80" "foo%" "foo%zz"
                    "foo%2" "example.com:65536" ":80"))
      (when (pazuzu::valid-host-p host)
        (fail "accepted ~a" host)))
    (dolist (host '("[::1]" "[::ffff:192.0.2.1]" "[v1.example]"
                    "[1:2:3:4:5:6:192.0.2.1]" "example.com:" "foo%2ecom" "a!b"))
      (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                  (format nil "Host: ~a" host)))
                     200))
    (dolist (host '("[::::]" "[1]" "[::ffff:192.0.2.01]" "[v1.]" "foo%zz"))
      (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                  (format nil "Host: ~a" host)))
                     400))
    (expect-status (exchange port (request-text "GET http://[::1]/ HTTP/1.1"
                                                "Host: example.com"))
                   200)
    (expect-status (exchange port (request-text "GET http://[::::]/ HTTP/1.1"
                                                "Host: example.com"))
                   400)
    (let ((socket (connect port))
          (stream-id 1))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (h2-handshake stream)
             (dolist (pair '(("[::1]" . "pazuzu")
                             ("[::::]" . "Bad Request")
                             ("[::ffff:192.0.2.1]" . "pazuzu")
                             ("[::ffff:192.0.2.01]" . "Bad Request")
                             ("[v1.example]" . "pazuzu")))
               (h2-write stream (h2-frame 1 #x05 stream-id
                                          (h2-request-block port :authority (car pair))))
               (h2-expect-body stream stream-id (cdr pair))
               (incf stream-id 2))
             (h2-write stream (h2-frame 1 #x05 stream-id
                                        (h2-request-block port
                                                          :authority "example.com"
                                                          :host "example.com:")))
             (h2-expect-body stream stream-id "pazuzu")
             (incf stream-id 2)
             (h2-write stream (h2-frame 1 #x05 stream-id (h2-request-block port)))
             (h2-expect-body stream stream-id "pazuzu"))
        (ignore-errors (usocket:socket-close socket))))))

(defun tls-renegotiation-test (port)
  "RFC 9113 §9.2.1. HTTP/2 over TLS 1.2 does not complete renegotiation."
  (check "TLS renegotiation does not complete"
    ;; The first handshake selects h2. A client renegotiation then ends
    ;; the connection without a second negotiated TLS 1.2 session.
    (multiple-value-bind (out err code)
        (uiop:run-program
         (list "timeout" "3" "openssl" "s_client" "-connect"
               (format nil "127.0.0.1:~d" port)
               "-tls1_2" "-alpn" "h2")
         :input (make-string-input-stream (format nil "R~%"))
         :output :string
         :error-output :string
         :ignore-error-status t)
      (let ((text (concatenate 'string (or out "") (or err ""))))
        (unless (search "ALPN protocol: h2" text)
          (fail "alpn missing"))
        (let ((reneg (search "RENEGOTIATING" text)))
          (unless reneg
            (fail "no renegotiation attempt"))
          (when (search "New, TLSv1.2" text :start2 (+ reneg 13))
            (fail "renegotiation completed")))
        (unless (and code (plusp code))
          (fail "exit ~s" code))))))

(defun tls-close-notify-test (port)
  "RFC 9112 §9.8. The server sends a TLS closure alert before closing."
  (check "a TLS close sends close_notify"
    ;; HTTP/1.0 has no keep-alive, so the server closes after the body.
    ;; The first close_notify is the one the server sends.
    (multiple-value-bind (out err code)
        (uiop:run-program
         (list "timeout" "3" "openssl" "s_client" "-connect"
               (format nil "127.0.0.1:~d" port)
               "-alpn" "http/1.1" "-msg" "-ign_eof")
         :input (make-string-input-stream
                 (format nil "GET / HTTP/1.0~c~c~c~c"
                         #\Return #\Newline #\Return #\Newline))
         :output :string
         :error-output :string
         :ignore-error-status t)
      (declare (ignore code))
      (let ((text (concatenate 'string (or out "") (or err ""))))
        (unless (search "pazuzu" text)
          (fail "body missing"))
        (let ((pos (search "close_notify" text)))
          (unless pos
            (fail "no close_notify"))
          (let ((line (subseq text
                              (or (position #\Newline text :end pos :from-end t)
                                  0)
                              pos)))
            (unless (search "<<<" line)
              (fail "client alert first"))))))))

(defun tls-post-handshake-auth-test (port)
  "RFC 9113 §9.2.3. No post-handshake TLS 1.3 CertificateRequest."
  (check "no post-handshake certificate request"
    ;; The client enables post-handshake authentication. The server
    ;; still selects h2 and sends no CertificateRequest.
    (multiple-value-bind (text code)
        (command-text "timeout" "3" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-alpn" "h2" "-enable_pha" "-msg")
      (declare (ignore code))
      (unless (search "ALPN protocol: h2" text)
        (fail "alpn ~s" text))
      (when (search "CertificateRequest" text)
        (fail "certificate request")))))

(defun tls-compression-test (port)
  "RFC 9113 §9.2.1. HTTP/2 over TLS 1.2 does not negotiate compression."
  (check "TLS compression is not negotiated"
    ;; The client offers TLS compression. The server selects none and
    ;; still completes HTTP/2.
    (multiple-value-bind (text code)
        (command-text "timeout" "3" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-tls1_2" "-comp" "-alpn" "h2")
      (declare (ignore code))
      (unless (search "Compression: NONE" text)
        (fail "compression ~s" text))
      (unless (search "ALPN protocol: h2" text)
        (fail "alpn ~s" text)))))

(defun h2c-alpn-test (port)
  "RFC 9113 §3.2. The server does not select the h2c identifier."
  (check "h2c is not selected"
    ;; Offered alone, the handshake fails. Offered beside http/1.1, the
    ;; selected protocol is http/1.1.
    (multiple-value-bind (text code)
        (command-text "timeout" "3" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-alpn" "h2c")
      (when (search "ALPN protocol: h2c" text)
        (fail "selected h2c ~s" text))
      (unless (and code (plusp code))
        (fail "h2c exit ~s text ~s" code text))
      (unless (search "no application protocol" text :test #'char-equal)
        (fail "h2c alert ~s" text)))
    (multiple-value-bind (text code)
        (command-text "timeout" "3" "openssl" "s_client" "-connect"
                      (format nil "127.0.0.1:~d" port)
                      "-alpn" "h2c,http/1.1")
      (declare (ignore code))
      (when (search "ALPN protocol: h2c" text)
        (fail "selected h2c beside http/1.1 ~s" text))
      (unless (search "ALPN protocol: http/1.1" text)
        (fail "alpn ~s" text)))))

