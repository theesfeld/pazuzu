;;; WebSocket checks.

(in-package #:pazuzu/tests)

(defun read-reply-headers-only (stream)
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
      (declare (ignore status-line))
      (make-reply :status status :headers headers :body #()))))

(defun write-masked-text (stream text)
  (let* ((payload (octets text))
         (mask #(1 2 3 4)))
    (write-byte #x81 stream)
    (write-byte (logior #x80 (length payload)) stream)
    (write-sequence mask stream)
    (loop for index below (length payload)
          do (write-byte (logxor (aref payload index) (aref mask (mod index 4))) stream))
    (finish-output stream)))

(defun read-server-text (stream)
  (let* ((first (read-byte stream))
         (second (read-byte stream))
         (nbytes (logand second #x7f)))
    (unless (zerop (logand second #x80))
      (fail "server frame was masked"))
    (let ((payload (read-n stream nbytes)))
      (unless (= (logand first #x0f) 1)
        (fail "opcode ~d" (logand first #x0f)))
      (babel:octets-to-string payload :encoding :utf-8))))

(defun ws-open (port &optional (path "/ws"))
  (let ((socket (connect port)))
    (let ((stream (usocket:socket-stream socket)))
      (write-sequence (octets (request-text
                               (format nil "GET ~a HTTP/1.1" path)
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
      (values socket stream))))

(defun write-masked-frame (stream opcode payload &key (fin t) (length-form :minimal))
  (let* ((payload (cond ((stringp payload) (octets payload))
                        ((typep payload '(vector (unsigned-byte 8))) payload)
                        (t (coerce payload '(vector (unsigned-byte 8))))))
         (nbytes (length payload))
         (mask #(1 2 3 4)))
    (write-byte (logior (if fin #x80 0) (logand opcode #x0f)) stream)
    (ecase length-form
      (:minimal
       (cond ((< nbytes 126)
              (write-byte (logior #x80 nbytes) stream))
             ((< nbytes 65536)
              (write-byte (logior #x80 126) stream)
              (write-byte (ldb (byte 8 8) nbytes) stream)
              (write-byte (ldb (byte 8 0) nbytes) stream))
             (t
              (write-byte (logior #x80 127) stream)
              (loop for shift from 56 downto 0 by 8
                    do (write-byte (ldb (byte 8 shift) nbytes) stream)))))
      (:16
       (write-byte (logior #x80 126) stream)
       (write-byte (ldb (byte 8 8) nbytes) stream)
       (write-byte (ldb (byte 8 0) nbytes) stream))
      (:64
       (write-byte (logior #x80 127) stream)
       (loop for shift from 56 downto 0 by 8
             do (write-byte (ldb (byte 8 shift) nbytes) stream))))
    (write-sequence mask stream)
    (loop for index below nbytes
          do (write-byte (logxor (aref payload index) (aref mask (mod index 4))) stream))
    (finish-output stream)))

(defun write-masked-length64-high (stream opcode)
  "64-bit payload length with the high bit set. The body is not sent."
  (write-byte (logior #x80 (logand opcode #x0f)) stream)
  (write-byte (logior #x80 127) stream)
  (write-byte #x80 stream)
  (loop repeat 7 do (write-byte 0 stream))
  (write-sequence #(1 2 3 4) stream)
  (finish-output stream))

(defun write-masked-length64-value (stream opcode length)
  "64-bit payload length. The body is not sent."
  (write-byte (logior #x80 (logand opcode #x0f)) stream)
  (write-byte (logior #x80 127) stream)
  (loop for shift from 56 downto 0 by 8
        do (write-byte (ldb (byte 8 shift) length) stream))
  (write-sequence #(1 2 3 4) stream)
  (finish-output stream))

(defun websocket-oversized-frame-test (port)
  "RFC 6455 §10.4. A declared length of 2^60 is above the message limit.
The server closes with 1009 before that payload is read."
  (check "a WebSocket frame of 2^60 bytes is rejected"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-length64-value stream 1 (ash 1 60))
             (expect-ws-close stream 1009))
        (ignore-errors (usocket:socket-close socket))))))

(defun read-server-frame (stream)
  (let* ((first (read-byte stream))
         (second (read-byte stream))
         (nbytes (logand second #x7f)))
    (unless (zerop (logand second #x80))
      (fail "server frame was masked"))
    (when (>= nbytes 126)
      (fail "server frame length ~d" nbytes))
    (values (logand first #x0f)
            (if (zerop nbytes) #() (read-n stream nbytes)))))

(defun websocket-key-grammar-test (port)
  "RFC 6455 §§4.2.1 and 4.3. Sec-WebSocket-Key is base64-value-non-empty.
A space is not a base64-character, so the server stops the handshake."
  (check "a WebSocket key with a space fails the handshake"
    (let ((socket (connect port)))
      (unwind-protect
           (let ((stream (usocket:socket-stream socket)))
             (write-sequence (octets (request-text
                                      "GET /ws HTTP/1.1"
                                      "Host: 127.0.0.1"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Key: dGhl IHNhbXBsZSBub25jZQ=="
                                      "Sec-WebSocket-Version: 13"))
                             stream)
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (string-equal (header reply "upgrade") "websocket")
                 (fail "upgraded"))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after a spaced key" (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-protocol-token-test (port)
  "RFC 6455 §§4.1 and 4.2.1. A subprotocol element is one token. A space
is not part of a token, so the server stops the handshake."
  (check "a WebSocket subprotocol that is not a token fails the handshake"
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
                                      "Sec-WebSocket-Protocol: chat bar"))
                             stream)
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-protocol")
                 (fail "protocol ~s" (header reply "sec-websocket-protocol")))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after a non-token subprotocol"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-empty-protocol-test (port)
  "RFC 6455 §§4.1 and 4.2.1. Sec-WebSocket-Protocol-Client is 1#token.
An empty field is not that list, so the server stops the handshake."
  (check "an empty WebSocket subprotocol fails the handshake"
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
                                      "Sec-WebSocket-Protocol:"))
                             stream)
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-protocol")
                 (fail "protocol ~s" (header reply "sec-websocket-protocol")))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after an empty subprotocol"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-repeated-protocol-test (port)
  "RFC 6455 §4.1. Subprotocol elements are unique tokens. Two field
lines that both say chat fail the connection. chat and superchat still
complete the handshake, and neither is selected."
  (check "a repeated WebSocket subprotocol fails the connection"
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
                                      "Sec-WebSocket-Protocol: chat"))
                             stream)
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-protocol")
                 (fail "protocol ~s" (header reply "sec-websocket-protocol")))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after a repeated subprotocol"
                       (reply-status second)))))
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
                                      "Sec-WebSocket-Protocol: chat, superchat"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "list status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "list accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-protocol")
                 (fail "selected ~s" (header reply "sec-websocket-protocol")))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-bad-extension-test (port)
  "RFC 6455 §9.1. A quoted extension parameter that is not a token after
unescaping fails the connection. A quoted-pair that unescapes to a token
still completes the handshake, and the extension is not selected."
  (check "a malformed WebSocket extension fails the connection"
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
                                      "Sec-WebSocket-Extensions: foo; bar=\"a b\""))
                             stream)
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (string-equal (header reply "upgrade") "websocket")
                 (fail "upgraded"))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after a malformed extension"
                       (reply-status second)))))
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
                                      "Sec-WebSocket-Extensions: foo; bar=\"ba\\z\""))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply-headers-only stream)))
               (unless (= (reply-status reply) 101)
                 (fail "quoted status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "quoted accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-extensions")
                 (fail "selected ~s" (header reply "sec-websocket-extensions")))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-empty-extension-test (port)
  "RFC 6455 §9.1. extension-list is 1#extension. An empty field does not
match that grammar, so the server fails the handshake."
  (check "an empty WebSocket extension list fails the handshake"
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
                                      "Sec-WebSocket-Extensions:"))
                             stream)
             (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))
                             stream)
             (finish-output stream)
             (let ((reply (read-reply stream)))
               (expect-status reply 400)
               (when (header reply "sec-websocket-accept")
                 (fail "accept ~s" (header reply "sec-websocket-accept")))
               (when (header reply "sec-websocket-extensions")
                 (fail "extensions ~s" (header reply "sec-websocket-extensions")))
               (unless (member "close" (connection-options reply) :test #'string=)
                 (fail "connection ~s" (header reply "connection"))))
             (let ((second (handler-case (read-reply stream)
                             (error () nil))))
               (when second
                 (fail "answered ~s after an empty extension list"
                       (reply-status second)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-second-message-test (port)
  "RFC 6455 §6.2. After one data message, the next data frame is a new
message. The two payloads are not concatenated."
  (check "a later WebSocket data frame is a new message"
    (multiple-value-bind (socket stream) (ws-open port "/ws-two")
      (unwind-protect
           (progn
             (write-masked-frame stream 1 "one")
             (write-masked-frame stream 1 "two")
             (multiple-value-bind (opcode payload) (read-server-frame stream)
               (unless (= opcode 1)
                 (fail "first opcode ~d" opcode))
               (unless (string= (babel:octets-to-string payload :encoding :utf-8) "one")
                 (fail "first ~s" payload)))
             (multiple-value-bind (opcode payload) (read-server-frame stream)
               (unless (= opcode 1)
                 (fail "second opcode ~d" opcode))
               (unless (string= (babel:octets-to-string payload :encoding :utf-8) "two")
                 (fail "second ~s" payload)))
             (expect-ws-close stream 1000))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-minimal-length-test (port)
  "RFC 6455 §5.2. The server uses the shortest length encoding. A
126-byte data frame is the 16-bit form, not the 64-bit form."
  (check "a server frame of 126 bytes uses a 16-bit length"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (let ((body (make-array 126 :element-type '(unsigned-byte 8)
                                       :initial-element 97)))
             (write-masked-frame stream 1 body)
             (let* ((first (read-byte stream))
                    (second (read-byte stream)))
               (unless (= (logand first #x80) #x80)
                 (fail "fin ~d" first))
               (unless (zerop (logand first #x70))
                 (fail "rsv ~d" first))
               (unless (= (logand first #x0f) 1)
                 (fail "opcode ~d" first))
               (unless (zerop (logand second #x80))
                 (fail "masked ~d" second))
               (unless (= (logand second #x7f) 126)
                 (fail "length form ~d" (logand second #x7f)))
               (let ((hi (read-byte stream))
                     (lo (read-byte stream)))
                 (unless (and (zerop hi) (= lo 126))
                   (fail "length ~d ~d" hi lo)))
               (unless (equalp (read-n stream 126) body)
                 (fail "echo mismatch")))
             (expect-ws-close stream 1000))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-length64-test (port)
  "RFC 6455 §5.2. A 65536-byte payload uses the 8-byte length, and the
most significant bit of that length is clear."
  (check "a 65536-byte server frame keeps the length high bit clear"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (let ((body (make-array 65536 :element-type '(unsigned-byte 8)
                                       :initial-element 97)))
             (write-masked-frame stream 1 body)
             (let* ((first (read-byte stream))
                    (second (read-byte stream)))
               (unless (= (logand first #x80) #x80)
                 (fail "fin ~d" first))
               (unless (zerop (logand first #x70))
                 (fail "rsv ~d" first))
               (unless (= (logand first #x0f) 1)
                 (fail "opcode ~d" first))
               (unless (zerop (logand second #x80))
                 (fail "masked ~d" second))
               (unless (= (logand second #x7f) 127)
                 (fail "length form ~d" (logand second #x7f)))
               (let* ((hi (read-byte stream))
                      (length (ash hi 56)))
                 (unless (zerop (logand hi #x80))
                   (fail "high bit ~d" hi))
                 (loop for shift from 48 downto 0 by 8
                       do (setf length (logior length (ash (read-byte stream) shift))))
                 (unless (= length 65536)
                   (fail "length ~d" length)))
               (unless (equalp (read-n stream 65536) body)
                 (fail "echo mismatch")))
             (expect-ws-close stream 1000))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-tcp-close-test (port)
  "RFC 6455 §5.5.1. After the server sends Close, it closes the
underlying TCP connection. The echo is hi and the close code is 1000."
  (check "the server closes TCP after a WebSocket Close"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 1 "hi")
             (multiple-value-bind (opcode payload) (read-server-frame stream)
               (unless (and (= opcode 1) (equalp payload (octets "hi")))
                 (fail "echo ~d ~s" opcode payload)))
             (expect-ws-close stream 1000)
             (let ((next (handler-case
                             (sb-sys:with-deadline (:seconds 2)
                               (read-byte stream nil :eof))
                           (sb-sys:deadline-timeout () :open)
                           (error () :eof))))
               (unless (eq next :eof)
                 (fail "still open ~s" next))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-pong-frame-test (port)
  "RFC 6455 §5.5. A pong is a control frame, so it is one frame with FIN
set, no reserved bits, and a payload of at most 125 bytes. The payload
matches the ping."
  (check "a server pong is one frame"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 9 "xy")
             (let* ((first (read-byte stream))
                    (second (read-byte stream))
                    (nbytes (logand second #x7f)))
               (unless (= (logand first #x80) #x80)
                 (fail "fin ~d" first))
               (unless (zerop (logand first #x70))
                 (fail "rsv ~d" first))
               (unless (= (logand first #x0f) 10)
                 (fail "opcode ~d" first))
               (unless (zerop (logand second #x80))
                 (fail "masked ~d" second))
               (unless (<= nbytes 125)
                 (fail "length ~d" nbytes))
               (let ((payload (if (zerop nbytes) #() (read-n stream nbytes))))
                 (unless (equalp payload (octets "xy"))
                   (fail "pong ~s" payload)))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-ping-after-close-test (port)
  "RFC 6455 §5.5.2. A Ping is answered with a Pong unless a Close frame
was already received. The client sends Close, then a masked Ping."
  (check "a WebSocket ping after a received Close is not answered with a Pong"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 8 #(3 #xE8))
             (write-masked-frame stream 9 "xy")
             (expect-ws-close stream 1000)
             (let ((next (handler-case
                             (sb-sys:with-deadline (:seconds 2)
                               (read-byte stream nil :eof))
                           (sb-sys:deadline-timeout () :open)
                           (error () :eof))))
               (when (and (integerp next) (= (logand next #x0f) 10))
                 (fail "pong after close"))
               (unless (eq next :eof)
                 (fail "after close ~s" next))))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-binary-opcode-test (port)
  "RFC 6455 §§5.6 and 6.1. Binary data is opcode 2. A masked frame of
octets 0 and 255 is echoed as one unmasked binary frame, then close 1000."
  (check "a binary WebSocket message uses opcode 2"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 2 #(0 255))
             (let* ((first (read-byte stream))
                    (second (read-byte stream))
                    (nbytes (logand second #x7f)))
               (unless (= (logand first #x80) #x80)
                 (fail "fin ~d" first))
               (unless (zerop (logand first #x70))
                 (fail "rsv ~d" first))
               (unless (= (logand first #x0f) 2)
                 (fail "opcode ~d" first))
               (unless (zerop (logand second #x80))
                 (fail "masked ~d" second))
               (unless (= nbytes 2)
                 (fail "length ~d" nbytes))
               (let ((payload (read-n stream nbytes)))
                 (unless (equalp payload #(0 255))
                   (fail "payload ~s" payload))))
             (expect-ws-close stream 1000))
        (ignore-errors (usocket:socket-close socket))))))

(defun websocket-binary-fragment-test (port)
  "RFC 6455 §§5.4 and 6.2. A fragmented message notes its type from the
first frame. Opcode 2, then two opcode 0 frames, are one binary message.
The echo is one unmasked frame of those octets in order, then close 1000."
  (check "a fragmented WebSocket message keeps its first-frame type"
    (multiple-value-bind (socket stream) (ws-open port)
      (unwind-protect
           (progn
             (write-masked-frame stream 2 #(0) :fin nil)
             (write-masked-frame stream 0 #(1) :fin nil)
             (write-masked-frame stream 0 #(255))
             (let* ((first (read-byte stream))
                    (second (read-byte stream))
                    (nbytes (logand second #x7f)))
               (unless (= (logand first #x80) #x80)
                 (fail "fin ~d" first))
               (unless (zerop (logand first #x70))
                 (fail "rsv ~d" first))
               (unless (= (logand first #x0f) 2)
                 (fail "opcode ~d" first))
               (unless (zerop (logand second #x80))
                 (fail "masked ~d" second))
               (unless (= nbytes 3)
                 (fail "length ~d" nbytes))
               (let ((payload (read-n stream nbytes)))
                 (unless (equalp payload #(0 1 255))
                   (fail "payload ~s" payload))))
             (expect-ws-close stream 1000))
        (ignore-errors (usocket:socket-close socket))))))

(defun expect-ws-close (stream code)
  (multiple-value-bind (opcode payload) (read-server-frame stream)
    (unless (= opcode 8)
      (fail "close opcode ~d" opcode))
    (unless (>= (length payload) 2)
      (fail "close payload length ~d" (length payload)))
    (let ((got (logior (ash (aref payload 0) 8) (aref payload 1))))
      (unless (= got code)
        (fail "close code ~d" got)))))

(defun ppcre-or-scan (text pattern)
  "Pull the first capture out of a tiny anchored pattern with one group."
  (let* ((open (search "([^" pattern))
         (prefix (subseq pattern 0 open))
         (suffix (subseq pattern (+ open (length "([^\"]+)")))))
    (let ((start (search prefix text)))
      (unless start
        (fail "no ~a in ~s" prefix text))
      (let* ((value-start (+ start (length prefix)))
             (value-end (search suffix text :start2 value-start)))
        (unless value-end
          (fail "no suffix ~a in ~s" suffix text))
        (subseq text value-start value-end)))))

(defun curl-version (url &rest args)
  (let* ((body "/tmp/pazuzu-curl-body")
         (version (uiop:run-program
                   (append (list "curl" "-sS" "--max-time" "8" "--connect-timeout" "3"
                                 "-o" body "-w" "%{http_version}")
                           args (list url))
                   :output :string
                   :error-output :string
                   :ignore-error-status t))
         (text (ignore-errors (alexandria:read-file-into-string body))))
    (ignore-errors (delete-file body))
    (values (string-trim '(#\Newline #\Return #\Space) version) text)))

(defun command-text (&rest args)
  (multiple-value-bind (out err code)
      (uiop:run-program args
                        :input (make-string 0)
                        :output :string
                        :error-output :string
                        :ignore-error-status t)
    (values (concatenate 'string (or out "") (or err "")) code)))

(defun write-lines (path lines)
  (with-open-file (out path :direction :output :if-exists :supersede :if-does-not-exist :create)
    (dolist (line lines)
      (write-line line out))))

