(in-package #:pazuzu)

(defconstant +websocket-guid+
  (if (boundp '+websocket-guid+)
      (symbol-value '+websocket-guid+)
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

(defun websocket-accept (key)
  (cl-base64:usb8-array-to-base64-string
   (ironclad:digest-sequence
    :sha1
    (utf8-octets (concatenate 'string key +websocket-guid+)))))

(defun header-lists-token-p (headers name token)
  (some (lambda (value)
          (member token (split-commas value) :test #'string-equal))
        (header-values headers name)))

(defun websocket-base64-char-p (char)
  (or (char<= #\A char #\Z)
      (char<= #\a char #\z)
      (char<= #\0 char #\9)
      (char= char #\+)
      (char= char #\/)))

(defun websocket-base64-value-p (value)
  "RFC 6455 §4.3 base64-value-non-empty. A space is not a base64-character,
and '=' appears only as the final padding group."
  (let ((n (length value)))
    (when (and (plusp n) (zerop (mod n 4)))
      (multiple-value-bind (pad data)
          (cond ((and (>= n 2)
                      (char= (char value (- n 2)) #\=)
                      (char= (char value (1- n)) #\=))
                 (values 2 2))
                ((char= (char value (1- n)) #\=)
                 (values 1 3))
                (t (values 0 0)))
        (let ((head (- n (if (plusp pad) 4 0))))
          (and (>= head 0)
               (loop for index below (+ head data)
                     always (websocket-base64-char-p (char value index)))))))))

(defun valid-websocket-key-p (key)
  "RFC 6455 §§4.2.1 and 4.3. The key matches base64-value-non-empty and
decodes to 16 octets."
  (and (websocket-base64-value-p key)
       (handler-case
           (let ((decoded (cl-base64:base64-string-to-usb8-array key)))
             (= (length decoded) 16))
         (error () nil))))

(defstruct websocket
  stream
  (closed nil)
  (max-message (* 1024 1024)))

(defun read-ws-bytes (stream count)
  (read-exact stream count))

(defun read-ws-integer (octets)
  (let ((value 0))
    (loop for byte across octets
          do (setf value (logior (ash value 8) byte)))
    value))

(defun write-ws-frame (stream opcode payload)
  (let ((length (length payload))
        (byte0 (logior #x80 opcode)))
    (write-byte byte0 stream)
    (cond ((< length 126)
           (write-byte length stream))
          ((< length 65536)
           (write-byte 126 stream)
           (write-byte (ldb (byte 8 8) length) stream)
           (write-byte (ldb (byte 8 0) length) stream))
          (t
           (write-byte 127 stream)
           (loop for shift from 56 downto 0 by 8
                 do (write-byte (ldb (byte 8 shift) length) stream))))
    (write-sequence payload stream)
    (finish-output stream)))

(defun websocket-send (socket data &key (type nil type-supplied))
  "RFC 6455 §§5.6 and 6.1. A string is text (opcode 1). Octets are binary
(opcode 2) unless TYPE names the other interpretation."
  (when (websocket-closed socket)
    (error "WebSocket is closed."))
  (let* ((kind (cond (type-supplied type)
                     ((stringp data) :text)
                     (t :binary)))
         (payload (if (stringp data) (utf8-octets data) (simple-octets data)))
         (opcode (ecase kind (:text 1) (:binary 2))))
    (write-ws-frame (websocket-stream socket) opcode payload)))

(defun websocket-status-sendable-p (code)
  "RFC 6455 §7.4 and the IANA close-code registry. 1010 is client-only.
1004, 1005, 1006, and 1015 must not appear on the wire. 1016-2999 are unassigned."
  (or (member code '(1000 1001 1002 1003 1007 1008 1009 1011 1012 1013 1014))
      (<= 3000 code 4999)))

(defun websocket-status-receivable-p (code)
  "A received close status. Unknown codes in the registered ranges are kept.
1004, 1005, 1006, and 1015 must not be sent, and 0-999 and 5000-65535 are unused."
  (and (<= 1000 code 4999)
       (not (member code '(1004 1005 1006 1015)))))

(defun utf8-octets-p (octets)
  (handler-case
      (progn (babel:octets-to-string octets :encoding :utf-8 :errorp t) t)
    (error () nil)))

(defun websocket-close-reply (payload)
  "Status to send after a Close body (RFC 6455 §§5.5.1, 7.4, and 8.1).
One byte is a protocol error. A reason that is not UTF-8 is 1007."
  (let ((nbytes (length payload)))
    (cond ((zerop nbytes) 1000)
          ((= nbytes 1) 1002)
          (t
           (let ((code (logior (ash (aref payload 0) 8) (aref payload 1)))
                 (reason (subseq payload 2)))
             (cond ((not (utf8-octets-p reason)) 1007)
                   ((not (websocket-status-receivable-p code)) 1002)
                   ((websocket-status-sendable-p code) code)
                   (t 1000)))))))

(defun websocket-close (socket &key (code 1000) (reason ""))
  (unless (websocket-status-sendable-p code)
    (error "WebSocket close code ~d must not be sent." code))
  (let ((reason-octets (utf8-octets reason)))
    (when (> (length reason-octets) 123)
      (error "WebSocket close reason exceeds 123 bytes."))
    (unless (websocket-closed socket)
      (setf (websocket-closed socket) t)
      (let ((payload (make-array (+ 2 (length reason-octets))
                                 :element-type '(unsigned-byte 8))))
        (setf (aref payload 0) (ldb (byte 8 8) code)
              (aref payload 1) (ldb (byte 8 0) code))
        (replace payload reason-octets :start1 2)
        (ignore-errors (write-ws-frame (websocket-stream socket) 8 payload))))))

(defun ws-length-illegal-p (len7 nbytes)
  "RFC 6455 §5.2. Use the minimal length encoding. The 64-bit high bit is 0."
  (or (and (= len7 126) (< nbytes 126))
      (and (= len7 127)
           (or (< nbytes 65536)
               (>= nbytes (ash 1 63))))))

(defun discard-ws-remainder (stream second)
  "Drop a short unread frame body so close does not reset the connection."
  (let ((len7 (logand second #x7f)))
    (when (< len7 126)
      (ignore-errors
        (read-ws-bytes stream (+ (if (plusp (logand second #x80)) 4 0) len7))))))

(defun read-ws-frame (socket)
  (let* ((stream (websocket-stream socket))
         (first (read-byte stream nil :eof)))
    (when (eq first :eof)
      (setf (websocket-closed socket) t)
      (return-from read-ws-frame nil))
    (let* ((fin (plusp (logand first #x80)))
           (rsv (logand first #x70))
           (opcode (logand first #x0f))
           (second (read-byte stream)))
      (when (plusp rsv)
        ;; Drop a short body so the TCP close is not a reset (RFC 6455 §5.1).
        (discard-ws-remainder stream second)
        (websocket-close socket :code 1002 :reason "reserved bits")
        (return-from read-ws-frame nil))
      (unless (plusp (logand second #x80))
        (discard-ws-remainder stream second)
        (websocket-close socket :code 1002 :reason "client frame unmasked")
        (return-from read-ws-frame nil))
      (let* ((len7 (logand second #x7f))
             (nbytes (cond ((< len7 126) len7)
                           ((= len7 126) (read-ws-integer (read-ws-bytes stream 2)))
                           (t (read-ws-integer (read-ws-bytes stream 8))))))
        (when (ws-length-illegal-p len7 nbytes)
          (websocket-close socket :code 1002 :reason "bad length")
          (return-from read-ws-frame nil))
        ;; RFC 6455 §5.5: every control opcode is at most 125 bytes and FIN is set.
        ;; Reject before reading the payload so an illegal length is not buffered.
        (when (and (<= 8 opcode 15) (or (not fin) (> nbytes 125)))
          (websocket-close socket :code 1002 :reason "bad control frame")
          (return-from read-ws-frame nil))
        (when (> nbytes (websocket-max-message socket))
          (websocket-close socket :code 1009 :reason "frame too big")
          (return-from read-ws-frame nil))
        (let* ((mask (read-ws-bytes stream 4))
               (payload (read-ws-bytes stream nbytes)))
          (loop for index below (length payload)
                do (setf (aref payload index)
                         (logxor (aref payload index) (aref mask (mod index 4)))))
          (values fin opcode payload))))))

(defun websocket-receive (socket)
  "Return a string, an octet vector, or NIL when the peer closes."
  (when (websocket-closed socket)
    (return-from websocket-receive nil))
  (let ((fragments nil)
        (type nil))
    (loop
      (multiple-value-bind (fin opcode payload) (read-ws-frame socket)
        (unless opcode
          (return-from websocket-receive nil))
        (case opcode
          (1 (when type
               (websocket-close socket :code 1002 :reason "interleaved message")
               (return-from websocket-receive nil))
             (setf type :text fragments (list payload)))
          (2 (when type
               (websocket-close socket :code 1002 :reason "interleaved message")
               (return-from websocket-receive nil))
             (setf type :binary fragments (list payload)))
          (0 (unless type
               (websocket-close socket :code 1002 :reason "unexpected continuation")
               (return-from websocket-receive nil))
             (push payload fragments))
          (8 (websocket-close socket :code (websocket-close-reply payload))
             (return-from websocket-receive nil))
          ;; RFC 6455 §5.4: a ping or pong between fragments must not drop them.
          (9 (unless (websocket-closed socket)
               (write-ws-frame (websocket-stream socket) 10 payload)))
          (10 nil)
          (t (websocket-close socket :code 1002 :reason "bad opcode")
             (return-from websocket-receive nil)))
        (when (and fin type (member opcode '(0 1 2)))
          (let ((message (concat-octets (nreverse fragments))))
            (when (> (length message) (websocket-max-message socket))
              (websocket-close socket :code 1009 :reason "message too big")
              (return-from websocket-receive nil))
            (return-from websocket-receive
              (if (eq type :text)
                  (handler-case (babel:octets-to-string message :encoding :utf-8)
                    (error ()
                      (websocket-close socket :code 1007 :reason "bad utf-8")
                      nil))
                  message))))))))

(defun websocket-handshake-p (request)
  ;; RFC 9110 §7.8: an Upgrade received on HTTP/1.0 MUST be ignored.
  (and (= (request-http-version request) 11)
       (string= (request-method request) "GET")
       (header-lists-token-p (request-headers request) "upgrade" "websocket")
       (header-lists-token-p (request-headers request) "connection" "upgrade")
       (request-header request "sec-websocket-key")))

(defun websocket-version-ok-p (headers)
  "RFC 6455 §§4.2.1 and 11.3.5. The request has one Sec-WebSocket-Version,
and its value is 13."
  (let ((values (header-values headers "sec-websocket-version")))
    (and values
         (null (rest values))
         (string= (string-trim '(#\Space #\Tab) (first values)) "13"))))

(defun websocket-qdtext-p (character)
  "RFC 2616 TEXT, which RFC 6455 §9.1 uses for qdtext, plus HTAB as LWS.
DQUOTE is a delimiter, not qdtext."
  (let ((code (char-code character)))
    (and (not (char= character #\"))
         (or (eql character #\Tab)
             (and (> code 31) (/= code 127))))))

(defun websocket-skip-ows (value index)
  (loop while (and (< index (length value))
                   (or (char= (char value index) #\Space)
                       (char= (char value index) #\Tab)))
        do (incf index))
  index)

(defun websocket-read-token (value index)
  "Return (values token next). TOKEN is NIL when INDEX is not a tchar."
  (let ((start index)
        (end (length value)))
    (loop while (and (< index end) (token-char-p (char value index)))
          do (incf index))
    (if (> index start)
        (values (subseq value start index) index)
        (values nil index))))

(defun websocket-read-quoted-token (value index)
  "RFC 6455 §9.1. A quoted-string unescapes quoted-pairs, and the result
must be one token. Return (values token next) or NIL NIL."
  (let ((end (length value)))
    (unless (and (< index end) (char= (char value index) #\"))
      (return-from websocket-read-quoted-token (values nil nil)))
    (let ((out (make-array 16 :element-type 'character :adjustable t :fill-pointer 0)))
      (incf index)
      (loop
        (when (>= index end)
          (return-from websocket-read-quoted-token (values nil nil)))
        (let ((character (char value index)))
          (incf index)
          (cond ((char= character #\")
                 (return))
                ((char= character #\\)
                 (when (>= index end)
                   (return-from websocket-read-quoted-token (values nil nil)))
                 (let ((escaped (char value index)))
                   (unless (<= (char-code escaped) 127)
                     (return-from websocket-read-quoted-token (values nil nil)))
                   (vector-push-extend escaped out)
                   (incf index)))
                ((websocket-qdtext-p character)
                 (vector-push-extend character out))
                (t (return-from websocket-read-quoted-token (values nil nil))))))
      (if (token-string-p out)
          (values out index)
          (values nil nil)))))

(defun websocket-read-param-value (value index)
  (if (and (< index (length value)) (char= (char value index) #\"))
      (websocket-read-quoted-token value index)
      (websocket-read-token value index)))

(defun websocket-extension-list-p (value)
  "RFC 6455 §9.1 extension-list, including the implied *LWS around
separators. At least one extension is required. Empty list members
do not count."
  (let ((index (websocket-skip-ows value 0))
        (end (length value))
        (found nil))
    (loop
      (when (>= index end)
        (return found))
      (if (char= (char value index) #\,)
          (progn
            (incf index)
            (setf index (websocket-skip-ows value index)))
          (progn
            (multiple-value-bind (name next) (websocket-read-token value index)
              (unless name
                (return-from websocket-extension-list-p nil))
              (setf index (websocket-skip-ows value next)
                    found t))
            (loop while (and (< index end) (char= (char value index) #\;))
                  do (incf index)
                     (setf index (websocket-skip-ows value index))
                     (multiple-value-bind (parameter next) (websocket-read-token value index)
                       (unless parameter
                         (return-from websocket-extension-list-p nil))
                       (setf index (websocket-skip-ows value next)))
                     (when (and (< index end) (char= (char value index) #\=))
                       (incf index)
                       (setf index (websocket-skip-ows value index))
                       (multiple-value-bind (parameter-value next)
                           (websocket-read-param-value value index)
                         (unless parameter-value
                           (return-from websocket-extension-list-p nil))
                         (setf index (websocket-skip-ows value next)))))
            (cond ((>= index end) (return t))
                  ((char= (char value index) #\,)
                   (incf index)
                   (setf index (websocket-skip-ows value index)))
                  (t (return-from websocket-extension-list-p nil))))))))

(defun websocket-extensions-ok-p (headers)
  "RFC 6455 §9.1. Absent means the client offered nothing. Repeated
field lines are one list. A value that is not the extension grammar
fails the handshake."
  (let ((values (header-values headers "sec-websocket-extensions")))
    (or (null values)
        (websocket-extension-list-p (format nil "~{~a~^,~}" values)))))

(defun websocket-unique-token-list-p (value)
  "RFC 6455 §4.1. 1#token, and every token is a different string.
Empty list members do not count."
  (let ((index (websocket-skip-ows value 0))
        (end (length value))
        (seen nil)
        (found nil))
    (loop
      (when (>= index end)
        (return found))
      (if (char= (char value index) #\,)
          (progn
            (incf index)
            (setf index (websocket-skip-ows value index)))
          (multiple-value-bind (token next) (websocket-read-token value index)
            (unless token
              (return-from websocket-unique-token-list-p nil))
            (when (member token seen :test #'string=)
              (return-from websocket-unique-token-list-p nil))
            (push token seen)
            (setf found t
                  index (websocket-skip-ows value next))
            (cond ((>= index end) (return t))
                  ((char= (char value index) #\,)
                   (incf index)
                   (setf index (websocket-skip-ows value index)))
                  (t (return-from websocket-unique-token-list-p nil))))))))

(defun websocket-protocol-ok-p (headers)
  "RFC 6455 §4.1. Absent means the client offered no subprotocol.
Repeated field lines are one list."
  (let ((values (header-values headers "sec-websocket-protocol")))
    (or (null values)
        (websocket-unique-token-list-p (format nil "~{~a~^,~}" values)))))

(defun websocket-protocol-rejected ()
  (make-response :status 400
                 :content-type "text/plain; charset=utf-8"
                 :body "malformed WebSocket protocol"))

(defun websocket-extensions-rejected ()
  (make-response :status 400
                 :content-type "text/plain; charset=utf-8"
                 :body "malformed WebSocket extensions"))

(defun websocket-version-rejected ()
  (make-response :status 400
                 :headers '(("sec-websocket-version" . "13"))
                 :content-type "text/plain; charset=utf-8"
                 :body "WebSocket version must be 13"))

(defun perform-websocket-handshake (stream request handler)
  (let* ((keys (header-values (request-headers request) "sec-websocket-key"))
         (key (first keys)))
    ;; RFC 6455 §11.3.1. Sec-WebSocket-Key appears once. A second field
    ;; is not the opening handshake (Section 4.2.1).
    (unless (and key (null (rest keys)) (valid-websocket-key-p key))
      (protocol-error 400 :detail "bad websocket key"))
    (unless (websocket-version-ok-p (request-headers request))
      (write-response stream request (websocket-version-rejected) :close-connection t)
      (return-from perform-websocket-handshake :closed))
    ;; RFC 6455 §9.1. A malformed offer fails the connection before 101.
    (unless (websocket-extensions-ok-p (request-headers request))
      (write-response stream request (websocket-extensions-rejected) :close-connection t)
      (return-from perform-websocket-handshake :closed))
    ;; RFC 6455 §4.1. Subprotocol names are unique tokens.
    (unless (websocket-protocol-ok-p (request-headers request))
      (write-response stream request (websocket-protocol-rejected) :close-connection t)
      (return-from perform-websocket-handshake :closed))
    ;; RFC 9110 §7.8. A declared body already got 100 from read-request.
    (when (and (expect-continue-p (request-headers request)
                                  (request-http-version request))
               (not (header-value (request-headers request) "content-length"))
               (not (transfer-codings (request-headers request))))
      (send-continue stream))
    (write-ascii stream "HTTP/1.1 101 Switching Protocols")
    (write-crlf stream)
    (write-header-fields stream
                         `(("upgrade" . "websocket")
                           ("connection" . "Upgrade")
                           ("sec-websocket-accept" . ,(websocket-accept key))
                           ("server" . "pazuzu")))
    (write-crlf stream)
    (finish-output stream)
    (funcall handler (make-websocket :stream stream))
    :closed))

(defclass octet-pipe (sb-gray:fundamental-binary-input-stream
                      sb-gray:fundamental-binary-output-stream)
  ((lock :initform (bt:make-lock "pazuzu-pipe") :reader pipe-lock)
   (cv :initform (bt:make-condition-variable) :reader pipe-cv)
   (inbox :initform (make-array 256 :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer 0)
          :reader pipe-inbox)
   (in-pos :initform 0 :accessor pipe-in-pos)
   (outbox :initform (make-array 256 :element-type '(unsigned-byte 8)
                                     :adjustable t :fill-pointer 0)
           :reader pipe-outbox)
   (out-pos :initform 0 :accessor pipe-out-pos)
   (input-closed :initform nil :accessor pipe-input-closed)
   (output-closed :initform nil :accessor pipe-output-closed)
   (on-output :initform nil :initarg :on-output :accessor pipe-on-output)))

(defun make-octet-pipe (&key on-output)
  (make-instance 'octet-pipe :on-output on-output))

(defun pipe-compact (buffer pos)
  (when (and (plusp pos) (> pos 4096))
    (replace buffer buffer :start2 pos)
    (decf (fill-pointer buffer) pos)
    0))

(defun pipe-append (buffer octets)
  (let ((start (fill-pointer buffer)))
    (when (> (+ start (length octets)) (array-total-size buffer))
      (adjust-array buffer (+ start (length octets) 256)))
    (incf (fill-pointer buffer) (length octets))
    (replace buffer octets :start1 start)))

(defun pipe-feed (pipe octets)
  (bt:with-lock-held ((pipe-lock pipe))
    (unless (pipe-input-closed pipe)
      (pipe-append (pipe-inbox pipe) octets)
      (bt:condition-notify (pipe-cv pipe)))))

(defun pipe-shutdown (pipe)
  (bt:with-lock-held ((pipe-lock pipe))
    (setf (pipe-input-closed pipe) t
          (pipe-output-closed pipe) t)
    (bt:condition-notify (pipe-cv pipe)))
  (let ((notify (pipe-on-output pipe)))
    (when notify
      (funcall notify pipe))))

(defmethod stream-element-type ((stream octet-pipe))
  '(unsigned-byte 8))

(defmethod close ((stream octet-pipe) &key abort)
  (declare (ignore abort))
  (pipe-shutdown stream)
  t)

(defmethod sb-gray:stream-read-byte ((stream octet-pipe))
  (bt:with-lock-held ((pipe-lock stream))
    (loop while (and (>= (pipe-in-pos stream) (fill-pointer (pipe-inbox stream)))
                     (not (pipe-input-closed stream)))
          do (bt:condition-wait (pipe-cv stream) (pipe-lock stream)))
    (if (>= (pipe-in-pos stream) (fill-pointer (pipe-inbox stream)))
        :eof
        (prog1 (aref (pipe-inbox stream) (pipe-in-pos stream))
          (incf (pipe-in-pos stream))
          (let ((next (pipe-compact (pipe-inbox stream) (pipe-in-pos stream))))
            (when next
              (setf (pipe-in-pos stream) next)))))))

(defmethod sb-gray:stream-read-sequence ((stream octet-pipe) sequence &optional (start 0) end)
  (let ((end (or end (length sequence)))
        (index start))
    (loop while (< index end)
          for byte = (sb-gray:stream-read-byte stream)
          until (eq byte :eof)
          do (setf (elt sequence index) byte)
             (incf index))
    index))

(defun pipe-note-output (pipe)
  (let ((notify (pipe-on-output pipe)))
    (when notify
      (funcall notify pipe))))

(defmethod sb-gray:stream-write-byte ((stream octet-pipe) byte)
  (bt:with-lock-held ((pipe-lock stream))
    (when (pipe-output-closed stream)
      (error "WebSocket output is closed."))
    (let ((buffer (pipe-outbox stream)))
      (when (= (fill-pointer buffer) (array-total-size buffer))
        (adjust-array buffer (+ (fill-pointer buffer) 256)))
      (vector-push-extend byte buffer)))
  byte)

(defmethod sb-gray:stream-write-sequence ((stream octet-pipe) sequence &optional (start 0) end)
  (let ((end (or end (length sequence)))
        (octets (if (typep sequence '(vector (unsigned-byte 8)))
                    sequence
                    (map '(vector (unsigned-byte 8)) #'identity sequence))))
    (bt:with-lock-held ((pipe-lock stream))
      (when (pipe-output-closed stream)
        (error "WebSocket output is closed."))
      (pipe-append (pipe-outbox stream) (subseq octets start end))))
  sequence)

(defmethod sb-gray:stream-finish-output ((stream octet-pipe))
  (pipe-note-output stream))

(defmethod sb-gray:stream-force-output ((stream octet-pipe))
  (pipe-note-output stream))

(defun pipe-copy-output (pipe destination length)
  "Copy up to LENGTH output bytes into DESTINATION. Return (values count eof)."
  (bt:with-lock-held ((pipe-lock pipe))
    (let* ((available (- (fill-pointer (pipe-outbox pipe)) (pipe-out-pos pipe)))
           (count (min length available)))
      (loop for index below count
            do (setf (cffi:mem-ref destination :uint8 index)
                     (aref (pipe-outbox pipe) (+ (pipe-out-pos pipe) index))))
      (incf (pipe-out-pos pipe) count)
      (let ((next (pipe-compact (pipe-outbox pipe) (pipe-out-pos pipe))))
        (when next
          (setf (pipe-out-pos pipe) next)))
      (values count
              (and (pipe-output-closed pipe)
                   (= (pipe-out-pos pipe) (fill-pointer (pipe-outbox pipe))))))))

(defun pipe-take-output (pipe length)
  "Copy up to LENGTH output bytes into a fresh vector. Return (values octets eof)."
  (bt:with-lock-held ((pipe-lock pipe))
    (let* ((available (- (fill-pointer (pipe-outbox pipe)) (pipe-out-pos pipe)))
           (count (min length available))
           (octets (make-array count :element-type '(unsigned-byte 8))))
      (replace octets (pipe-outbox pipe) :start2 (pipe-out-pos pipe))
      (incf (pipe-out-pos pipe) count)
      (let ((next (pipe-compact (pipe-outbox pipe) (pipe-out-pos pipe))))
        (when next
          (setf (pipe-out-pos pipe) next)))
      (values octets
              (and (pipe-output-closed pipe)
                   (= (pipe-out-pos pipe) (fill-pointer (pipe-outbox pipe))))))))

(defun websocket-extended-response (request)
  "Response headers for an extended CONNECT websocket (RFC 8441 / RFC 9220).
The stream stays open; the caller supplies the body."
  (let ((key (request-header request "sec-websocket-key")))
    (unless (and key (valid-websocket-key-p key))
      (protocol-error 400 :detail "bad websocket key"))
    (unless (websocket-version-ok-p (request-headers request))
      (return-from websocket-extended-response (websocket-version-rejected)))
    (unless (websocket-extensions-ok-p (request-headers request))
      (return-from websocket-extended-response (websocket-extensions-rejected)))
    (unless (websocket-protocol-ok-p (request-headers request))
      (return-from websocket-extended-response (websocket-protocol-rejected)))
    (make-response :status 200
                   :headers `(("sec-websocket-accept" . ,(websocket-accept key)))
                   :body nil)))

(defun start-websocket-thread (server handler pipe)
  (note-thread
   server
   (bt:make-thread
    (lambda ()
      (unwind-protect
           (handler-case (funcall handler (make-websocket :stream pipe))
             (error (condition)
               (format *error-output* "pazuzu: websocket: ~a~%" condition)))
        (pipe-shutdown pipe)))
    :name "pazuzu-websocket")))
