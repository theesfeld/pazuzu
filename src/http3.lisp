(in-package #:pazuzu)

(native-version "ngtcp2_version" 'libngtcp2 #x011900 "ngtcp2")
(native-version "nghttp3_version" 'libnghttp3 #x011200 "nghttp3")

(defconstant +ngtcp2-callback-failure+ -502)
(defconstant +ngtcp2-stream-data-blocked+ -208)
(defconstant +ngtcp2-stream-id-blocked+ -206)
(defconstant +ngtcp2-stream-shut-wr+ -219)
(defconstant +ngtcp2-stream-not-found+ -220)
(defconstant +ngtcp2-closing+ -223)
(defconstant +ngtcp2-draining+ -224)
(defconstant +ngtcp2-write-more+ -230)
(defconstant +ngtcp2-retry+ -231)
(defconstant +ngtcp2-drop-conn+ -232)
(defconstant +ngtcp2-crypto+ -213)
(defconstant +ngtcp2-version-negotiation+ -235)
(defconstant +ngtcp2-handshake-timeout+ -236)
(defconstant +ngtcp2-idle-close+ -238)
(defconstant +ngtcp2-proto+ -203)
(defconstant +ngtcp2-stream-state+ -221)
(defconstant +nghttp3-wouldblock+ -103)
(defconstant +nghttp3-malformed-header+ -105)
(defconstant +nghttp3-malformed-messaging+ -107)
(defconstant +nghttp3-frame-unexpected+ -601)
(defconstant +h3-id-error+ #x0108)
(defconstant +h3-frame-cancel-push+ 3)
(defconstant +nghttp3-callback-failure+ -902)
(defconstant +h3-data-eof+ #x01)
(defconstant +h3-write-more+ #x01)
(defconstant +h3-write-fin+ #x02)
(defconstant +quic-v1+ 1)
(defconstant +h3-no-error+ #x0100)
(defconstant +h3-frame-headers+ 1)
(defconstant +qpack-emit+ 1)
(defconstant +qpack-final+ 2)
(defconstant +qpack-blocked+ 4)
(defconstant +quic-connection-refused+ #x02)
(defconstant +quic-invalid-token+ #x0b)
(defconstant +retry-token-timeout+ 10000000000)
(defconstant +retry-token-type+ 1)
(defconstant +uint64-max+ (1- (ash 1 64)))

(cffi:defcfun ("ngtcp2_crypto_ossl_init" ngtcp2-crypto-init :library libngtcp2-crypto) :int)
(cffi:defcfun ("ngtcp2_crypto_ossl_ctx_new" ngtcp2-crypto-ctx-new :library libngtcp2-crypto) :int
  (out :pointer) (ssl :pointer))
(cffi:defcfun ("ngtcp2_crypto_ossl_ctx_del" ngtcp2-crypto-ctx-del :library libngtcp2-crypto) :void
  (ctx :pointer))
(cffi:defcfun ("ngtcp2_crypto_ossl_configure_server_session" ngtcp2-crypto-configure-server
               :library libngtcp2-crypto) :int
  (ssl :pointer))
(cffi:defcfun ("ngtcp2_accept" ngtcp2-accept :library libngtcp2) :int
  (dest :pointer) (packet :pointer) (length :unsigned-long))
(cffi:defcfun ("ngtcp2_crypto_generate_retry_token2" ngtcp2-generate-retry-token
               :library libngtcp2-crypto) :long
  (token :pointer) (secret :pointer) (secretlen :unsigned-long) (version :uint32)
  (remote :pointer) (remotelen :unsigned-int)
  (retry-scid :pointer) (odcid :pointer) (ts :uint64))
(cffi:defcfun ("ngtcp2_crypto_verify_retry_token2" ngtcp2-verify-retry-token
               :library libngtcp2-crypto) :int
  (odcid :pointer) (token :pointer) (tokenlen :unsigned-long)
  (secret :pointer) (secretlen :unsigned-long) (version :uint32)
  (remote :pointer) (remotelen :unsigned-int)
  (dcid :pointer) (timeout :uint64) (ts :uint64))
(cffi:defcfun ("ngtcp2_crypto_write_retry" ngtcp2-write-retry
               :library libngtcp2-crypto) :long
  (dest :pointer) (destlen :unsigned-long) (version :uint32)
  (dcid :pointer) (scid :pointer) (odcid :pointer)
  (token :pointer) (tokenlen :unsigned-long))
(cffi:defcfun ("ngtcp2_crypto_write_connection_close" ngtcp2-write-stateless-close
               :library libngtcp2-crypto) :long
  (dest :pointer) (destlen :unsigned-long) (version :uint32)
  (dcid :pointer) (scid :pointer) (error-code :uint64)
  (reason :pointer) (reasonlen :unsigned-long))
(cffi:defcfun ("ngtcp2_conn_server_new_versioned" ngtcp2-server-new :library libngtcp2) :int
  (out :pointer) (dcid :pointer) (scid :pointer) (path :pointer) (version :uint32)
  (callbacks-version :int) (callbacks :pointer) (settings-version :int) (settings :pointer)
  (params-version :int) (params :pointer) (memory :pointer) (user-data :pointer))
(cffi:defcfun ("ngtcp2_conn_del" ngtcp2-conn-del :library libngtcp2) :void
  (conn :pointer))
(cffi:defcfun ("ngtcp2_conn_set_tls_native_handle" ngtcp2-set-tls-native :library libngtcp2) :void
  (conn :pointer) (handle :pointer))
(cffi:defcfun ("ngtcp2_conn_read_pkt_versioned" ngtcp2-read-pkt :library libngtcp2) :int
  (conn :pointer) (path :pointer) (pkt-info-version :int) (pkt-info :pointer)
  (packet :pointer) (length :unsigned-long) (ts :uint64))
(cffi:defcfun ("ngtcp2_conn_writev_stream_versioned" ngtcp2-writev-stream :library libngtcp2) :long
  (conn :pointer) (path :pointer) (pkt-info-version :int) (pkt-info :pointer)
  (dest :pointer) (destlen :unsigned-long) (datalen :pointer) (flags :uint32)
  (stream-id :int64) (vecs :pointer) (veccnt :unsigned-long) (ts :uint64))
(cffi:defcfun ("ngtcp2_conn_write_connection_close_versioned" ngtcp2-write-close :library libngtcp2) :long
  (conn :pointer) (path :pointer) (pkt-info-version :int) (pkt-info :pointer)
  (dest :pointer) (destlen :unsigned-long) (ccerr :pointer) (ts :uint64))
(cffi:defcfun ("ngtcp2_conn_update_pkt_tx_time" ngtcp2-update-tx :library libngtcp2) :void
  (conn :pointer) (ts :uint64))
(cffi:defcfun ("ngtcp2_conn_get_expiry" ngtcp2-expiry :library libngtcp2) :uint64
  (conn :pointer))
(cffi:defcfun ("ngtcp2_conn_handle_expiry" ngtcp2-handle-expiry :library libngtcp2) :int
  (conn :pointer) (ts :uint64))
(cffi:defcfun ("ngtcp2_conn_extend_max_stream_offset" ngtcp2-extend-stream :library libngtcp2) :int
  (conn :pointer) (stream-id :int64) (datalen :uint64))
(cffi:defcfun ("ngtcp2_conn_extend_max_offset" ngtcp2-extend-conn :library libngtcp2) :void
  (conn :pointer) (datalen :uint64))
(cffi:defcfun ("ngtcp2_conn_shutdown_stream_read" ngtcp2-shutdown-read :library libngtcp2) :int
  (conn :pointer) (flags :uint32) (stream-id :int64) (app-error :uint64))
(cffi:defcfun ("ngtcp2_conn_shutdown_stream_write" ngtcp2-shutdown-write :library libngtcp2) :int
  (conn :pointer) (flags :uint32) (stream-id :int64) (app-error :uint64))
(cffi:defcfun ("ngtcp2_conn_open_uni_stream" ngtcp2-open-uni :library libngtcp2) :int
  (conn :pointer) (stream-id :pointer) (user-data :pointer))
(cffi:defcfun ("ngtcp2_cid_init" ngtcp2-cid-init :library libngtcp2) :void
  (cid :pointer) (data :pointer) (length :unsigned-long))
(cffi:defcfun ("ngtcp2_pkt_decode_version_cid" ngtcp2-decode-version-cid :library libngtcp2) :int
  (dest :pointer) (data :pointer) (length :unsigned-long) (short-dcidlen :unsigned-long))
(cffi:defcfun ("ngtcp2_pkt_write_version_negotiation" ngtcp2-write-vn :library libngtcp2) :long
  (dest :pointer) (destlen :unsigned-long) (unused-random :uint8)
  (dcid :pointer) (dcidlen :unsigned-long)
  (scid :pointer) (scidlen :unsigned-long)
  (versions :pointer) (count :unsigned-long))
(cffi:defcfun ("ngtcp2_path_storage_init" ngtcp2-path-init :library libngtcp2) :void
  (path :pointer) (local :pointer) (local-len :unsigned-long)
  (remote :pointer) (remote-len :unsigned-long) (user-data :pointer))
(cffi:defcfun ("ngtcp2_path_storage_zero" ngtcp2-path-zero :library libngtcp2) :void
  (path :pointer))
(cffi:defcfun ("ngtcp2_settings_default_versioned" ngtcp2-settings-default :library libngtcp2) :void
  (version :int) (settings :pointer))
(cffi:defcfun ("ngtcp2_transport_params_default_versioned" ngtcp2-params-default :library libngtcp2) :void
  (version :int) (params :pointer))
(cffi:defcfun ("ngtcp2_ccerr_set_liberr" ngtcp2-ccerr-liberr :library libngtcp2) :void
  (ccerr :pointer) (liberr :int) (reason :pointer) (length :unsigned-long))
(cffi:defcfun ("ngtcp2_ccerr_set_application_error" ngtcp2-ccerr-app :library libngtcp2) :void
  (ccerr :pointer) (code :uint64) (reason :pointer) (length :unsigned-long))
(cffi:defcfun ("ngtcp2_conn_get_conn_info_versioned" ngtcp2-conn-info :library libngtcp2) :void
  (conn :pointer) (version :int) (info :pointer))
(cffi:defcfun ("nghttp3_settings_default_versioned" nghttp3-settings-default :library libnghttp3) :void
  (version :int) (settings :pointer))
(cffi:defcfun ("nghttp3_conn_server_new_versioned" nghttp3-server-new :library libnghttp3) :int
  (out :pointer) (callbacks-version :int) (callbacks :pointer)
  (settings-version :int) (settings :pointer) (memory :pointer) (user-data :pointer))
(cffi:defcfun ("nghttp3_conn_del" nghttp3-conn-del :library libnghttp3) :void
  (conn :pointer))
(cffi:defcfun ("nghttp3_conn_bind_control_stream" nghttp3-bind-control :library libnghttp3) :int
  (conn :pointer) (stream-id :int64))
(cffi:defcfun ("nghttp3_conn_bind_qpack_streams" nghttp3-bind-qpack :library libnghttp3) :int
  (conn :pointer) (encoder :int64) (decoder :int64))
(cffi:defcfun ("nghttp3_conn_read_stream2" nghttp3-read-stream :library libnghttp3) :long
  (conn :pointer) (stream-id :int64) (src :pointer) (length :unsigned-long) (fin :int) (ts :uint64))
(cffi:defcfun ("nghttp3_conn_shutdown_stream_read" nghttp3-shutdown-read :library libnghttp3) :int
  (conn :pointer) (stream-id :int64))
(cffi:defcfun ("nghttp3_conn_writev_stream" nghttp3-writev :library libnghttp3) :long
  (conn :pointer) (stream-id :pointer) (fin :pointer) (vecs :pointer) (count :unsigned-long))
(cffi:defcfun ("nghttp3_conn_add_write_offset" nghttp3-add-write-offset :library libnghttp3) :int
  (conn :pointer) (stream-id :int64) (n :unsigned-long))
(cffi:defcfun ("nghttp3_conn_add_ack_offset" nghttp3-add-ack-offset :library libnghttp3) :int
  (conn :pointer) (stream-id :int64) (n :uint64))
(cffi:defcfun ("nghttp3_conn_block_stream" nghttp3-block-stream :library libnghttp3) :void
  (conn :pointer) (stream-id :int64))
(cffi:defcfun ("nghttp3_conn_unblock_stream" nghttp3-unblock-stream :library libnghttp3) :int
  (conn :pointer) (stream-id :int64))
(cffi:defcfun ("nghttp3_conn_resume_stream" nghttp3-resume-stream :library libnghttp3) :int
  (conn :pointer) (stream-id :int64))
(cffi:defcfun ("nghttp3_conn_close_stream2" nghttp3-close-stream :library libnghttp3) :int
  (conn :pointer) (flags :uint32) (stream-id :int64) (rx :uint64) (tx :uint64))
(cffi:defcfun ("nghttp3_conn_submit_response" nghttp3-submit-response :library libnghttp3) :int
  (conn :pointer) (stream-id :int64) (fields :pointer) (count :unsigned-long) (reader :pointer))
(cffi:defcfun ("nghttp3_conn_submit_info" nghttp3-submit-info :library libnghttp3) :int
  (conn :pointer) (stream-id :int64) (fields :pointer) (count :unsigned-long))
(cffi:defcfun ("nghttp3_err_infer_quic_app_error_code" nghttp3-app-error :library libnghttp3) :uint64
  (liberr :int))
(cffi:defcfun ("nghttp3_mem_default" nghttp3-mem-default :library libnghttp3) :pointer)
(cffi:defcfun ("nghttp3_qpack_decoder_new" nghttp3-qpack-decoder-new :library libnghttp3) :int
  (decoder :pointer) (hard-max :unsigned-long) (max-blocked :unsigned-long) (memory :pointer))
(cffi:defcfun ("nghttp3_qpack_decoder_del" nghttp3-qpack-decoder-del :library libnghttp3) :void
  (decoder :pointer))
(cffi:defcfun ("nghttp3_qpack_stream_context_new" nghttp3-qpack-sctx-new :library libnghttp3) :int
  (context :pointer) (stream-id :int64) (memory :pointer))
(cffi:defcfun ("nghttp3_qpack_stream_context_del" nghttp3-qpack-sctx-del :library libnghttp3) :void
  (context :pointer))
(cffi:defcfun ("nghttp3_qpack_stream_context_reset" nghttp3-qpack-sctx-reset :library libnghttp3) :void
  (context :pointer))
(cffi:defcfun ("nghttp3_qpack_decoder_read_request" nghttp3-qpack-read-request :library libnghttp3) :long
  (decoder :pointer) (context :pointer) (field :pointer) (flags :pointer)
  (src :pointer) (length :unsigned-long) (fin :int))
(cffi:defcfun ("nghttp3_rcbuf_decref" nghttp3-rcbuf-decref :library libnghttp3) :void
  (buffer :pointer))
(cffi:defcstruct h3-qpack-nv
  (name :pointer)
  (value :pointer)
  (token :int32)
  (flags :uint8))
(cffi:defcfun ("SSL_set_ex_data" %ssl-set-ex-data :library cl+ssl::libssl) :int
  (ssl :pointer) (index :int) (arg :pointer))

;; Returned by value. libffi matches the System V register return.
;; sb-alien on SBCL 2.2.9 reads that 16-byte struct from the wrong place
;; and treats a pointer as the length. cffi-libffi has to be loaded
;; before this macro expands.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (asdf:load-system :cffi-libffi))
(cffi:defcstruct nghttp3-vec
  (base :pointer)
  (len :unsigned-long))

(cffi:defcfun ("nghttp3_rcbuf_get_buf" %h3-rcbuf-buf :library libnghttp3)
    (:struct nghttp3-vec)
  (rcbuf :pointer))

(defvar *h3-quic-callbacks* nil)
(defvar *h3-http-callbacks* nil)
(defvar *h3-http-settings* nil)
(defvar *h3-reader* nil)
(defvar *h3-ossl* nil)

(defvar *h3-sendonly-reset* (make-hash-table :test #'eq :weakness :key)
  "True when the last ngtcp2 log line for this connection is a received
RESET_STREAM on a server send-only stream. The pair is replaced as a
whole so a reader sees one answer.")

(defconstant +h3-initial-rtt+ 333000000
  "ngtcp2 NGTCP2_DEFAULT_INITIAL_RTT, in nanoseconds.")
(defconstant +h3-cstat+ 8200)
(defconstant +h3-pktns+ 720)
(defconstant +h3-hs-pktns+ 712)
(defconstant +h3-largest-acked+ 2216)
(defconstant +h3-cc-pkt-num+ 2256)
(defconstant +h3-cc+ 8760)
(defconstant +h3-cc-reset+ 8824)
(defconstant +h3-pacing-next+ 6016)
(defconstant +h3-pacing-comp+ 6024)
(defconstant +h3-rtb+ 1312)
(defconstant +h3-rtb-cc-pkt+ 224)
(defconstant +h3-rtb-cc-bytes+ 232)
(defconstant +h3-rst+ 8624)
(defconstant +h3-rst-delivered+ 80)
(defvar *h3-cc-layout-ok* nil
  "True after a fresh connection's congestion block matches ngtcp2 1.25.0.
Writes are refused when this stays false.")
(defvar *h3-path-reset-log* nil)
(defvar *h3-path-log-lock* (bt:make-lock "pazuzu-h3-path-log"))
(defvar *h3-path-rtt-guard* (make-hash-table :test #'eq :weakness :key))
(defvar *h3-first-peer* (make-hash-table :test #'eq :weakness :key))
(defvar *h3-rtt-moved* (make-hash-table :test #'eq :weakness :key))
(defvar *h3-initial-cwnd* (make-hash-table :test #'eq :weakness :key))

(defun h3-path-note (entry)
  (bt:with-lock-held (*h3-path-log-lock*)
    (when (< (length *h3-path-reset-log*) 64)
      (push entry *h3-path-reset-log*))))

(defun h3-clear-path-log ()
  (bt:with-lock-held (*h3-path-log-lock*)
    (setf *h3-path-reset-log* nil)))

(defun h3-path-log ()
  (bt:with-lock-held (*h3-path-log-lock*)
    (reverse *h3-path-reset-log*)))

(defstruct h3-endpoint
  server socket fd context wake local-host local-port
  (connections (make-hash-table :test #'equalp))
  (lock (bt:make-lock "pazuzu-h3"))
  (retry-secret (simple-octets (ironclad:random-data 32)))
  pending
  (alive t)
  draining
  drained)

(defstruct h3-conn
  endpoint quic http3 ssl crypto conn-ref path pin peer
  (cids nil)
  (streams (make-hash-table))
  (lock (bt:make-lock "pazuzu-h3-conn"))
  dirty closing freed admitted
  app-close
  ;; Set when the peer's control stream carries CANCEL_PUSH. This server
  ;; never sends PUSH_PROMISE, so that push ID is unknown (RFC 9114 §7.2.3).
  id-error
  ;; Per-stream HTTP/3 frame state. nghttp3 removes a field whose value
  ;; violates RFC 9113 §8.2.1 instead of resetting the stream, so the
  ;; origin decodes the same header block and supplies the stream error.
  (wires (make-hash-table :test #'eql))
  ;; Server-initiated unidirectional streams opened for HTTP/3, in order.
  ;; Bound once the control stream and both QPACK streams exist.
  uni-ids
  uni-bound
  ;; Stateless reset tokens for destination connection IDs this endpoint
  ;; has started using. Unused and retired identifiers are absent
  ;; (RFC 9000 §10.3.1). Each entry is (sequence . token).
  (reset-tokens nil))

(defstruct h3-stream
  id method scheme authority path protocol
  headers trailers
  (header-bytes 0)
  (field-count 0)
  in-trailers
  (body (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  overflow header-error dispatched reset websocket pipe
  message-error
  source buffer (buffer-pos 0) foreign (unacked 0) submitted
  continue early
  (started (get-internal-real-time)))

(defstruct h3-wire
  id
  (phase :type)
  (acc 0)
  (need 0)
  frame-type
  (left 0)
  headers-p
  qpack
  qctx
  (pending (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  malformed
  ;; A regular field has already been emitted in this header section.
  ;; A later pseudo-header makes the section malformed (RFC 9114 §4.3).
  regular
  ;; Pseudo-header names already emitted in this header section.
  ;; A repeated name is malformed (RFC 9114 §4.3.1).
  pseudos
  ;; A header section has already been seen on this request stream.
  ;; A later HEADERS frame is trailers (RFC 9114 §4.3).
  saw-headers
  trailers
  ;; Value of :method in the current header section, if one was present.
  method
  ;; :scheme, :authority, and Host in the current header section.
  ;; An http or https request needs one of the last two (RFC 9114 §4.3.1).
  scheme
  authority
  host)

(defun h3-from (user-data)
  (pointer-pin user-data))

(defun h3-stream (conn stream-id)
  (and conn (gethash stream-id (h3-conn-streams conn))))

(defun ipv6-host-p (host)
  (and (vectorp host) (= (length host) 16)))

(defun format-ip (host)
  (cond ((and (vectorp host) (= (length host) 4))
         (format nil "~d.~d.~d.~d"
                 (aref host 0) (aref host 1) (aref host 2) (aref host 3)))
        ((ipv6-host-p host)
         (with-output-to-string (out)
           (loop for index from 0 below 16 by 2
                 do (unless (zerop index)
                      (write-char #\: out))
                    (format out "~x" (logior (ash (aref host index) 8)
                                             (aref host (1+ index)))))))
        (t (princ-to-string host))))

(defun fill-sockaddr-in (pointer host port)
  (foreign-zero pointer 16)
  (setf (cffi:mem-ref pointer :uint16) 2)
  (setf (cffi:mem-ref pointer :uint8 2) (ldb (byte 8 8) port))
  (setf (cffi:mem-ref pointer :uint8 3) (ldb (byte 8 0) port))
  (loop for index below 4
        do (setf (cffi:mem-ref pointer :uint8 (+ 4 index)) (aref host index))))

(defun fill-sockaddr (pointer host port)
  "Write a sockaddr_in or sockaddr_in6. Return the address length."
  (cond ((ipv6-host-p host)
         (foreign-zero pointer 28)
         (setf (cffi:mem-ref pointer :uint16) 10)
         (setf (cffi:mem-ref pointer :uint8 2) (ldb (byte 8 8) port))
         (setf (cffi:mem-ref pointer :uint8 3) (ldb (byte 8 0) port))
         (loop for index below 16
               do (setf (cffi:mem-ref pointer :uint8 (+ 8 index)) (aref host index)))
         28)
        (t
         (fill-sockaddr-in pointer host port)
         16)))

(defun path-remote (path)
  (let ((addr (cffi:mem-ref path :pointer 16))
        (len (cffi:mem-ref path :unsigned-long 24)))
    (when (and addr (not (cffi:null-pointer-p addr)) (>= len 8))
      (let ((port (logior (ash (cffi:mem-ref addr :uint8 2) 8)
                          (cffi:mem-ref addr :uint8 3))))
        (case (cffi:mem-ref addr :uint16)
          (2 (values (foreign-to-octets (cffi:inc-pointer addr 4) 4) port))
          (10 (values (foreign-to-octets (cffi:inc-pointer addr 8) 16) port)))))))

(defun h3-send (endpoint path dest length &optional (ecn 0))
  "Send the datagram ngtcp2 just wrote. ECN is the codepoint ngtcp2 stored
in the packet info. The socket default stays NOT_ECT."
  (multiple-value-bind (host port) (path-remote path)
    (when (and host port (h3-endpoint-fd endpoint) (>= (h3-endpoint-fd endpoint) 0))
      (ignore-errors
        (udp-sendmsg (h3-endpoint-fd endpoint) host port dest length ecn)))))

(defun h3-connections (endpoint)
  (bt:with-lock-held ((h3-endpoint-lock endpoint))
    (remove-duplicates (alexandria:hash-table-values (h3-endpoint-connections endpoint)))))

(defun h3-index (endpoint cid conn)
  (let ((key (copy-seq (simple-octets cid))))
    (bt:with-lock-held ((h3-endpoint-lock endpoint))
      (setf (gethash key (h3-endpoint-connections endpoint)) conn)
      (pushnew key (h3-conn-cids conn) :test #'equalp))))

(defun h3-find (endpoint cid)
  (bt:with-lock-held ((h3-endpoint-lock endpoint))
    (gethash (simple-octets cid) (h3-endpoint-connections endpoint))))

(defun h3-mark-dirty (conn stream-id)
  (bt:with-lock-held ((h3-conn-lock conn))
    (pushnew stream-id (h3-conn-dirty conn)))
  (let ((endpoint (h3-conn-endpoint conn)))
    (when (and endpoint (h3-endpoint-alive endpoint))
      (eventfd-write (h3-endpoint-wake endpoint)))))

(defun h3-resume-conn (conn)
  (let ((ids (bt:with-lock-held ((h3-conn-lock conn))
               (shiftf (h3-conn-dirty conn) nil))))
    (when (h3-conn-http3 conn)
      (dolist (id ids)
        (ignore-errors (nghttp3-resume-stream (h3-conn-http3 conn) id))))))

(defun rcbuf-latin1 (rcbuf)
  "Latin-1 text of an nghttp3 rcbuf. %H3-RCBUF-BUF returns the vec by
value as a property list (base pointer, length)."
  (let* ((vec (%h3-rcbuf-buf rcbuf))
         (len (getf vec 'len))
         (base (getf vec 'base)))
    (unless (and (numberp len) (<= len (ash 1 20))
                 base (not (cffi:null-pointer-p base)))
      (error "rcbuf length ~a" len))
    (let ((octets (make-array len :element-type '(unsigned-byte 8))))
      (loop for index below len
            do (setf (aref octets index) (cffi:mem-ref base :uint8 index)))
      (babel:octets-to-string octets :encoding :iso-8859-1))))

(defun h3-extend (conn stream-id amount)
  (when (and conn (h3-conn-quic conn) (not (h3-conn-freed conn)) (plusp amount))
    (ngtcp2-extend-stream (h3-conn-quic conn) stream-id amount)
    (ngtcp2-extend-conn (h3-conn-quic conn) amount)))

(defun h3-queue (conn stream-id response &key head websocket)
  (let ((endpoint (h3-conn-endpoint conn)))
    (when (and endpoint (h3-endpoint-alive endpoint))
      (bt:with-lock-held ((h3-endpoint-lock endpoint))
        (push (list conn stream-id response head websocket) (h3-endpoint-pending endpoint)))
      (eventfd-write (h3-endpoint-wake endpoint)))))

(defun h3-stub-request (conn stream)
  (make-request :method (or (h3-stream-method stream) "GET")
                :target (or (h3-stream-path stream) "/")
                :path "/"
                :http-version 30
                :headers (h3-stream-headers stream)
                :scheme "https"
                :host (or (h3-stream-authority stream) "")
                :body (ascii-octets "")))

(defun h3-adopt-host-authority (stream)
  "RFC 9114 §4.3.1. An https request may carry its authority in Host when
:authority is absent. One valid Host becomes that authority."
  (when (h3-stream-authority stream)
    (return-from h3-adopt-host-authority nil))
  (let ((hosts (header-values (h3-stream-headers stream) "host")))
    (when (and hosts (null (rest hosts)) (valid-host-p (first hosts)))
      (setf (h3-stream-authority stream) (first hosts)))))

(defun h3-origin-request (conn stream)
  (h3-adopt-host-authority stream)
  (unless (and (h3-stream-method stream) (h3-stream-path stream)
               (h3-stream-authority stream) (h3-stream-scheme stream))
    (protocol-error 400 :detail "missing pseudo-header"))
  (unless (token-string-p (h3-stream-method stream))
    (protocol-error 400 :detail "bad method"))
  ;; RFC 3986 scheme is case-insensitive. The stored scheme stays https.
  (unless (string-equal (h3-stream-scheme stream) "https")
    (protocol-error 400 :detail "scheme"))
  (unless (valid-host-p (h3-stream-authority stream))
    (protocol-error 400 :detail "bad authority"))
  (reject-authority-host (h3-stream-authority stream)
                         (h3-stream-headers stream)
                         "https")
  (multiple-value-bind (path query target)
      (split-pseudo-path (h3-stream-method stream) (h3-stream-path stream))
    (make-request :method (h3-stream-method stream)
                  :target target
                  :path path
                  :query query
                  :http-version 30
                  :headers (setf (h3-stream-headers stream)
                                 (collapse-cookie-fields
                                  (nreverse (h3-stream-headers stream))))
                  :trailers (setf (h3-stream-trailers stream)
                                  (retain-trailer-fields
                                   (nreverse (h3-stream-trailers stream))))
                  :body (copy-seq (h3-stream-body stream))
                  :host (h3-stream-authority stream)
                  :scheme "https"
                  :peer (or (h3-conn-peer conn) ""))))

(defun h3-submit (conn stream response &key head)
  (when (or (h3-stream-submitted stream) (null (h3-conn-http3 conn)))
    (return-from h3-submit nil))
  ;; A final HEADERS with a 1xx status does not complete the response.
  ;; Interim 100 uses h3-submit-info.
  (when (< (response-status response) 200)
    (setf response (plain-error 500)))
  (let* ((logged (h3-stub-request conn stream))
         (server (h3-endpoint-server (h3-conn-endpoint conn))))
    (setf (request-peer logged) (or (h3-conn-peer conn) ""))
    (setf response (origin-decorate server logged response))
    ;; Build the field list before any body thread. A malformed field
    ;; becomes one 500, and the stream is not marked submitted yet.
    (handler-case (response-wire-fields response)
      (error (condition)
        (error-log (server-logger server) "error" "pazuzu: ~a" condition)
        (setf response (origin-decorate server logged (plain-error 500)))))
    (note-response server logged response
                   :seconds (/ (max 0 (- (get-internal-real-time) (h3-stream-started stream)))
                               internal-time-units-per-second)))
  (let* ((status (response-status response))
         (body (emitted-body response))
         (streaming (functionp body))
         (file (and (file-body-p body) body))
         (known (unless (or streaming file) (response-octets body)))
         (send-body (and (status-has-body-p status) (not head)
                         (or streaming
                             (and file (plusp (file-body-count file)))
                             (eq (h3-stream-source stream) :pipe)
                             (and known (plusp (length known)))))))
    (when (and (or streaming file) send-body)
      (let ((pipe (make-octet-pipe
                   :on-output (lambda (ignored)
                                (declare (ignore ignored))
                                (h3-mark-dirty conn (h3-stream-id stream))))))
        (setf (h3-stream-pipe stream) pipe
              (h3-stream-source stream) :pipe)
        (note-thread (h3-endpoint-server (h3-conn-endpoint conn))
                     (bt:make-thread
                      (lambda ()
                        (unwind-protect
                             (handler-case
                                 (if file
                                     (call-with-file-chunks
                                      file
                                      (lambda (octets)
                                        (write-sequence octets pipe)
                                        (finish-output pipe)))
                                     (funcall body
                                              (lambda (octets)
                                                (write-sequence (simple-octets octets) pipe)
                                                (finish-output pipe))))
                               (error (condition)
                                 (format *error-output* "pazuzu: stream: ~a~%" condition)))
                          (pipe-shutdown pipe)))
                      :name "pazuzu-stream"))))
    (when (and send-body known (not streaming) (not file)
               (not (eq (h3-stream-source stream) :pipe)))
      (setf (h3-stream-source stream) :buffer
            (h3-stream-buffer stream) known
            (h3-stream-buffer-pos stream) 0))
    (let ((fields (response-wire-fields response)))
      ;; A function stream has no length. A file span does, and the pipe
      ;; writes exactly that many octets.
      (when (and (eq (h3-stream-source stream) :pipe) (not file))
        (setf fields (remove "content-length" fields :key #'car :test #'string=)))
      (setf (h3-stream-submitted stream) t)
      (call-with-nv fields
        (lambda (nva count)
          (nghttp3-submit-response (h3-conn-http3 conn) (h3-stream-id stream)
                                   nva count
                                   (if send-body (h3-reader) (cffi:null-pointer))))))))

(defun h3-arm-websocket (conn stream)
  (handler-case
      (let* ((request (h3-origin-request conn stream))
             (server (h3-endpoint-server (h3-conn-endpoint conn)))
             (route (find-route server (request-path request)
                                 (request-host request))))
        (cond ((null route) (h3-queue conn (h3-stream-id stream) (plain-error 404)))
              ((not (route-websocket route))
               (h3-queue conn (h3-stream-id stream) (plain-error 501)))
              (t (let ((response (websocket-extended-response request)))
                   (when (= (response-status response) 200)
                     (setf (h3-stream-websocket stream) t
                           (h3-stream-pipe stream)
                           (make-octet-pipe :on-output
                                            (lambda (ignored)
                                              (declare (ignore ignored))
                                              (h3-mark-dirty conn (h3-stream-id stream))))
                           (h3-stream-source stream) :pipe))
                   (h3-queue conn (h3-stream-id stream) response
                             :websocket (and (= (response-status response) 200)
                                             (route-handler route)))))))
    (protocol-error (condition)
      (h3-queue conn (h3-stream-id stream) (protocol-error-response condition)))
    (error (condition)
      (format *error-output* "pazuzu: websocket: ~a~%" condition)
      (h3-queue conn (h3-stream-id stream) (plain-error 500)))))

(defun h3-spawn (conn stream)
  (handler-case
      (let* ((request (h3-origin-request conn stream))
             (server (h3-endpoint-server (h3-conn-endpoint conn)))
             (head (string= (h3-stream-method stream) "HEAD"))
             (id (h3-stream-id stream)))
        (note-thread server
                     (bt:make-thread
                      (lambda ()
                        (let* ((*request-id* (new-request-id))
                               (result (handler-case (dispatch server request)
                                        (protocol-error (condition)
                                          (protocol-error-response condition))
                                        (error (condition)
                                          (format *error-output* "pazuzu: [~a] ~a~%"
                                                  (or *request-id* "-") condition)
                                          (plain-error 500)))))
                          (h3-queue conn id
                                    (if (eq result :websocket) (plain-error 400) result)
                                    :head head)))
                      :name "pazuzu-h3-request")))
    (protocol-error (condition)
      (h3-queue conn (h3-stream-id stream) (protocol-error-response condition)))))

(defun h3-submit-info (conn stream)
  "Non-final :status 100. The final response is submitted later."
  (when (or (null (h3-conn-http3 conn)) (h3-conn-freed conn)
            (h3-stream-submitted stream) (h3-stream-reset stream))
    (return-from h3-submit-info nil))
  (call-with-nv '((":status" . "100"))
    (lambda (nva count)
      (let ((rv (nghttp3-submit-info (h3-conn-http3 conn) (h3-stream-id stream)
                                     nva count)))
        (unless (zerop rv)
          (error "nghttp3_conn_submit_info returned ~d" rv)))))
  t)

(defun h3-early-response (conn stream)
  "Final response decided from headers, or NIL when the body is required."
  (cond ((h3-stream-header-error stream)
         (plain-error (h3-stream-header-error stream)))
        ((h3-stream-overflow stream)
         (plain-error 413))
        ((request-limited-p (h3-endpoint-server (h3-conn-endpoint conn))
                            (or (h3-conn-peer conn) ""))
         (too-many-response))
        ;; RFC 9110 §9.3.6. A classic CONNECT with an empty or invalid port
        ;; is 400. Extended CONNECT names an origin and is not this check.
        ((and (equal (h3-stream-method stream) "CONNECT")
              (not (h3-stream-protocol stream))
              (not (connect-authority-ok-p (h3-stream-authority stream))))
         (plain-error 400))
        ((equal (h3-stream-method stream) "CONNECT")
         (plain-error 501))
        (t (handler-case
               (status-before-content (h3-endpoint-server (h3-conn-endpoint conn))
                                      (h3-origin-request conn stream))
             (protocol-error (condition)
               (protocol-error-response condition))))))

(defun h3-note-continue (conn stream)
  "RFC 9110 §10.1.1. Queue 100, or a final status known without the body."
  (handler-case
      (when (continue-expectation (h3-stream-headers stream))
        (let ((early (h3-early-response conn stream)))
          (cond (early
                 (setf (h3-stream-dispatched stream) t
                       (h3-stream-early stream) early))
                (t (setf (h3-stream-continue stream) t)))))
    (protocol-error (condition)
      (setf (h3-stream-dispatched stream) t
            (h3-stream-early stream) (protocol-error-response condition)))))

(defun h3-flush-expectations (conn)
  "Submit a queued 100 or early final response after nghttp3_conn_read_stream
has returned. A request that already ended in this read skips 100."
  (when (or (null conn) (h3-conn-freed conn) (null (h3-conn-http3 conn)))
    (return-from h3-flush-expectations nil))
  (handler-case
      (maphash (lambda (id stream)
                 (declare (ignore id))
                 (cond ((h3-stream-early stream)
                        (let ((response (h3-stream-early stream)))
                          (setf (h3-stream-early stream) nil)
                          (h3-submit conn stream response)))
                       ((and (h3-stream-continue stream)
                             (not (h3-stream-dispatched stream))
                             (not (h3-stream-reset stream)))
                        (setf (h3-stream-continue stream) nil)
                        (h3-submit-info conn stream))))
               (h3-conn-streams conn))
    (error (condition)
      (format *error-output* "pazuzu: continue: ~a~%" condition))))

(defun h3-finish-request (conn stream)
  (when (or (null stream) (h3-stream-dispatched stream) (h3-stream-reset stream)
            (h3-stream-message-error stream))
    (return-from h3-finish-request nil))
  (setf (h3-stream-dispatched stream) t)
  (when (request-limited-p (h3-endpoint-server (h3-conn-endpoint conn))
                           (or (h3-conn-peer conn) ""))
    (h3-queue conn (h3-stream-id stream) (too-many-response))
    (return-from h3-finish-request nil))
  (cond ((h3-stream-header-error stream)
         (h3-queue conn (h3-stream-id stream) (plain-error (h3-stream-header-error stream))))
        ((h3-stream-overflow stream)
         (h3-queue conn (h3-stream-id stream) (plain-error 413)))
        ((and (equal (h3-stream-method stream) "CONNECT")
              (equal (h3-stream-protocol stream) "websocket"))
         (h3-arm-websocket conn stream))
        ;; RFC 9110 §9.3.6. Reject an empty or invalid port before the
        ;; tunnel refusal. A present port in 0..65535 stays 501.
        ((and (equal (h3-stream-method stream) "CONNECT")
              (not (h3-stream-protocol stream))
              (not (connect-authority-ok-p (h3-stream-authority stream))))
         (h3-queue conn (h3-stream-id stream) (plain-error 400)))
        ((equal (h3-stream-method stream) "CONNECT")
         (h3-queue conn (h3-stream-id stream) (plain-error 501)))
        (t (h3-spawn conn stream))))

(defun h3-deliver (conn stream-id response head websocket)
  (let ((stream (h3-stream conn stream-id)))
    (unless (and stream (h3-conn-http3 conn) (h3-conn-quic conn)
                 (not (h3-conn-freed conn)))
      (return-from h3-deliver nil))
    (handler-case (h3-submit conn stream response :head head)
      (error (condition)
        (format *error-output* "pazuzu: http3: ~a~%" condition)
        (unless (h3-stream-submitted stream)
          (ignore-errors (h3-submit conn stream (plain-error 500) :head head)))))
    (when (and websocket (h3-stream-pipe stream))
      (start-websocket-thread (h3-endpoint-server (h3-conn-endpoint conn))
                              websocket
                              (h3-stream-pipe stream)))))

(defun h3-drain-pending (endpoint)
  (let ((items (bt:with-lock-held ((h3-endpoint-lock endpoint))
                 (shiftf (h3-endpoint-pending endpoint) nil))))
    (dolist (item (nreverse items))
      (destructuring-bind (conn stream-id response head websocket) item
        (h3-deliver conn stream-id response head websocket)))))

(cffi:defcallback h3-get-conn :pointer ((conn-ref :pointer))
  (cffi:mem-ref conn-ref :pointer 8))

(defun h3-open-local-unis (h3)
  "Open the HTTP/3 control stream and both QPACK streams when the peer's
unidirectional limit allows it (RFC 9000 §19.11). A limit of zero leaves
the connection open; a later MAX_STREAMS frame is what raises the limit.
Call again after ngtcp2 has processed the datagram so a MAX_STREAMS value
that does not increase the limit has already been ignored."
  (when (or (null h3) (h3-conn-freed h3) (h3-conn-uni-bound h3)
            (null (h3-conn-quic h3)) (null (h3-conn-http3 h3)))
    (return-from h3-open-local-unis nil))
  (let ((ids (copy-list (h3-conn-uni-ids h3))))
    (cffi:with-foreign-object (sid :int64)
      (loop while (< (length ids) 3)
            for rv = (ngtcp2-open-uni (h3-conn-quic h3) sid (cffi:null-pointer))
            do (cond ((zerop rv)
                      (setf ids (append ids (list (cffi:mem-ref sid :int64)))))
                     ((eql rv +ngtcp2-stream-id-blocked+)
                      (setf (h3-conn-uni-ids h3) ids)
                      (return-from h3-open-local-unis nil))
                     (t
                      (setf (h3-conn-uni-ids h3) ids)
                      (return-from h3-open-local-unis +ngtcp2-callback-failure+)))))
    (setf (h3-conn-uni-ids h3) ids)
    (when (= (length ids) 3)
      (unless (and (zerop (nghttp3-bind-control (h3-conn-http3 h3) (first ids)))
                   (zerop (nghttp3-bind-qpack (h3-conn-http3 h3) (second ids) (third ids))))
        (return-from h3-open-local-unis +ngtcp2-callback-failure+))
      (setf (h3-conn-uni-bound h3) t)))
  nil)

(cffi:defcallback h3-handshake-completed :int ((conn :pointer) (user-data :pointer))
  (declare (ignore conn))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (let ((rv (h3-open-local-unis h3)))
        (when rv
          (return-from h3-handshake-completed rv)))
      ;; RFC 9000 §13.2.1. ngtcp2 discards the Handshake packet number
      ;; space when this callback returns, which drops an acknowledgement
      ;; that has not been written yet. Write it first.
      (let ((endpoint (h3-conn-endpoint h3)))
        (when (and endpoint (eq (h3-write-packet endpoint h3) :dead))
          (return-from h3-handshake-completed +ngtcp2-callback-failure+)))))
  0)

(defun h3-client-bidi-p (stream-id)
  "Client-initiated bidirectional streams carry HTTP/3 requests (RFC 9000)."
  (and (not (minusp stream-id)) (zerop (logand stream-id 3))))

(defun h3-client-uni-p (stream-id)
  "Client-initiated unidirectional streams carry control and QPACK (RFC 9000)."
  (and (not (minusp stream-id)) (= (logand stream-id 3) 2)))

(defun h3-drop-wire (conn stream-id)
  (when (null conn)
    (return-from h3-drop-wire nil))
  (let ((wire (gethash stream-id (h3-conn-wires conn))))
    (when wire
      (when (h3-wire-qctx wire)
        (nghttp3-qpack-sctx-del (h3-wire-qctx wire))
        (setf (h3-wire-qctx wire) nil))
      (when (h3-wire-qpack wire)
        (nghttp3-qpack-decoder-del (h3-wire-qpack wire))
        (setf (h3-wire-qpack wire) nil))
      (remhash stream-id (h3-conn-wires conn)))))

(defun h3-drop-wires (conn)
  (when conn
    (maphash (lambda (id stream)
               (declare (ignore stream))
               (h3-drop-wire conn id))
             (h3-conn-wires conn))))

(defun h3-mark-section-malformed (conn wire)
  "RFC 9114 §4.1.2: a field value that violates RFC 9113 §8.2.1 makes the
message malformed. nghttp3 discards that field and continues."
  (setf (h3-wire-malformed wire) t)
  (let ((stream (h3-stream conn (h3-wire-id wire))))
    (when stream
      (setf (h3-stream-message-error stream) t))))

(defun h3-apply-wire (conn stream-id)
  (let ((stream (and conn (h3-stream conn stream-id)))
        (wire (and conn (gethash stream-id (h3-conn-wires conn)))))
    (when (and stream wire (h3-wire-malformed wire))
      (setf (h3-stream-message-error stream) t))))

(defun h3-wire-prepare-qpack (wire)
  "A decoder per request stream. The origin advertises a QPACK dynamic
table capacity of zero, so each header block stands alone."
  (when (and (h3-wire-qpack wire) (h3-wire-qctx wire))
    (return-from h3-wire-prepare-qpack t))
  (let ((memory (nghttp3-mem-default)))
    (cffi:with-foreign-objects ((decoder :pointer) (context :pointer))
      (let ((drv (nghttp3-qpack-decoder-new decoder 0 0 memory)))
        (unless (zerop drv)
          (return-from h3-wire-prepare-qpack nil))
        (setf (h3-wire-qpack wire) (cffi:mem-ref decoder :pointer)))
      (let ((srv (nghttp3-qpack-sctx-new context (h3-wire-id wire) memory)))
        (unless (zerop srv)
          (nghttp3-qpack-decoder-del (h3-wire-qpack wire))
          (setf (h3-wire-qpack wire) nil)
          (return-from h3-wire-prepare-qpack nil))
        (setf (h3-wire-qctx wire) (cffi:mem-ref context :pointer)))))
  t)

(defun h3-field-name-malformed-p (name)
  "RFC 9113 §8.2.1 and RFC 9114 §10.3. One leading colon marks a
pseudo-header. Every other octet must be outside 0x00-0x20, 0x41-0x5a,
and 0x7f-0xff, and must not be a colon."
  (let ((length (length name))
        (start 0))
    (when (zerop length)
      (return-from h3-field-name-malformed-p t))
    (when (char= (char name 0) #\:)
      (setf start 1))
    (or (= start length)
        (loop for index from start below length
              for code = (char-code (char name index))
              thereis (or (<= code #x20)
                          (<= #x41 code #x5a)
                          (>= code #x7f)
                          (= code #x3a))))))

(defun h3-qpack-note (conn wire field)
  (let ((name (cffi:foreign-slot-value field '(:struct h3-qpack-nv) 'name))
        (value (cffi:foreign-slot-value field '(:struct h3-qpack-nv) 'value)))
    (unwind-protect
         (let ((raw-name (and name (rcbuf-latin1 name)))
               (raw-value (rcbuf-latin1 value)))
           ;; RFC 9114 §4.3. Pseudo-header fields come before regular
           ;; fields. One that appears later makes the message malformed.
           (when (and raw-name (plusp (length raw-name)))
             (if (char= (char raw-name 0) #\:)
                 ;; :status is a response pseudo-header. A request that
                 ;; carries it is malformed (RFC 9114 §4.3).
                 (cond ((or (h3-wire-trailers wire)
                            (h3-wire-regular wire)
                            (member raw-name (h3-wire-pseudos wire) :test #'string=)
                            (not (member raw-name
                                         '(":method" ":scheme" ":authority"
                                           ":path" ":protocol")
                                         :test #'string=)))
                        (h3-mark-section-malformed conn wire))
                       (t (push raw-name (h3-wire-pseudos wire))
                          (cond ((string= raw-name ":method")
                                 (setf (h3-wire-method wire) raw-value)
                                 ;; RFC 9110 §9.1: method = token. An
                                 ;; invalid value is malformed (RFC 9114
                                 ;; §4.1.2 and §4.3.1).
                                 (unless (token-string-p raw-value)
                                   (h3-mark-section-malformed conn wire)))
                                ((string= raw-name ":scheme")
                                 (setf (h3-wire-scheme wire) raw-value)
                                 ;; RFC 3986 §3.1 scheme. An invalid
                                 ;; value is malformed (RFC 9114
                                 ;; §4.1.2 and §4.3.1).
                                 (unless (scheme-string-p raw-value)
                                   (h3-mark-section-malformed conn wire)))
                                ((string= raw-name ":authority")
                                 (setf (h3-wire-authority wire) raw-value)))))
                 (progn
                   (setf (h3-wire-regular wire) t)
                   (when (string= raw-name "host")
                     (setf (h3-wire-host wire) raw-value)
                     ;; RFC 9114 §4.3.1. Host, when present, is not empty.
                     (when (zerop (length raw-value))
                       (h3-mark-section-malformed conn wire))))))
           ;; RFC 9114 §4.3.1. :path is path-absolute or *, and not empty
           ;; for an https request. :authority is not empty when present.
           (when (and raw-name (string= raw-name ":authority")
                      (zerop (length raw-value)))
             (h3-mark-section-malformed conn wire))
           (when (and raw-name (string= raw-name ":path")
                      (or (find #\# raw-value)
                          (not (or (string= raw-value "*")
                                   (and (plusp (length raw-value))
                                        (char= (char raw-value 0) #\/))))))
             ;; RFC 9114 §4.3.1. :path is path-absolute and an optional
             ;; query. A fragment delimiter is not either production, so
             ;; the value is invalid and the message is malformed (§4.1.2).
             (h3-mark-section-malformed conn wire))
           ;; RFC 9114 §10.3. field-content excludes DEL and other octets
           ;; that RFC 9113 §8.2.1 still allows in a field value.
           (when (or (http-field-value-malformed-p raw-value)
                     (not (field-value-ok-p raw-value))
                     (and raw-name (h3-field-name-malformed-p raw-name)))
             (h3-mark-section-malformed conn wire)))
      (when name (nghttp3-rcbuf-decref name))
      (when value (nghttp3-rcbuf-decref value)))))

(defun h3-qpack-decode (conn wire fin)
  (let* ((buf (h3-wire-pending wire))
         (total (fill-pointer buf))
         (simple (when (plusp total)
                   (replace (make-array total :element-type '(unsigned-byte 8)) buf))))
    (cffi:with-foreign-objects ((field '(:struct h3-qpack-nv)) (flags :uint8))
      (loop with offset = 0
            for step from 0
            while (<= step (+ total 2))
            for nread = (if simple
                            (cffi:with-pointer-to-vector-data (pointer simple)
                              (progn
                                (setf (cffi:mem-ref flags :uint8) 0)
                                (nghttp3-qpack-read-request
                                 (h3-wire-qpack wire) (h3-wire-qctx wire)
                                 field flags (cffi:inc-pointer pointer offset)
                                 (- total offset) (if fin 1 0))))
                            (progn
                              (setf (cffi:mem-ref flags :uint8) 0)
                              (nghttp3-qpack-read-request
                               (h3-wire-qpack wire) (h3-wire-qctx wire)
                               field flags (cffi:null-pointer) 0 (if fin 1 0))))
            do (when (or (< nread 0) (> offset total))
                 (setf (fill-pointer buf) 0)
                 (return))
               (incf offset nread)
               (when (> offset total)
                 (setf (fill-pointer buf) 0)
                 (return))
               (let ((flag (cffi:mem-ref flags :uint8)))
                 (when (logtest flag +qpack-emit+)
                   (h3-qpack-note conn wire field))
                 (when (or (h3-wire-malformed wire) (logtest flag +qpack-final+))
                   (when (logtest flag +qpack-final+)
                     ;; RFC 9114 §4.3.1. A request includes exactly one
                     ;; :method, and, unless it is CONNECT, one :scheme
                     ;; and one :path. Omitting one makes the message
                     ;; malformed.
                     (unless (h3-wire-trailers wire)
                       (cond ((not (member ":method" (h3-wire-pseudos wire)
                                           :test #'string=))
                              (h3-mark-section-malformed conn wire))
                             ((not (equal (h3-wire-method wire) "CONNECT"))
                              (unless (and (member ":scheme" (h3-wire-pseudos wire)
                                                   :test #'string=)
                                           (member ":path" (h3-wire-pseudos wire)
                                                   :test #'string=))
                                (h3-mark-section-malformed conn wire)))
                             ;; RFC 9114 §4.4. A CONNECT request omits :scheme
                             ;; and :path unless it is an extended CONNECT
                             ;; (RFC 8441), which carries :protocol.
                             ((and (not (member ":protocol" (h3-wire-pseudos wire)
                                                :test #'string=))
                                   (or (member ":scheme" (h3-wire-pseudos wire)
                                               :test #'string=)
                                       (member ":path" (h3-wire-pseudos wire)
                                               :test #'string=)
                                       (not (h3-wire-authority wire))))
                              (h3-mark-section-malformed conn wire)))
                       ;; RFC 9114 §4.3.1. http and https require :authority
                       ;; or Host. Omitting both makes the message malformed.
                       (let ((scheme (h3-wire-scheme wire))
                             (authority (h3-wire-authority wire)))
                         (when (and (stringp scheme)
                                    (member scheme '("http" "https")
                                            :test #'string-equal))
                           (cond ((and (not authority)
                                       (not (h3-wire-host wire)))
                                  (h3-mark-section-malformed conn wire))
                                 ;; RFC 9114 §4.3.1. :authority excludes
                                 ;; userinfo. An invalid pseudo-header
                                 ;; value is malformed (§4.1.2).
                                 ((and (stringp authority)
                                       (find #\@ authority))
                                  (h3-mark-section-malformed conn wire))))))
                     (nghttp3-qpack-sctx-reset (h3-wire-qctx wire)))
                   (setf (fill-pointer buf) 0)
                   (return))
                 (when (or (zerop nread) (logtest flag +qpack-blocked+))
                   (when (< offset total)
                     (replace buf buf :start1 0 :start2 offset :end2 total))
                   (setf (fill-pointer buf) (max 0 (- total offset)))
                   (return)))))))

(defun h3-qpack-feed (conn wire pointer nbytes fin)
  (when (h3-wire-malformed wire)
    (return-from h3-qpack-feed nil))
  (let ((buf (h3-wire-pending wire)))
    (when (> (+ (fill-pointer buf) nbytes) +max-header-bytes+)
      (h3-mark-section-malformed conn wire)
      (setf (fill-pointer buf) 0)
      (return-from h3-qpack-feed nil))
    (unless (h3-wire-prepare-qpack wire)
      (return-from h3-qpack-feed nil))
    (loop for index below nbytes
          do (vector-push-extend (cffi:mem-ref pointer :uint8 index) buf))
    (h3-qpack-decode conn wire fin)))

(defun h3-take-varint (wire byte)
  "Consume one byte of an HTTP/3 variable-length integer. Return the
value, or :more when more bytes are required."
  (cond ((zerop (h3-wire-need wire))
         (let ((width (ash 1 (ash byte -6)))
               (acc (logand byte #x3f)))
           (cond ((= width 1) acc)
                 (t (setf (h3-wire-acc wire) acc
                          (h3-wire-need wire) (1- width))
                    :more))))
        (t
         (setf (h3-wire-acc wire) (logior (ash (h3-wire-acc wire) 8) byte))
         (decf (h3-wire-need wire))
         (if (zerop (h3-wire-need wire))
             (h3-wire-acc wire)
             :more))))

(defun h3-scan-bidi (conn stream-id data datalen)
  "Read HEADERS payloads on a request stream and record a message error
when a field name or value is not valid on the wire."
  (handler-case
      (let ((wire (or (gethash stream-id (h3-conn-wires conn))
                      (setf (gethash stream-id (h3-conn-wires conn))
                            (make-h3-wire :id stream-id))))
            (index 0))
        (loop while (< index datalen)
              do (ecase (h3-wire-phase wire)
                   (:type
                    (let ((value (h3-take-varint wire (cffi:mem-ref data :uint8 index))))
                      (incf index)
                      (unless (eq value :more)
                        (setf (h3-wire-frame-type wire) value
                              (h3-wire-phase wire) :length
                              (h3-wire-need wire) 0))))
                   (:length
                    (let ((value (h3-take-varint wire (cffi:mem-ref data :uint8 index))))
                      (incf index)
                      (unless (eq value :more)
                        (setf (h3-wire-left wire) value
                              (h3-wire-headers-p wire) (eql (h3-wire-frame-type wire) +h3-frame-headers+)
                              (h3-wire-phase wire) :payload
                              (h3-wire-need wire) 0)
                        (when (h3-wire-headers-p wire)
                          (setf (h3-wire-regular wire) nil
                                (h3-wire-pseudos wire) nil
                                (h3-wire-method wire) nil
                                (h3-wire-scheme wire) nil
                                (h3-wire-authority wire) nil
                                (h3-wire-host wire) nil
                                (h3-wire-trailers wire) (h3-wire-saw-headers wire)))
                        (when (zerop value)
                          (when (h3-wire-headers-p wire)
                            (h3-qpack-feed conn wire (cffi:null-pointer) 0 t)
                            (setf (h3-wire-saw-headers wire) t))
                          (setf (h3-wire-phase wire) :type
                                (h3-wire-headers-p wire) nil)))))
                   (:payload
                    (let* ((available (- datalen index))
                           (take (min available (h3-wire-left wire))))
                      (when (h3-wire-headers-p wire)
                        (h3-qpack-feed conn wire (cffi:inc-pointer data index) take
                                       (= take (h3-wire-left wire))))
                      (decf (h3-wire-left wire) take)
                      (incf index take)
                      (when (zerop (h3-wire-left wire))
                        (when (h3-wire-headers-p wire)
                          (setf (h3-wire-saw-headers wire) t))
                        (setf (h3-wire-phase wire) :type
                              (h3-wire-headers-p wire) nil
                              (h3-wire-need wire) 0)))))))
    (error (condition)
      (pazuzu-trace "h3 field scan: ~a" condition))))

(defun h3-scan-control (conn stream-id data datalen)
  "Watch the peer control stream for CANCEL_PUSH. This server sends no
PUSH_PROMISE, so every such frame names an unknown push ID (RFC 9114
§7.2.3) and the connection error is H3_ID_ERROR rather than the
H3_FRAME_UNEXPECTED nghttp3 reports for unsupported push."
  (handler-case
      (let ((wire (or (gethash stream-id (h3-conn-wires conn))
                      (setf (gethash stream-id (h3-conn-wires conn))
                            (make-h3-wire :id stream-id :phase :uni-type))))
            (index 0))
        (loop while (< index datalen)
              do (ecase (h3-wire-phase wire)
                   (:uni-type
                    (let ((value (h3-take-varint wire (cffi:mem-ref data :uint8 index))))
                      (incf index)
                      (unless (eq value :more)
                        (setf (h3-wire-need wire) 0)
                        (if (eql value 0)
                            (setf (h3-wire-phase wire) :type)
                            (setf (h3-wire-phase wire) :ignore)))))
                   (:ignore
                    (setf index datalen))
                   (:type
                    (let ((value (h3-take-varint wire (cffi:mem-ref data :uint8 index))))
                      (incf index)
                      (unless (eq value :more)
                        (when (eql value +h3-frame-cancel-push+)
                          (setf (h3-conn-id-error conn) t))
                        (setf (h3-wire-frame-type wire) value
                              (h3-wire-phase wire) :length
                              (h3-wire-need wire) 0))))
                   (:length
                    (let ((value (h3-take-varint wire (cffi:mem-ref data :uint8 index))))
                      (incf index)
                      (unless (eq value :more)
                        (setf (h3-wire-left wire) value
                              (h3-wire-phase wire) :payload
                              (h3-wire-need wire) 0)
                        (when (zerop value)
                          (setf (h3-wire-phase wire) :type)))))
                   (:payload
                    (let* ((available (- datalen index))
                           (take (min available (h3-wire-left wire))))
                      (decf (h3-wire-left wire) take)
                      (incf index take)
                      (when (zerop (h3-wire-left wire))
                        (setf (h3-wire-phase wire) :type
                              (h3-wire-need wire) 0)))))))
    (error (condition)
      (pazuzu-trace "h3 control scan: ~a" condition))))

(defun h3-message-liberr-p (liberr)
  "nghttp3 codes for a malformed HTTP message (RFC 9114 §4.1.2)."
  (or (eql liberr +nghttp3-malformed-header+)
      (eql liberr +nghttp3-malformed-messaging+)))

(defun h3-read-stream-error (h3 stream-id liberr)
  "A malformed request is a stream error H3_MESSAGE_ERROR (RFC 9114 §4.1.2).
nghttp3 returns that as a negative code from read_stream. Reset the request
stream and keep the connection. A control stream, a QPACK stream, or any
other library error is a connection error: remember the HTTP/3 code so the
CONNECTION_CLOSE is not a QUIC transport error."
  (let ((app (nghttp3-app-error liberr)))
    (cond ((and (h3-message-liberr-p liberr)
                (h3-client-bidi-p stream-id)
                (h3-conn-http3 h3)
                (h3-conn-quic h3))
           (let ((rv (nghttp3-shutdown-read (h3-conn-http3 h3) stream-id)))
             (when (< rv 0)
               (setf (h3-conn-app-close h3) (nghttp3-app-error rv))
               (return-from h3-read-stream-error +ngtcp2-callback-failure+)))
           (ngtcp2-shutdown-read (h3-conn-quic h3) 0 stream-id app)
           (ngtcp2-shutdown-write (h3-conn-quic h3) 0 stream-id app)
           (let ((stream (h3-stream h3 stream-id)))
             (when stream
               (setf (h3-stream-reset stream) t)
               (when (h3-stream-pipe stream)
                 (pipe-shutdown (h3-stream-pipe stream)))))
           0)
          (t
           (setf (h3-conn-app-close h3)
                 (if (and (h3-conn-id-error h3)
                          (eql liberr +nghttp3-frame-unexpected+))
                     +h3-id-error+
                     app))
           +ngtcp2-callback-failure+))))

(cffi:defcallback h3-recv-stream-data :int
    ((conn :pointer) (flags :uint32) (stream-id :int64) (offset :uint64)
     (data :pointer) (datalen :unsigned-long) (user-data :pointer) (stream-ud :pointer))
  (declare (ignore conn offset stream-ud))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (when (and h3 (h3-conn-http3 h3))
        (when (and (h3-client-bidi-p stream-id) (plusp datalen))
          (h3-scan-bidi h3 stream-id data datalen))
        (when (and (h3-client-uni-p stream-id) (plusp datalen))
          (h3-scan-control h3 stream-id data datalen))
        (let ((consumed (nghttp3-read-stream (h3-conn-http3 h3) stream-id data datalen
                                             (if (logtest flags 1) 1 0)
                                             (monotonic-ns))))
          (cond ((< consumed 0)
                 (let ((rv (h3-read-stream-error h3 stream-id consumed)))
                   (when (< rv 0)
                     (return-from h3-recv-stream-data rv))))
                (t
                 (when (plusp consumed)
                   (ngtcp2-extend-stream (h3-conn-quic h3) stream-id consumed)
                   (ngtcp2-extend-conn (h3-conn-quic h3) consumed))
                 (h3-flush-expectations h3)
                 (let ((stream (h3-stream h3 stream-id)))
                   (when (and stream (h3-stream-message-error stream)
                              (not (h3-stream-reset stream)))
                     (let ((rv (h3-read-stream-error h3 stream-id +nghttp3-malformed-header+)))
                       (when (< rv 0)
                         (return-from h3-recv-stream-data rv))))))))))
    0))

(cffi:defcallback h3-acked-offset :int
    ((conn :pointer) (stream-id :int64) (offset :uint64) (datalen :uint64)
     (user-data :pointer) (stream-ud :pointer))
  (declare (ignore conn offset stream-ud))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (when (and h3 (h3-conn-http3 h3))
        (nghttp3-add-ack-offset (h3-conn-http3 h3) stream-id datalen)))
    0))

(cffi:defcallback h3-rand :void ((dest :pointer) (destlen :unsigned-long) (ctx :pointer))
  (declare (ignore ctx))
  (handler-case (octets-to-foreign (ironclad:random-data destlen) dest)
    (error (condition)
      (format *error-output* "pazuzu: ~a~%" condition)
      (foreign-zero dest destlen))))

(cffi:defcallback h3-extend-max :int
    ((conn :pointer) (stream-id :int64) (max-data :uint64)
     (user-data :pointer) (stream-ud :pointer))
  (declare (ignore conn max-data stream-ud))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (when (and h3 (h3-conn-http3 h3))
        (nghttp3-unblock-stream (h3-conn-http3 h3) stream-id)))
    0))

(defun h3-reset-token-diff (packet token)
  "Zero when the last 16 bytes of PACKET equal TOKEN. Every byte is
visited so the comparison does not leak the token (RFC 9000 §10.3.1)."
  (let ((diff 0)
        (start (- (length packet) 16)))
    (loop for i below 16
          do (setf diff (logior diff (logxor (aref packet (+ start i))
                                             (aref token i)))))
    diff))

(defun h3-stateless-reset-p (conn packet)
  "RFC 9000 §10.3.1. A datagram is a Stateless Reset when its last 16
bytes equal a token for a destination connection ID this endpoint has
used. Tokens for unused or retired connection IDs are not in the list."
  (let ((tokens (and conn (h3-conn-reset-tokens conn))))
    (when (or (null tokens) (< (length packet) 21))
      (return-from h3-stateless-reset-p nil))
    (let ((matched 0))
      (dolist (pair tokens)
        (setf matched (logior matched
                              (logand 1 (logxor 1 (min 1 (h3-reset-token-diff packet (cdr pair))))))))
      (plusp matched))))

(defun h3-drain-stateless-reset (endpoint packet host port)
  "Enter draining for every connection with this peer whose used token
matches PACKET. Draining retires the connection and sends nothing."
  (when (< (length packet) 21)
    (return-from h3-drain-stateless-reset nil))
  (let ((peer (format-ip host)))
    (dolist (conn (h3-connections endpoint))
      (when (and (equal (h3-conn-peer conn) peer)
                 (not (h3-conn-freed conn))
                 (h3-stateless-reset-p conn packet))
        (h3-retire endpoint conn)))))

(cffi:defcallback h3-dcid-status :int
    ((conn :pointer) (status :int) (seq :uint64) (cid :pointer) (token :pointer)
     (user-data :pointer))
  (declare (ignore conn cid))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (when h3
        (cond ((and (zerop status) (not (cffi:null-pointer-p token)))
               (let ((octets (make-array 16 :element-type '(unsigned-byte 8))))
                 (loop for index below 16
                       do (setf (aref octets index)
                                (cffi:mem-ref token :uint8 index)))
                 (setf (h3-conn-reset-tokens h3)
                       (acons seq octets
                              (remove seq (h3-conn-reset-tokens h3) :key #'car)))))
              ((= status 1)
               (setf (h3-conn-reset-tokens h3)
                     (remove seq (h3-conn-reset-tokens h3) :key #'car))))))
    0))

(cffi:defcallback h3-new-cid :int
    ((conn :pointer) (cid :pointer) (token :pointer) (cidlen :unsigned-long) (user-data :pointer))
  (declare (ignore conn))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (when h3
        (let ((bytes (ironclad:random-data cidlen))
              (reset (ironclad:random-data 16)))
          (cffi:with-pointer-to-vector-data (pointer bytes)
            (ngtcp2-cid-init cid pointer cidlen))
          (octets-to-foreign reset token)
          (h3-index (h3-conn-endpoint h3) bytes h3))))
    0))

(cffi:defcallback h3-stream-close :int
    ((conn :pointer) (flags :uint32) (stream-id :int64) (rx :uint64) (tx :uint64)
     (user-data :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +ngtcp2-callback-failure+
    (let ((h3 (h3-from user-data)))
      (when (and h3 (h3-conn-http3 h3))
        (nghttp3-close-stream (h3-conn-http3 h3) flags stream-id rx tx)))
    0))

(cffi:defcallback h3-h3-acked :int
    ((conn :pointer) (stream-id :int64) (datalen :uint64)
     (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let* ((h3 (h3-from conn-ud))
           (stream (h3-stream h3 stream-id)))
      (when stream
        (decf (h3-stream-unacked stream) datalen)
        (when (and (h3-stream-foreign stream) (<= (h3-stream-unacked stream) 0))
          (cffi:foreign-free (h3-stream-foreign stream))
          (setf (h3-stream-foreign stream) nil
                (h3-stream-unacked stream) 0)
          (h3-mark-dirty h3 stream-id))))
    0))

(cffi:defcallback h3-h3-recv-data :int
    ((conn :pointer) (stream-id :int64) (data :pointer) (datalen :unsigned-long)
     (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let* ((h3 (h3-from conn-ud))
           (stream (h3-stream h3 stream-id)))
      (when stream
        (cond ((h3-stream-pipe stream)
               (pipe-feed (h3-stream-pipe stream) (foreign-to-octets data datalen)))
              ((h3-stream-overflow stream) nil)
              ((> (+ (length (h3-stream-body stream)) datalen)
                  (server-max-body (h3-endpoint-server (h3-conn-endpoint h3))))
               (setf (h3-stream-overflow stream) t))
              (t (loop for index below datalen
                       do (vector-push-extend (cffi:mem-ref data :uint8 index)
                                              (h3-stream-body stream))))))
      (h3-extend h3 stream-id datalen))
    0))

(cffi:defcallback h3-h3-deferred :int
    ((conn :pointer) (stream-id :int64) (consumed :unsigned-long)
     (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (h3-extend (h3-from conn-ud) stream-id consumed)
    0))

(cffi:defcallback h3-h3-begin-headers :int
    ((conn :pointer) (stream-id :int64) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let ((h3 (h3-from conn-ud)))
      (when (and h3 (not (h3-stream h3 stream-id)))
        (setf (gethash stream-id (h3-conn-streams h3))
              (make-h3-stream :id stream-id)))
      (h3-apply-wire h3 stream-id))
    0))

(defun h3-note-header (stream name value)
  (incf (h3-stream-field-count stream))
  (incf (h3-stream-header-bytes stream) (+ (length name) (length value)))
  ;; RFC 9114 §10.3. A character outside field-content, including DEL,
  ;; makes the message malformed even when it is not CR, LF, or NUL.
  (when (or (http-field-value-malformed-p value)
            (not (field-value-ok-p value)))
    (setf (h3-stream-message-error stream) t))
  (when (or (> (h3-stream-field-count stream) +max-header-fields+)
            (> (h3-stream-header-bytes stream) +max-header-bytes+))
    (setf (h3-stream-header-error stream) 431))
  (cond ((h3-stream-in-trailers stream)
         (push (cons name value) (h3-stream-trailers stream)))
        ((and (plusp (length name)) (char= (char name 0) #\:))
         (cond ((string= name ":method")
                (setf (h3-stream-method stream) value)
                ;; RFC 9110 §9.1 method = token. Reject before the
                ;; 400 path so the stream error is H3_MESSAGE_ERROR.
                (unless (token-string-p value)
                  (setf (h3-stream-message-error stream) t)))
               ((string= name ":scheme")
                (setf (h3-stream-scheme stream) value)
                (unless (scheme-string-p value)
                  (setf (h3-stream-message-error stream) t)))
               ((string= name ":authority") (setf (h3-stream-authority stream) value))
               ((string= name ":path")
                (setf (h3-stream-path stream) value)
                (when (find #\# value)
                  (setf (h3-stream-message-error stream) t)))
               ((string= name ":protocol") (setf (h3-stream-protocol stream) value))))
        (t (push (cons name value) (h3-stream-headers stream)))))

(cffi:defcallback h3-h3-recv-header :int
    ((conn :pointer) (stream-id :int64) (token :int32) (name :pointer) (value :pointer)
     (flags :uint8) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn token flags stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let ((stream (h3-stream (h3-from conn-ud) stream-id)))
      (when stream
        (let ((raw-name (rcbuf-latin1 name)))
          (when (h3-field-name-malformed-p raw-name)
            (setf (h3-stream-message-error stream) t))
          (h3-note-header stream (string-downcase raw-name) (rcbuf-latin1 value)))))
    0))

(cffi:defcallback h3-h3-end-headers :int
    ((conn :pointer) (stream-id :int64) (fin :int) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let* ((h3 (h3-from conn-ud))
           (stream (h3-stream h3 stream-id)))
      (when (and stream (not (h3-stream-message-error stream)))
        (if (and (equal (h3-stream-method stream) "CONNECT")
                 (equal (h3-stream-protocol stream) "websocket"))
            (h3-finish-request h3 stream)
            (if (plusp fin)
                (h3-finish-request h3 stream)
                (h3-note-continue h3 stream)))))
    0))

(cffi:defcallback h3-h3-begin-trailers :int
    ((conn :pointer) (stream-id :int64) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let* ((h3 (h3-from conn-ud))
           (stream (h3-stream h3 stream-id)))
      (when stream
        (setf (h3-stream-in-trailers stream) t))
      (h3-apply-wire h3 stream-id))
    0))

(cffi:defcallback h3-h3-recv-trailer :int
    ((conn :pointer) (stream-id :int64) (token :int32) (name :pointer) (value :pointer)
     (flags :uint8) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn token flags stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let ((stream (h3-stream (h3-from conn-ud) stream-id)))
      (when stream
        (setf (h3-stream-in-trailers stream) t)
        (let ((raw-name (rcbuf-latin1 name)))
          (when (h3-field-name-malformed-p raw-name)
            (setf (h3-stream-message-error stream) t))
          (h3-note-header stream (string-downcase raw-name) (rcbuf-latin1 value)))))
    0))

(cffi:defcallback h3-h3-end-trailers :int
    ((conn :pointer) (stream-id :int64) (fin :int) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (when (plusp fin)
      (h3-finish-request (h3-from conn-ud) (h3-stream (h3-from conn-ud) stream-id)))
    0))

(cffi:defcallback h3-h3-stop-sending :int
    ((conn :pointer) (stream-id :int64) (app-error :uint64)
     (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let ((h3 (h3-from conn-ud)))
      (when (and h3 (h3-conn-quic h3))
        (ngtcp2-shutdown-read (h3-conn-quic h3) 0 stream-id app-error)))
    0))

(cffi:defcallback h3-h3-reset :int
    ((conn :pointer) (stream-id :int64) (app-error :uint64)
     (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let ((h3 (h3-from conn-ud)))
      (when (and h3 (h3-conn-quic h3))
        (ngtcp2-shutdown-write (h3-conn-quic h3) 0 stream-id app-error)))
    0))

(cffi:defcallback h3-h3-end-stream :int
    ((conn :pointer) (stream-id :int64) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (h3-finish-request (h3-from conn-ud) (h3-stream (h3-from conn-ud) stream-id))
    0))

(cffi:defcallback h3-h3-stream-close :int
    ((conn :pointer) (flags :uint32) (stream-id :int64) (rx :uint64) (tx :uint64)
     (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn flags rx tx stream-ud))
  (with-callback-guard +nghttp3-callback-failure+
    (let* ((h3 (h3-from conn-ud))
           (stream (h3-stream h3 stream-id)))
      (when stream
        (when (h3-stream-pipe stream)
          (pipe-shutdown (h3-stream-pipe stream)))
        (when (h3-stream-foreign stream)
          (cffi:foreign-free (h3-stream-foreign stream))
          (setf (h3-stream-foreign stream) nil))
        (remhash stream-id (h3-conn-streams h3)))
      (h3-drop-wire h3 stream-id))
    0))

(cffi:defcallback h3-h3-rand :void ((dest :pointer) (destlen :unsigned-long))
  (handler-case (octets-to-foreign (ironclad:random-data destlen) dest)
    (error (condition)
      (format *error-output* "pazuzu: ~a~%" condition)
      (foreign-zero dest destlen))))

(defun h3-fill-chunk (stream vec flags)
  (multiple-value-bind (octets eof)
      (ecase (h3-stream-source stream)
        (:pipe (pipe-take-output (h3-stream-pipe stream) 16384))
        (:buffer
         (let* ((buffer (h3-stream-buffer stream))
                (pos (h3-stream-buffer-pos stream))
                (count (min 16384 (max 0 (- (length buffer) pos)))))
           (incf (h3-stream-buffer-pos stream) count)
           (values (subseq buffer pos (+ pos count))
                   (>= (h3-stream-buffer-pos stream) (length buffer))))))
    (cond ((and (zerop (length octets)) (not eof))
           +nghttp3-wouldblock+)
          (t
           (when (plusp (length octets))
             (let ((foreign (cffi:foreign-alloc :uint8 :count (length octets))))
               (octets-to-foreign octets foreign)
               (setf (h3-stream-foreign stream) foreign
                     (h3-stream-unacked stream) (length octets)
                     (cffi:mem-ref vec :pointer) foreign
                     (cffi:mem-ref vec :unsigned-long 8) (length octets))))
           (setf (cffi:mem-ref flags :uint32) (if eof +h3-data-eof+ 0))
           (if (plusp (length octets)) 1 0)))))

(cffi:defcallback h3-read-data :long
    ((conn :pointer) (stream-id :int64) (vec :pointer) (veccnt :unsigned-long)
     (flags :pointer) (conn-ud :pointer) (stream-ud :pointer))
  (declare (ignore conn stream-ud))
  (setf (cffi:mem-ref flags :uint32) 0)
  (with-callback-guard +nghttp3-callback-failure+
    (let ((stream (h3-stream (h3-from conn-ud) stream-id)))
      (cond ((or (null stream) (zerop veccnt))
             (setf (cffi:mem-ref flags :uint32) +h3-data-eof+)
             0)
            ((h3-stream-foreign stream)
             +nghttp3-wouldblock+)
            ((null (h3-stream-source stream))
             (setf (cffi:mem-ref flags :uint32) +h3-data-eof+)
             0)
            (t (h3-fill-chunk stream vec flags))))))

(defun crypto-symbol (name)
  (or (cffi:foreign-symbol-pointer name :library 'libngtcp2-crypto)
      (cffi:foreign-symbol-pointer name :library 'libngtcp2)
      (error "pazuzu: ~a is not exported by libngtcp2_crypto_ossl" name)))

(defun h3-reader ()
  (or *h3-reader*
      (let ((reader (cffi:foreign-alloc :uint8 :count 8)))
        (foreign-zero reader 8)
        (setf (cffi:mem-ref reader :pointer) (cffi:callback h3-read-data))
        (setf *h3-reader* reader))))

(defun h3-cstat (conn)
  (cffi:inc-pointer conn +h3-cstat+))

(defun h3-cc-signature-ok (conn)
  "The installed ngtcp2 connection starts with the 1.25.0 RTT block.
A mismatch means the offsets are not the ones this process may write."
  (let ((base (h3-cstat conn)))
    (and (= (cffi:mem-ref base :uint64 0) 0)
         (= (cffi:mem-ref base :uint64 8) +uint64-max+)
         (= (cffi:mem-ref base :uint64 16) +h3-initial-rtt+)
         (= (cffi:mem-ref base :uint64 24) (floor +h3-initial-rtt+ 2))
         (= (cffi:mem-ref base :uint64 32) +h3-initial-rtt+))))

(defun h3-note-cc-layout (h3 conn)
  (unless *h3-cc-layout-ok*
    (when (h3-cc-signature-ok conn)
      (cffi:with-foreign-object (info :uint8 128)
        (foreign-zero info 128)
        (ngtcp2-conn-info conn 2 info)
        (let ((direct (cffi:mem-ref (h3-cstat conn) :uint64 112))
              (reported (cffi:mem-ref info :uint64 32)))
          (when (and (plusp direct) (= direct reported))
            (setf *h3-cc-layout-ok* t))))))
  (when *h3-cc-layout-ok*
    (let ((cwnd (cffi:mem-ref (h3-cstat conn) :uint64 112)))
      (setf (gethash h3 *h3-initial-cwnd*) cwnd)
      (h3-path-note (list :initial cwnd)))))

(defun h3-remember-peer (h3 host port)
  (unless (gethash h3 *h3-first-peer*)
    (setf (gethash h3 *h3-first-peer*) (list (copy-seq host) port))))

(defun h3-same-peer-p (h3 host port)
  (let ((first (gethash h3 *h3-first-peer*)))
    (and first host port
         (= port (second first))
         (equalp host (first first)))))

(defun h3-note-rtt-moved (h3 conn)
  (unless (gethash h3 *h3-rtt-moved*)
    (let ((base (h3-cstat conn)))
      (when (or (plusp (cffi:mem-ref base :uint64 0))
                (/= (cffi:mem-ref base :uint64 16) +h3-initial-rtt+))
        (setf (gethash h3 *h3-rtt-moved*) t)))))

(defun h3-initial-window (mtu)
  (if (plusp mtu)
      (min (* 10 mtu) (max (* 2 mtu) 14720))
      0))

(defun h3-reset-pktns-cc (pktns)
  "Match ngtcp2_rtb_reset_cc_state. The following bytes-in-flight count
must be zero too: loss detection divides it by the MTU to choose the
packet threshold, and packets below the new cc_pkt_num are never
subtracted from it."
  (when (and pktns (not (cffi:null-pointer-p pktns)))
    (let ((last (cffi:mem-ref pktns :int64)))
      (when (<= -1 last (1- (ash 1 62)))
        (setf (cffi:mem-ref pktns :int64 (+ +h3-rtb+ +h3-rtb-cc-pkt+)) (1+ last)
              (cffi:mem-ref pktns :uint64 (+ +h3-rtb+ +h3-rtb-cc-bytes+)) 0)
        last))))

(defun h3-reset-rst (conn)
  "Match ngtcp2_rst_reset. The delivery total is what HyStart stores as
the next round after cc->reset clears next_round_delivered. pkt_id is
left alone, as the library reset leaves it."
  (let ((rst (cffi:inc-pointer conn +h3-rst+)))
    (loop for offset from 0 below 80 by 8
          do (setf (cffi:mem-ref rst :uint64 offset) 0))
    (setf (cffi:mem-ref rst :uint64 0) +uint64-max+
          (cffi:mem-ref rst :uint64 24) +uint64-max+
          (cffi:mem-ref rst :int64 64) -1
          (cffi:mem-ref rst :uint64 +h3-rst-delivered+) 0
          (cffi:mem-ref rst :uint64 88) 0
          (cffi:mem-ref rst :uint64 96) 0
          (cffi:mem-ref rst :uint64 104) 0
          (cffi:mem-ref rst :uint64 112) 0
          (cffi:mem-ref rst :int 128) 0)))

(defun h3-write-initial-rtt (conn latest min-rtt smoothed rttvar cwnd)
  (let ((base (h3-cstat conn)))
    (setf (cffi:mem-ref base :uint64 0) latest
          (cffi:mem-ref base :uint64 8) min-rtt
          (cffi:mem-ref base :uint64 16) smoothed
          (cffi:mem-ref base :uint64 24) rttvar
          (cffi:mem-ref base :uint64 112) cwnd)))

(defun h3-reset-path-cc (h3 conn)
  "RFC 9000 §9.4. Put this path back at the initial window and initial RTT.
ngtcp2 has no public reset, and its confirmation path skips the one it
already ran when the address first changed. The RTT sample does not look
at the congestion threshold, so the guard restores this triple when a
later ACK names a packet sent before the reset."
  (unless *h3-cc-layout-ok*
    (return-from h3-reset-path-cc nil))
  (let* ((base (h3-cstat conn))
         (before-latest (cffi:mem-ref base :uint64 0))
         (before-min (cffi:mem-ref base :uint64 8))
         (before-smoothed (cffi:mem-ref base :uint64 16))
         (before-cwnd (cffi:mem-ref base :uint64 112))
         (initial (cffi:mem-ref base :uint64 32))
         (mtu (cffi:mem-ref base :unsigned-long 144))
         (cwnd (or (gethash h3 *h3-initial-cwnd*) (h3-initial-window mtu)))
         (before-bytes (cffi:mem-ref (cffi:inc-pointer conn +h3-pktns+) :uint64
                                     (+ +h3-rtb+ +h3-rtb-cc-bytes+)))
         (before-delivered (cffi:mem-ref conn :uint64 (+ +h3-rst+ +h3-rst-delivered+)))
         (last (h3-reset-pktns-cc (cffi:inc-pointer conn +h3-pktns+))))
    (unless (and last (plusp cwnd) (= initial +h3-initial-rtt+))
      (return-from h3-reset-path-cc nil))
    (h3-reset-pktns-cc (cffi:mem-ref conn :pointer +h3-hs-pktns+))
    (h3-path-note (list :before before-latest before-min before-smoothed before-cwnd
                        (if (gethash h3 *h3-rtt-moved*) 1 0)
                        before-bytes before-delivered))
    (setf (cffi:mem-ref base :uint64 0) 0
          (cffi:mem-ref base :uint64 8) +uint64-max+
          (cffi:mem-ref base :uint64 16) initial
          (cffi:mem-ref base :uint64 24) (floor initial 2)
          (cffi:mem-ref base :uint64 40) +uint64-max+
          (cffi:mem-ref base :unsigned-long 48) 0
          (cffi:mem-ref base :uint64 56) +uint64-max+
          (cffi:mem-ref base :uint64 112) cwnd
          (cffi:mem-ref base :uint64 120) +uint64-max+
          (cffi:mem-ref base :uint64 128) +uint64-max+
          (cffi:mem-ref base :uint64 136) 0
          (cffi:mem-ref base :uint64 152) 0)
    (let ((reset (cffi:mem-ref conn :pointer +h3-cc-reset+)))
      (when (and reset (not (cffi:null-pointer-p reset)))
        (cffi:foreign-funcall-pointer reset ()
                                      :pointer (cffi:inc-pointer conn +h3-cc+)
                                      :pointer base
                                      :uint64 (monotonic-ns)
                                      :void)))
    (h3-write-initial-rtt conn 0 +uint64-max+ initial (floor initial 2) cwnd)
    (h3-reset-rst conn)
    (setf (cffi:mem-ref conn :uint64 +h3-pacing-next+) +uint64-max+
          (cffi:mem-ref conn :uint64 +h3-pacing-comp+) 0)
    (setf (gethash h3 *h3-path-rtt-guard*)
          (list (1+ last) 0 +uint64-max+ initial (floor initial 2)))
    (h3-path-note (list :confirmed
                        (cffi:mem-ref base :uint64 0)
                        (cffi:mem-ref base :uint64 8)
                        (cffi:mem-ref base :uint64 16)
                        (cffi:mem-ref base :uint64 112)
                        (cffi:mem-ref (cffi:inc-pointer conn +h3-pktns+) :uint64
                                      (+ +h3-rtb+ +h3-rtb-cc-bytes+))
                        (cffi:mem-ref conn :uint64 (+ +h3-rst+ +h3-rst-delivered+))))))

(defun h3-guard-rtt (h3 conn)
  "An ACK whose largest packet was sent before the path reset must not
move the estimator. A larger acknowledgement is a sample from the new
path and disarms the guard."
  (let ((guard (gethash h3 *h3-path-rtt-guard*)))
    (when guard
      (let ((largest (cffi:mem-ref conn :int64 +h3-largest-acked+)))
        (cond ((< largest (first guard))
               (h3-write-initial-rtt conn (second guard) (third guard)
                                     (fourth guard) (fifth guard)
                                     (cffi:mem-ref (h3-cstat conn) :uint64 112))
               (let ((base (h3-cstat conn)))
                 (h3-path-note (list :stale
                                     (cffi:mem-ref base :uint64 0)
                                     (cffi:mem-ref base :uint64 8)
                                     (cffi:mem-ref base :uint64 16)))))
              (t (remhash h3 *h3-path-rtt-guard*)))))))

(cffi:defcallback h3-path-validated :int
    ((conn :pointer) (flags :uint32) (path :pointer) (fallback :pointer)
     (result :int) (user-data :pointer))
  (declare (ignore flags fallback))
  (with-callback-guard 0
    (when (and (zerop result) conn (not (cffi:null-pointer-p conn)))
      (let ((h3 (h3-from user-data)))
        (when (and h3 (not (h3-conn-freed h3)))
          (multiple-value-bind (host port) (path-remote path)
            (when (and host port (not (h3-same-peer-p h3 host port)))
              (h3-reset-path-cc h3 conn)))))))
  0)

(defun h3-ensure-state ()
  (unless *h3-ossl*
    (unless (zerop (ngtcp2-crypto-init))
      (error "ngtcp2_crypto_ossl_init failed"))
    (setf *h3-ossl* t))
  (unless *h3-quic-callbacks*
    (let ((callbacks (cffi:foreign-alloc :uint8 :count 376)))
      (foreign-zero callbacks 376)
      (loop for (offset name) in
            '((8 "ngtcp2_crypto_recv_client_initial_cb")
              (16 "ngtcp2_crypto_recv_crypto_data_cb")
              (40 "ngtcp2_crypto_encrypt_cb")
              (48 "ngtcp2_crypto_decrypt_cb")
              (56 "ngtcp2_crypto_hp_mask_cb")
              (152 "ngtcp2_crypto_update_key_cb")
              (232 "ngtcp2_crypto_delete_crypto_aead_ctx_cb")
              (240 "ngtcp2_crypto_delete_crypto_cipher_ctx_cb")
              (272 "ngtcp2_crypto_get_path_challenge_data_cb")
              (288 "ngtcp2_crypto_version_negotiation_cb")
              (352 "ngtcp2_crypto_get_path_challenge_data2_cb"))
            do (setf (cffi:mem-ref callbacks :pointer offset) (crypto-symbol name)))
      (setf (cffi:mem-ref callbacks :pointer 24) (cffi:callback h3-handshake-completed)
            (cffi:mem-ref callbacks :pointer 64) (cffi:callback h3-recv-stream-data)
            (cffi:mem-ref callbacks :pointer 72) (cffi:callback h3-acked-offset)
            (cffi:mem-ref callbacks :pointer 128) (cffi:callback h3-rand)
            (cffi:mem-ref callbacks :pointer 160) (cffi:callback h3-path-validated)
            (cffi:mem-ref callbacks :pointer 200) (cffi:callback h3-extend-max)
            (cffi:mem-ref callbacks :pointer 336) (cffi:callback h3-new-cid)
            (cffi:mem-ref callbacks :pointer 344) (cffi:callback h3-dcid-status)
            (cffi:mem-ref callbacks :pointer 368) (cffi:callback h3-stream-close))
      (setf *h3-quic-callbacks* callbacks)))
  (unless *h3-http-callbacks*
    (let ((callbacks (cffi:foreign-alloc :uint8 :count 160)))
      (foreign-zero callbacks 160)
      (setf (cffi:mem-ref callbacks :pointer 0) (cffi:callback h3-h3-acked)
            (cffi:mem-ref callbacks :pointer 16) (cffi:callback h3-h3-recv-data)
            (cffi:mem-ref callbacks :pointer 24) (cffi:callback h3-h3-deferred)
            (cffi:mem-ref callbacks :pointer 32) (cffi:callback h3-h3-begin-headers)
            (cffi:mem-ref callbacks :pointer 40) (cffi:callback h3-h3-recv-header)
            (cffi:mem-ref callbacks :pointer 48) (cffi:callback h3-h3-end-headers)
            (cffi:mem-ref callbacks :pointer 56) (cffi:callback h3-h3-begin-trailers)
            (cffi:mem-ref callbacks :pointer 64) (cffi:callback h3-h3-recv-trailer)
            (cffi:mem-ref callbacks :pointer 72) (cffi:callback h3-h3-end-trailers)
            (cffi:mem-ref callbacks :pointer 80) (cffi:callback h3-h3-stop-sending)
            (cffi:mem-ref callbacks :pointer 88) (cffi:callback h3-h3-end-stream)
            (cffi:mem-ref callbacks :pointer 96) (cffi:callback h3-h3-reset)
            (cffi:mem-ref callbacks :pointer 136) (cffi:callback h3-h3-rand)
            (cffi:mem-ref callbacks :pointer 152) (cffi:callback h3-h3-stream-close))
      (setf *h3-http-callbacks* callbacks)))
  (unless *h3-http-settings*
    (let ((settings (cffi:foreign-alloc :uint8 :count 72)))
      (nghttp3-settings-default 4 settings)
      (setf (cffi:mem-ref settings :uint64) 65536
            (cffi:mem-ref settings :uint8 32) 1)
      (setf *h3-http-settings* settings)))
  (h3-reader))

(defun h3-free (conn)
  (when (or (null conn) (h3-conn-freed conn))
    (return-from h3-free nil))
  (setf (h3-conn-freed conn) t)
  (h3-drop-wires conn)
  (when (h3-conn-quic conn)
    (ngtcp2-conn-del (h3-conn-quic conn))
    (setf (h3-conn-quic conn) nil))
  (when (h3-conn-http3 conn)
    (nghttp3-conn-del (h3-conn-http3 conn))
    (setf (h3-conn-http3 conn) nil))
  (when (h3-conn-ssl conn)
    (%ssl-set-ex-data (h3-conn-ssl conn) 0 (cffi:null-pointer))
    (cl+ssl::ssl-free (h3-conn-ssl conn))
    (setf (h3-conn-ssl conn) nil))
  (when (h3-conn-crypto conn)
    (ngtcp2-crypto-ctx-del (h3-conn-crypto conn))
    (setf (h3-conn-crypto conn) nil))
  (when (h3-conn-conn-ref conn)
    (cffi:foreign-free (h3-conn-conn-ref conn))
    (setf (h3-conn-conn-ref conn) nil))
  (when (h3-conn-path conn)
    (cffi:foreign-free (h3-conn-path conn))
    (setf (h3-conn-path conn) nil))
  (unpin (h3-conn-pin conn))
  (setf (h3-conn-pin conn) nil))

(defun h3-retire (endpoint conn)
  (unless (h3-conn-freed conn)
    (let ((admitted (shiftf (h3-conn-admitted conn) nil))
          (peer (h3-conn-peer conn))
          (server (h3-endpoint-server endpoint)))
      (bt:with-lock-held ((h3-endpoint-lock endpoint))
        (dolist (cid (h3-conn-cids conn))
          (remhash cid (h3-endpoint-connections endpoint)))
        (setf (h3-conn-cids conn) nil))
      (maphash (lambda (id stream)
                 (declare (ignore id))
                 (when (h3-stream-pipe stream)
                   (pipe-shutdown (h3-stream-pipe stream)))
                 (when (h3-stream-foreign stream)
                   (cffi:foreign-free (h3-stream-foreign stream))
                   (setf (h3-stream-foreign stream) nil)))
               (h3-conn-streams conn))
      (h3-free conn)
      (when admitted
        (release-http3 server peer)))))

(defun h3-fail-conn (conn code &key application)
  (when (or (null conn) (null (h3-conn-quic conn)) (h3-conn-closing conn) (h3-conn-freed conn))
    (return-from h3-fail-conn nil))
  (setf (h3-conn-closing conn) t)
  (let ((endpoint (h3-conn-endpoint conn)))
    (cffi:with-foreign-objects ((ccerr :uint8 40) (path :uint8 96) (pkt-info :uint8 8) (dest :uint8 2048))
      (foreign-zero ccerr 40)
      (foreign-zero pkt-info 8)
      (ngtcp2-path-zero path)
      (if application
          (ngtcp2-ccerr-app ccerr code (cffi:null-pointer) 0)
          (ngtcp2-ccerr-liberr ccerr code (cffi:null-pointer) 0))
      (let ((n (ngtcp2-write-close (h3-conn-quic conn) path 1 pkt-info dest 2048 ccerr (monotonic-ns))))
        (when (and endpoint (plusp n))
          (h3-send endpoint path dest n (cffi:mem-ref pkt-info :uint8)))))
    (h3-retire endpoint conn)))

(defun h3-open-tls (conn)
  (let ((ctx (borrow-endpoint-context (h3-conn-endpoint conn))))
    (unless ctx
      (error "HTTP/3 TLS context is gone"))
    (unwind-protect
         (let ((ssl (cl+ssl::ssl-new ctx)))
           (when (or (null ssl) (cffi:null-pointer-p ssl))
             (error "SSL_new failed"))
           (setf (h3-conn-ssl conn) ssl)
           (cffi:with-foreign-object (out :pointer)
             (let ((rv (ngtcp2-crypto-ctx-new out ssl)))
               (unless (zerop rv)
                 (error "ngtcp2_crypto_ossl_ctx_new returned ~d" rv))
               (setf (h3-conn-crypto conn) (cffi:mem-ref out :pointer)))))
      (release-context ctx))))

(defun h3-put-cid (struct octets)
  (let ((octets (simple-octets octets)))
    (if (zerop (length octets))
        (ngtcp2-cid-init struct (cffi:null-pointer) 0)
        (cffi:with-pointer-to-vector-data (pointer octets)
          (ngtcp2-cid-init struct pointer (length octets))))))

(defun h3-cid-octets (cid)
  (let ((len (cffi:mem-ref cid :unsigned-long)))
    (when (<= len 20)
      (foreign-to-octets (cffi:inc-pointer cid 8) len))))

(defun foreign-index (pointer length needle)
  "Index of NEEDLE in the foreign bytes at POINTER, or NIL."
  (let* ((octets (babel:string-to-octets needle :encoding :ascii))
         (size (length octets)))
    (when (<= size length)
      (loop for start from 0 to (- length size)
            when (loop for offset below size
                       always (= (cffi:mem-aref pointer :uint8 (+ start offset))
                                 (aref octets offset)))
              return start))))

(defun h3-log-sendonly-reset-p (pointer length)
  "True when this ngtcp2 log line is a received RESET_STREAM for a
server send-only stream. That stream id ends in the bits 11 (RFC 9000
§2.1). libngtcp2 reports the frame as NGTCP2_ERR_PROTO; the close
code for this one frame is decided from the line."
  (when (and (foreign-index pointer length " RESET_STREAM(")
             (foreign-index pointer length "rx "))
    (let ((id-at (foreign-index pointer length " id=0x")))
      (when id-at
        (let ((value 0)
              (digits 0)
              (index (+ id-at 6)))
          (loop while (< index length)
                for byte = (cffi:mem-aref pointer :uint8 index)
                for nibble = (digit-char-p (code-char byte) 16)
                while nibble
                do (setf value (logior (ash value 4) nibble)
                         digits (1+ digits)
                         index (1+ index)))
          (and (plusp digits) (= (logand value 3) 3)))))))

(cffi:defcallback h3-log-write :void
    ((user-data :pointer) (msg :pointer) (len :unsigned-long))
  (with-callback-guard nil
    (let ((conn (h3-from user-data)))
      (when conn
        (setf (gethash conn *h3-sendonly-reset*)
              (h3-log-sendonly-reset-p msg len))))))

(defun h3-open-quic (conn version original-dcid client-scid our-scid &key retry-scid token)
  "ORIGINAL-DCID is the client's first Initial destination. After a verified
Retry, RETRY-SCID is this packet's destination and TOKEN is copied into the
connection settings as a Retry token."
  (h3-ensure-state)
  (cffi:with-foreign-objects ((out :pointer)
                              (dcid :uint8 32)
                              (scid :uint8 32)
                              (settings :uint8 208)
                              (params :uint8 344))
    (h3-put-cid dcid client-scid)
    (h3-put-cid scid our-scid)
    (ngtcp2-settings-default 4 settings)
    (setf (cffi:mem-ref settings :uint64 16) (monotonic-ns)
          (cffi:mem-ref settings :pointer 200) (cffi:callback h3-log-write))
    (ngtcp2-params-default 1 params)
    ;; initial_max_streams_uni is 8. Three streams are required
    ;; (control, QPACK encoder, QPACK decoder). The extra room lets a
    ;; duplicate stream type be received and rejected (RFC 9204 §4.2).
    (setf (cffi:mem-ref params :uint64 192) (* 256 1024)
          (cffi:mem-ref params :uint64 200) (* 256 1024)
          (cffi:mem-ref params :uint64 208) (* 256 1024)
          (cffi:mem-ref params :uint64 216) (* 1024 1024)
          (cffi:mem-ref params :uint64 224) 100
          (cffi:mem-ref params :uint64 232) 8
          (cffi:mem-ref params :uint64 240) (* 30 1000000000)
          (cffi:mem-ref params :uint64 256) 7
          (cffi:mem-ref params :uint8 290) 1)
    (h3-put-cid (cffi:inc-pointer params 96) original-dcid)
    (when retry-scid
      (h3-put-cid (cffi:inc-pointer params 160) retry-scid)
      (setf (cffi:mem-ref params :uint8 292) 1))
    (flet ((create ()
             (let ((rv (ngtcp2-server-new out dcid scid (h3-conn-path conn) version
                                          5 *h3-quic-callbacks* 4 settings 1 params
                                          (cffi:null-pointer)
                                          (cffi:make-pointer (h3-conn-pin conn)))))
               (unless (zerop rv)
                 (error "ngtcp2_conn_server_new_versioned returned ~d" rv))
               (setf (h3-conn-quic conn) (cffi:mem-ref out :pointer))
               (h3-note-cc-layout conn (cffi:mem-ref out :pointer)))))
      (if token
          (cffi:with-pointer-to-vector-data (token-ptr (simple-octets token))
            (setf (cffi:mem-ref settings :pointer 48) token-ptr
                  (cffi:mem-ref settings :unsigned-long 56) (length token)
                  (cffi:mem-ref settings :int 64) +retry-token-type+)
            (create))
          (create)))
    (ngtcp2-set-tls-native (h3-conn-quic conn) (h3-conn-crypto conn))
    (setf (cffi:mem-ref (h3-conn-conn-ref conn) :pointer) (cffi:callback h3-get-conn)
          (cffi:mem-ref (h3-conn-conn-ref conn) :pointer 8) (h3-conn-quic conn))
    (%ssl-set-ex-data (h3-conn-ssl conn) 0 (h3-conn-conn-ref conn))
    (cl+ssl::ssl-set-accept-state (h3-conn-ssl conn))
    (unless (zerop (ngtcp2-crypto-configure-server (h3-conn-ssl conn)))
      (error "ngtcp2_crypto_ossl_configure_server_session failed"))))

(defun h3-open-http3 (conn)
  (cffi:with-foreign-object (out :pointer)
    (let ((rv (nghttp3-server-new out 4 *h3-http-callbacks* 4 *h3-http-settings*
                                  (cffi:null-pointer)
                                  (cffi:make-pointer (h3-conn-pin conn)))))
      (unless (zerop rv)
        (error "nghttp3_conn_server_new_versioned returned ~d" rv))
      (setf (h3-conn-http3 conn) (cffi:mem-ref out :pointer)))))

(defun h3-accept (endpoint host port version original-dcid client-scid &key retry-scid token)
  (let ((conn (make-h3-conn :endpoint endpoint
                            :peer (format-ip host)
                            :path (cffi:foreign-alloc :uint8 :count 96)
                            :conn-ref (cffi:foreign-alloc :uint8 :count 16))))
    (setf (h3-conn-pin conn) (pin conn))
    (handler-case
        (cffi:with-foreign-objects ((local :uint8 28) (remote :uint8 28))
          (let ((local-len (fill-sockaddr local (h3-endpoint-local-host endpoint)
                                          (h3-endpoint-local-port endpoint)))
                (remote-len (fill-sockaddr remote host port)))
            (ngtcp2-path-init (h3-conn-path conn) local local-len remote remote-len
                              (cffi:null-pointer)))
          (let ((our (ironclad:random-data 18)))
            (h3-open-tls conn)
            (h3-open-quic conn version original-dcid client-scid our
                          :retry-scid retry-scid :token token)
            (h3-open-http3 conn)
            (h3-index endpoint our conn)
            (when retry-scid
              (h3-index endpoint retry-scid conn)))
          conn)
      (error (condition)
        (pazuzu-trace "h3 accept: ~a" condition)
        (h3-free conn)
        nil))))

(defun h3-decode (packet)
  (cffi:with-foreign-object (dest :uint8 40)
    (foreign-zero dest 40)
    (cffi:with-pointer-to-vector-data (pointer packet)
      (let ((rv (ngtcp2-decode-version-cid dest pointer (length packet) 18)))
        (if (or (zerop rv) (eql rv +ngtcp2-version-negotiation+))
            (let ((dcidlen (cffi:mem-ref dest :unsigned-long 16))
                  (scidlen (cffi:mem-ref dest :unsigned-long 32)))
              (values rv
                      (cffi:mem-ref dest :uint32)
                      (foreign-to-octets (cffi:mem-ref dest :pointer 8) dcidlen)
                      (foreign-to-octets (cffi:mem-ref dest :pointer 24) scidlen)))
            (values rv nil nil nil))))))

(defun h3-read-varint (packet index)
  "Return the QUIC variable-length integer at INDEX and the next index."
  (when (< index (length packet))
    (let* ((first (aref packet index))
           (size (ash 1 (ash first -6))))
      (when (<= (+ index size) (length packet))
        (let ((raw 0))
          (loop for offset from 0 below size
                do (setf raw (logior (ash raw 8) (aref packet (+ index offset)))))
          (values (logand raw (1- (ash 1 (- (* 8 size) 2))))
                  (+ index size)))))))

(defun h3-long-packet-end (packet start)
  "Index of the first byte after the long-header packet at START.
NIL when START is not a complete long-header packet with a length."
  (let ((len (length packet)))
    (when (and (< start len)
               (logtest (aref packet start) #x80)
               (<= (+ start 7) len))
      (let ((type (logand (ash (aref packet start) -4) 3))
            (index (+ start 6 (aref packet (+ start 5)))))
        (when (< index len)
          (let ((scid (aref packet index)))
            (incf index (1+ scid))
            (when (and (<= index len) (/= type 3))
              (when (zerop type)
                (multiple-value-bind (token-len next) (h3-read-varint packet index)
                  (unless (and token-len (<= (+ next token-len) len))
                    (return-from h3-long-packet-end nil))
                  (setf index (+ next token-len))))
              (multiple-value-bind (payload-len next) (h3-read-varint packet index)
                (when (and payload-len (<= (+ next payload-len) len))
                  (+ next payload-len))))))))))

(defun h3-simple-slice (packet start end)
  (let ((out (make-array (- end start) :element-type '(unsigned-byte 8))))
    (replace out packet :start2 start :end2 end)
    out))

(defun h3-coalesced-slices (packet)
  "RFC 9000 §12.2. Yield each long-header packet that is followed by
another long-header packet. A discarded packet must not hide the rest
of the datagram. Trailing padding stays with the preceding packet."
  (let ((len (length packet))
        (start 0)
        (cuts nil))
    (loop
      (let ((end (h3-long-packet-end packet start)))
        (cond ((and end (< end len) (logtest (aref packet end) #x80))
               (push end cuts)
               (setf start end))
              (t (return)))))
    (if (null cuts)
        (list packet)
        (let ((slices nil)
              (from 0))
          (dolist (cut (nreverse cuts))
            (push (h3-simple-slice packet from cut) slices)
            (setf from cut))
          (push (h3-simple-slice packet from len) slices)
          (nreverse slices)))))

(defun h3-guard-conn (endpoint conn thunk)
  "Run THUNK for one connection. An error retires CONN and leaves the rest."
  (handler-case (funcall thunk)
    (error (condition)
      (format *error-output* "pazuzu: http3 connection: ~a~%" condition)
      (when (and endpoint conn)
        (ignore-errors (h3-retire endpoint conn))))))

(defun h3-read-conn (endpoint conn packet host port &optional (ecn 0))
  (when (or (null (h3-conn-quic conn)) (h3-conn-freed conn) (h3-conn-closing conn))
    (return-from h3-read-conn nil))
  (h3-guard-conn endpoint conn
                 (lambda () (h3-read-conn-body endpoint conn packet host port ecn))))

(defun h3-read-conn-body (endpoint conn packet host port &optional (ecn 0))
  (when (or (null (h3-conn-quic conn)) (h3-conn-freed conn) (h3-conn-closing conn))
    (return-from h3-read-conn-body nil))
  (h3-remember-peer conn host port)
  ;; RFC 9000 §10.3.1. A datagram that cannot be decrypted can still be
  ;; a Stateless Reset. Matching a used token enters draining and sends
  ;; no further packets. The check runs before read_pkt so a failure to
  ;; decrypt cannot hide the token.
  (when (h3-stateless-reset-p conn packet)
    (h3-retire endpoint conn)
    (return-from h3-read-conn-body nil))
  (cffi:with-foreign-objects ((path :uint8 96) (pkt-info :uint8 8) (local :uint8 28) (remote :uint8 28))
    (let ((local-len (fill-sockaddr local (h3-endpoint-local-host endpoint)
                                    (h3-endpoint-local-port endpoint)))
          (remote-len (fill-sockaddr remote host port)))
      (ngtcp2-path-init path local local-len remote remote-len (cffi:null-pointer)))
    (dolist (slice (h3-coalesced-slices packet))
      (when (or (null (h3-conn-quic conn)) (h3-conn-freed conn) (h3-conn-closing conn))
        (return))
      (foreign-zero pkt-info 8)
      (setf (cffi:mem-ref pkt-info :uint8) (logand (or ecn 0) 3))
      (h3-note-rtt-moved conn (h3-conn-quic conn))
      (cffi:with-pointer-to-vector-data (pointer slice)
        (let ((rv (ngtcp2-read-pkt (h3-conn-quic conn) path 1 pkt-info pointer (length slice) (monotonic-ns))))
          (cond ((zerop rv)
                 (let ((opened (h3-open-local-unis conn)))
                   (when opened
                     (h3-fail-conn conn opened)
                     (return))))
                ((member rv (list +ngtcp2-retry+ +ngtcp2-drop-conn+ +ngtcp2-draining+
                                  +ngtcp2-closing+ +ngtcp2-idle-close+))
                 (h3-retire endpoint conn)
                 (return))
                ((< rv 0)
                 (let ((app (shiftf (h3-conn-app-close conn) nil))
                       ;; RFC 9000 §19.4. RESET_STREAM on a send-only
                       ;; stream is STREAM_STATE_ERROR. ngtcp2 returns
                       ;; NGTCP2_ERR_PROTO for that one frame. Other
                       ;; PROTOCOL_VIOLATION results stay 0x0a.
                       (code (if (and (eql rv +ngtcp2-proto+)
                                      (gethash conn *h3-sendonly-reset*))
                                 +ngtcp2-stream-state+
                                 rv)))
                   (if app
                       (h3-fail-conn conn app :application t)
                       (h3-fail-conn conn code)))
                 (return)))
          (when (and (h3-conn-quic conn) (not (h3-conn-freed conn)))
            (h3-guard-rtt conn (h3-conn-quic conn)))))))
  (when (and (h3-conn-quic conn) (not (h3-conn-freed conn)))
    (h3-resume-conn conn)))

(defun h3-send-raw (endpoint host port packet)
  (when (and host port packet (h3-endpoint-socket endpoint))
    (ignore-errors
      (sb-bsd-sockets:socket-send (h3-endpoint-socket endpoint)
                                  packet (length packet)
                                  :address (list host port)))))

(defun h3-cid-pointer-octets (cid)
  "A simple octet vector that can be pinned. A zero-length connection ID
still needs a pointer; the caller passes the real length separately."
  (let ((octets (simple-octets cid)))
    (if (plusp (length octets))
        octets
        (make-array 1 :element-type '(unsigned-byte 8)))))

(defun h3-send-version-negotiation (endpoint host port dcid scid)
  "Answer an unsupported QUIC version (RFC 9000 §17.2.1). The client's
source and destination connection IDs are swapped in the reply. A QUIC v1
length limit does not decide whether to answer."
  (when (or (null dcid) (null scid))
    (return-from h3-send-version-negotiation nil))
  (cffi:with-foreign-objects ((dest :uint8 1200) (versions :uint32 1))
    (setf (cffi:mem-ref versions :uint32) +quic-v1+)
    (let ((client-scid (h3-cid-pointer-octets scid))
          (client-dcid (h3-cid-pointer-octets dcid)))
      (cffi:with-pointer-to-vector-data (scid-ptr client-scid)
        (cffi:with-pointer-to-vector-data (dcid-ptr client-dcid)
          (let ((n (ngtcp2-write-vn dest 1200 (random 256)
                                    scid-ptr (length scid)
                                    dcid-ptr (length dcid)
                                    versions 1)))
            (when (plusp n)
              (h3-send-raw endpoint host port (foreign-to-octets dest n)))))))))

(defun h3-initial-header (packet)
  "Return VERSION, DCID, SCID, and TOKEN when PACKET is an acceptable first
Initial. The token is copied out of the datagram. NIL otherwise."
  (cffi:with-foreign-object (hd :uint8 256)
    (foreign-zero hd 256)
    (cffi:with-pointer-to-vector-data (pointer packet)
      (unless (zerop (ngtcp2-accept hd pointer (length packet)))
        (return-from h3-initial-header nil))
      (let ((dcid (h3-cid-octets hd))
            (scid (h3-cid-octets (cffi:inc-pointer hd 32)))
            (tokenlen (cffi:mem-ref hd :unsigned-long 80))
            (token-ptr (cffi:mem-ref hd :pointer 72)))
        (unless (and dcid scid (<= 8 (length dcid) 20))
          (return-from h3-initial-header nil))
        (values (cffi:mem-ref hd :uint32 104)
                dcid
                scid
                (if (and (plusp tokenlen)
                         token-ptr
                         (not (cffi:null-pointer-p token-ptr)))
                    (foreign-to-octets token-ptr tokenlen)
                    nil))))))

(defun h3-send-stateless (endpoint host port version client-scid client-dcid error-code)
  "CONNECTION_CLOSE in an Initial. CLIENT-SCID is the destination the client
reads, and CLIENT-DCID is the connection ID the Initial keys are derived from."
  (cffi:with-foreign-objects ((dest :uint8 1200)
                              (dcid :uint8 32)
                              (scid :uint8 32))
    (h3-put-cid dcid client-scid)
    (h3-put-cid scid client-dcid)
    (let ((n (ngtcp2-write-stateless-close dest 1200 version dcid scid error-code
                                           (cffi:null-pointer) 0)))
      (when (plusp n)
        (h3-send-raw endpoint host port (foreign-to-octets dest n))))))

(defun h3-send-retry (endpoint host port version original-dcid client-scid)
  "Stateless Retry. The new source connection ID is sealed into the token."
  (let ((retry-scid (ironclad:random-data 18))
        (secret (h3-endpoint-retry-secret endpoint)))
    (cffi:with-foreign-objects ((remote :uint8 28)
                                (odcid :uint8 32)
                                (client :uint8 32)
                                (chosen :uint8 32)
                                (token :uint8 128)
                                (dest :uint8 1200))
      (let ((remote-len (fill-sockaddr remote host port)))
        (h3-put-cid odcid original-dcid)
        (h3-put-cid client client-scid)
        (h3-put-cid chosen retry-scid)
        (cffi:with-pointer-to-vector-data (secret-ptr secret)
          (let ((tokenlen (ngtcp2-generate-retry-token
                           token secret-ptr (length secret) version
                           remote remote-len chosen odcid (monotonic-ns))))
            (when (plusp tokenlen)
              (let ((n (ngtcp2-write-retry dest 1200 version client chosen odcid
                                           token tokenlen)))
                (when (plusp n)
                  (h3-send-raw endpoint host port (foreign-to-octets dest n)))))))))))

(defun h3-verify-retry (endpoint host port version token packet-dcid)
  "Return the original destination connection ID, or NIL when TOKEN is bad."
  (cffi:with-foreign-objects ((remote :uint8 28)
                              (odcid :uint8 32)
                              (dcid :uint8 32))
    (let ((remote-len (fill-sockaddr remote host port))
          (secret (h3-endpoint-retry-secret endpoint)))
      (h3-put-cid dcid packet-dcid)
      (cffi:with-pointer-to-vector-data (secret-ptr secret)
        (cffi:with-pointer-to-vector-data (token-ptr (simple-octets token))
          (when (zerop (ngtcp2-verify-retry-token
                        odcid token-ptr (length token)
                        secret-ptr (length secret) version
                        remote remote-len dcid
                        +retry-token-timeout+ (monotonic-ns)))
            (h3-cid-octets odcid)))))))

(defun h3-accept-initial (endpoint host port packet)
  "Retry a tokenless Initial. Admit a verified token, then accept. A full cap
is CONNECTION_REFUSED and does not consume a connection."
  (multiple-value-bind (version dcid scid token) (h3-initial-header packet)
    (unless version
      (return-from h3-accept-initial nil))
    (cond ((null token)
           (h3-send-retry endpoint host port version dcid scid)
           nil)
          (t
           (let ((original (h3-verify-retry endpoint host port version token dcid)))
             (cond ((null original)
                    (h3-send-stateless endpoint host port version scid dcid
                                       +quic-invalid-token+)
                    nil)
                   (t
                    (let* ((server (h3-endpoint-server endpoint))
                           (peer (format-ip host)))
                      (cond ((admit-http3 server peer)
                             (let ((created (h3-accept endpoint host port version original scid
                                                       :retry-scid dcid :token token)))
                               (cond (created
                                      (setf (h3-conn-admitted created) t)
                                      created)
                                     (t
                                      (release-http3 server peer)
                                      nil))))
                            (t
                             (count-reject (server-metrics server))
                             (h3-send-stateless endpoint host port version scid dcid
                                                +quic-connection-refused+)
                             nil))))))))))

(defun h3-on-packet (endpoint packet host port &optional (ecn 0))
  (unless (and (h3-endpoint-alive endpoint)
               (server-running (h3-endpoint-server endpoint))
               (plusp (length packet)))
    (return-from h3-on-packet nil))
  (multiple-value-bind (rv version dcid scid) (h3-decode packet)
    (when (eql rv +ngtcp2-version-negotiation+)
      (h3-send-version-negotiation endpoint host port dcid scid)
      (return-from h3-on-packet nil))
    (unless (and (zerop rv) dcid (plusp (length dcid)))
      (return-from h3-on-packet nil))
    ;; RFC 9000 §17.2. A version 1 long header with the fixed bit clear
    ;; is not a valid packet. Drop it before Retry or admission.
    (when (and (= version +quic-v1+)
               (logtest (aref packet 0) #x80)
               (not (logtest (aref packet 0) #x40)))
      (return-from h3-on-packet nil))
    (let ((conn (h3-find endpoint dcid)))
      (cond (conn (h3-read-conn endpoint conn packet host port ecn))
            ((and (logtest (aref packet 0) #x80)
                  (zerop (logand (aref packet 0) #x30))
                  (= version +quic-v1+)
                  (<= 8 (length dcid) 20)
                  scid)
             (let ((created (h3-accept-initial endpoint host port packet)))
               (when created
                 (h3-read-conn endpoint created packet host port ecn))))
            ;; RFC 9000 §10.3.1. A datagram that cannot be associated
            ;; with a connection is still compared with tokens for
            ;; connection IDs this endpoint has used toward that peer.
            (t (h3-drain-stateless-reset endpoint packet host port))))))

(defun h3-pull (conn stream fin vecs)
  (cond ((or (null (h3-conn-http3 conn)) (h3-conn-closing conn) (h3-conn-freed conn))
         0)
        (t (let ((count (nghttp3-writev (h3-conn-http3 conn) stream fin vecs 16)))
             (cond ((eql count +nghttp3-wouldblock+)
                    (setf (cffi:mem-ref stream :int64) -1
                          (cffi:mem-ref fin :int) 0)
                    0)
                   ((< count 0)
                    (h3-fail-conn conn (nghttp3-app-error count) :application t)
                    :dead)
                   (t count))))))

(defun h3-write-packet (endpoint conn)
  (when (or (null (h3-conn-quic conn)) (h3-conn-freed conn) (h3-conn-closing conn))
    (return-from h3-write-packet :dead))
  (let ((ts (monotonic-ns)))
    (cffi:with-foreign-objects ((path :uint8 96) (pkt-info :uint8 8) (dest :uint8 2048)
                                (stream :int64) (fin :int) (vecs :uint8 (* 16 16)) (taken :long))
      (ngtcp2-path-zero path)
      (foreign-zero pkt-info 8)
      (loop for spin below 64
            do (setf (cffi:mem-ref stream :int64) -1
                     (cffi:mem-ref fin :int) 0
                     (cffi:mem-ref taken :long) -1)
               (let ((count (h3-pull conn stream fin vecs)))
                 (when (eq count :dead)
                   (return :dead))
                 (let* ((stream-id (cffi:mem-ref stream :int64))
                        (flags (logior +h3-write-more+
                                       (if (plusp (cffi:mem-ref fin :int)) +h3-write-fin+ 0)))
                        (n (ngtcp2-writev-stream (h3-conn-quic conn) path 1 pkt-info dest 2048 taken
                                                 flags stream-id
                                                 (if (plusp count) vecs (cffi:null-pointer))
                                                 (max 0 count) ts))
                        (accepted (cffi:mem-ref taken :long)))
                   (cond ((eql n +ngtcp2-write-more+)
                          (when (and (h3-conn-http3 conn) (>= accepted 0))
                            (nghttp3-add-write-offset (h3-conn-http3 conn) stream-id accepted)))
                         ((eql n +ngtcp2-stream-data-blocked+)
                          (when (h3-conn-http3 conn)
                            (nghttp3-block-stream (h3-conn-http3 conn) stream-id)))
                         ((or (eql n +ngtcp2-stream-shut-wr+) (eql n +ngtcp2-stream-not-found+))
                          nil)
                         ((< n 0)
                          (h3-fail-conn conn n)
                          (return :dead))
                         (t
                          (when (and (h3-conn-http3 conn) (>= accepted 0))
                            (nghttp3-add-write-offset (h3-conn-http3 conn) stream-id accepted))
                          (when (h3-conn-quic conn)
                            (ngtcp2-update-tx (h3-conn-quic conn) (monotonic-ns)))
                          (when (plusp n)
                            (h3-send endpoint path dest n (cffi:mem-ref pkt-info :uint8)))
                          (return n)))))))))

(defun h3-write-all (endpoint)
  (dolist (conn (h3-connections endpoint))
    (when (and (h3-conn-quic conn) (not (h3-conn-freed conn)) (not (h3-conn-closing conn)))
      (h3-guard-conn endpoint conn
                     (lambda ()
                       (h3-resume-conn conn)
                       (loop for burst below 32
                             for n = (h3-write-packet endpoint conn)
                             while (and (numberp n) (plusp n))))))))

(defun h3-handle-expiries (endpoint now)
  (dolist (conn (h3-connections endpoint))
    (when (and (h3-conn-quic conn) (not (h3-conn-freed conn)))
      (let ((expiry (ngtcp2-expiry (h3-conn-quic conn))))
        (when (and (< expiry +uint64-max+) (<= expiry now))
          (let ((rv (ngtcp2-handle-expiry (h3-conn-quic conn) now)))
            (cond ((eql rv +ngtcp2-idle-close+) (h3-retire endpoint conn))
                  ((< rv 0) (h3-fail-conn conn rv)))))))))

(defun h3-timeout (endpoint now)
  (let ((nearest nil))
    (dolist (conn (h3-connections endpoint))
      (when (and (h3-conn-quic conn) (not (h3-conn-freed conn)))
        (let ((expiry (ngtcp2-expiry (h3-conn-quic conn))))
          (when (and (< expiry +uint64-max+)
                     (or (null nearest) (< expiry nearest)))
            (setf nearest expiry)))))
    (if (null nearest)
        1000
        (min 1000 (max 0 (ceiling (- nearest now) 1000000))))))

(defun h3-recv (endpoint buffer)
  (handler-case
      (udp-recvmsg (h3-endpoint-fd endpoint) buffer
                   (ipv6-host-p (h3-endpoint-local-host endpoint)))
    (error ()
      (setf (h3-endpoint-alive endpoint) nil)
      nil)))

(defun h3-graceful (endpoint)
  "Send H3_NO_ERROR on every connection, then leave the read loop."
  (dolist (conn (h3-connections endpoint))
    (h3-fail-conn conn +h3-no-error+ :application t))
  (setf (h3-endpoint-drained endpoint) t
        (h3-endpoint-alive endpoint) nil))

(defun h3-drive (endpoint buffer)
  (when (h3-endpoint-draining endpoint)
    (h3-graceful endpoint)
    (return-from h3-drive nil))
  (let* ((now (monotonic-ns))
         (ready (poll-fds (list (list (h3-endpoint-fd endpoint) +pollin+)
                                (list (h3-endpoint-wake endpoint) +pollin+))
                          (h3-timeout endpoint now))))
    (when (h3-endpoint-draining endpoint)
      (h3-graceful endpoint)
      (return-from h3-drive nil))
    (h3-handle-expiries endpoint (monotonic-ns))
    (when (and ready (logtest (first ready) +pollnval+))
      (setf (h3-endpoint-alive endpoint) nil)
      (return-from h3-drive nil))
    (when (and ready (logtest (second ready) +pollin+))
      (eventfd-drain (h3-endpoint-wake endpoint))
      (dolist (conn (h3-connections endpoint))
        (when (h3-conn-quic conn)
          (h3-resume-conn conn)))
      (h3-drain-pending endpoint))
    (when (and ready (h3-endpoint-alive endpoint) (logtest (first ready) +pollin+))
      (loop for packet = (multiple-value-bind (buf len host port ecn) (h3-recv endpoint buffer)
                           (when (and buf len (plusp len) host)
                             (list (simple-octets (subseq buf 0 len)) host port (or ecn 0))))
            while packet
            do (h3-on-packet endpoint (first packet) (second packet) (third packet)
                             (fourth packet))))
    (when (h3-endpoint-alive endpoint)
      (h3-write-all endpoint))))

(defun h3-drop-all (endpoint)
  (dolist (conn (h3-connections endpoint))
    (h3-retire endpoint conn)))

(defun h3-loop (endpoint)
  (let ((buffer (make-array 65535 :element-type '(unsigned-byte 8))))
    (loop while (and (h3-endpoint-alive endpoint)
                     (not (h3-endpoint-drained endpoint))
                     (or (server-running (h3-endpoint-server endpoint))
                         (h3-endpoint-draining endpoint)))
          ;; Borrow the context for this pass. Reload drops the server's reference
          ;; without freeing a context this pass, or an SSL object, still holds.
          do (call-with-borrowed-h3-context endpoint
               (lambda () (h3-drive endpoint buffer))))))

(defun h3-serve (endpoint)
  (unwind-protect
       (handler-case
           (h3-loop endpoint)
         (error (condition)
           (format *error-output* "pazuzu: http3: ~a~%" condition)))
    (h3-drop-all endpoint)
    (when (h3-endpoint-wake endpoint)
      (let ((fd (h3-endpoint-wake endpoint)))
        (setf (h3-endpoint-wake endpoint) nil)
        (posix-close fd)))))

(defun http3-bind (host port)
  (let* ((ipv6 (ipv6-host-p host))
         (socket (make-instance (if ipv6
                                    'sb-bsd-sockets:inet6-socket
                                    'sb-bsd-sockets:inet-socket)
                                :type :datagram :protocol :udp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (let ((fd (sb-bsd-sockets:socket-file-descriptor socket)))
      (set-udp-dont-fragment fd ipv6)
      (unless (set-udp-recv-ecn fd ipv6)
        (error "could not receive ECN marks")))
    (sb-bsd-sockets:socket-bind socket host port)
    (set-nonblock (sb-bsd-sockets:socket-file-descriptor socket))
    socket))

(defun start-http3 (server socket)
  "Run the HTTP/3 endpoint for SERVER on the already bound UDP SOCKET."
  (h3-ensure-state)
  (multiple-value-bind (host port) (sb-bsd-sockets:socket-name socket)
    (let ((endpoint (make-h3-endpoint :server server
                                      :socket socket
                                      :fd (sb-bsd-sockets:socket-file-descriptor socket)
                                      :context (server-h3-context server)
                                      :wake (make-eventfd)
                                      :local-host host
                                      :local-port port)))
      (note-thread server
                   (bt:make-thread (lambda () (h3-serve endpoint)) :name "pazuzu-quic"))
      endpoint)))

(defun http3-shutdown (endpoint)
  "Unblock the QUIC thread and the streams it owns. The thread frees the connections."
  (when endpoint
    (setf (h3-endpoint-alive endpoint) nil)
    (dolist (conn (h3-connections endpoint))
      (maphash (lambda (id stream)
                 (declare (ignore id))
                 (when (h3-stream-pipe stream)
                   (pipe-shutdown (h3-stream-pipe stream))))
               (h3-conn-streams conn)))
    (eventfd-write (h3-endpoint-wake endpoint))
    (when (h3-endpoint-socket endpoint)
      (ignore-errors (sb-bsd-sockets:socket-close (h3-endpoint-socket endpoint))))))
