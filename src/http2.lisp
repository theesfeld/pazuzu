(in-package #:pazuzu)

(native-version "nghttp2_version" 'libnghttp2 #x014600 "nghttp2")

(defconstant +h2-deferred+ -508)
(defconstant +h2-callback-failure+ -902)
(defconstant +h2-temporal-callback-failure+ -521)
(defconstant +h2-err-flow-control+ -524)
(defconstant +h2-eof-flag+ 1)
(defconstant +h2-end-stream+ 1)
(defconstant +h2-ack+ 1)
(defconstant +h2-headers+ 1)
(defconstant +h2-data+ 0)
(defconstant +h2-continuation+ 9)
(defconstant +h2-ping+ 6)
(defconstant +h2-goaway-type+ 7)
(defconstant +h2-hcat-request+ 0)
(defconstant +h2-hcat-headers+ 3)
(defconstant +h2-protocol-error+ #x01)
(defconstant +h2-flow-control-error+ #x03)
(defconstant +h2-stream-closed+ #x05)
(defconstant +ssl-error-want-read+ 2)
(defconstant +ssl-error-want-write+ 3)
(defconstant +ssl-error-zero-return+ 6)

(alexandria:define-constant +h2-preface+
  (coerce #(80 82 73 32 42 32 72 84 84 80 47 50 46 48 13 10 13 10 83 77 13 10 13 10)
          '(simple-array (unsigned-byte 8) (*)))
  :test #'equalp)

(cffi:defcfun ("SSL_read" %ssl-read :library cl+ssl::libssl) :int
  (ssl :pointer) (buffer :pointer) (count :int))
(cffi:defcfun ("SSL_write" %ssl-write :library cl+ssl::libssl) :int
  (ssl :pointer) (buffer :pointer) (count :int))
(cffi:defcfun ("SSL_get_error" %ssl-get-error :library cl+ssl::libssl) :int
  (ssl :pointer) (ret :int))

(cffi:defcfun ("nghttp2_session_callbacks_new" nghttp2-callbacks-new :library libnghttp2) :int
  (out :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_del" nghttp2-callbacks-del :library libnghttp2) :void
  (callbacks :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_frame_recv_callback"
               nghttp2-set-on-frame-recv :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_data_chunk_recv_callback"
               nghttp2-set-on-data :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_stream_close_callback"
               nghttp2-set-on-stream-close :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_begin_headers_callback"
               nghttp2-set-on-begin-headers :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_header_callback"
               nghttp2-set-on-header :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_begin_frame_callback"
               nghttp2-set-on-begin-frame :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_invalid_frame_recv_callback"
               nghttp2-set-on-invalid :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_callbacks_set_on_invalid_header_callback"
               nghttp2-set-on-invalid-header :library libnghttp2) :void
  (callbacks :pointer) (function :pointer))
(cffi:defcfun ("nghttp2_session_server_new3" nghttp2-server-new :library libnghttp2) :int
  (out :pointer) (callbacks :pointer) (user-data :pointer) (option :pointer) (memory :pointer))
(cffi:defcfun ("nghttp2_session_del" nghttp2-session-del :library libnghttp2) :void
  (session :pointer))
(cffi:defcfun ("nghttp2_session_mem_recv2" nghttp2-mem-recv :library libnghttp2) :long
  (session :pointer) (input :pointer) (length :unsigned-long))
(cffi:defcfun ("nghttp2_session_mem_send2" nghttp2-mem-send :library libnghttp2) :long
  (session :pointer) (data :pointer))
(cffi:defcfun ("nghttp2_session_resume_data" nghttp2-resume-data :library libnghttp2) :int
  (session :pointer) (stream-id :int32))
(cffi:defcfun ("nghttp2_session_want_read" nghttp2-want-read :library libnghttp2) :int
  (session :pointer))
(cffi:defcfun ("nghttp2_session_want_write" nghttp2-want-write :library libnghttp2) :int
  (session :pointer))
(cffi:defcfun ("nghttp2_submit_response2" nghttp2-submit-response :library libnghttp2) :int
  (session :pointer) (stream-id :int32) (fields :pointer) (count :unsigned-long) (provider :pointer))
(cffi:defcfun ("nghttp2_submit_headers" nghttp2-submit-headers :library libnghttp2) :int32
  (session :pointer) (flags :uint8) (stream-id :int32) (priority :pointer)
  (fields :pointer) (count :unsigned-long) (user-data :pointer))
(cffi:defcfun ("nghttp2_submit_settings" nghttp2-submit-settings :library libnghttp2) :int
  (session :pointer) (flags :uint8) (entries :pointer) (count :unsigned-long))
(cffi:defcfun ("nghttp2_submit_rst_stream" nghttp2-rst :library libnghttp2) :int
  (session :pointer) (flags :uint8) (stream-id :int32) (error-code :uint32))
(cffi:defcfun ("nghttp2_is_fatal" nghttp2-fatal-p :library libnghttp2) :int
  (code :int))
(cffi:defcfun ("nghttp2_submit_goaway" nghttp2-submit-goaway :library libnghttp2) :int
  (session :pointer) (flags :uint8) (last-stream-id :int32) (error-code :uint32)
  (data :pointer) (length :unsigned-long))
(cffi:defcfun ("nghttp2_session_terminate_session" nghttp2-terminate :library libnghttp2) :int
  (session :pointer) (error-code :uint32))
(cffi:defcfun ("nghttp2_submit_ping" nghttp2-submit-ping :library libnghttp2) :int
  (session :pointer) (flags :uint8) (data :pointer))

(defconstant +h2-goaway-last-stream+ (1- (ash 1 31))
  "Largest stream id a server may name in GOAWAY (RFC 9113).")

(defmacro with-callback-guard (fail &body body)
  `(handler-case (progn ,@body)
     (error (condition)
       (format *error-output* "pazuzu: ~a~%" condition)
       ,fail)))

(defun frame-stream-id (frame)
  (cffi:mem-ref frame :int32 8))

(defun frame-type (frame)
  (cffi:mem-ref frame :uint8 12))

(defun frame-flags (frame)
  (cffi:mem-ref frame :uint8 13))

(defun frame-header-category (frame)
  (cffi:mem-ref frame :int 56))

(defun foreign-latin1 (pointer length)
  (babel:octets-to-string (foreign-to-octets pointer length) :encoding :iso-8859-1))

(defun call-with-nv (pairs function)
  "Call FUNCTION with a foreign nghttp2/nghttp3 name-value array. The callee
must copy the fields before returning; the strings are freed afterwards."
  (let ((count (length pairs))
        (allocated nil))
    (unwind-protect
         (cffi:with-foreign-object (fields :uint8 (max 40 (* count 40)))
           (loop for (name . value) in pairs
                 for index from 0
                 for base = (cffi:inc-pointer fields (* index 40))
                 for name-ptr = (cffi:foreign-string-alloc name :encoding :latin-1)
                 for value-ptr = (cffi:foreign-string-alloc value :encoding :latin-1)
                 do (push name-ptr allocated)
                    (push value-ptr allocated)
                    (foreign-zero base 40)
                    (setf (cffi:mem-ref base :pointer) name-ptr
                          (cffi:mem-ref base :pointer 8) value-ptr
                          (cffi:mem-ref base :unsigned-long 16) (length name)
                          (cffi:mem-ref base :unsigned-long 24) (length value)))
           (funcall function (if (zerop count) (cffi:null-pointer) fields) count))
      (dolist (pointer allocated)
        (cffi:foreign-string-free pointer)))))

(defstruct h2-io fd ssl)

(defstruct h2-conn
  server io scheme peer session pin wake
  (streams (make-hash-table))
  (seen-streams (make-hash-table))
  ;; Stream ids closed before the peer sent END_STREAM. Frames already
  ;; in flight after our RST_STREAM are discarded (RFC 9113 §5.1).
  (discard-inflight (make-hash-table))
  (peer-stream-id 0)
  (lock (bt:make-lock "pazuzu-h2"))
  dirty goaway peer-goaway
  (preface-left 24)
  (frame-fill 0)
  (frame-need 0)
  (frame-hdr (make-array 9 :element-type '(unsigned-byte 8))))

(defstruct h2-stream
  id method scheme authority path protocol
  headers trailers
  (header-bytes 0)
  (field-count 0)
  in-trailers remote-closed
  (body (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  overflow header-error dispatched websocket pipe
  source buffer (buffer-pos 0) submitted
  continue
  (started (get-internal-real-time)))

(defun h2-terminate (conn error-code)
  "Queue a connection error. nghttp2 ignores some idle and closed-stream
frames that RFC 9113 requires to be PROTOCOL_ERROR or STREAM_CLOSED."
  (when (and conn (h2-conn-session conn) (not (h2-conn-goaway conn)))
    (setf (h2-conn-goaway conn) t)
    (nghttp2-terminate (h2-conn-session conn) error-code)))

(defun h2-unexpected-stream (conn stream-id)
  "HEADERS or DATA for a client stream nghttp2 will not reject itself.
A smaller unused id is PROTOCOL_ERROR (RFC 9113 §5.1.1). A frame after
the stream closed is STREAM_CLOSED (RFC 9113 §5.1), except frames that
were in flight when this endpoint reset an open stream."
  (when (and conn (plusp stream-id) (oddp stream-id) (not (h2-conn-goaway conn)))
    (when (gethash stream-id (h2-conn-discard-inflight conn))
      (return-from h2-unexpected-stream nil))
    (let ((live (gethash stream-id (h2-conn-streams conn))))
      (cond ((and live (h2-stream-remote-closed live))
             (h2-terminate conn +h2-stream-closed+))
            ((> stream-id (h2-conn-peer-stream-id conn))
             nil)
            ((null live)
             (h2-terminate conn
                           (if (gethash stream-id (h2-conn-seen-streams conn))
                               +h2-stream-closed+
                               +h2-protocol-error+)))))))

(defun h2-remote-closed-ids (conn)
  "Stream ids whose request side was already closed before this read.
A DATA frame in the same read may itself set remote-closed, and that
frame is legal."
  (let ((closed (make-hash-table)))
    (maphash (lambda (id stream)
               (when (h2-stream-remote-closed stream)
                 (setf (gethash id closed) t)))
             (h2-conn-streams conn))
    closed))

(defun h2-saw-frame-header (conn header closed-before)
  "nghttp2 does not call on_begin_frame for a DATA frame it has already
decided to ignore. RFC 9113 still requires STREAM_CLOSED or PROTOCOL_ERROR."
  (let ((length (logior (ash (aref header 0) 16)
                        (ash (aref header 1) 8)
                        (aref header 2)))
        (type (aref header 3))
        (stream-id (logand (logior (ash (aref header 5) 24)
                                   (ash (aref header 6) 16)
                                   (ash (aref header 7) 8)
                                   (aref header 8))
                           #x7fffffff)))
    (remhash conn *h2-priority-rest*)
    (when (and (= type 3) (plusp stream-id))
      (h2-note-peer-rst conn stream-id))
    (when (and (plusp stream-id)
               (or (= type +h2-data+) (= type +h2-headers+))
               (h2-peer-rst-p conn stream-id))
      (h2-terminate conn +h2-stream-closed+))
    (setf (h2-conn-frame-need conn) length)
    (when (= type 2)
      (cond ((zerop stream-id)
             (h2-terminate conn +h2-protocol-error+))
            ((= length 5)
             (setf (gethash conn *h2-priority-rest*)
                   (cons stream-id
                         (make-array 5 :element-type '(unsigned-byte 8)
                                     :fill-pointer 0))))))
    (when (or (= type +h2-data+) (= type +h2-continuation+))
      (cond ((and (plusp stream-id) (gethash stream-id closed-before))
             (h2-terminate conn +h2-stream-closed+))
            ((null (gethash stream-id (h2-conn-streams conn)))
             ;; Already freed, or a smaller id that was never opened.
             ;; A larger unseen id falls through to the idle check below:
             ;; h2-unexpected-stream treats that as a new HEADERS stream.
             (h2-unexpected-stream conn stream-id)))
      (when (and (plusp stream-id) (oddp stream-id)
                 (> stream-id (h2-conn-peer-stream-id conn))
                 (not (gethash stream-id (h2-conn-seen-streams conn))))
        (h2-terminate conn +h2-protocol-error+)))))

(defun h2-scan-frames (conn buffer length closed-before)
  "Walk bytes nghttp2 has already accepted and catch ignored DATA."
  (let ((offset 0))
    (loop while (< offset length)
          do (cond ((plusp (h2-conn-preface-left conn))
                    (let ((skip (min (h2-conn-preface-left conn) (- length offset))))
                      (decf (h2-conn-preface-left conn) skip)
                      (incf offset skip)))
                   ((plusp (h2-conn-frame-need conn))
                    (let ((skip (min (h2-conn-frame-need conn) (- length offset))))
                      (h2-priority-take conn buffer offset skip)
                      (decf (h2-conn-frame-need conn) skip)
                      (incf offset skip)))
                   (t
                    (let* ((header (h2-conn-frame-hdr conn))
                           (have (h2-conn-frame-fill conn))
                           (take (min (- 9 have) (- length offset))))
                      (loop for index below take
                            do (setf (aref header (+ have index))
                                     (cffi:mem-ref buffer :uint8 (+ offset index))))
                      (incf offset take)
                      (incf (h2-conn-frame-fill conn) take)
                      (when (= (h2-conn-frame-fill conn) 9)
                        (h2-saw-frame-header conn header closed-before)
                        (setf (h2-conn-frame-fill conn) 0))))))))

(defun h2-note-peer-stream (conn stream-id)
  (when (and conn (plusp stream-id) (oddp stream-id)
             (> stream-id (h2-conn-peer-stream-id conn)))
    (setf (h2-conn-peer-stream-id conn) stream-id)
    (setf (gethash stream-id (h2-conn-seen-streams conn)) t)))

(cffi:defcallback h2-on-begin-frame :int
    ((session :pointer) (hd :pointer) (user-data :pointer))
  (declare (ignore session))
  (with-callback-guard +h2-callback-failure+
    (let ((conn (pointer-pin user-data))
          (type (frame-type hd))
          (stream-id (frame-stream-id hd)))
      (when conn
        (cond ((= type +h2-headers+)
               (h2-unexpected-stream conn stream-id)
               (h2-note-peer-stream conn stream-id))
              ((or (= type +h2-data+) (= type +h2-continuation+))
               (h2-unexpected-stream conn stream-id)
               (when (and (plusp stream-id) (oddp stream-id)
                          (> stream-id (h2-conn-peer-stream-id conn))
                          (not (gethash stream-id (h2-conn-seen-streams conn))))
                 (h2-terminate conn +h2-protocol-error+))))))
    0))

(defun foreign-value-malformed-p (pointer length)
  "RFC 9113 §8.2.1 on the raw field value."
  (when (and (plusp length)
             (let ((first (cffi:mem-ref pointer :uint8 0))
                   (last (cffi:mem-ref pointer :uint8 (1- length))))
               (or (= first 9) (= first 32) (= last 9) (= last 32))))
    (return-from foreign-value-malformed-p t))
  (loop for index below length
        for byte = (cffi:mem-ref pointer :uint8 index)
        thereis (or (zerop byte) (= byte 10) (= byte 13))))

(cffi:defcallback h2-on-invalid-header :int
    ((session :pointer) (frame :pointer) (name :pointer) (name-length :unsigned-long)
     (value :pointer) (value-length :unsigned-long) (flags :uint8) (user-data :pointer))
  (declare (ignore session frame flags user-data))
  (with-callback-guard +h2-callback-failure+
    ;; nghttp2 ignores an invalid regular field unless this callback asks
    ;; for a stream reset. RFC 9113 §8.2.1 makes CR, LF, NUL, and leading
    ;; or trailing whitespace a malformed message (PROTOCOL_ERROR). A field
    ;; nghttp2 ignores for another reason, such as a Host that is not an
    ;; authority, stays ignored.
    (if (or (not (token-string-p (foreign-latin1 name name-length)))
            (foreign-value-malformed-p value value-length))
        +h2-temporal-callback-failure+
        0)))

(cffi:defcallback h2-on-invalid :int
    ((session :pointer) (frame :pointer) (lib-error :int) (user-data :pointer))
  (declare (ignore user-data))
  (with-callback-guard +h2-callback-failure+
    ;; A stream window overflow is a stream error (RFC 9113 §6.9.1):
    ;; RST_STREAM FLOW_CONTROL_ERROR. nghttp2 instead queues a connection
    ;; GOAWAY and sets TERM_ON_SEND, which then drops a queued RST_STREAM
    ;; (session_prep_frame refuses it once the session is closing). Returning
    ;; non-zero skips that GOAWAY so the RST can be written. A connection
    ;; window overflow has stream id 0 and still uses the library GOAWAY.
    (if (and (= lib-error +h2-err-flow-control+)
             (plusp (frame-stream-id frame))
             (zerop (nghttp2-rst session 0 (frame-stream-id frame)
                                 +h2-flow-control-error+)))
        1
        0)))

(defun h2-mark-dirty (conn stream-id)
  (bt:with-lock-held ((h2-conn-lock conn))
    (pushnew stream-id (h2-conn-dirty conn)))
  (eventfd-write (h2-conn-wake conn)))

(defun h2-resume-dirty (conn)
  (let ((ids (bt:with-lock-held ((h2-conn-lock conn))
               (shiftf (h2-conn-dirty conn) nil))))
    (dolist (id ids)
      (ignore-errors (nghttp2-resume-data (h2-conn-session conn) id)))))

(defun h2-find (user-data stream-id)
  (let ((conn (pointer-pin user-data)))
    (values conn (and conn (gethash stream-id (h2-conn-streams conn))))))

(cffi:defcallback h2-on-begin-headers :int
    ((session :pointer) (frame :pointer) (user-data :pointer))
  (declare (ignore session))
  (with-callback-guard +h2-callback-failure+
    (when (= (frame-type frame) +h2-headers+)
      (multiple-value-bind (conn stream) (h2-find user-data (frame-stream-id frame))
        (declare (ignore stream))
        (when conn
          (cond ((= (frame-header-category frame) +h2-hcat-request+)
                 (setf (gethash (frame-stream-id frame) (h2-conn-streams conn))
                       (make-h2-stream :id (frame-stream-id frame))))
                ((= (frame-header-category frame) +h2-hcat-headers+)
                 (let ((existing (gethash (frame-stream-id frame) (h2-conn-streams conn))))
                   (when existing
                     (setf (h2-stream-in-trailers existing) t))))))))
    0))

(cffi:defcallback h2-on-header :int
    ((session :pointer) (frame :pointer) (name :pointer) (name-length :unsigned-long)
     (value :pointer) (value-length :unsigned-long) (flags :uint8) (user-data :pointer))
  (declare (ignore session flags))
  (with-callback-guard +h2-callback-failure+
    (multiple-value-bind (conn stream) (h2-find user-data (frame-stream-id frame))
      (declare (ignore conn))
      (when stream
        (incf (h2-stream-field-count stream))
        (incf (h2-stream-header-bytes stream) (+ name-length value-length))
        (when (or (> (h2-stream-field-count stream) +max-header-fields+)
                  (> (h2-stream-header-bytes stream) +max-header-bytes+))
          (setf (h2-stream-header-error stream) 431))
        (let ((field (string-downcase (foreign-latin1 name name-length)))
              (text (foreign-latin1 value value-length)))
          (cond ((h2-stream-in-trailers stream)
                 (push (cons field text) (h2-stream-trailers stream)))
                ((and (plusp (length field)) (char= (char field 0) #\:))
                 (cond ((string= field ":method") (setf (h2-stream-method stream) text))
                       ((string= field ":scheme") (setf (h2-stream-scheme stream) text))
                       ((string= field ":authority") (setf (h2-stream-authority stream) text))
                       ((string= field ":path") (setf (h2-stream-path stream) text))
                       ((string= field ":protocol") (setf (h2-stream-protocol stream) text))))
                (t (push (cons field text) (h2-stream-headers stream)))))))
    0))

(cffi:defcallback h2-on-data :int
    ((session :pointer) (flags :uint8) (stream-id :int32) (data :pointer)
     (length :unsigned-long) (user-data :pointer))
  (declare (ignore session flags))
  (with-callback-guard +h2-callback-failure+
    (multiple-value-bind (conn stream) (h2-find user-data stream-id)
      (when stream
        (cond ((h2-stream-pipe stream)
               (pipe-feed (h2-stream-pipe stream) (foreign-to-octets data length)))
              ((h2-stream-overflow stream) nil)
              ((> (+ (length (h2-stream-body stream)) length)
                  (server-max-body (h2-conn-server conn)))
               (setf (h2-stream-overflow stream) t))
              (t (loop for index below length
                       do (vector-push-extend (cffi:mem-ref data :uint8 index)
                                              (h2-stream-body stream)))))))
    0))

(cffi:defcallback h2-data-read :long
    ((session :pointer) (stream-id :int32) (buffer :pointer) (length :unsigned-long)
     (data-flags :pointer) (source :pointer) (user-data :pointer))
  (declare (ignore session source))
  (setf (cffi:mem-ref data-flags :uint32) 0)
  (with-callback-guard +h2-callback-failure+
    (multiple-value-bind (conn stream) (h2-find user-data stream-id)
      (declare (ignore conn))
      (cond ((or (null stream) (null (h2-stream-source stream)))
             (setf (cffi:mem-ref data-flags :uint32) +h2-eof-flag+)
             0)
            ((eq (h2-stream-source stream) :pipe)
             (multiple-value-bind (count eof)
                 (pipe-copy-output (h2-stream-pipe stream) buffer length)
               (when eof
                 (setf (cffi:mem-ref data-flags :uint32) +h2-eof-flag+))
               (if (and (zerop count) (not eof)) +h2-deferred+ count)))
            (t
             (let* ((octets (h2-stream-buffer stream))
                    (pos (h2-stream-buffer-pos stream))
                    (count (min length (max 0 (- (length octets) pos)))))
               (octets-to-foreign (subseq octets pos (+ pos count)) buffer)
               (incf (h2-stream-buffer-pos stream) count)
               (when (>= (h2-stream-buffer-pos stream) (length octets))
                 (setf (cffi:mem-ref data-flags :uint32) +h2-eof-flag+))
               count))))))

(cffi:defcallback h2-on-stream-close :int
    ((session :pointer) (stream-id :int32) (error-code :uint32) (user-data :pointer))
  (declare (ignore session error-code))
  (with-callback-guard +h2-callback-failure+
    (multiple-value-bind (conn stream) (h2-find user-data stream-id)
      (when stream
        ;; The peer had not ended the stream. A following frame was
        ;; sent before it saw this close, so it is not a connection error.
        (unless (h2-stream-remote-closed stream)
          (setf (gethash stream-id (h2-conn-discard-inflight conn)) t))
        (when (h2-stream-pipe stream)
          (pipe-shutdown (h2-stream-pipe stream)))
        (remhash stream-id (h2-conn-streams conn))))
    0))

(defun h2-stub-request (conn stream)
  (make-request :method (or (h2-stream-method stream) "GET")
                :target (or (h2-stream-path stream) "/")
                :path "/"
                :http-version 20
                :headers (h2-stream-headers stream)
                :scheme (h2-conn-scheme conn)
                :host (or (h2-stream-authority stream) "")
                :body (ascii-octets "")))

(defun h2-submit (conn stream response &key provider head)
  (when (h2-stream-submitted stream)
    (return-from h2-submit nil))
  ;; HEADERS with END_STREAM and a 1xx status is malformed (RFC 9113 §8.1).
  ;; Interim 100 uses h2-submit-continue, which does not set END_STREAM.
  (when (< (response-status response) 200)
    (setf response (plain-error 500)))
  (let ((logged (h2-stub-request conn stream)))
    (setf (request-peer logged) (or (h2-conn-peer conn) ""))
    (setf response (origin-decorate (h2-conn-server conn) logged response))
    ;; A malformed field must still produce one response. Mark the stream
    ;; submitted only after the field list can be built.
    (handler-case (response-wire-fields response)
      (error (condition)
        (error-log (server-logger (h2-conn-server conn)) "error" "pazuzu: ~a" condition)
        (setf response (origin-decorate (h2-conn-server conn) logged (plain-error 500)))))
    (setf (h2-stream-submitted stream) t)
    (note-response (h2-conn-server conn) logged response
                   :seconds (/ (max 0 (- (get-internal-real-time) (h2-stream-started stream)))
                               internal-time-units-per-second)))
  (let* ((status (response-status response))
         (body (emitted-body response))
         (streaming (functionp body))
         (file (and (file-body-p body) body))
         (known (unless (or streaming file) (response-octets body)))
         (send-body (and provider (status-has-body-p status) (not head)
                         (or streaming
                             (and file (plusp (file-body-count file)))
                             (eq (h2-stream-source stream) :pipe)
                             (and known (plusp (length known)))))))
    (when (and (or streaming file) send-body)
      (let ((pipe (make-octet-pipe
                   :on-output (lambda (ignored)
                                (declare (ignore ignored))
                                (h2-mark-dirty conn (h2-stream-id stream))))))
        (setf (h2-stream-pipe stream) pipe
              (h2-stream-source stream) :pipe)
        (note-thread (h2-conn-server conn)
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
               (not (eq (h2-stream-source stream) :pipe)))
      (setf (h2-stream-source stream) :buffer
            (h2-stream-buffer stream) known
            (h2-stream-buffer-pos stream) 0))
    (let ((fields (response-wire-fields response)))
      ;; A function stream has no length. A file span does, and the pipe
      ;; writes exactly that many octets.
      (when (and (eq (h2-stream-source stream) :pipe) (not file))
        (setf fields (remove "content-length" fields :key #'car :test #'string=)))
      (call-with-nv fields
        (lambda (nva count)
          (if send-body
              (cffi:with-foreign-object (provider-struct :uint8 16)
                (foreign-zero provider-struct 16)
                (setf (cffi:mem-ref provider-struct :pointer 8) (cffi:callback h2-data-read))
                (nghttp2-submit-response (h2-conn-session conn) (h2-stream-id stream)
                                         nva count provider-struct))
              (nghttp2-submit-response (h2-conn-session conn) (h2-stream-id stream)
                                       nva count (cffi:null-pointer))))))))

(defun h2-fail (conn stream status &optional response)
  "Send STATUS and its reason phrase, or RESPONSE when the error already
built one. The body must follow the Content-Length; a HEADERS frame with
END_STREAM and a non-zero length is a protocol error (RFC 9113 §8.1.1 /
RFC 9110 §8.6)."
  (h2-submit conn stream
             (or response
                 (make-response :status status
                                :content-type "text/plain; charset=utf-8"
                                :body (reason-phrase status)))
             :provider t
             :head (equal (h2-stream-method stream) "HEAD")))

(defun h2-submit-continue (conn stream)
  "HEADERS :status 100, without END_STREAM. Does not mark the final response."
  (call-with-nv '((":status" . "100"))
    (lambda (nva count)
      (let ((rv (nghttp2-submit-headers (h2-conn-session conn) 0
                                        (h2-stream-id stream)
                                        (cffi:null-pointer)
                                        nva count
                                        (cffi:null-pointer))))
        (when (minusp rv)
          (error "nghttp2_submit_headers returned ~d" rv)))))
  t)

(defun h2-early-response (conn stream)
  "Final response decided from headers, or NIL when the body is required."
  (cond ((h2-stream-header-error stream)
         (plain-error (h2-stream-header-error stream)))
        ((h2-stream-overflow stream)
         (plain-error 413))
        ((request-limited-p (h2-conn-server conn) (or (h2-conn-peer conn) ""))
         (too-many-response))
        ;; RFC 9110 §9.3.6. A classic CONNECT with an empty or invalid port
        ;; is 400. Extended CONNECT names an origin and is not this check.
        ((and (equal (h2-stream-method stream) "CONNECT")
              (not (h2-stream-protocol stream))
              (not (connect-authority-ok-p (h2-stream-authority stream))))
         (plain-error 400))
        ((equal (h2-stream-method stream) "CONNECT")
         (plain-error 501))
        (t (handler-case
               (status-before-content (h2-conn-server conn)
                                      (build-origin-request conn stream 20))
             (protocol-error (condition)
               (protocol-error-response condition))))))

(defun h2-note-continue (conn stream)
  "RFC 9110 §10.1.1. Remember to send 100 before the next read, or send
the final status now when the method and target already decide it."
  (handler-case
      (when (continue-expectation (h2-stream-headers stream))
        (let ((early (h2-early-response conn stream)))
          (cond (early
                 (setf (h2-stream-dispatched stream) t)
                 (h2-submit conn stream early :provider t))
                (t (setf (h2-stream-continue stream) t)))))
    (protocol-error (condition)
      (setf (h2-stream-dispatched stream) t)
      (h2-fail conn stream (protocol-error-status condition)
                        (protocol-error-response condition)))))

(defun h2-send-continues (conn)
  "Send a queued 100 only when this recv did not already finish the request.
A body in the same buffer is allowed to skip 100 (RFC 9110 §10.1.1)."
  (when (and conn (h2-conn-session conn) (not (h2-conn-goaway conn)))
    (handler-case
        (maphash (lambda (id stream)
                   (declare (ignore id))
                   (when (and (h2-stream-continue stream)
                              (not (h2-stream-dispatched stream))
                              (not (h2-stream-remote-closed stream))
                              (not (h2-stream-submitted stream)))
                     (setf (h2-stream-continue stream) nil)
                     (h2-submit-continue conn stream)))
                 (h2-conn-streams conn))
      (error (condition)
        (format *error-output* "pazuzu: continue: ~a~%" condition)))))

(defun split-pseudo-path (method raw)
  (reject-fragment raw)
  (cond ((string= raw "*")
         (unless (string= method "OPTIONS")
           (protocol-error 400 :detail "asterisk-form"))
         (values "/" nil "*"))
        ((or (null raw) (zerop (length raw)) (char/= (char raw 0) #\/))
         (protocol-error 400 :detail "bad :path"))
        (t (let ((mark (position #\? raw)))
             (values (normalize-path (if mark (subseq raw 0 mark) raw))
                     (and mark (subseq raw (1+ mark)))
                     raw)))))

(defun build-origin-request (conn stream version)
  (unless (and (h2-stream-method stream) (h2-stream-path stream) (h2-stream-authority stream)
               (h2-stream-scheme stream))
    (protocol-error 400 :detail "missing pseudo-header"))
  (unless (token-string-p (h2-stream-method stream))
    (protocol-error 400 :detail "bad method"))
  ;; RFC 3986 scheme is case-insensitive. The stored scheme is the listener's.
  (unless (string-equal (h2-stream-scheme stream) (h2-conn-scheme conn))
    (protocol-error 400 :detail "scheme"))
  (unless (valid-host-p (h2-stream-authority stream))
    (protocol-error 400 :detail "bad authority"))
  (reject-authority-host (h2-stream-authority stream)
                         (h2-stream-headers stream)
                         (h2-conn-scheme conn))
  (multiple-value-bind (path query target)
      (split-pseudo-path (h2-stream-method stream) (h2-stream-path stream))
    (make-request :method (h2-stream-method stream)
                  :target target
                  :path path
                  :query query
                  :http-version version
                  :headers (setf (h2-stream-headers stream)
                                 (collapse-cookie-fields
                                  (nreverse (h2-stream-headers stream))))
                  :trailers (setf (h2-stream-trailers stream)
                                  (retain-trailer-fields
                                   (nreverse (h2-stream-trailers stream))))
                  :body (h2-stream-body stream)
                  :host (h2-stream-authority stream)
                  :scheme (h2-conn-scheme conn)
                  :peer (or (h2-conn-peer conn) ""))))

(defun h2-open-websocket (conn stream)
  (setf (h2-stream-dispatched stream) t)
  (when (request-limited-p (h2-conn-server conn) (or (h2-conn-peer conn) ""))
    (h2-submit conn stream (too-many-response) :provider t)
    (return-from h2-open-websocket nil))
  (setf (h2-stream-websocket stream) t)
  (handler-case
      (let* ((request (build-origin-request conn stream 20))
             (route (find-route (h2-conn-server conn) (request-path request)
                                 (request-host request))))
        (cond ((null route) (h2-fail conn stream 404))
              ((not (route-websocket route)) (h2-fail conn stream 501))
              (t (let ((response (websocket-extended-response request)))
                   (if (= (response-status response) 200)
                       (let ((pipe (make-octet-pipe
                                    :on-output (lambda (ignored)
                                                 (declare (ignore ignored))
                                                 (h2-mark-dirty conn (h2-stream-id stream))))))
                         (setf (h2-stream-pipe stream) pipe
                               (h2-stream-source stream) :pipe)
                         (h2-submit conn stream response :provider t)
                         (start-websocket-thread (h2-conn-server conn)
                                                 (route-handler route) pipe))
                       (h2-submit conn stream response :provider t))))))
    (protocol-error (condition) (h2-fail conn stream (protocol-error-status condition)
                        (protocol-error-response condition)))
    (error (condition)
      (format *error-output* "pazuzu: websocket: ~a~%" condition)
      (h2-fail conn stream 500))))

(defun h2-dispatch-stream (conn stream)
  (when (h2-stream-dispatched stream)
    (return-from h2-dispatch-stream nil))
  (setf (h2-stream-dispatched stream) t)
  (cond ((h2-stream-header-error stream)
         (h2-fail conn stream (h2-stream-header-error stream)))
        ((h2-stream-overflow stream)
         (h2-fail conn stream 413))
        ;; RFC 9113 §8.3.1. :authority for http or https excludes userinfo.
        ;; An invalid pseudo-header value is malformed (§8.1.1).
        ((and (h2-stream-authority stream)
              (find #\@ (h2-stream-authority stream))
              (member (h2-stream-scheme stream) '("http" "https")
                      :test #'string-equal))
         (nghttp2-rst (h2-conn-session conn) 0 (h2-stream-id stream)
                      +h2-protocol-error+))
        ;; RFC 9113 §8.3.1. :path is absolute-path and an optional query.
        ;; A fragment is not a valid value, so the request is malformed.
        ((and (stringp (h2-stream-path stream))
              (find #\# (h2-stream-path stream)))
         (nghttp2-rst (h2-conn-session conn) 0 (h2-stream-id stream)
                      +h2-protocol-error+))
        ;; RFC 3986 §3.1 and RFC 9113 §8.3.1. :scheme is one URI scheme.
        ((and (stringp (h2-stream-scheme stream))
              (not (scheme-string-p (h2-stream-scheme stream))))
         (nghttp2-rst (h2-conn-session conn) 0 (h2-stream-id stream)
                      +h2-protocol-error+))
        ((and (equal (h2-stream-method stream) "CONNECT")
              (equal (h2-stream-protocol stream) "websocket"))
         (h2-open-websocket conn stream))
        ;; RFC 9113 §8.5. A CONNECT request includes :authority. Omitting
        ;; it is malformed (PROTOCOL_ERROR), not a tunnel refusal.
        ((and (equal (h2-stream-method stream) "CONNECT")
              (not (h2-stream-protocol stream))
              (not (h2-stream-authority stream)))
         (nghttp2-rst (h2-conn-session conn) 0 (h2-stream-id stream)
                      +h2-protocol-error+))
        ;; RFC 9110 §9.3.6. Reject an empty or invalid port before the
        ;; tunnel refusal. A present port in 0..65535 stays 501.
        ((and (equal (h2-stream-method stream) "CONNECT")
              (not (h2-stream-protocol stream))
              (not (connect-authority-ok-p (h2-stream-authority stream))))
         (h2-fail conn stream 400))
        ((equal (h2-stream-method stream) "CONNECT")
         (h2-fail conn stream 501))
        ((request-limited-p (h2-conn-server conn) (or (h2-conn-peer conn) ""))
         (h2-submit conn stream (too-many-response) :provider t))
        (t
         (handler-case
             (let* ((request (build-origin-request conn stream 20))
                    (result (dispatch (h2-conn-server conn) request)))
               (if (eq result :websocket)
                   (h2-fail conn stream 400)
                   (h2-submit conn stream result
                              :provider t
                              :head (string= (h2-stream-method stream) "HEAD"))))
           (protocol-error (condition)
             (h2-fail conn stream (protocol-error-status condition)
                        (protocol-error-response condition)))
           (error (condition)
             (format *error-output* "pazuzu: ~a~%" condition)
             (h2-fail conn stream 500))))))

(cffi:defcallback h2-on-frame-recv :int
    ((session :pointer) (frame :pointer) (user-data :pointer))
  (with-callback-guard +h2-callback-failure+
    (let ((type (frame-type frame))
          (flags (frame-flags frame)))
      (multiple-value-bind (conn stream) (h2-find user-data (frame-stream-id frame))
        (when (and stream (logtest flags +h2-end-stream+)
                   (or (= type +h2-headers+) (= type +h2-data+)))
          (setf (h2-stream-remote-closed stream) t))
        (cond ((and conn (= type +h2-goaway-type+))
               (setf (h2-conn-peer-goaway conn) t))
              ((and conn (= type +h2-ping+)
                    (not (logtest flags +h2-ack+))
                    (h2-conn-peer-goaway conn))
               ;; After GOAWAY, nghttp2 treats the session as closing and
               ;; skips the automatic PING ACK (RFC 9113 §6.7).
               (nghttp2-submit-ping session +h2-ack+ (cffi:inc-pointer frame 16)))
              (stream
               (cond ((and (= type +h2-headers+)
                           (= (frame-header-category frame) +h2-hcat-request+))
                      (if (and (equal (h2-stream-method stream) "CONNECT")
                               (equal (h2-stream-protocol stream) "websocket"))
                          (h2-open-websocket conn stream)
                          (if (logtest flags +h2-end-stream+)
                              (h2-dispatch-stream conn stream)
                              (h2-note-continue conn stream))))
                     ((and (= type +h2-headers+)
                           (= (frame-header-category frame) +h2-hcat-headers+)
                           (logtest flags +h2-end-stream+))
                      (h2-dispatch-stream conn stream))
                     ((and (= type +h2-data+)
                           (logtest flags +h2-end-stream+))
                      (h2-dispatch-stream conn stream)))))))
    0))

(defvar *h2-peer-rst* (make-hash-table :test 'eq :weakness :key)
  "Stream ids for which this connection has received RST_STREAM.
A later DATA or HEADERS frame on that stream is STREAM_CLOSED
(RFC 9113 §5.1, the rule h2spec 5.1/8 and 5.1/9 execute). Frames that
arrived before the RST in the same byte stream are not that error.
WINDOW_UPDATE stays legal: the suite accepts it on a closed stream.")

(defun h2-note-peer-rst (conn stream-id)
  (let ((table (or (gethash conn *h2-peer-rst*)
                   (setf (gethash conn *h2-peer-rst*) (make-hash-table)))))
    (setf (gethash stream-id table) t)))

(defun h2-peer-rst-p (conn stream-id)
  (let ((table (gethash conn *h2-peer-rst*)))
    (and table (gethash stream-id table))))

(defvar *h2-priority-rest* (make-hash-table :test 'eq :weakness :key)
  "Bytes still needed to see whether a PRIORITY frame depends on its own stream.
nghttp2 1.70 reads a 5-octet PRIORITY and then discards it. RFC 9113 §6.3
still requires stream identifier 0 to be PROTOCOL_ERROR. RFC 7540 §5.3.1,
which h2spec executes, requires a self-dependent PRIORITY to be PROTOCOL_ERROR.
The dependency is the low 31 bits of the first four payload octets.")

(defun h2-priority-take (conn buffer offset count)
  (let ((pending (gethash conn *h2-priority-rest*)))
    (when pending
      (let ((stream-id (car pending))
            (got (cdr pending)))
        (loop for index below count
              while (< (fill-pointer got) 5)
              do (vector-push (cffi:mem-ref buffer :uint8 (+ offset index)) got))
        (when (= (fill-pointer got) 5)
          (remhash conn *h2-priority-rest*)
          (when (= stream-id
                   (logand (logior (ash (aref got 0) 24)
                                   (ash (aref got 1) 16)
                                   (ash (aref got 2) 8)
                                   (aref got 3))
                           #x7fffffff))
            ;; Idle streams are not in the nghttp2 map, so a RST_STREAM
            ;; for this id is ignored. A connection error carries the
            ;; same code, which is what the frame requires to be reported.
            (h2-terminate conn +h2-protocol-error+)))))))

(defvar *h2-callbacks* nil)

(defun h2-callbacks ()
  (or *h2-callbacks*
      (cffi:with-foreign-object (out :pointer)
        (unless (zerop (nghttp2-callbacks-new out))
          (error "nghttp2_session_callbacks_new failed"))
        (let ((callbacks (cffi:mem-ref out :pointer)))
          (nghttp2-set-on-frame-recv callbacks (cffi:callback h2-on-frame-recv))
          (nghttp2-set-on-data callbacks (cffi:callback h2-on-data))
          (nghttp2-set-on-stream-close callbacks (cffi:callback h2-on-stream-close))
          (nghttp2-set-on-begin-headers callbacks (cffi:callback h2-on-begin-headers))
          (nghttp2-set-on-header callbacks (cffi:callback h2-on-header))
          (nghttp2-set-on-begin-frame callbacks (cffi:callback h2-on-begin-frame))
          (nghttp2-set-on-invalid callbacks (cffi:callback h2-on-invalid))
          (nghttp2-set-on-invalid-header callbacks (cffi:callback h2-on-invalid-header))
          (setf *h2-callbacks* callbacks)))))

(defun h2-open-session (conn)
  (cffi:with-foreign-object (out :pointer)
    (let ((status (nghttp2-server-new out (h2-callbacks) (cffi:make-pointer (h2-conn-pin conn))
                                      (cffi:null-pointer) (cffi:null-pointer))))
      (unless (zerop status)
        (error "nghttp2_session_server_new3 returned ~d" status))
      (setf (h2-conn-session conn) (cffi:mem-ref out :pointer)))))

(defun h2-submit-settings (conn)
  ;; 0x04 SETTINGS_INITIAL_WINDOW_SIZE is not sent. A smaller value shrinks
  ;; every open stream window, and RFC 9113 §6.9.3 requires DATA that still
  ;; fit the previous window to be accepted. nghttp2 1.70 reports that
  ;; DATA as a connection error of FLOW_CONTROL_ERROR.
  (cffi:with-foreign-object (entries :uint8 32)
    (loop for (id value) in '((#x03 100) (#x06 65536) (#x08 1) (#x09 1))
          for index from 0
          do (setf (cffi:mem-ref entries :int32 (* index 8)) id
                   (cffi:mem-ref entries :uint32 (+ (* index 8) 4)) value))
    (nghttp2-submit-settings (h2-conn-session conn) 0 entries 4)))

(defun h2-read-some (io buffer length)
  (if (h2-io-ssl io)
      (let ((count (%ssl-read (h2-io-ssl io) buffer length)))
        (cond ((plusp count) count)
              (t (case (%ssl-get-error (h2-io-ssl io) count)
                   (#.+ssl-error-want-read+ :want-read)
                   (#.+ssl-error-want-write+ :want-write)
                   (#.+ssl-error-zero-return+ :eof)
                   (t :eof)))))
      (let ((count (%read (h2-io-fd io) buffer length)))
        (cond ((plusp count) count)
              ((zerop count) :eof)
              ((= (errno) +eintr+) :want-read)
              ((= (errno) +eagain+) :want-read)
              (t :eof)))))

(defun h2-write-some (io buffer length)
  (if (h2-io-ssl io)
      (let ((count (%ssl-write (h2-io-ssl io) buffer length)))
        (cond ((plusp count) count)
              (t (case (%ssl-get-error (h2-io-ssl io) count)
                   (#.+ssl-error-want-read+ :want-read)
                   (#.+ssl-error-want-write+ :want-write)
                   (t :eof)))))
      (let ((count (%write (h2-io-fd io) buffer length)))
        (cond ((plusp count) count)
              ((= (errno) +eintr+) :want-write)
              ((= (errno) +eagain+) :want-write)
              (t :eof)))))

(defun h2-write-all (io buffer length)
  (let ((done 0))
    (loop while (< done length)
          do (let ((count (h2-write-some io (cffi:inc-pointer buffer done) (- length done))))
               (if (numberp count)
                   (incf done count)
                   (return-from h2-write-all count)))))
  :ok)

(defun h2-flush (conn)
  (cffi:with-foreign-object (data :pointer)
    (loop for count = (nghttp2-mem-send (h2-conn-session conn) data)
          do (cond ((zerop count) (return :ok))
                   ((< count 0) (return count))
                   (t (let ((wrote (h2-write-all (h2-conn-io conn)
                                                (cffi:mem-ref data :pointer) count)))
                        (unless (eq wrote :ok)
                          (return wrote))))))))

(defun h2-consume (conn buffer length)
  (let ((offset 0))
    (loop while (< offset length)
          for closed-before = (h2-remote-closed-ids conn)
          for count = (nghttp2-mem-recv (h2-conn-session conn)
                                        (cffi:inc-pointer buffer offset)
                                        (- length offset))
          do (cond ((< count 0) (return-from h2-consume count))
                   ((zerop count)
                    (h2-send-continues conn)
                    (return-from h2-consume offset))
                   (t (h2-scan-frames conn (cffi:inc-pointer buffer offset) count
                                      closed-before)
                      (incf offset count))))
    (h2-send-continues conn)
    offset))

(defun h2-register (conn)
  (let ((server (h2-conn-server conn)))
    (bt:with-lock-held ((server-lock server))
      (push conn (server-h2-conns server)))))

(defun h2-unregister (conn)
  (let ((server (h2-conn-server conn)))
    (bt:with-lock-held ((server-lock server))
      (setf (server-h2-conns server) (remove conn (server-h2-conns server))))))

(defun h2-goaway (conn)
  "Tell the peer this connection is finished (RFC 9113 §5.4, NO_ERROR).
A connection error already queued is flushed and not replaced."
  (when (h2-conn-session conn)
    (unless (h2-conn-goaway conn)
      (setf (h2-conn-goaway conn) t)
      (ignore-errors
        (nghttp2-submit-goaway (h2-conn-session conn) 0 +h2-goaway-last-stream+ 0
                               (cffi:null-pointer) 0)))
    (ignore-errors (h2-flush conn))))

(defun h2-stopping (conn)
  (not (server-running (h2-conn-server conn))))

(defun h2-quiescent-p (conn)
  (and (zerop (nghttp2-want-read (h2-conn-session conn)))
       (zerop (nghttp2-want-write (h2-conn-session conn)))))

(defun h2-consume-result (conn buffer count)
  "Feed COUNT bytes to nghttp2. Flush a queued GOAWAY on any library error.
Return true when the connection must close."
  (let ((consumed (h2-consume conn buffer count)))
    (when (and (numberp consumed) (< consumed 0))
      (h2-flush conn)
      (plusp (nghttp2-fatal-p consumed)))))

(defun h2-drain-pending (conn buffer &optional (timeout-ms 0))
  "Read octets the kernel already has. close() with unread data sends RST.
TIMEOUT-MS waits once for the first octet. Later reads do not wait.
Return true when any octets were consumed and the peer has not hung up."
  (let ((fd (h2-io-fd (h2-conn-io conn)))
        (got nil)
        (wait timeout-ms))
    (loop
      (let ((ready (poll-fds (list (list fd +pollin+)) wait)))
        (setf wait 0)
        (unless (and ready (logtest (or (first ready) 0) +pollin+))
          (return got)))
      (let ((count (h2-read-some (h2-conn-io conn) buffer 16384)))
        (cond ((not (numberp count)) (return nil))
              (t (setf got t)
                 (when (h2-consume-result conn buffer count)
                   (return nil))))))))

(defun h2-loop (conn)
  (let ((buffer (cffi:foreign-alloc :uint8 :count 16384)))
    (unwind-protect
         (loop
           (when (h2-stopping conn)
             (h2-goaway conn)
             (return))
           (h2-resume-dirty conn)
           (let ((flushed (h2-flush conn)))
             (when (or (eq flushed :eof) (and (numberp flushed) (< flushed 0)))
               (return)))
           (when (h2-stopping conn)
             (h2-goaway conn)
             (return))
           ;; want_read is 0 after a peer GOAWAY with no active streams, and
           ;; after our own termination GOAWAY has been written. Leaving
           ;; immediately drops a following PING and RSTs if it is still queued.
           (when (h2-quiescent-p conn)
             ;; A peer GOAWAY makes want_read 0 before a PING written
             ;; immediately after it arrives. Closing then RSTs that PING.
             (unless (h2-drain-pending conn buffer
                                       (if (h2-conn-peer-goaway conn) 250 0))
               (return)))
           (let* ((socket-fd (h2-io-fd (h2-conn-io conn)))
                  (revents (poll-fds (list (list socket-fd (logior +pollin+ +pollout+))
                                           (list (h2-conn-wake conn) +pollin+))
                                     1000))
                  (socket-events (or (first revents) 0))
                  (wake-events (or (second revents) 0)))
             (when (h2-stopping conn)
               (h2-goaway conn)
               (return))
             (when (logtest socket-events (logior +pollnval+ +pollerr+ +pollhup+))
               (when (logtest socket-events +pollin+)
                 (let ((count (h2-read-some (h2-conn-io conn) buffer 16384)))
                   (when (numberp count)
                     (h2-consume-result conn buffer count))))
               (h2-flush conn)
               (return))
             (when (logtest wake-events +pollin+)
               (eventfd-drain (h2-conn-wake conn))
               (h2-resume-dirty conn))
             (when (logtest socket-events +pollin+)
               (let ((count (h2-read-some (h2-conn-io conn) buffer 16384)))
                 (cond ((eq count :eof)
                        (h2-flush conn)
                        (return))
                       ((and (numberp count) (h2-consume-result conn buffer count))
                        (return)))))))
      (when (h2-conn-session conn)
        (ignore-errors (h2-drain-pending conn buffer))
        (ignore-errors (h2-flush conn)))
      (cffi:foreign-free buffer))))

(defun h2-close (conn)
  (when (h2-conn-session conn)
    (nghttp2-session-del (h2-conn-session conn))
    (setf (h2-conn-session conn) nil))
  (when (h2-conn-wake conn)
    (posix-close (h2-conn-wake conn))
    (setf (h2-conn-wake conn) nil))
  (unpin (h2-conn-pin conn))
  (setf (h2-conn-pin conn) nil))

(defun usocket-fd (socket)
  (sb-bsd-sockets:socket-file-descriptor (usocket:socket socket)))

(defun serve-http2 (server socket ssl-stream &key scheme peer)
  "Speak HTTP/2 on SOCKET. SSL-STREAM is the completed TLS stream, or NIL for
cleartext prior knowledge (RFC 9113 §3.3)."
  (let* ((fd (usocket-fd socket))
         (conn (make-h2-conn :server server
                             :io (make-h2-io :fd fd
                                             :ssl (and ssl-stream
                                                       (cl+ssl::ssl-stream-handle ssl-stream)))
                             :scheme scheme
                             :peer peer)))
    (setf (h2-conn-pin conn) (pin conn)
          (h2-conn-wake conn) (make-eventfd))
    (set-tcp-nodelay fd)
    (set-nonblock fd)
    (h2-register conn)
    (unwind-protect
         (handler-case
             (progn
               (h2-open-session conn)
               (h2-submit-settings conn)
               (h2-loop conn))
           (error (condition)
             (format *error-output* "pazuzu: http2: ~a~%" condition)))
      (h2-unregister conn)
      (dolist (stream (alexandria:hash-table-values (h2-conn-streams conn)))
        (when (h2-stream-pipe stream)
          (pipe-shutdown (h2-stream-pipe stream))))
      (h2-close conn))))

(defun preface-matches-p (buffer count)
  (loop for index below count
        always (= (cffi:mem-ref buffer :uint8 index)
                  (aref +h2-preface+ index))))

(defun peeked-request-line (buffer count)
  "The first peeked line, without its CRLF, or NIL when the line is unfinished."
  (loop for index from 0 below (1- count)
        when (and (= (cffi:mem-ref buffer :uint8 index) 13)
                  (= (cffi:mem-ref buffer :uint8 (1+ index)) 10))
          return (babel:octets-to-string (foreign-to-octets buffer index)
                                         :encoding :iso-8859-1)))

(defun http1-request-line-p (line)
  "True when LINE has the request-line shape and an HTTP/x.y version.
A non-token method stays on the HTTP/1 parser, which answers 400. Any
major version stays there too, so HTTP/2.0 in this framing is 505 rather
than an HTTP/2 connection error."
  (let ((first (position #\Space line))
        (last (position #\Space line :from-end t)))
    (and first last (> last first)
         (not (find #\Space line :start (1+ first) :end last))
         (plusp (- last (1+ first)))
         (http-version-token-p (subseq line (1+ last))))))

(defun write-all-fd (fd octets)
  (cffi:with-pointer-to-vector-data (pointer octets)
    (loop with sent = 0
          with spins = 0
          while (and (< sent (length octets)) (< spins 50))
          for n = (%write fd (cffi:inc-pointer pointer sent)
                          (- (length octets) sent))
          do (cond ((plusp n) (incf sent n))
                   ((and (< n 0) (= (errno) +eintr+)) nil)
                   ((and (< n 0) (= (errno) +eagain+))
                    (incf spins)
                    (poll-fds (list (list fd +pollout+)) 200))
                   (t (return sent)))
          finally (return sent))))

(defun drain-fd (fd)
  "Read until the kernel buffer is empty so a later close is not a reset.
MSG_DONTWAIT is required: Linux accept() does not copy O_NONBLOCK onto the
new socket, and a blocking recv here deadlocks with a peer that is reading
the GOAWAY until this side closes."
  (cffi:with-foreign-object (buffer :uint8 4096)
    (loop with spins = 0
          while (< spins 64)
          for n = (%recv fd buffer 4096 +msg-dontwait+)
          do (cond ((plusp n) (incf spins))
                   ((and (< n 0) (= (errno) +eintr+)) nil)
                   (t (return))))))

(defun reject-bad-preface (fd)
  "An invalid connection preface is a connection error of type PROTOCOL_ERROR
(RFC 9113 §3.4). Write GOAWAY and drain the unread bytes before the socket
is closed."
  (write-all-fd fd (load-time-value
                    (coerce #(#x00 #x00 #x08 #x07 #x00
                              #x00 #x00 #x00 #x00
                              #x00 #x00 #x00 #x00
                              #x00 #x00 #x00 #x01)
                            '(simple-array (unsigned-byte 8) (*)))
                    t))
  (drain-fd fd))

(defun preface-kind (fd &key (timeout 5) (running (constantly t)))
  "Classify a cleartext connection without consuming octets.
:h2 is the 24-byte connection preface. :http is a request line whose
version is HTTP/x.y, or an unfinished line that is not a preface prefix.
:reject is a finished line that is not that request line. :idle is a timeout or
a stop before any of those. A strict prefix of the preface, including
\"PRI * HTTP/2.0\" followed by one CRLF, is held until 24 bytes arrive.
The peek is non-blocking. A ready poll with EAGAIN, or a poll that stays
ready without POLLIN, must still observe the deadline."
  (cffi:with-foreign-object (buffer :uint8 256)
    (loop with deadline = (+ (get-internal-real-time)
                             (* timeout internal-time-units-per-second))
          with peek-flags = (logior +msg-peek+ +msg-dontwait+)
          do (unless (funcall running)
               (return :idle))
             (when (> (get-internal-real-time) deadline)
               (return :idle))
             (let ((ready (poll-fds (list (list fd +pollin+)) 200)))
               (when ready
                 (let ((revents (or (first ready) 0)))
                   (cond ((logtest revents +pollnval+)
                          (return :http))
                         ((not (logtest revents +pollin+))
                          (when (logtest revents (logior +pollhup+ +pollerr+))
                            (return :http)))
                         (t
                          (let ((count (%recv fd buffer 256 peek-flags)))
                            (cond ((and (< count 0)
                                        (member (errno) (list +eintr+ +eagain+)))
                                   nil)
                                  ((<= count 0) (return :http))
                                  ((and (>= count 24) (preface-matches-p buffer 24))
                                   (return :h2))
                                  ((and (< count 24) (preface-matches-p buffer count))
                                   nil)
                                  (t
                                   (let ((line (peeked-request-line buffer count)))
                                     (return (cond ((null line) :http)
                                                   ((http1-request-line-p line) :http)
                                                   (t :reject)))))))))))))))
