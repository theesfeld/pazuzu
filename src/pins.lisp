(in-package #:pazuzu)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))

(cffi:define-foreign-library libnghttp2
  (t (:default "libnghttp2")))

(cffi:define-foreign-library libngtcp2
  (t (:default "libngtcp2")))

(cffi:define-foreign-library libngtcp2-crypto
  (t (:default "libngtcp2_crypto_ossl")))

(cffi:define-foreign-library libnghttp3
  (t (:default "libnghttp3")))

(cffi:use-foreign-library libnghttp2)
(cffi:use-foreign-library libngtcp2)
(cffi:use-foreign-library libngtcp2-crypto)
(cffi:use-foreign-library libnghttp3)

(defvar *pin-lock* (bt:make-lock "pazuzu-pins"))
(defvar *pins* (make-hash-table :test #'eql))
(defvar *next-pin* 0)

(defun pin (object)
  (bt:with-lock-held (*pin-lock*)
    (let ((id (incf *next-pin*)))
      (setf (gethash id *pins*) object)
      id)))

(defun unpin (id)
  (when id
    (bt:with-lock-held (*pin-lock*)
      (remhash id *pins*))))

(defun pinned (id)
  (bt:with-lock-held (*pin-lock*)
    (gethash id *pins*)))

(defun pin-pointer (object)
  (cffi:make-pointer (pin object)))

(defun pointer-pin (pointer)
  (when (and pointer (not (cffi:null-pointer-p pointer)))
    (pinned (cffi:pointer-address pointer))))

(cffi:defcfun ("memset" %memset) :pointer
  (destination :pointer)
  (byte :int)
  (count :unsigned-long))

(defun foreign-zero (pointer size)
  (%memset pointer 0 size))

(cffi:defcfun ("__errno_location" %errno-location) :pointer)

(defun errno ()
  (cffi:mem-ref (%errno-location) :int))

(defconstant +eagain+ 11)
(defconstant +eintr+ 4)

(cffi:defcfun ("read" %read) :long
  (fd :int)
  (buffer :pointer)
  (count :unsigned-long))

(cffi:defcfun ("write" %write) :long
  (fd :int)
  (buffer :pointer)
  (count :unsigned-long))

(cffi:defcfun ("recv" %recv) :long
  (fd :int)
  (buffer :pointer)
  (length :unsigned-long)
  (flags :int))

(cffi:defcfun ("close" posix-close) :int
  (fd :int))

(cffi:defcfun ("fcntl" %fcntl) :int
  (fd :int)
  (command :int)
  (argument :int))

(cffi:defcfun ("setsockopt" %setsockopt) :int
  (fd :int)
  (level :int)
  (name :int)
  (value :pointer)
  (length :unsigned-int))

(cffi:defcfun ("getsockopt" %getsockopt) :int
  (fd :int)
  (level :int)
  (name :int)
  (value :pointer)
  (length :pointer))

(cffi:defcfun ("eventfd" %eventfd) :int
  (initial :unsigned-int)
  (flags :int))

(cffi:defcfun ("poll" %poll) :int
  (fds :pointer)
  (count :unsigned-long)
  (timeout-ms :int))

(cffi:defcfun ("clock_gettime" %clock-gettime) :int
  (clock :int)
  (timespec :pointer))

(defconstant +pollin+ 1)
(defconstant +pollout+ 4)
(defconstant +pollerr+ 8)
(defconstant +pollhup+ 16)
(defconstant +pollnval+ 32)
(defconstant +msg-peek+ 2)
(defconstant +msg-dontwait+ #x40)
(defconstant +o-nonblock+ 2048)
(defconstant +efd-cloexec-nonblock+ #x80800)

(defun set-nonblock (fd)
  (let ((flags (%fcntl fd 3 0)))
    (when (>= flags 0)
      (%fcntl fd 4 (logior flags +o-nonblock+)))))

(defun set-blocking (fd)
  "Clear O_NONBLOCK. accept(2) on Linux does not copy the listener's flags,
and a blocking read is what the HTTP/1.1 parser waits on."
  (let ((flags (%fcntl fd 3 0)))
    (when (>= flags 0)
      (%fcntl fd 4 (logand flags (lognot +o-nonblock+))))))

(defun set-tcp-nodelay (fd)
  (cffi:with-foreign-object (value :int)
    (setf (cffi:mem-ref value :int) 1)
    (%setsockopt fd 6 1 value (cffi:foreign-type-size :int))))

(defun set-udp-dont-fragment (fd ipv6)
  "RFC 9000 §14. QUIC datagrams are not fragmented. An IPv4 socket always
sets the DF bit. An IPv6 socket prohibits fragmentation."
  (cffi:with-foreign-object (value :int)
    (let ((size (cffi:foreign-type-size :int)))
      (unless (if ipv6
                  (and (progn
                         (setf (cffi:mem-ref value :int) 1)
                         (zerop (%setsockopt fd 41 62 value size)))
                       (progn
                         (setf (cffi:mem-ref value :int) 2)
                         (zerop (%setsockopt fd 41 23 value size))))
                  (progn
                    (setf (cffi:mem-ref value :int) 2)
                    (zerop (%setsockopt fd 0 10 value size))))
        (error "could not disable IP fragmentation")))))

(cffi:defcfun ("sendmsg" %sendmsg) :long
  (fd :int)
  (message :pointer)
  (flags :int))

(cffi:defcfun ("recvmsg" %recvmsg) :long
  (fd :int)
  (message :pointer)
  (flags :int))

(defun set-udp-recv-ecn (fd ipv6)
  "RFC 9000 §13.4. Ask the kernel for the received TOS or traffic class
on each datagram. IP_RECVTOS is 13. IPV6_RECVTCLASS is 66."
  (cffi:with-foreign-object (value :int)
    (setf (cffi:mem-ref value :int) 1)
    (zerop (%setsockopt fd
                        (if ipv6 41 0)
                        (if ipv6 66 13)
                        value
                        (cffi:foreign-type-size :int)))))

(defun control-ecn (control length ipv6)
  "The ECN codepoint from one recvmsg control buffer, or 0."
  (let ((offset 0)
        (ecn 0))
    (loop while (and (< offset length) (>= (- length offset) 16))
          for cmsg-len = (cffi:mem-ref control :unsigned-long offset)
          while (and (>= cmsg-len 16) (<= (+ offset cmsg-len) length))
          do (when (and (>= cmsg-len 20)
                        (if ipv6
                            (and (= (cffi:mem-ref control :int (+ offset 8)) 41)
                                 (= (cffi:mem-ref control :int (+ offset 12)) 67))
                            (and (= (cffi:mem-ref control :int (+ offset 8)) 0)
                                 (= (cffi:mem-ref control :int (+ offset 12)) 1))))
               (setf ecn (logand (cffi:mem-ref control :uint8 (+ offset 16)) 3)))
             (let ((step (logand (+ cmsg-len 7) (lognot 7))))
               (when (zerop step)
                 (return))
               (incf offset step)))
    ecn))

(defun udp-sendmsg (fd host port buffer length ecn)
  "Send one datagram. ECN is the two-bit codepoint. Zero sends NOT_ECT and
attaches no traffic-class message, so a previous datagram cannot stick."
  (cffi:with-foreign-objects ((message :uint8 56)
                              (iov :uint8 16)
                              (name :uint8 28)
                              (control :uint8 32))
    (foreign-zero message 56)
    (foreign-zero control 32)
    (let ((namelen (fill-sockaddr name host port))
          (ipv6 (ipv6-host-p host))
          (mark (logand ecn 3)))
      (setf (cffi:mem-ref iov :pointer) buffer
            (cffi:mem-ref iov :unsigned-long 8) length
            (cffi:mem-ref message :pointer) name
            (cffi:mem-ref message :unsigned-int 8) namelen
            (cffi:mem-ref message :pointer 16) iov
            (cffi:mem-ref message :unsigned-long 24) 1)
      (when (plusp mark)
        (setf (cffi:mem-ref control :unsigned-long) 20
              (cffi:mem-ref control :int 8) (if ipv6 41 0)
              (cffi:mem-ref control :int 12) (if ipv6 67 1)
              (cffi:mem-ref control :int 16) mark
              (cffi:mem-ref message :pointer 32) control
              (cffi:mem-ref message :unsigned-long 40) 24))
      (let ((n (%sendmsg fd message +msg-dontwait+)))
        (cond ((>= n 0) n)
              ((member (errno) (list +eagain+ +eintr+)) nil)
              (t nil))))))

(defun udp-recvmsg (fd buffer ipv6)
  "Read one datagram into BUFFER. Return BUFFER, length, host octets, port,
and the ECN codepoint. NIL on EAGAIN or EINTR."
  (cffi:with-foreign-objects ((message :uint8 56)
                              (iov :uint8 16)
                              (name :uint8 28)
                              (control :uint8 32))
    (foreign-zero message 56)
    (foreign-zero name 28)
    (foreign-zero control 32)
    (cffi:with-pointer-to-vector-data (pointer buffer)
      (setf (cffi:mem-ref iov :pointer) pointer
            (cffi:mem-ref iov :unsigned-long 8) (length buffer)
            (cffi:mem-ref message :pointer) name
            (cffi:mem-ref message :unsigned-int 8) 28
            (cffi:mem-ref message :pointer 16) iov
            (cffi:mem-ref message :unsigned-long 24) 1
            (cffi:mem-ref message :pointer 32) control
            (cffi:mem-ref message :unsigned-long 40) 32)
      (let ((n (%recvmsg fd message +msg-dontwait+)))
        (cond ((> n 0)
               (let* ((family (cffi:mem-ref name :uint16))
                      (port (logior (ash (cffi:mem-ref name :uint8 2) 8)
                                    (cffi:mem-ref name :uint8 3)))
                      (host (case family
                              (2 (foreign-to-octets (cffi:inc-pointer name 4) 4))
                              (10 (foreign-to-octets (cffi:inc-pointer name 8) 16))))
                      (used (cffi:mem-ref message :unsigned-long 40)))
                 (when host
                   (values buffer n host port
                           (control-ecn control (min 32 (max 0 used)) ipv6)))))
              ((member (errno) (list +eagain+ +eintr+)) nil)
              (t (error "recvmsg failed")))))))

(defun monotonic-ns ()
  (cffi:with-foreign-object (timespec :uint8 16)
    (%clock-gettime 1 timespec)
    (+ (* (cffi:mem-ref timespec :long) 1000000000)
       (cffi:mem-ref timespec :long 8))))

(defun make-eventfd ()
  (let ((fd (%eventfd 0 +efd-cloexec-nonblock+)))
    (when (< fd 0)
      (error "eventfd failed"))
    fd))

(defun eventfd-write (fd)
  (when (and fd (>= fd 0))
    (cffi:with-foreign-object (value :uint64)
      (setf (cffi:mem-ref value :uint64) 1)
      (%write fd value 8))))

(defun eventfd-drain (fd)
  (cffi:with-foreign-object (value :uint64)
    (loop for n = (%read fd value 8)
          while (> n 0))))

(defun set-pollfd (base index fd events)
  (let ((slot (cffi:inc-pointer base (* index 8))))
    (setf (cffi:mem-ref slot :int) fd
          (cffi:mem-ref slot :short 4) events
          (cffi:mem-ref slot :short 6) 0)))

(defun pollfd-revents (base index)
  (cffi:mem-ref (cffi:inc-pointer base (+ (* index 8) 6)) :short))

(defun poll-fds (fd-events timeout-ms)
  "FD-EVENTS is a list of (fd events). Return the revents list, or NIL on timeout."
  (let ((count (length fd-events)))
    (cffi:with-foreign-object (fds :uint8 (* count 8))
      (loop for (fd events) in fd-events
            for index from 0
            do (set-pollfd fds index fd events))
      (let ((ready (%poll fds count timeout-ms)))
        (cond ((zerop ready) nil)
              ((< ready 0)
               (if (= (errno) +eintr+)
                   nil
                   (error "poll failed")))
              (t (loop for index below count
                       collect (pollfd-revents fds index))))))))

(defun foreign-to-octets (pointer length)
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (loop for index below length
          do (setf (aref out index) (cffi:mem-ref pointer :uint8 index)))
    out))

(defun octets-to-foreign (octets pointer)
  (loop for byte across octets
        for index from 0
        do (setf (cffi:mem-ref pointer :uint8 index) byte)))

(defun native-version (function-name library expected label)
  (cffi:load-foreign-library library)
  (let ((symbol (cffi:foreign-symbol-pointer function-name :library library)))
    (unless symbol
      (error "~a is not available" label))
    (let ((info (cffi:foreign-funcall-pointer symbol () :int 0 :pointer)))
      (when (cffi:null-pointer-p info)
        (error "~a is not available" label))
      (let ((number (cffi:mem-ref info :int 4)))
        (unless (= number expected)
          (error "~a version #x~(~x~) does not match the ABI this server was built against (#x~(~x~))."
                 label number expected))))))

(defvar *pazuzu-trace* nil)

(defun pazuzu-trace (format-string &rest args)
  (when *pazuzu-trace*
    (apply #'format *error-output* format-string args)
    (terpri *error-output*)
    (finish-output *error-output*)))
