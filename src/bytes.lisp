(in-package #:pazuzu)

(defun write-ascii (stream string)
  (loop for character across string
        for code = (char-code character)
        do (if (< code 128)
               (write-byte code stream)
               (error "Non-ASCII octet in a protocol element: ~s" character))))

(defun write-crlf (stream)
  (write-byte 13 stream)
  (write-byte 10 stream))

(defun ascii-octets (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defun latin1-string (octets)
  (babel:octets-to-string octets :encoding :iso-8859-1))

(defun utf8-octets (string)
  (babel:string-to-octets string :encoding :utf-8))

(defun simple-octets (sequence)
  (if (typep sequence '(simple-array (unsigned-byte 8) (*)))
      sequence
      (coerce sequence '(simple-array (unsigned-byte 8) (*)))))

(defvar *saw-request-octet* nil
  "Set when a request read consumes an octet. Idle timeouts stay quiet.")

(defvar *read-ahead* nil
  "Per-connection header buffer. SERVE-STREAM binds it. Writes stay on the
socket stream, so this does not sit on the response path.")

(defstruct read-ahead
  (buffer (make-array 8192 :element-type '(unsigned-byte 8)))
  (start 0)
  (end 0))

(defun socket-write-fd (stream)
  "File descriptor of a cleartext socket stream, or NIL.
A TLS stream is not a bare fd-stream, and sendfile cannot write it."
  (when (typep stream 'sb-sys:fd-stream)
    (sb-sys:fd-stream-fd stream)))

(defun fill-read-ahead (stream)
  "Pull octets the inner stream can return without waiting for a full buffer.
read-sequence on a socket blocks until the destination is full, which stalls
a short header. The first read-byte waits for one octet. listen is then true
only for octets already buffered, and the loop stops before the next wait.
Return NIL at EOF."
  (let* ((ahead *read-ahead*)
         (buffer (read-ahead-buffer ahead))
         (first (read-byte stream nil :eof)))
    (when (eq first :eof)
      (setf (read-ahead-start ahead) 0
            (read-ahead-end ahead) 0)
      (return-from fill-read-ahead nil))
    (setf (aref buffer 0) first)
    (let ((end 1))
      (loop while (and (< end (length buffer)) (listen stream))
            for byte = (read-byte stream nil :eof)
            until (eq byte :eof)
            do (setf (aref buffer end) byte)
               (incf end))
      (setf (read-ahead-start ahead) 0
            (read-ahead-end ahead) end))
    t))

(defun read-byte-eof (stream)
  (let ((ahead *read-ahead*))
    (when ahead
      (when (>= (read-ahead-start ahead) (read-ahead-end ahead))
        (unless (fill-read-ahead stream)
          (return-from read-byte-eof :eof)))
      (setf *saw-request-octet* t)
      (return-from read-byte-eof
        (prog1 (aref (read-ahead-buffer ahead) (read-ahead-start ahead))
          (incf (read-ahead-start ahead))))))
  (let ((byte (read-byte stream nil :eof)))
    (unless (eq byte :eof)
      (setf *saw-request-octet* t))
    byte))

(defun read-crlf-line (stream max-length &key on-too-long)
  "Read one CRLF-terminated line. Bare LF and bare CR are rejected.
A clean EOF before any octet of the line signals end-of-request.
ON-TOO-LONG is the status used when the line exceeds MAX-LENGTH."
  (let ((buffer (make-array 128 :element-type '(unsigned-byte 8)
                                :adjustable t :fill-pointer 0))
        (saw-octet nil))
    (loop for byte = (read-byte-eof stream)
          do (cond
               ((eq byte :eof)
                (if saw-octet
                    (protocol-error 400 :detail "truncated line")
                    (error 'end-of-request)))
               ((= byte 10)
                (protocol-error 400 :detail "bare LF"))
               ((= byte 13)
                (let ((next (read-byte-eof stream)))
                  (unless (eql next 10)
                    (protocol-error 400 :detail "bare CR"))
                  (return (latin1-string buffer))))
               (t
                (setf saw-octet t)
                (when (>= (fill-pointer buffer) max-length)
                  (protocol-error (or on-too-long 400) :detail "line too long"))
                (vector-push-extend byte buffer))))))

(defun read-exact (stream count)
  (let ((buffer (make-array count :element-type '(unsigned-byte 8)))
        (got 0)
        (ahead *read-ahead*))
    (when (and ahead (< (read-ahead-start ahead) (read-ahead-end ahead)))
      (let ((take (min count (- (read-ahead-end ahead) (read-ahead-start ahead)))))
        (replace buffer (read-ahead-buffer ahead)
                 :start1 0 :end1 take
                 :start2 (read-ahead-start ahead))
        (incf (read-ahead-start ahead) take)
        (setf got take)
        (setf *saw-request-octet* t)))
    (loop while (< got count)
          for next = (read-sequence buffer stream :start got)
          do (when (= next got)
               (protocol-error 400 :detail "truncated body"))
             (setf got next)
             (setf *saw-request-octet* t))
    buffer))

(defun append-octets (buffer more)
  (let ((start (fill-pointer buffer)))
    (when (> (+ start (length more)) (array-total-size buffer))
      (adjust-array buffer (max 16 (+ start (length more) (floor (length more) 2)))))
    (incf (fill-pointer buffer) (length more))
    (replace buffer more :start1 start)
    buffer))

(defun token-char-p (character)
  "RFC 9110 §5.6.2. tchar is ASCII ALPHA, DIGIT, or one of !#$%&'*+-.^_`|~."
  (let ((code (char-code character)))
    (or (<= 48 code 57)
        (<= 65 code 90)
        (<= 97 code 122)
        (find character "!#$%&'*+-.^_`|~" :test #'char=))))

(defun token-string-p (string)
  (and (plusp (length string))
       (every #'token-char-p string)))

(defun scheme-char-p (character first)
  "RFC 3986 §3.1. A scheme starts with ALPHA. Later octets may be
DIGIT or one of + - ."
  (let ((code (char-code character)))
    (or (<= 65 code 90)
        (<= 97 code 122)
        (and (not first)
             (or (<= 48 code 57)
                 (eql character #\+)
                 (eql character #\-)
                 (eql character #\.))))))

(defun scheme-string-p (string)
  (and (stringp string)
       (plusp (length string))
       (scheme-char-p (char string 0) t)
       (loop for index from 1 below (length string)
             always (scheme-char-p (char string index) nil))))

(defconstant +max-request-line+ 8000)
(defconstant +max-header-bytes+ 65536)
(defconstant +max-header-fields+ 100)
