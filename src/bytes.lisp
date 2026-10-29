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

(defun read-byte-eof (stream)
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
  (let ((buffer (make-array count :element-type '(unsigned-byte 8))))
    (loop for got = 0 then next
          while (< got count)
          for next = (read-sequence buffer stream :start got)
          do (when (= next got)
               (protocol-error 400 :detail "truncated body")))
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
