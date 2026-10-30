(in-package #:pazuzu)

(defun compressible-type-p (content-type)
  (when content-type
    (let ((main (media-type-main content-type)))
      (or (string-equal main "text" :end1 (min 5 (length main)))
          (and (>= (length main) 5) (string-equal main "text/" :end1 5))
          (member main
                  '("application/json" "application/javascript" "text/javascript"
                    "application/xml" "image/svg+xml" "application/xhtml+xml"
                    "text/html" "text/plain" "text/css")
                  :test #'string-equal)))))

(defun parse-accept-encoding (header)
  "Alist of (coding . q). The coding * is kept. identity is not implied by *."
  (loop for item in (split-commas header)
        for parts = (split-parameters item)
        for name = (string-downcase (string-trim '(#\Space #\Tab) (first parts)))
        when (plusp (length name))
          collect (cons name (parse-q (rest parts)))))

(defun coding-quality (clauses name)
  "RFC 9110 §12.5.3. * does not match identity. *;q=0 excludes identity
unless identity itself is listed."
  (let ((explicit (assoc name clauses :test #'string=))
        (star (assoc "*" clauses :test #'string=)))
    (cond (explicit (cdr explicit))
          ((and star (string/= name "identity")) (cdr star))
          ((and (string= name "identity") star (zerop (cdr star))) 0)
          ((string= name "identity") 1)
          (t 0))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (cffi:define-foreign-library libbrotlienc
    (t (:default "libbrotlienc")))
  (cffi:define-foreign-library libbrotlidec
    (t (:default "libbrotlidec")))
  (cffi:define-foreign-library libzstd
    (t (:default "libzstd")))
  (cffi:use-foreign-library libbrotlienc)
  (cffi:use-foreign-library libbrotlidec)
  (cffi:use-foreign-library libzstd))

(cffi:defcfun ("BrotliEncoderMaxCompressedSize" brotli-max-compressed-size
               :library libbrotlienc)
    :unsigned-long
  (input-size :unsigned-long))

(cffi:defcfun ("BrotliEncoderCompress" brotli-encoder-compress :library libbrotlienc)
    :int
  (quality :int)
  (lgwin :int)
  (mode :int)
  (input-size :unsigned-long)
  (input :pointer)
  (encoded-size :pointer)
  (encoded :pointer))

(cffi:defcfun ("BrotliDecoderDecompress" brotli-decoder-decompress :library libbrotlidec)
    :int
  (encoded-size :unsigned-long)
  (encoded :pointer)
  (decoded-size :pointer)
  (decoded :pointer))

(cffi:defcfun ("ZSTD_compressBound" zstd-compress-bound :library libzstd)
    :unsigned-long
  (source-size :unsigned-long))

(cffi:defcfun ("ZSTD_compress" zstd-compress :library libzstd)
    :unsigned-long
  (destination :pointer)
  (capacity :unsigned-long)
  (source :pointer)
  (source-size :unsigned-long)
  (level :int))

(cffi:defcfun ("ZSTD_decompress" zstd-decompress :library libzstd)
    :unsigned-long
  (destination :pointer)
  (capacity :unsigned-long)
  (source :pointer)
  (source-size :unsigned-long))

(cffi:defcfun ("ZSTD_getFrameContentSize" zstd-frame-content-size :library libzstd)
    :uint64
  (source :pointer)
  (source-size :unsigned-long))

(cffi:defcfun ("ZSTD_isError" zstd-error-p :library libzstd)
    :unsigned-int
  (code :unsigned-long))

(cffi:defcfun ("BrotliEncoderCreateInstance" brotli-encoder-create :library libbrotlienc)
    :pointer
  (alloc :pointer) (free :pointer) (opaque :pointer))
(cffi:defcfun ("BrotliEncoderDestroyInstance" brotli-encoder-destroy :library libbrotlienc)
    :void
  (state :pointer))
(cffi:defcfun ("BrotliEncoderSetParameter" brotli-encoder-set-parameter :library libbrotlienc)
    :int
  (state :pointer) (param :int) (value :uint32))
(cffi:defcfun ("BrotliEncoderCompressStream" brotli-encoder-compress-stream :library libbrotlienc)
    :int
  (state :pointer) (op :int)
  (available-in :pointer) (next-in :pointer)
  (available-out :pointer) (next-out :pointer)
  (total-out :pointer))
(cffi:defcfun ("BrotliEncoderIsFinished" brotli-encoder-finished :library libbrotlienc)
    :int
  (state :pointer))

(cffi:defcstruct zstd-in-buffer
  (src :pointer)
  (size :unsigned-long)
  (pos :unsigned-long))

(cffi:defcstruct zstd-out-buffer
  (dst :pointer)
  (size :unsigned-long)
  (pos :unsigned-long))

(cffi:defcfun ("ZSTD_createCCtx" zstd-create-cctx :library libzstd) :pointer)
(cffi:defcfun ("ZSTD_freeCCtx" zstd-free-cctx :library libzstd) :unsigned-long
  (ctx :pointer))
(cffi:defcfun ("ZSTD_CCtx_setParameter" zstd-cctx-set-parameter :library libzstd)
    :unsigned-long
  (ctx :pointer) (param :int) (value :int))
(cffi:defcfun ("ZSTD_compressStream2" zstd-compress-stream2 :library libzstd)
    :unsigned-long
  (ctx :pointer) (output :pointer) (input :pointer) (directive :int))

(defconstant +zstd-contentsize-unknown+ (1- (ash 1 64)))
(defconstant +zstd-contentsize-error+ (- (ash 1 64) 2))

(defun choose-content-coding (request content-type body-length &key prefer-identity)
  "Return br, zstd, gzip, deflate, identity, or :none.
On equal quality above zero, br wins, then zstd, gzip, and deflate.
A range request keeps identity when that representation is acceptable."
  (let ((header (header-list-value (request-headers request) "accept-encoding")))
    (unless (and header (compressible-type-p content-type) (plusp body-length))
      (return-from choose-content-coding 'identity))
    (let* ((clauses (parse-accept-encoding header))
           (identity-q (coding-quality clauses "identity")))
      (when prefer-identity
        (return-from choose-content-coding
          (if (> identity-q 0) 'identity :none)))
      (let ((best nil)
            (best-q -1))
        (dolist (candidate '((br "br") (zstd "zstd") (gzip "gzip")
                             (deflate "deflate") (identity "identity")))
          (let ((quality (coding-quality clauses (second candidate))))
            (when (> quality best-q)
              (setf best (first candidate)
                    best-q quality))))
        (if (> best-q 0) best :none)))))

(defun brotli-encode (octets)
  (let* ((input (simple-octets octets))
         (bound (brotli-max-compressed-size (length input)))
         (output (make-array bound :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (input-pointer input)
      (cffi:with-pointer-to-vector-data (output-pointer output)
        (cffi:with-foreign-object (encoded-size :unsigned-long)
          (setf (cffi:mem-ref encoded-size :unsigned-long) bound)
          (unless (= 1 (brotli-encoder-compress 5 22 0 (length input)
                                                input-pointer encoded-size
                                                output-pointer))
            (error "brotli encode failed"))
          (subseq output 0 (cffi:mem-ref encoded-size :unsigned-long)))))))

(defun zstd-encode (octets)
  (let* ((input (simple-octets octets))
         (bound (zstd-compress-bound (length input)))
         (output (make-array bound :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (input-pointer input)
      (cffi:with-pointer-to-vector-data (output-pointer output)
        (let ((produced (zstd-compress output-pointer bound input-pointer
                                       (length input) 3)))
          (when (plusp (zstd-error-p produced))
            (error "zstd encode failed"))
          (subseq output 0 produced))))))

(defun encode-body (octets coding)
  (ecase coding
    (identity octets)
    (gzip (salza2:compress-data (simple-octets octets) 'salza2:gzip-compressor))
    (deflate (salza2:compress-data (simple-octets octets) 'salza2:zlib-compressor))
    (br (brotli-encode octets))
    (zstd (zstd-encode octets))))

(defun concat-encoded-chunks (chunks size)
  (let ((out (make-array size :element-type '(unsigned-byte 8)))
        (start 0))
    (dolist (chunk (nreverse chunks))
      (replace out chunk :start1 start)
      (incf start (length chunk)))
    out))

(defun salza-encode-file (file designator)
  "Gzip or deflate FILE one chunk at a time. The callback is installed
after MAKE-INSTANCE, which is when salza2 will flush the header."
  (let ((chunks nil)
        (size 0)
        (compressor (make-instance designator)))
    (setf (salza2:callback compressor)
          (lambda (buffer end)
            (incf size end)
            (push (subseq buffer 0 end) chunks)))
    (call-with-file-chunks file
                           (lambda (chunk)
                             (salza2:compress-octet-vector chunk compressor)))
    (salza2:finish-compression compressor)
    (concat-encoded-chunks chunks size)))

(defun brotli-encode-file (file)
  "Same quality and window as BROTLI-ENCODE. Input is read in chunks."
  (let ((state (brotli-encoder-create (cffi:null-pointer) (cffi:null-pointer)
                                      (cffi:null-pointer)))
        (chunks nil)
        (size 0))
    (when (or (null state) (cffi:null-pointer-p state))
      (error "brotli encode failed"))
    (unwind-protect
         (progn
           ;; BROTLI_PARAM_QUALITY is 1 and BROTLI_PARAM_LGWIN is 2.
           (unless (and (= 1 (brotli-encoder-set-parameter state 1 5))
                        (= 1 (brotli-encoder-set-parameter state 2 22)))
             (error "brotli encode failed"))
           (cffi:with-foreign-objects ((avail-in :unsigned-long)
                                       (next-in :pointer)
                                       (avail-out :unsigned-long)
                                       (next-out :pointer)
                                       (total :unsigned-long))
             (setf (cffi:mem-ref total :unsigned-long) 0)
             (let ((outbuf (make-array 65536 :element-type '(unsigned-byte 8))))
               (cffi:with-pointer-to-vector-data (outptr outbuf)
                 (labels ((take-output ()
                            (let ((produced (- (length outbuf)
                                               (cffi:mem-ref avail-out :unsigned-long))))
                              (when (plusp produced)
                                (incf size produced)
                                (push (subseq outbuf 0 produced) chunks))))
                          (pump (op)
                            (loop
                              (setf (cffi:mem-ref avail-out :unsigned-long) (length outbuf)
                                    (cffi:mem-ref next-out :pointer) outptr)
                              (unless (= 1 (brotli-encoder-compress-stream
                                            state op avail-in next-in
                                            avail-out next-out total))
                                (error "brotli encode failed"))
                              (take-output)
                              (when (and (zerop (cffi:mem-ref avail-in :unsigned-long))
                                         (or (/= op 2)
                                             (= 1 (brotli-encoder-finished state))))
                                (return)))))
                   (call-with-file-chunks
                    file
                    (lambda (chunk)
                      (cffi:with-pointer-to-vector-data (inptr chunk)
                        (setf (cffi:mem-ref avail-in :unsigned-long) (length chunk)
                              (cffi:mem-ref next-in :pointer) inptr)
                        ;; BROTLI_OPERATION_PROCESS
                        (pump 0))))
                   (setf (cffi:mem-ref avail-in :unsigned-long) 0
                         (cffi:mem-ref next-in :pointer) (cffi:null-pointer))
                   ;; BROTLI_OPERATION_FINISH
                   (pump 2)))))
           (concat-encoded-chunks chunks size))
      (brotli-encoder-destroy state))))

(defun zstd-encode-file (file)
  "Level 3, matching ZSTD-ENCODE. Input is read in chunks."
  (let ((ctx (zstd-create-cctx))
        (chunks nil)
        (size 0))
    (when (or (null ctx) (cffi:null-pointer-p ctx))
      (error "zstd encode failed"))
    (unwind-protect
         (progn
           ;; ZSTD_c_compressionLevel is 100.
           (let ((set (zstd-cctx-set-parameter ctx 100 3)))
             (when (plusp (zstd-error-p set))
               (error "zstd encode failed")))
           (cffi:with-foreign-objects ((in '(:struct zstd-in-buffer))
                                       (out '(:struct zstd-out-buffer)))
             (let ((outbuf (make-array 65536 :element-type '(unsigned-byte 8))))
               (cffi:with-pointer-to-vector-data (outptr outbuf)
                 (setf (cffi:foreign-slot-value out '(:struct zstd-out-buffer) 'dst) outptr
                       (cffi:foreign-slot-value out '(:struct zstd-out-buffer) 'size)
                       (length outbuf))
                 (labels ((emit (directive)
                            (setf (cffi:foreign-slot-value out '(:struct zstd-out-buffer) 'pos) 0)
                            (let ((ret (zstd-compress-stream2 ctx out in directive)))
                              (when (plusp (zstd-error-p ret))
                                (error "zstd encode failed"))
                              (let ((produced (cffi:foreign-slot-value
                                               out '(:struct zstd-out-buffer) 'pos)))
                                (when (plusp produced)
                                  (incf size produced)
                                  (push (subseq outbuf 0 produced) chunks)))
                              ret)))
                   (call-with-file-chunks
                    file
                    (lambda (chunk)
                      (cffi:with-pointer-to-vector-data (inptr chunk)
                        (setf (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'src) inptr
                              (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'size)
                              (length chunk)
                              (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'pos) 0)
                        ;; ZSTD_e_continue. Stop once this chunk is consumed.
                        (loop while (< (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'pos)
                                       (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'size))
                              do (emit 0)))))
                   (setf (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'src)
                         (cffi:null-pointer)
                         (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'size) 0
                         (cffi:foreign-slot-value in '(:struct zstd-in-buffer) 'pos) 0)
                   ;; ZSTD_e_end
                   (loop until (zerop (emit 2)))))))
           (concat-encoded-chunks chunks size))
      (zstd-free-cctx ctx))))

(defun encode-file-body (file coding)
  "Content-coding of a file span. The uncompressed bytes are not held
all at once. The compressed result is one vector because Content-Length
and the strong validator are the encoded representation."
  (ecase coding
    (gzip (salza-encode-file file 'salza2:gzip-compressor))
    (deflate (salza-encode-file file 'salza2:zlib-compressor))
    (br (brotli-encode-file file))
    (zstd (zstd-encode-file file))))

(defun content-coding-kind (coding)
  "The coding this origin can remove, or NIL when it is not implemented.
RFC 9110 §8.4. An empty token is identity. x-gzip is gzip."
  (let ((name (string-downcase (string-trim '(#\Space #\Tab) coding))))
    (cond ((or (string= name "") (string= name "identity")) :identity)
          ((string= name "br") :br)
          ((string= name "zstd") :zstd)
          ((string= name "deflate") :deflate)
          ((or (string= name "gzip") (string= name "x-gzip")) :gzip)
          (t nil))))

(defun supported-content-codings ()
  "Codings this origin can remove, in the order a response lists them."
  "gzip, deflate, br, zstd")

(defun unsupported-coding-response ()
  "RFC 9110 §12.5.3. A 415 caused by a content-coding lists the codings
this origin can remove. identity stays acceptable because it is not
excluded, so it is not named here."
  (make-response :status 415
                 :content-type "text/plain; charset=utf-8"
                 :headers `(("accept-encoding" . ,(supported-content-codings)))
                 :body (reason-phrase 415)))

(defun protocol-error-response (condition)
  "The response for CONDITION. Only a content-coding 415 carries
Accept-Encoding (RFC 9110 §12.5.3)."
  (if (and (= (protocol-error-status condition) 415)
           (equal (protocol-error-detail condition) "content-encoding"))
      (unsupported-coding-response)
      (make-response :status (protocol-error-status condition)
                     :content-type "text/plain; charset=utf-8"
                     :body (reason-phrase (protocol-error-status condition)))))

(defun decode-content-encoding (octets coding max-body)
  (let ((kind (content-coding-kind coding)))
    (case kind
      (:identity octets)
      (:br (brotli-decode octets max-body))
      (:zstd (zstd-decode octets max-body))
      ((:gzip :deflate)
       (handler-case
           (let ((out (make-array (1+ max-body) :element-type '(unsigned-byte 8))))
             (multiple-value-bind (consumed produced)
                 (chipz:decompress out (if (eq kind :deflate) 'chipz:zlib 'chipz:gzip)
                                   (simple-octets octets))
               (declare (ignore consumed))
               (when (> produced max-body)
                 (protocol-error 413 :detail "decompressed body"))
               (subseq out 0 produced)))
         (protocol-error (condition) (error condition))
         (error () (protocol-error 400 :detail "content-encoding"))))
      (t (protocol-error 415 :detail "content-encoding")))))

(defun brotli-decode (octets max-body)
  (let* ((input (simple-octets octets))
         (capacity (1+ max-body))
         (output (make-array capacity :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (input-pointer input)
      (cffi:with-pointer-to-vector-data (output-pointer output)
        (cffi:with-foreign-object (decoded-size :unsigned-long)
          (setf (cffi:mem-ref decoded-size :unsigned-long) capacity)
          (let ((result (brotli-decoder-decompress (length input) input-pointer
                                                   decoded-size output-pointer)))
            (cond ((= result 3) (protocol-error 413 :detail "decompressed body"))
                  ((= result 1)
                   (let ((produced (cffi:mem-ref decoded-size :unsigned-long)))
                     (when (> produced max-body)
                       (protocol-error 413 :detail "decompressed body"))
                     (subseq output 0 produced)))
                  (t (protocol-error 400 :detail "content-encoding")))))))))

(defun zstd-decode (octets max-body)
  (let* ((input (simple-octets octets))
         (capacity (1+ max-body))
         (output (make-array capacity :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (input-pointer input)
      (cffi:with-pointer-to-vector-data (output-pointer output)
        (let ((declared (zstd-frame-content-size input-pointer (length input))))
          (when (and (/= declared +zstd-contentsize-unknown+)
                     (/= declared +zstd-contentsize-error+)
                     (> declared max-body))
            (protocol-error 413 :detail "decompressed body"))
          (let ((produced (zstd-decompress output-pointer capacity input-pointer
                                           (length input))))
            (when (plusp (zstd-error-p produced))
              (protocol-error 400 :detail "content-encoding"))
            (when (> produced max-body)
              (protocol-error 413 :detail "decompressed body"))
            (subseq output 0 produced)))))))
