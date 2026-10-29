(in-package #:pazuzu)

(defstruct representation
  content-type
  language
  body
  etag
  last-modified)

(defun etag-opaque (tag)
  "Return the quoted opaque tag, dropping a weak W/ prefix.
The prefix is case-sensitive (RFC 9110 §8.8.3)."
  (let ((text (string-trim '(#\Space #\Tab) tag)))
    (when (and (>= (length text) 2)
               (char= (char text 0) #\W)
               (char= (char text 1) #\/))
      (setf text (string-trim '(#\Space #\Tab) (subseq text 2))))
    (when (and (>= (length text) 2)
               (char= (char text 0) #\")
               (char= (char text (1- (length text))) #\"))
      text)))

(defun etag-weak-p (tag)
  (let ((text (string-trim '(#\Space #\Tab) tag)))
    (and (>= (length text) 2)
         (char= (char text 0) #\W)
         (char= (char text 1) #\/))))

(defun etags-match-p (left right &key weak)
  (let ((a (etag-opaque left))
        (b (etag-opaque right)))
    (and a b
         (string= a b)
         (or weak (not (or (etag-weak-p left) (etag-weak-p right)))))))

(defun split-etag-list (value)
  "RFC 9110 §8.8.3. A comma inside the quoted opaque-tag is part of the tag.
A backslash is an etagc, not a quoted-pair."
  (when (string-equal (string-trim '(#\Space #\Tab) value) "*")
    (return-from split-etag-list :any))
  (let ((tags (split-list-elements value :escape nil)))
    (when (some (lambda (tag) (string= tag "*")) tags)
      (protocol-error 400 :detail "invalid etag list"))
    tags))

(defun precondition-failure (status)
  (make-response :status status
                 :content-type "text/plain; charset=utf-8"
                 :body (reason-phrase status)))

(defun evaluate-preconditions (request &key etag last-modified (has-representation t))
  "Apply RFC 9110 §13.2.2. Return NIL when the method may proceed, or a
304/412 response when it must not. HAS-REPRESENTATION is true when the
origin has a current representation for the target."
  (let* ((method (request-method request))
         (headers (request-headers request))
         (if-match (header-list-value headers "if-match"))
         (if-unmodified (single-date-field headers "if-unmodified-since"))
         (if-none (header-list-value headers "if-none-match"))
         (if-modified (single-date-field headers "if-modified-since"))
         (safe (or (string= method "GET") (string= method "HEAD"))))
    (labels ((match-list (value weak)
               (let ((tags (split-etag-list value)))
                 (cond ((eq tags :any) has-representation)
                       ((null etag) nil)
                       (t (some (lambda (tag)
                                  (etags-match-p tag etag :weak weak))
                                tags))))))
      ;; RFC 9110 §13.2.1. CONNECT, OPTIONS, and TRACE do not select or
      ;; modify a representation, so their conditionals are ignored.
      (when (member method '("OPTIONS" "CONNECT" "TRACE") :test #'string=)
        (return-from evaluate-preconditions nil))
      (when if-match
        (let ((ok (match-list if-match nil)))
          (unless ok
            (return-from evaluate-preconditions (precondition-failure 412)))))
      (when (and (null if-match) if-unmodified)
        (let ((stamp (parse-http-date if-unmodified)))
          (when (and stamp last-modified (> last-modified stamp))
            (return-from evaluate-preconditions (precondition-failure 412)))))
      (when if-none
        (let ((matched (match-list if-none t)))
          (when matched
            (return-from evaluate-preconditions
              (if safe
                  (make-response :status 304 :etag etag :last-modified last-modified :body nil)
                  (precondition-failure 412))))))
      (when (and safe (null if-none) if-modified last-modified)
        (let ((stamp (parse-http-date if-modified)))
          (when (and stamp (<= last-modified stamp))
            (return-from evaluate-preconditions
              (make-response :status 304 :etag etag :last-modified last-modified :body nil)))))
      nil)))

(defun if-range-matches-p (request &key etag last-modified)
  "NIL means Range must be ignored. T means Range applies."
  (declare (ignore last-modified))
  (let ((value (request-header request "if-range")))
    (unless value
      (return-from if-range-matches-p t))
    (let ((text (string-trim '(#\Space #\Tab) value)))
      (when (zerop (length text))
        (return-from if-range-matches-p nil))
      (if (or (char= (char text 0) #\")
              (and (>= (length text) 2)
                   (char= (char text 0) #\W)
                   (char= (char text 1) #\/)))
          (and etag (etags-match-p text etag :weak nil))
          ;; An HTTP-date is a weak validator unless the origin knows the
          ;; representation did not change twice in that second (RFC 9110
          ;; §§8.8.2.2 and 13.1.5). This origin has no such record, so the
          ;; If-Range condition is false and Range is ignored.
          nil))))

(defun parse-byte-range (spec length)
  "Return (start . end) inclusive, NIL when unsatisfiable, or :malformed."
  (let ((dash (position #\- spec)))
    (unless dash
      (return-from parse-byte-range :malformed))
    (let ((left (subseq spec 0 dash))
          (right (subseq spec (1+ dash))))
      (cond
        ((and (plusp (length left)) (every #'digit-char-p left)
              (or (zerop (length right)) (every #'digit-char-p right)))
         (let ((start (parse-integer left))
               (end (if (plusp (length right))
                        (parse-integer right)
                        (1- length))))
           (if (or (minusp end) (< end start) (>= start length))
               nil
               (cons start (min end (1- length))))))
        ((and (zerop (length left)) (plusp (length right)) (every #'digit-char-p right))
         (let ((suffix (parse-integer right)))
           ;; RFC 9110 §14.1.2. A positive suffix of a zero-length
           ;; representation is satisfiable: the whole representation.
           (cond ((zerop suffix) nil)
                 ((zerop length) :entire)
                 (t (cons (max 0 (- length suffix)) (1- length))))))
        (t :malformed)))))

(defun parse-range-header (value length)
  "Return a list of inclusive (start . end) conses, :unsatisfiable, or :ignore."
  (let ((text (string-trim '(#\Space #\Tab) value)))
    (unless (and (> (length text) 6) (string-equal text "bytes=" :end1 6))
      (return-from parse-range-header :ignore))
    (let ((specs (split-commas (subseq text 6)))
          (ranges nil)
          (entire nil))
      (when (null specs)
        (return-from parse-range-header :ignore))
      (dolist (spec specs)
        (let ((parsed (parse-byte-range (string-trim '(#\Space #\Tab) spec) length)))
          (cond ((eq parsed :malformed)
                 (return-from parse-range-header :ignore))
                ((eq parsed :entire)
                 (setf entire t))
                (parsed
                 (push parsed ranges)))))
      (cond (ranges (nreverse ranges))
            (entire :entire)
            (t :unsatisfiable)))))

(defun slice-octets (octets start end)
  (subseq octets start (1+ end)))

(defun apply-range (request octets &key etag last-modified content-type)
  "Return NIL to keep the full representation, or a response for 206 or 416.
Range is defined only for GET. An unknown range unit is ignored."
  (unless (and (string= (request-method request) "GET")
               (request-header request "range"))
    (return-from apply-range nil))
  (unless (if-range-matches-p request :etag etag :last-modified last-modified)
    (return-from apply-range nil))
  (let ((parsed (parse-range-header (request-header request "range") (length octets))))
    (cond
      ((or (eq parsed :ignore) (eq parsed :entire)) nil)
      ((eq parsed :unsatisfiable)
       (make-response :status 416
                      :headers `(("content-range" . ,(format nil "bytes */~d" (length octets))))
                      :content-type "text/plain; charset=utf-8"
                      :body "Range Not Satisfiable"))
      ((null (rest parsed))
       (let* ((range (first parsed))
              (slice (slice-octets octets (car range) (cdr range))))
         (make-response :status 206
                        :body slice
                        :headers `(("content-range" . ,(format nil "bytes ~d-~d/~d"
                                                               (car range) (cdr range) (length octets)))
                                   ("accept-ranges" . "bytes")))))
      (t
       (let ((boundary (multipart-boundary octets content-type)))
         (make-response :status 206
                        :content-type (format nil "multipart/byteranges; boundary=~a" boundary)
                        :headers '(("accept-ranges" . "bytes"))
                        :body (build-multipart octets parsed boundary content-type)))))))

(defun multipart-boundary (octets &optional extra)
  "A delimiter that does not occur in OCTETS or EXTRA (RFC 2046)."
  (let ((haystack (simple-octets octets)))
    (when (and extra (plusp (length extra))
               (every (lambda (character) (<= (char-code character) 255)) extra))
      (setf haystack (concatenate '(simple-array (unsigned-byte 8) (*))
                                  haystack (ascii-octets extra))))
    (loop for attempt below 64
          for boundary = (if (< attempt 8)
                             (format nil "pazuzu~8,'0x" (random (ash 1 32)))
                             (format nil "pazuzu~16,'0x~d" (random (ash 1 64)) attempt))
          unless (search (ascii-octets boundary) haystack)
            return boundary
          finally (error "no multipart boundary is absent from the body"))))

(defun concat-octets (pieces)
  (let* ((total (reduce #'+ pieces :key #'length :initial-value 0))
         (out (make-array total :element-type '(unsigned-byte 8)))
         (start 0))
    (dolist (piece pieces)
      (replace out piece :start1 start)
      (incf start (length piece)))
    out))

(defun multipart-type-line (content-type)
  "RFC 9110 §15.3.7.2: each part SHOULD carry the 200's Content-Type.
The line ends with CRLF (RFC 2046)."
  (if (and content-type
           (field-value-ok-p content-type)
           (not (find #\Return content-type))
           (not (find #\Newline content-type)))
      (format nil "Content-Type: ~a~c~c" content-type #\Return #\Newline)
      ""))

(defun build-multipart (octets ranges boundary content-type)
  "multipart/byteranges body. Delimiters and field lines end with CRLF (RFC 2046)."
  (let ((chunks nil)
        (type-line (multipart-type-line content-type)))
    (dolist (range ranges)
      (push (utf8-octets
             (format nil "--~a~c~c~aContent-Range: bytes ~d-~d/~d~c~c~c~c"
                     boundary #\Return #\Newline
                     type-line
                     (car range) (cdr range) (length octets)
                     #\Return #\Newline #\Return #\Newline))
            chunks)
      (push (slice-octets octets (car range) (cdr range)) chunks)
      (push (ascii-octets (format nil "~c~c" #\Return #\Newline)) chunks))
    (push (utf8-octets (format nil "--~a--~c~c" boundary #\Return #\Newline)) chunks)
    (concat-octets (nreverse chunks))))

(defun media-type-main (content-type)
  (string-trim '(#\Space #\Tab)
               (subseq content-type 0 (or (position #\; content-type) (length content-type)))))

(defun parse-quality (text)
  "Parse an HTTP qvalue (0-1, up to three fraction digits) without the Lisp reader."
  (let ((text (string-trim '(#\Space #\Tab) text))
        (dot nil))
    (when (zerop (length text))
      (return-from parse-quality 0))
    (loop for character across text
          do (cond ((char= character #\.)
                    (when dot
                      (return-from parse-quality 0))
                    (setf dot t))
                   ((not (digit-char-p character))
                    (return-from parse-quality 0))))
    (let* ((dot-pos (or (position #\. text) (length text)))
           (whole (if (zerop dot-pos) 0 (parse-integer text :end dot-pos)))
           (fraction-text (if (< dot-pos (length text)) (subseq text (1+ dot-pos)) ""))
           (fraction (if (or (zerop (length fraction-text)) (> (length fraction-text) 3))
                         (if (zerop (length fraction-text)) 0 (return-from parse-quality 0))
                         (/ (parse-integer fraction-text) (expt 10 (length fraction-text)))))
           (number (+ whole fraction)))
      (if (<= 0 number 1) number 0))))

(defun parse-q (parameters)
  (let ((q 1))
    (dolist (parameter parameters)
      (let* ((text (string-trim '(#\Space #\Tab) parameter))
             (equals (position #\= text)))
        (when (and equals
                   (string-equal (string-trim '(#\Space #\Tab) (subseq text 0 equals)) "q"))
          (setf q (parse-quality (subseq text (1+ equals)))))))
    q))

(defun split-parameters (value)
  "RFC 9110 §§5.6.6 and 8.3.1. A semicolon inside a quoted-string is not a
parameter separator, and a backslash inside quotes is a quoted-pair."
  (split-list-elements value :escape t :separator #\;))

(defun quoted-pair-octet-p (character)
  "Octet that may follow a backslash in a quoted-pair (RFC 9110 §5.6.4)."
  (let ((code (char-code character)))
    (or (char= character #\Tab)
        (char= character #\Space)
        (<= 33 code 126)
        (<= 128 code 255))))

(defun unquote-parameter-value (value)
  "RFC 9110 §5.6.4. A quoted-pair is the octet after the backslash.
A token is unchanged. An invalid quoted-string is returned trimmed."
  (let ((text (string-trim '(#\Space #\Tab) (or value ""))))
    (unless (and (plusp (length text)) (char= (char text 0) #\"))
      (return-from unquote-parameter-value text))
    (let ((out (make-array (length text) :element-type 'character :fill-pointer 0)))
      (loop with index = 1
            while (< index (length text))
            do (let ((character (char text index)))
                 (cond
                   ((char= character #\")
                    (return-from unquote-parameter-value
                      (if (= index (1- (length text)))
                          (coerce out 'string)
                          text)))
                   ((char= character #\\)
                    (incf index)
                    (when (>= index (length text))
                      (return-from unquote-parameter-value text))
                    (let ((escaped (char text index)))
                      (unless (quoted-pair-octet-p escaped)
                        (return-from unquote-parameter-value text))
                      (vector-push escaped out))
                    (incf index))
                   ((qdtext-p character)
                    (vector-push character out)
                    (incf index))
                   (t (return-from unquote-parameter-value text)))))
      text)))

(defun media-type-parameters (content-type)
  "Alist of (name . value) from a media type. Names are downcased. q is omitted.
Quoted-pairs are replaced by the following octet (RFC 9110 §5.6.4)."
  (let ((semi (position #\; content-type))
        (parameters nil))
    (when semi
      (dolist (part (split-parameters (subseq content-type (1+ semi))))
        (let* ((text (string-trim '(#\Space #\Tab) part))
               (equals (position #\= text)))
          (when (and equals (plusp equals))
            (let ((name (string-downcase
                         (string-trim '(#\Space #\Tab) (subseq text 0 equals)))))
              (unless (string= name "q")
                (push (cons name (unquote-parameter-value (subseq text (1+ equals))))
                      parameters)))))))
    (nreverse parameters)))

(defun accept-parameters-match-p (wanted have)
  "Every parameter on the media range is present on the representation."
  (every (lambda (wanted-pair)
           (let ((found (assoc (car wanted-pair) have :test #'string=)))
             (and found (string-equal (cdr wanted-pair) (cdr found)))))
         wanted))

(defun parse-accept (header)
  "List of (type subtype q specificity parameters).
A type/subtype outranks type/*, which outranks */*. Parameters add precedence
inside that class (RFC 9110 §12.5.1). q is the quality, not a media parameter."
  (loop for item in (split-commas header)
        for parts = (split-parameters item)
        for type-text = (string-trim '(#\Space #\Tab) (first parts))
        for slash = (position #\/ type-text)
        when slash
          collect (let ((type (subseq type-text 0 slash))
                        (subtype (subseq type-text (1+ slash)))
                        (parameters nil)
                        (q 1))
                    (dolist (parameter (rest parts))
                      (let* ((text (string-trim '(#\Space #\Tab) parameter))
                             (equals (position #\= text)))
                        (when (and equals (plusp equals))
                          (let ((name (string-downcase
                                       (string-trim '(#\Space #\Tab) (subseq text 0 equals))))
                                (raw (subseq text (1+ equals))))
                            (if (string= name "q")
                                (setf q (parse-quality (string-trim '(#\Space #\Tab) raw)))
                                (push (cons name (unquote-parameter-value raw)) parameters))))))
                    (setf parameters (nreverse parameters))
                    (list type subtype q
                          (cond ((and (string= type "*") (string= subtype "*")) 0)
                                ((or (string= type "*") (string= subtype "*"))
                                 (+ 1 (length parameters)))
                                (t (+ 100 (length parameters))))
                          parameters))))

(defun accept-q (clauses content-type)
  (let* ((main (media-type-main content-type))
         (slash (position #\/ main))
         (type (if slash (subseq main 0 slash) main))
         (subtype (if slash (subseq main (1+ slash)) "*"))
         (have (media-type-parameters content-type))
         (best-q 0)
         (best-spec -1)
         (matched nil))
    (dolist (clause clauses)
      (destructuring-bind (ctype csubtype q spec parameters) clause
        (when (and (or (string-equal ctype type) (string= ctype "*"))
                   (or (string-equal csubtype subtype) (string= csubtype "*"))
                   (or (string/= ctype "*") (string= csubtype "*"))
                   (accept-parameters-match-p parameters have))
          (setf matched t)
          (when (or (> spec best-spec)
                    (and (= spec best-spec) (> q best-q)))
            (setf best-spec spec best-q q)))))
    (if matched best-q 0)))

(defun parse-accept-language (header)
  (loop for item in (split-commas header)
        for parts = (split-parameters item)
        for tag = (string-trim '(#\Space #\Tab) (first parts))
        when (plusp (length tag))
          collect (cons (string-downcase tag) (parse-q (rest parts)))))

(defun language-range-matches-p (range tag)
  "RFC 4647 basic filtering. * matches every tag. A shorter range matches
only when the next tag character is a hyphen."
  (or (string= range "*")
      (and (plusp (length range))
           (<= (length range) (length tag))
           (string= range tag :end2 (length range))
           (or (= (length range) (length tag))
               (char= (char tag (length range)) #\-)))))

(defun language-q (clauses language)
  "Quality of the longest matching language-range. RFC 9110 §12.5.4 uses
the basic filtering scheme, whose HTTP quality is that of the longest match
(RFC 2616 §14.4). * is shorter than any concrete range, so en-gb;q=0
rejects British English even when en;q=1 also matches."
  (unless language
    (return-from language-q 1))
  (let ((tag (string-downcase language))
        (best-length -1)
        (best-q nil))
    (dolist (clause clauses)
      (let ((range (car clause)))
        (when (language-range-matches-p range tag)
          (let ((len (if (string= range "*") 0 (length range))))
            (when (or (> len best-length)
                      (and (= len best-length)
                           (> (cdr clause) (or best-q -1))))
              (setf best-length len
                    best-q (cdr clause)))))))
    (or best-q 0)))

(defun select-representation (request representations)
  "Pick one representation using Accept and Accept-Language. Return the
representation, or a 406 response when none is acceptable. A present but
empty field lists nothing, so every mentioned dimension is unacceptable
(RFC 9110 §12.4.3). A representation with no language stays acceptable."
  (let* ((accept (header-list-value (request-headers request) "accept"))
         (language (header-list-value (request-headers request) "accept-language"))
         (accept-clauses (and accept (parse-accept accept)))
         (language-clauses (and language (parse-accept-language language)))
         (best nil)
         (best-score -1))
    (dolist (representation representations)
      (let ((aq (cond ((null accept) 1)
                      ((null accept-clauses) 0)
                      (t (accept-q accept-clauses
                                   (representation-content-type representation)))))
            (lq (cond ((or (null language)
                           (null (representation-language representation)))
                      1)
                      ((null language-clauses) 0)
                      (t (language-q language-clauses
                                     (representation-language representation))))))
        (when (and (> aq 0) (> lq 0))
          (let ((score (+ aq (* lq 0.001))))
            (when (> score best-score)
              (setf best representation best-score score))))))
    (or best
        (make-response :status 406
                       :content-type "text/plain; charset=utf-8"
                       :body "Not Acceptable"))))
