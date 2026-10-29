(in-package #:pazuzu)

(defun cookie-octet-p (character)
  "RFC 6265 cookie-octet. Excludes CTLs, whitespace, DQUOTE, comma, semicolon, and backslash."
  (let ((code (char-code character)))
    (or (= code #x21)
        (<= #x23 code #x2B)
        (<= #x2D code #x3A)
        (<= #x3C code #x5B)
        (<= #x5D code #x7E))))

(defun cookie-path-ok-p (path)
  "path-value is any CHAR except CTLs and semicolon (RFC 6265 §4.1.1)."
  (and (plusp (length path))
       (every (lambda (character)
                (let ((code (char-code character)))
                  (and (<= 32 code 126) (not (char= character #\;)))))
              path)))

(defun cookie-domain-ok-p (domain)
  "domain-value is a subdomain, optionally with one leading dot."
  (let ((text (if (and (plusp (length domain)) (char= (char domain 0) #\.))
                  (subseq domain 1)
                  domain)))
    (and (plusp (length text))
         (every (lambda (character)
                  (let ((code (char-code character)))
                    (or (<= 48 code 57)
                        (<= 65 code 90)
                        (<= 97 code 122)
                        (char= character #\.)
                        (char= character #\-))))
                text))))

(defun parse-cookie-header (value)
  "Parse one Cookie field value into an alist of (name . value), RFC 6265."
  (let ((cookies nil))
    (dolist (piece (uiop:split-string value :separator '(#\;)))
      (let* ((text (string-trim '(#\Space #\Tab) piece))
             (equals (position #\= text)))
        (when (and equals (plusp equals))
          (let ((name (subseq text 0 equals))
                (raw (subseq text (1+ equals))))
            (when (token-string-p name)
              (let ((cookie-value
                      (cond ((and (>= (length raw) 2)
                                  (char= (char raw 0) #\")
                                  (char= (char raw (1- (length raw))) #\"))
                             (subseq raw 1 (1- (length raw))))
                            (t raw))))
                (when (every #'cookie-octet-p cookie-value)
                  (push (cons name cookie-value) cookies))))))))
    (nreverse cookies)))

(defun cookies (request)
  (loop for value in (header-values (request-headers request) "cookie")
        nconc (parse-cookie-header value)))

(defun set-cookie (name value &key domain path expires max-age secure http-only same-site)
  "Return a (\"set-cookie\" . field-value) pair whose value matches RFC 6265."
  (unless (and (token-string-p name) (every #'cookie-octet-p value))
    (error "Cookie name or value is not a valid cookie-octet sequence."))
  (when (and domain (not (cookie-domain-ok-p domain)))
    (error "Cookie Domain is not a subdomain."))
  (when (and path (not (cookie-path-ok-p path)))
    (error "Cookie Path contains a CTL or a semicolon."))
  (when (and same-site (not (member same-site '("Strict" "Lax" "None") :test #'string-equal)))
    (error "SameSite must be Strict, Lax, or None."))
  (cons "set-cookie"
        (with-output-to-string (out)
          (format out "~a=~a" name value)
          (when expires
            (format out "; Expires=~a" (format-imf-fixdate expires)))
          (when max-age
            (unless (and (integerp max-age) (>= max-age 0))
              (error "Max-Age must be a non-negative integer."))
            (format out "; Max-Age=~d" max-age))
          (when domain
            (format out "; Domain=~a" domain))
          (when path
            (format out "; Path=~a" path))
          (when secure
            (write-string "; Secure" out))
          (when http-only
            (write-string "; HttpOnly" out))
          (when same-site
            (format out "; SameSite=~a" same-site)))))
