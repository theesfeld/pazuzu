(in-package #:pazuzu)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-posix))

(defstruct (server (:constructor %make-server))
  address
  port
  (routes nil)
  (lock (bt:make-lock "pazuzu"))
  (listeners nil)
  (threads nil)
  (clients nil)
  (running t)
  (max-body (* 1024 1024))
  (max-connections 128)
  (max-connections-per-peer 32)
  (read-timeout 30)
  (worker-target 2)
  (backlog 128)
  (h2-conns nil)
  (acceptors nil)
  (accept-lock (bt:make-lock "pazuzu-accept"))
  main-listener
  main-tls
  (peers (make-hash-table :test #'equal))
  (client-peers (make-hash-table :test #'eq))
  certificate
  private-key
  ssl-context
  (retired-contexts nil)
  hsts-max-age
  (hsts-include-subdomains nil)
  cors
  https-port
  clear-port
  quic-socket
  h3-context
  endpoint
  logger
  (metrics (make-metrics))
  metrics-address
  metrics-port
  metrics-listener
  (h3-count 0)
  metrics-token
  request-rate
  (rate-windows (make-hash-table :test #'equal))
  user
  group
  config-path
  ;; Base directory for a relative directory or host root. Default /var/www/.
  (file-root #p"/var/www/")
  ;; Raw :directories and :hosts values. NIL means that mapping is empty.
  directory-spec
  host-spec)

(defstruct route
  methods
  path
  prefix
  handler
  etag
  last-modified
  websocket
  ;; NIL matches every host. A name matches only that host, port excluded.
  host
  ;; NIL is a Lisp route. :directory and :host are replaced from the file.
  config)

(defstruct (cors-policy (:constructor make-cors-policy))
  origins
  methods
  headers
  credentials
  max-age)

(defparameter *method-order*
  '("GET" "HEAD" "POST" "PUT" "DELETE" "PATCH" "OPTIONS"))

(defun canonicalize-methods (methods)
  (let ((names (if (listp methods) methods (list methods))))
    (mapcar (lambda (name) (string-upcase (string name))) names)))

(defun ordered-methods (methods)
  (let ((present (canonicalize-methods methods)))
    (when (and (member "GET" present :test #'string=)
               (not (member "HEAD" present :test #'string=)))
      (push "HEAD" present))
    (unless (member "OPTIONS" present :test #'string=)
      (push "OPTIONS" present))
    (remove-if-not (lambda (name) (member name present :test #'string=))
                   *method-order*)))

(defun allow-value (methods)
  (format nil "~{~a~^, ~}" (ordered-methods methods)))

(defun route-replaces-p (old path)
  "An any-host route at PATH is replaced by a new any-host route.
A host-scoped route at the same path stays."
  (and (null (route-host old))
       (string= (route-path old) path)))

(defun add-route (server methods path handler &key prefix etag last-modified)
  "Register HANDLER for PATH. METHODS is a keyword or a list of keywords.
GET implies HEAD. OPTIONS is answered for every registered resource.
ETAG and LAST-MODIFIED are functions of the request. They are called
before an unsafe method when the request carries a precondition, and
before GET or HEAD when If-Match, If-None-Match, or If-Unmodified-Since
is present and Accept-Encoding is not."
  (let ((route (make-route :methods (canonicalize-methods methods)
                           :path (if (string= path "/") "/" (string-right-trim "/" path))
                           :prefix prefix
                           :handler handler
                           :etag etag
                           :last-modified last-modified)))
    (bt:with-lock-held ((server-lock server))
      (setf (server-routes server)
            (cons route (remove-if (lambda (old)
                                     (route-replaces-p old (route-path route)))
                                   (server-routes server)))))
    route))

(defun add-websocket-route (server path handler)
  (let ((route (make-route :methods '("GET")
                           :path path
                           :prefix nil
                           :handler handler
                           :websocket t)))
    (bt:with-lock-held ((server-lock server))
      (setf (server-routes server)
            (cons route (remove-if (lambda (old)
                                     (route-replaces-p old (route-path route)))
                                   (server-routes server)))))
    route))

(defun route-list (server)
  (bt:with-lock-held ((server-lock server))
    (copy-list (server-routes server))))

(defun route-match-score (route path)
  (cond ((string= (route-path route) path)
         (+ 100000 (length (route-path route))))
        ((and (route-prefix route)
              (or (string= path (route-path route))
                  (and (string/= (route-path route) "/")
                       (> (length path) (length (route-path route)))
                       (string= path (route-path route) :end1 (length (route-path route)))
                       (char= (char path (length (route-path route))) #\/))))
         (length (route-path route)))
        ((and (route-prefix route) (string= (route-path route) "/"))
         0)))

(defun host-name (authority)
  "Bare hostname. split-authority has already dropped the port and case."
  (multiple-value-bind (host port) (split-authority (or authority ""))
    (declare (ignore port))
    (when (and host (plusp (length host)))
      (string-right-trim "." host))))

(defun route-applies-p (route host-name)
  (or (null (route-host route))
      (and host-name (string= (route-host route) host-name))))

(defun find-route (server path &optional host)
  "The best route for PATH. HOST nil skips host-scoped routes.
A host-scoped route outranks an any-host route with the same path score."
  (let ((best nil)
        (best-score -1)
        (name (host-name host)))
    (dolist (route (route-list server))
      (when (route-applies-p route name)
        (let ((score (route-match-score route path)))
          (when (and score
                     (or (> score best-score)
                         (and (= score best-score)
                              (route-host route)
                              (not (and best (route-host best))))))
            (setf best route best-score score)))))
    best))

(defun method-allowed-p (route method)
  (or (member method (ordered-methods (route-methods route)) :test #'string=)
      (and (route-websocket route) (string= method "GET"))))

(defun status-before-content (server request)
  "A final response known without the content, or NIL when the handler
has to see it. Expect: 100-continue uses this so the origin does not
wait for a body it is going to reject (RFC 9110 §10.1.1).
The order matches dispatch. Framing is already done. An unknown
content-coding is 415. A header-known status other than 2xx or 412,
including a failed Authorization, is sent before preconditions
(RFC 9110 §13.2.1). Preconditions then use the current representation."
  (let ((misdirected (https-origin-rejected server request)))
    (when misdirected
      (return-from status-before-content misdirected)))
  (let ((method (request-method request)))
    (unless (recognized-method-p method)
      (return-from status-before-content (plain-error 501)))
    (unless (implemented-method-p method)
      (return-from status-before-content (plain-error 501)))
    (when (and (string= method "OPTIONS") (string= (request-target request) "*"))
      (return-from status-before-content nil))
    (let ((route (find-route server (request-path request) (request-host request))))
      (cond ((null route) (plain-error 404))
            ((not (method-allowed-p route method))
             (make-response :status 405
                            :headers `(("allow" . ,(allow-value (route-methods route))))
                            :content-type "text/plain; charset=utf-8"
                            :body "Method Not Allowed"))
            (t (ensure-allow
                (or (refused-content-coding (request-headers request))
                    (reject-before-content (route-handler route) request)
                    (precondition-guard route request))
                route))))))

(defun form-decode (text)
  (decode-percent (substitute #\Space #\+ text :test #'char=)))

(defun query-parameters (request)
  (let ((query (request-query request)))
    (if (null query)
        nil
        (loop for piece in (uiop:split-string query :separator '(#\&))
              for equals = (position #\= piece)
              collect (cons (form-decode (if equals (subseq piece 0 equals) piece))
                            (if equals (form-decode (subseq piece (1+ equals))) ""))))))

(defun plain-error (status)
  (make-response :status status
                 :content-type "text/plain; charset=utf-8"
                 :body (reason-phrase status)))

(defun normalize-result (result)
  (etypecase result
    (response result)
    (string (text-response result))
    ((vector (unsigned-byte 8)) (octet-response result))
    (null (empty-response 204))))

(defun add-vary (headers field)
  (let ((existing (header-value headers "vary")))
    (cond ((null existing) (acons "vary" field headers))
          ((member field (split-commas existing) :test #'string-equal) headers)
          (t (acons "vary" (concatenate 'string existing ", " field)
                    (remove-headers headers "vary"))))))

(defun merge-headers (response extra)
  (setf (response-headers response) (append extra (response-headers response)))
  response)

(defun cors-origin-allowed-p (policy origin)
  (and policy origin
       (or (eq (cors-policy-origins policy) :any)
           (member origin (cors-policy-origins policy) :test #'string=))))

(defun cors-allow-origin-headers (policy origin)
  (cond ((eq (cors-policy-origins policy) :any)
         (when (cors-policy-credentials policy)
           (error "CORS credentials cannot be combined with a wildcard origin."))
         '(("access-control-allow-origin" . "*")))
        (t
         `(("access-control-allow-origin" . ,origin)
           ,@(when (cors-policy-credentials policy)
               '(("access-control-allow-credentials" . "true")))))))

(defun apply-cors (server request response)
  (let ((policy (server-cors server))
        (origin (request-header request "origin")))
    (unless (cors-origin-allowed-p policy origin)
      (return-from apply-cors response))
    (merge-headers response (cors-allow-origin-headers policy origin))
    (unless (eq (cors-policy-origins policy) :any)
      (setf (response-headers response) (add-vary (response-headers response) "origin")))
    response))

(defun preflight-response (server route request)
  (let ((policy (server-cors server))
        (origin (request-header request "origin"))
        (asked (request-header request "access-control-request-method")))
    (unless (and policy origin asked (cors-origin-allowed-p policy origin))
      (return-from preflight-response nil))
    (let* ((methods (or (cors-policy-methods policy)
                        (ordered-methods (route-methods route))))
           (headers (cors-policy-headers policy))
           (fields (append (cors-allow-origin-headers policy origin)
                           `(("access-control-allow-methods" . ,(allow-value methods)))
                           (when headers
                             `(("access-control-allow-headers"
                                . ,(format nil "~{~a~^, ~}" headers))))
                           (when (cors-policy-max-age policy)
                             `(("access-control-max-age"
                                . ,(princ-to-string (cors-policy-max-age policy))))))))
      (make-response :status 204 :headers fields :body nil))))

(defun negotiation-vary (response representations)
  "RFC 9110 §12.5.5. Selection uses Accept for every representation, and
Accept-Language when any representation has a language. The field is
required even when this request omitted the header."
  (setf (response-headers response)
        (add-vary (response-headers response) "accept"))
  (when (some #'representation-language representations)
    (setf (response-headers response)
          (add-vary (response-headers response) "accept-language")))
  response)

(defun representation-response (request response)
  (let* ((representations (response-representations response))
         (selected (select-representation request representations)))
    (if (not (representation-p selected))
        (negotiation-vary selected representations)
        (negotiation-vary
         (make-response :status (response-status response)
                        :headers (response-headers response)
                        :body (representation-body selected)
                        :content-type (representation-content-type selected)
                        :language (representation-language selected)
                        :etag (or (representation-etag selected) (response-etag response))
                        :last-modified (or (representation-last-modified selected)
                                           (response-last-modified response))
                        :cache-control (response-cache-control response))
         representations))))

(defun partial-response (request full partial)
  "RFC 9110 §15.3.7. A 206 carries Date, Cache-Control, ETag, Expires,
Content-Location, and Vary when the 200 would have. Without If-Range it
also carries the representation fields the 200 would have sent."
  (let* ((if-range (request-header request "if-range"))
         (source (response-headers full))
         (drop (append '("content-length" "content-range" "transfer-encoding"
                         "cache-control" "content-type" "content-language"
                         "last-modified")
                       (when if-range '("content-encoding")))))
    (setf (response-etag partial) (or (response-etag partial) (response-etag full)))
    (setf (response-cache-control partial)
          (or (response-cache-control partial)
              (response-cache-control full)
              (header-value source "cache-control")))
    (unless if-range
      (unless (response-content-type partial)
        (setf (response-content-type partial) (response-content-type full)))
      (unless (response-language partial)
        (setf (response-language partial) (response-language full)))
      (unless (response-last-modified partial)
        (setf (response-last-modified partial) (response-last-modified full))))
    (setf (response-headers partial)
          (append (response-headers partial)
                  (apply #'remove-headers source drop)))
    partial))

(defun strong-representation-etag (octets)
  "Collision-resistant hash of these representation octets (RFC 9110 §8.8.1)."
  (format nil "\"~a\""
          (string-downcase
           (ironclad:byte-array-to-hex-string
            (ironclad:digest-sequence :sha256 (simple-octets octets))))))

(defun ensure-final-response (response)
  "The handler result is the final response. A 1xx is interim and cannot
be the only status on the exchange (RFC 9110 §§10.1.1 and 15.2). On
HTTP/2 that lone status would be a HEADERS frame with END_STREAM, which
is malformed (RFC 9113 §8.1). 101 is produced by the WebSocket handshake,
which does not come through here."
  (if (and response (< (response-status response) 200))
      (plain-error 500)
      response))

(defun ensure-challenge (response)
  "RFC 9110 §§11.6.1 and 15.5.2. A 401 with no challenge is given one.
A challenge the handler already chose is left as it is."
  (when (and (= (response-status response) 401)
             (not (header-value (response-headers response) "www-authenticate")))
    (setf (response-headers response)
          (acons "www-authenticate" "Basic realm=\"pazuzu\""
                 (response-headers response))))
  response)

(defun ensure-allow (response route)
  "RFC 9110 §§10.2.1 and 15.5.6. A 405 lists the methods this resource
supports. The route is that list. A field the handler wrote is replaced,
because a shorter list would omit a method the resource still allows."
  (when (and (typep response 'response)
             route
             (= (response-status response) 405))
    (setf (response-headers response)
          (acons "allow" (allow-value (route-methods route))
                 (remove-headers (response-headers response) "allow"))))
  response)

(defun finalize-response (request response)
  "Negotiation, preconditions, ranges, and content-coding for a 2xx representation."
  (setf response (ensure-challenge (ensure-final-response response)))
  (let ((mixed (and (string= (or (request-scheme request) "") "https")
                    (header-value (response-headers response) "pazuzu-mixed"))))
    (setf (response-headers response)
          (remove-headers (response-headers response) "pazuzu-mixed"))
    (when (response-representations response)
    (setf response (representation-response request response))
    (unless (<= 200 (response-status response) 299)
      (return-from finalize-response response)))
  (unless (<= 200 (response-status response) 299)
    (return-from finalize-response response))
  (let* ((octets (body-octets (response-body response)))
         (streaming (functionp (response-body response)))
         (range-wanted (and octets
                            (member (request-method request) '("GET" "HEAD")
                                    :test #'string=)
                            (request-header request "range")
                            (= (response-status response) 200)))
         (coding (cond
                   ;; RFC 9113 §10.6 and RFC 9114 §10.6. A secure body
                   ;; that mixes confidential and attacker-controlled
                   ;; data is not content-coded. One source still is.
                   (mixed 'identity)
                   ((and octets (not streaming))
                    (choose-content-coding request
                                           (response-content-type response)
                                           (length octets)
                                           :prefer-identity range-wanted))
                   (t 'identity))))
    (when (and (eq coding :none) range-wanted)
      (setf coding (choose-content-coding request
                                          (response-content-type response)
                                          (length octets)
                                          :prefer-identity nil)
            range-wanted nil))
    ;; Not a 2xx. Preconditions are ignored (RFC 9110 §13.2.1).
    (when (eq coding :none)
      (return-from finalize-response (plain-error 406)))
    (let ((encoded (if (eq coding 'identity)
                       octets
                       (encode-body octets coding))))
      ;; A strong tag for the uncoded bytes is not a validator for a
      ;; different content coding (RFC 9110 §8.8.1). The encoded octets
      ;; are known here, so their hash is a strong validator.
      (when (and (not (eq coding 'identity)) (response-etag response))
        (setf (response-etag response) (strong-representation-etag encoded)
              (response-headers response)
              (add-vary (response-headers response) "accept-encoding")))
      ;; GET and HEAD select the representation this response carries, so
      ;; their preconditions are evaluated here (RFC 9110 §13.1). An unsafe
      ;; method was already checked against the current representation. Its
      ;; result is a different message: a matching If-Match is answered with
      ;; that result (RFC 9110 §13.1.1), not a second 412 against an empty
      ;; validator.
      (let ((failed (and (member (request-method request) '("GET" "HEAD") :test #'string=)
                         (evaluate-preconditions request
                                                 :etag (response-etag response)
                                                 :last-modified (response-last-modified response)))))
        (when failed
          (setf (response-cache-control failed)
                (or (response-cache-control failed)
                    (response-cache-control response)
                    (header-value (response-headers response) "cache-control")))
          (cond
            ((= (response-status failed) 304)
             ;; RFC 9110 §15.4.5: Content-Location, Date, ETag, Vary,
             ;; Cache-Control, and Expires. Content-Type and
             ;; Content-Language are not among them.
             (setf (response-headers failed)
                   (append (response-headers failed)
                           (remove-headers (response-headers response)
                                           "content-type" "content-encoding"
                                           "content-language" "content-length"
                                           "content-range" "transfer-encoding"
                                           "cache-control")))
             (return-from finalize-response failed))
            (t
             (unless (response-content-type failed)
               (setf (response-content-type failed) (response-content-type response)))
             (setf (response-headers failed)
                   (append (response-headers failed) (response-headers response)))
             (return-from finalize-response failed)))))
      (when (and range-wanted (string= (request-method request) "GET"))
        (let ((ranged (apply-range request octets
                                   :etag (response-etag response)
                                   :last-modified (response-last-modified response)
                                   :content-type (response-content-type response))))
          (when ranged
            (setf response (partial-response request response ranged)
                  octets (body-octets (response-body ranged))
                  coding 'identity))))
      ;; RFC 9110 §14.2 defines range handling for GET only, so HEAD ignores
      ;; Range. RFC 9110 §8.6 forbids a Content-Length that is not the number
      ;; of octets GET would have sent for this same request. When those
      ;; lengths differ, the writers omit Content-Length. The representation
      ;; body stays in place so the connection is not closed.
      (when (and range-wanted (string= (request-method request) "HEAD"))
        (let* ((as-get (make-request :method "GET"
                                     :headers (request-headers request)))
               (ranged (apply-range as-get octets
                                    :etag (response-etag response)
                                    :last-modified (response-last-modified response)
                                    :content-type (response-content-type response)))
               (got (and ranged (body-octets (response-body ranged)))))
          (when (and ranged
                     (not (and (= (response-status ranged) 206)
                               got
                               (= (length got) (length octets)))))
            ;; The body stays the selected representation so the connection
            ;; is not closed the way a streamed body is. The writers drop
            ;; this field and do not emit Content-Length.
            (setf (response-headers response)
                  (acons "pazuzu-omit-length" "1" (response-headers response))
                  coding 'identity))))
      (unless (eq coding 'identity)
        (setf octets encoded
              (response-headers response)
              (add-vary (acons "content-encoding" (string-downcase (string coding))
                               (remove-headers (response-headers response) "content-encoding"))
                        "accept-encoding")))
      (when (and octets (= (response-status response) 200)
                 (not (header-value (response-headers response) "accept-ranges")))
        (setf (response-headers response)
              (acons "accept-ranges" "bytes" (response-headers response))))
      (unless streaming
        (setf (response-body response) octets))
      response))))

(defun body-octets (body)
  (cond ((null body) (ascii-octets ""))
        ((stringp body) (utf8-octets body))
        ((pathnamep body) (response-octets body))
        ((typep body '(vector (unsigned-byte 8))) (simple-octets body))
        (t nil)))

(defun content-coding-identity-p (coding)
  (eq (content-coding-kind coding) :identity))

(defun refused-content-coding (headers)
  "RFC 9110 §§8.4 and 10.1.1. A coding this origin cannot remove is 415.
That status is known from the header fields, before the content is read."
  (let ((encoding (header-list-value headers "content-encoding")))
    (when (and encoding
               (some (lambda (coding) (null (content-coding-kind coding)))
                     (split-commas encoding)))
      (unsupported-coding-response))))

(defun decode-request-body (request max-body)
  "Content-Encoding lists codings in the order they were applied (RFC 9110
§8.4). Decode from the outside in. Repeated field lines are one value
(RFC 9110 §5.2). A coding other than identity is a transformation."
  (let ((encoding (header-list-value (request-headers request) "content-encoding")))
    (when (and encoding (plusp (length (request-body request))))
      (dolist (coding (reverse (split-commas encoding)))
        (unless (content-coding-identity-p coding)
          (setf (request-transformed request) t))
        (setf (request-body request)
              (decode-content-encoding (request-body request) coding max-body))))))

(defun put-had-representation-p (route request)
  "RFC 9110 §9.3.4. True when this PUT already has a current representation.
The validators are read before the handler, so a store the handler fills
does not count as a representation that already existed. A route with no
validator function is left alone."
  (or (not (string= (request-method request) "PUT"))
      (not (or (route-etag route) (route-last-modified route)))
      (and (route-etag route) (funcall (route-etag route) request))
      (and (route-last-modified route)
           (funcall (route-last-modified route) request))))

(defun note-created-put (request response existed)
  "RFC 9110 §9.3.4. A successful PUT that had no current representation
is 201. EXISTED is that answer from before the handler ran. A successful
modification stays 200 or 204. A handler that already chose 201 is left
as it is."
  (when (and (not existed)
             (string= (request-method request) "PUT")
             (or (= (response-status response) 200)
                 (= (response-status response) 204)))
    (setf (response-status response) 201))
  response)

(defun strip-put-validators (request response)
  "RFC 9110 §9.3.4. A successful PUT sends no validator when the content
was transformed before it was saved."
  (when (and (string= (request-method request) "PUT")
             (request-transformed request)
             (<= 200 (response-status response) 299))
    (setf (response-etag response) nil
          (response-last-modified response) nil
          (response-headers response)
          (remove-headers (response-headers response) "etag" "last-modified")))
  response)

(defun precondition-guard (route request)
  "RFC 9110 §13.1.1. If-Match: * is false when the origin has no current
representation. A validator function that returns NIL says there is none.
A failed If-Match or If-Unmodified-Since, and a false If-None-Match,
on GET or HEAD are decided before the handler when Accept-Encoding is
absent, so the method is not performed (RFC 9110 §§13.1.1, 13.1.2, and
13.1.4). With Accept-Encoding present, the handler must run first: an
unacceptable coding is 406 and the precondition is ignored (RFC 9110
§13.2.1)."
  (let ((method (request-method request)))
    (when (member method '("OPTIONS" "CONNECT" "TRACE") :test #'string=)
      (return-from precondition-guard nil))
    (let ((get-like (member method '("GET" "HEAD") :test #'string=)))
      (when (and (or (route-etag route) (route-last-modified route))
                 (if get-like
                     (and (not (request-header request "accept-encoding"))
                          (or (request-header request "if-match")
                              (request-header request "if-none-match")
                              (request-header request "if-unmodified-since")))
                     (or (request-header request "if-match")
                         (request-header request "if-none-match")
                         (request-header request "if-unmodified-since"))))
        (let* ((etag (and (route-etag route) (funcall (route-etag route) request)))
               (modified (and (route-last-modified route)
                              (funcall (route-last-modified route) request)))
               (result (evaluate-preconditions
                        request
                        :etag etag
                        :last-modified modified
                        :has-representation (or etag modified
                                                (not (or (route-etag route)
                                                         (route-last-modified route)))))))
          ;; If-Modified-Since still waits for the selected response so a
          ;; 304 can carry that response's cache fields. A false
          ;; If-None-Match is final here (RFC 9110 §13.1.2).
          (if (and get-like result (= (response-status result) 304)
                   (not (request-header request "if-none-match")))
              nil
              result))))))

(defun dispatch (server request)
  (let ((misdirected (https-origin-rejected server request)))
    (when misdirected
      (return-from dispatch misdirected)))
  (let ((method (request-method request)))
    (unless (recognized-method-p method)
      (return-from dispatch (plain-error 501)))
    (unless (implemented-method-p method)
      (return-from dispatch (plain-error 501)))
    (when (and (string= method "OPTIONS") (string= (request-target request) "*"))
      (return-from dispatch
        (make-response :status 200
                       :headers `(("allow" . ,(allow-value *implemented-methods*)))
                       :body nil)))
    (let ((route (find-route server (request-path request) (request-host request))))
      (unless route
        (return-from dispatch (plain-error 404)))
      (let ((preflight (preflight-response server route request)))
        (when preflight
          (return-from dispatch preflight)))
      (when (and (route-websocket route) (websocket-handshake-p request))
        (return-from dispatch :websocket))
      (when (route-websocket route)
        (return-from dispatch
          ;; RFC 9110 §15.6.15: a 426 carries Upgrade. HTTP/2 and HTTP/3
          ;; cannot carry that field (RFC 9113 §8.2.2, RFC 9114 §4.2).
          ;; A GET on those protocols is not an extended CONNECT.
          (if (member (request-http-version request) '(10 11) :test #'=)
              (make-response :status 426
                             :headers '(("upgrade" . "websocket")
                                        ("connection" . "Upgrade"))
                             :content-type "text/plain; charset=utf-8"
                             :body "Upgrade Required")
              (plain-error 400))))
      (unless (method-allowed-p route method)
        (return-from dispatch
          (make-response :status 405
                         :headers `(("allow" . ,(allow-value (route-methods route))))
                         :content-type "text/plain; charset=utf-8"
                         :body "Method Not Allowed")))
      (when (and (string= method "OPTIONS")
                 (not (member "OPTIONS" (route-methods route) :test #'string=)))
        (return-from dispatch
          (make-response :status 200
                         :headers `(("allow" . ,(allow-value (route-methods route))))
                         :body nil)))
      (decode-request-body request (server-max-body server))
      ;; RFC 9110 §13.2.1. A failed Authorization is 401 from the header
      ;; fields. That status is not 2xx or 412, so preconditions are ignored.
      ;; Digest nc is recorded only when the handler accepts the request.
      (let ((denied (reject-before-content (route-handler route) request)))
        (when denied
          (return-from dispatch (ensure-allow denied route))))
      (let ((guard (precondition-guard route request)))
        (when guard
          (return-from dispatch (ensure-allow guard route))))
      (let ((handler-method (if (string= method "HEAD") "GET" method))
            (existed (put-had-representation-p route request)))
        (declare (ignore handler-method))
        (ensure-allow
         (strip-put-validators
          request
          (note-created-put
           request
           (finalize-response request (normalize-result (funcall (route-handler route) request)))
           existed))
         route)))))

(defun apply-alt-svc (server request response)
  (when (and (server-quic-socket server)
             (server-https-port server)
             (string= (request-scheme request) "https")
             (>= (response-status response) 200))
    (setf (response-headers response)
          (acons "alt-svc"
                 (format nil "h3=\":~d\"; ma=86400" (server-https-port server))
                 (remove-headers (response-headers response) "alt-svc"))))
  response)

(defun origin-decorate (server request response)
  "Add HSTS, CORS, and Alt-Svc. Used by every origin response, including
HTTP/2 and HTTP/3. The cleartext redirect listener does not call this."
  (apply-hsts server request response)
  (apply-cors server request response)
  (apply-alt-svc server request response)
  response)

(defun apply-hsts (server request response)
  (when (and (server-hsts-max-age server)
             (string= (request-scheme request) "https")
             (>= (response-status response) 200))
    (let ((value (format nil "max-age=~d~@[; includeSubDomains~]"
                         (server-hsts-max-age server)
                         (server-hsts-include-subdomains server))))
      (setf (response-headers response)
            (acons "strict-transport-security" value
                   (remove-headers (response-headers response) "strict-transport-security")))))
  response)

(defun https-location (request port)
  "An https URI for REQUEST on PORT. RFC 9110 §4.2.2 forbids an empty host."
  (let* ((host (or (request-host request) ""))
         (name (cond ((zerop (length host)) nil)
                     ((char= (char host 0) #\[)
                      (let ((close (position #\] host)))
                        (and close (subseq host 0 (1+ close)))))
                     ((position #\: host)
                      (subseq host 0 (position #\: host)))
                     (t host))))
    (when (and name (plusp (length name)))
      (let* ((target (request-target request))
             (path (if (and (plusp (length target)) (char= (char target 0) #\/))
                       target
                       (request-path request))))
        (format nil "https://~a~a~a"
                name
                (if (= port 443) "" (format nil ":~d" port))
                path)))))

(defun note-thread (server thread)
  (bt:with-lock-held ((server-lock server))
    (push thread (server-threads server))))

(defun forget-client (server socket)
  (bt:with-lock-held ((server-lock server))
    (let ((peer (gethash socket (server-client-peers server))))
      (remhash socket (server-client-peers server))
      (when peer
        (let ((left (1- (gethash peer (server-peers server) 1))))
          (if (plusp left)
              (setf (gethash peer (server-peers server)) left)
              (remhash peer (server-peers server))))))
    (setf (server-clients server) (remove socket (server-clients server)))))

(defun connection-count (server)
  "TCP clients plus admitted HTTP/3 connections. Call with SERVER-LOCK held."
  (+ (length (server-clients server)) (server-h3-count server)))

(defun admit-client (server socket)
  "Record SOCKET unless the global cap or the per-address cap is full.
The global cap counts HTTP/3 connections as well."
  (bt:with-lock-held ((server-lock server))
    (let* ((peer (peer-name socket))
           (from-peer (gethash peer (server-peers server) 0)))
      (cond ((or (>= (connection-count server) (server-max-connections server))
                 (>= from-peer (server-max-connections-per-peer server)))
             nil)
            (t
             (setf (gethash peer (server-peers server)) (1+ from-peer))
             (setf (gethash socket (server-client-peers server)) peer)
             (push socket (server-clients server))
             (count-accept (server-metrics server))
             t)))))

(defun admit-http3 (server peer)
  "Count one HTTP/3 connection for PEER. A stateless Retry does not call this.
Returns T when the connection is admitted."
  (bt:with-lock-held ((server-lock server))
    (let ((from-peer (gethash peer (server-peers server) 0)))
      (cond ((or (>= (connection-count server) (server-max-connections server))
                 (>= from-peer (server-max-connections-per-peer server)))
             nil)
            (t
             (incf (server-h3-count server))
             (setf (gethash peer (server-peers server)) (1+ from-peer))
             (count-accept (server-metrics server))
             t)))))

(defun release-http3 (server peer)
  "Drop one admitted HTTP/3 connection. Call this outside the endpoint lock."
  (when server
    (bt:with-lock-held ((server-lock server))
      (when (plusp (server-h3-count server))
        (decf (server-h3-count server)))
      (when peer
        (let ((left (1- (gethash peer (server-peers server) 1))))
          (if (plusp left)
              (setf (gethash peer (server-peers server)) left)
              (remhash peer (server-peers server))))))))

(defun wait-for (predicate seconds)
  (loop with deadline = (+ (get-internal-real-time)
                           (* seconds internal-time-units-per-second))
        until (or (funcall predicate)
                  (> (get-internal-real-time) deadline))
        do (sleep 0.01)))

(defun read-origin-request (server stream scheme peer &key early)
  "Read one request. An idle timeout closes quietly. A timeout after the
first octet is 408 Request Timeout. EARLY lets Expect: 100-continue
finish with the status the method and target already decide."
  (let ((*saw-request-octet* nil)
        (timeout (server-read-timeout server)))
    (flet ((read-it ()
             (read-request stream :scheme scheme :peer peer
                           :max-body (server-max-body server)
                           :early-response (when early
                                             (lambda (request)
                                               (status-before-content server request))))))
      (handler-case
          (if timeout
              (sb-sys:with-deadline (:seconds timeout)
                (read-it))
              (read-it))
        (sb-sys:deadline-timeout ()
          (if *saw-request-octet*
              (protocol-error 408 :detail "timeout")
              (error 'end-of-request)))))))

(defun response-byte-count (response)
  (let ((octets (and response (response-octets (emitted-body response)))))
    (and octets (length octets))))

(defun request-line (request)
  (if request
      (format nil "~a ~a ~a"
              (request-method request)
              (or (request-target request) (request-path request))
              (protocol-token (request-http-version request)))
      "-"))

(defun note-response (server request response &key seconds)
  "Count the response and, when an access log is open, write a combined-log line."
  (when (and server response)
    (let ((bytes (response-byte-count response)))
      (count-response (server-metrics server)
                      (protocol-label (if request (request-http-version request) 11))
                      (princ-to-string (response-status response))
                      (or bytes 0)
                      seconds)
      (access-log (server-logger server)
                  :peer (if request (request-peer request) "-")
                  :request (request-line request)
                  :status (response-status response)
                  :bytes bytes
                  :referer (and request (request-header request "referer"))
                  :user-agent (and request (request-header request "user-agent"))))))

(defun peer-name (socket)
  (handler-case
      (format-ip (usocket:get-peer-address socket))
    (error () "")))

(defun too-many-response ()
  "RFC 6585: 429 with Retry-After when the per-peer request rate is exhausted."
  (make-response :status 429
                 :headers '(("retry-after" . "1"))
                 :content-type "text/plain; charset=utf-8"
                 :body "Too Many Requests"))

(defun request-limited-p (server peer)
  "True when PEER has used this second's request budget. A null rate is unlimited."
  (let ((rate (server-request-rate server)))
    (unless (and rate (plusp rate))
      (return-from request-limited-p nil))
    (bt:with-lock-held ((server-lock server))
      (let* ((windows (server-rate-windows server))
             (now (get-universal-time))
             (key (or peer ""))
             (entry (gethash key windows))
             (count (if (and entry (= (car entry) now)) (cdr entry) 0)))
        (when (> (hash-table-count windows) 1024)
          (maphash (lambda (saved value)
                     (unless (= (car value) now)
                       (remhash saved windows)))
                   windows))
        (cond ((>= count rate) t)
              (t (setf (gethash key windows) (cons now (1+ count)))
                 nil))))))

(defun serve-stream (server stream &key scheme peer redirect)
  (handler-case
      (loop
        (let ((started (get-internal-real-time))
              (request (read-origin-request server stream scheme peer :early (not redirect))))
          (if (request-limited-p server peer)
              (let ((response (origin-decorate server request (too-many-response))))
                (note-response server request response
                               :seconds (/ (- (get-internal-real-time) started)
                                           internal-time-units-per-second))
                (when (write-response stream request response :close-connection nil)
                  (return)))
              (if redirect
                  (let* ((location (https-location request (server-https-port server)))
                         (response (if location
                                       (redirect-response location
                                                          :status (if (member (request-method request)
                                                                              '("GET" "HEAD")
                                                                              :test #'string=)
                                                                      301 308))
                                       (plain-error 400))))
                    (note-response server request response
                                   :seconds (/ (- (get-internal-real-time) started)
                                               internal-time-units-per-second))
                    (write-response stream request response :close-connection t)
                    (return))
                  (let ((result (dispatch server request)))
                    (when (eq result :websocket)
                      (note-response server request (make-response :status 101 :body nil))
                      (let ((route (find-route server (request-path request)
                                               (request-host request))))
                        (perform-websocket-handshake stream request (route-handler route)))
                      (return))
                    (origin-decorate server request result)
                    (let ((close (write-response stream request result
                                                 :suppress-body (string= (request-method request) "HEAD")
                                                 ;; RFC 9931 §8. A rejected CONNECT must not
                                                 ;; be followed by another request on this
                                                 ;; connection. A 2xx would be a tunnel.
                                                 :close-connection
                                                 (and (string= (request-method request) "CONNECT")
                                                      (not (<= 200 (response-status result) 299))))))
                      (note-response server request result
                                     :seconds (/ (- (get-internal-real-time) started)
                                                 internal-time-units-per-second))
                      (when close
                        (return))))))))
    (end-of-request ())
    (final-before-content (condition)
      (let* ((request (final-before-content-request condition))
             (response (origin-decorate server request
                                        (final-before-content-response condition))))
        (note-response server request response)
        ;; The content is still unread, so the connection cannot continue
        ;; (RFC 9110 §10.1.1, RFC 9112 §9.6).
        (ignore-errors (write-response stream request response :close-connection t))))
    (protocol-error (condition)
      (let ((response (protocol-error-response condition)))
        (note-response server nil response)
        (ignore-errors (write-response stream nil response :close-connection t))))
    (error (condition)
      (note-response server nil (plain-error 500))
      (ignore-errors
        (write-response stream nil (plain-error 500) :close-connection t))
      (error-log (server-logger server) "error" "pazuzu: ~a" condition))))

(cffi:defcfun ("SSL_CTX_up_ref" ssl-ctx-up-ref :library cl+ssl::libssl) :int
  (ctx :pointer))

(defun borrow-context (ctx)
  "One extra reference on CTX. The caller releases it with RELEASE-CONTEXT."
  (when (and ctx (not (cffi:null-pointer-p ctx)) (plusp (ssl-ctx-up-ref ctx)))
    ctx))

(defun release-context (ctx)
  (when (and ctx (not (cffi:null-pointer-p ctx)))
    (ignore-errors (cl+ssl:ssl-ctx-free ctx))))

(defun call-with-ssl-context (server function)
  "Borrow the HTTPS context for FUNCTION. A reload can free the server's own
reference while this borrow, and any SSL created from it, still holds one."
  (let ((ctx (bt:with-lock-held ((server-lock server))
               (borrow-context (server-ssl-context server)))))
    (unwind-protect
         (when ctx
           (cl+ssl:with-global-context (ctx)
             (funcall function)))
      (release-context ctx))))

(defun call-with-borrowed-h3-context (endpoint function)
  "Borrow the HTTP/3 context for one QUIC loop pass."
  (let ((ctx (bt:with-lock-held ((server-lock (h3-endpoint-server endpoint)))
               (borrow-context (h3-endpoint-context endpoint)))))
    (unwind-protect
         (when ctx
           (cl+ssl:with-global-context (ctx)
             (funcall function)))
      (release-context ctx))))

(defun borrow-endpoint-context (endpoint)
  (bt:with-lock-held ((server-lock (h3-endpoint-server endpoint)))
    (borrow-context (h3-endpoint-context endpoint))))

(defun reject-over-capacity (server socket &key tls)
  "Answer 503 and close. TLS clients complete the handshake first so the
status is visible inside the session."
  (count-reject (server-metrics server))
  (let ((raw (usocket:socket-stream socket)))
    (if tls
        (call-with-ssl-context
         server
         (lambda ()
           (let ((ssl (handler-case
                          (sb-sys:with-deadline (:seconds (or (server-read-timeout server) 30))
                            (cl+ssl:make-ssl-server-stream raw :external-format nil))
                        (sb-sys:deadline-timeout ()
                          nil))))
             (when ssl
               (unwind-protect (ignore-errors (write-response ssl nil (plain-error 503)
                                                              :close-connection t))
                 (ignore-errors (close ssl)))))))
        (ignore-errors (write-response raw nil (plain-error 503) :close-connection t)))))

(defun serve-admitted (server socket &key tls redirect)
  (let ((raw (usocket:socket-stream socket)))
    (cond (tls
           (call-with-ssl-context
            server
            (lambda ()
              (let ((ssl (handler-case
                             (sb-sys:with-deadline (:seconds (or (server-read-timeout server) 30))
                               (cl+ssl:make-ssl-server-stream raw :external-format nil))
                           (sb-sys:deadline-timeout ()
                             (return-from serve-admitted nil)))))
                (unwind-protect
                     (let ((alpn (handler-case (or (cl+ssl:get-selected-alpn-protocol ssl) "")
                                   (error () ""))))
                       (if (string= alpn "h2")
                           (serve-http2 server socket ssl
                                        :scheme "https"
                                        :peer (peer-name socket))
                           (serve-stream server ssl
                                         :scheme "https"
                                         :peer (peer-name socket))))
                  (ignore-errors (close ssl)))))))
          (redirect
           (serve-stream server raw
                         :scheme "http"
                         :peer (peer-name socket)
                         :redirect t))
          (t
           (let ((kind (preface-kind (usocket-fd socket)
                                     :timeout (min 5 (or (server-read-timeout server) 5))
                                     :running (lambda () (server-running server)))))
             (cond ((eq kind :h2)
                    (serve-http2 server socket nil
                                 :scheme "http"
                                 :peer (peer-name socket)))
                   ((eq kind :idle) nil)
                   ((eq kind :reject)
                    (reject-bad-preface (usocket-fd socket)))
                   (t
                    (serve-stream server raw
                                  :scheme "http"
                                  :peer (peer-name socket)))))))))

(defun serve-client (server socket &key tls redirect)
  (unwind-protect
       (cond ((not (admit-client server socket))
              (ignore-errors (reject-over-capacity server socket :tls tls)))
             (t
              (unwind-protect
                   (handler-case
                       (serve-admitted server socket :tls tls :redirect redirect)
                     (error (condition)
                       (error-log (server-logger server) "error"
                                  "pazuzu: connection failed: ~a" condition)))
                (forget-client server socket))))
    (ignore-errors (usocket:socket-close socket))))

(defun accept-loop (server listener &key tls redirect id)
  "Poll the listener so STOP can finish without waiting on a blocking accept.
Closing the fd from another thread does not wake accept on Linux. ID is the
accept worker number. A worker whose id is no longer below the target exits,
which is how SET-WORKERS shrinks the pool. REDIRECT passes a null id and runs
until STOP."
  (let ((fd (usocket-fd listener)))
    (loop while (and (server-running server)
                     (or (null id) (< id (server-worker-target server))))
          for ready = (poll-fds (list (list fd +pollin+)) 200)
          when (and ready (logtest (or (first ready) 0) +pollin+)
                     (server-running server))
            do (handler-case
                   (let ((client (usocket:socket-accept listener
                                                        :element-type '(unsigned-byte 8))))
                     (when client
                       (set-blocking (usocket-fd client))
                       (note-thread server
                                    (bt:make-thread
                                     (lambda ()
                                       (serve-client server client :tls tls :redirect redirect))
                                     :name "pazuzu-client"))))
                 (error ()
                   (unless (server-running server)
                     (return)))))))

(defparameter *tls-1.2* #x0303
  "OpenSSL TLS1_2_VERSION. Minimum version for this HTTPS listener (BCP 195).")

(defparameter *ssl-op-no-compression* #x20000)
(defparameter *ssl-op-no-renegotiation* #x40000000)

(defparameter *tls-1.2-ciphers*
  (concatenate 'string
               "ECDHE-ECDSA-AES128-GCM-SHA256:"
               "ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-ECDSA-AES256-GCM-SHA384:"
               "ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-CHACHA20-POLY1305:"
               "ECDHE-RSA-CHACHA20-POLY1305"))

(cffi:defcfun ("SSL_CTX_set_alpn_select_cb" %ssl-ctx-set-alpn-select-cb
               :library cl+ssl::libssl)
    :void
  (ctx :pointer)
  (callback :pointer)
  (arg :pointer))

(cffi:defcallback pazuzu-alpn-select :int
    ((ssl :pointer)
     (out :pointer)
     (outlen :pointer)
     (in :pointer)
     (inlen :unsigned-int)
     (arg :pointer))
  "Prefer h2, then http/1.1 (RFC 7301). Anything else is a fatal alert."
  (declare (ignore ssl arg))
  (let ((http11 nil)
        (index 0))
    (loop while (< index inlen) do
      (let ((length (cffi:mem-aref in :unsigned-char index)))
        (incf index)
        (when (> (+ index length) inlen)
          (return))
        (cond ((and (= length 2)
                    (string= (cffi:foreign-string-to-lisp in :offset index :count 2
                                                             :encoding :ascii)
                             "h2"))
               (setf (cffi:mem-aref out :pointer) (cffi:inc-pointer in index))
               (setf (cffi:mem-aref outlen :unsigned-char) 2)
               (return-from pazuzu-alpn-select 0))
              ((and (= length 8)
                    (string= (cffi:foreign-string-to-lisp in :offset index :count 8
                                                             :encoding :ascii)
                             "http/1.1"))
               (setf http11 (cffi:inc-pointer in index))))
        (incf index length)))
    (when http11
      (setf (cffi:mem-aref out :pointer) http11)
      (setf (cffi:mem-aref outlen :unsigned-char) 8)
      (return-from pazuzu-alpn-select 0)))
  2)

(cffi:defcallback pazuzu-alpn-h3 :int
    ((ssl :pointer)
     (out :pointer)
     (outlen :pointer)
     (in :pointer)
     (inlen :unsigned-int)
     (arg :pointer))
  "Select h3 for the QUIC listener (RFC 9114, RFC 7301)."
  (declare (ignore ssl arg))
  (let ((index 0))
    (loop while (< index inlen) do
      (let ((length (cffi:mem-aref in :unsigned-char index)))
        (incf index)
        (when (> (+ index length) inlen)
          (return))
        (when (and (= length 2)
                   (string= (cffi:foreign-string-to-lisp in :offset index :count 2
                                                            :encoding :ascii)
                            "h3"))
          (setf (cffi:mem-aref out :pointer) (cffi:inc-pointer in index))
          (setf (cffi:mem-aref outlen :unsigned-char) 2)
          (return-from pazuzu-alpn-h3 0))
        (incf index length))))
  2)

(defparameter *tls-1.3* #x0304
  "OpenSSL TLS1_3_VERSION. HTTP/3 is TLS 1.3 only.")

(defun make-h3-context (certificate private-key)
  (cl+ssl:ensure-initialized)
  (let ((context (cl+ssl:make-context
                  :certificate-chain-file (namestring certificate)
                  :private-key-file (namestring private-key)
                  :min-proto-version *tls-1.3*
                  :disabled-protocols (list cl+ssl:+ssl-op-no-sslv2+
                                            cl+ssl:+ssl-op-no-sslv3+
                                            cl+ssl:+ssl-op-no-tlsv1+
                                            cl+ssl:+ssl-op-no-tlsv1-1+
                                            cl+ssl::+ssl-op-no-tlsv1-2+)
                  :options (list cl+ssl::+ssl-op-all+
                                 *ssl-op-no-compression*
                                 *ssl-op-no-renegotiation*)
                  :verify-mode cl+ssl:+ssl-verify-none+)))
    (cl+ssl::ssl-ctx-set-max-proto-version context *tls-1.3*)
    (%ssl-ctx-set-alpn-select-cb context (cffi:callback pazuzu-alpn-h3)
                                  (cffi:null-pointer))
    context))

(defun make-https-context (certificate private-key)
  (cl+ssl:ensure-initialized)
  (let ((context (cl+ssl:make-context
                  :certificate-chain-file (namestring certificate)
                  :private-key-file (namestring private-key)
                  :min-proto-version *tls-1.2*
                  :disabled-protocols (list cl+ssl:+ssl-op-no-sslv2+
                                            cl+ssl:+ssl-op-no-sslv3+
                                            cl+ssl:+ssl-op-no-tlsv1+
                                            cl+ssl:+ssl-op-no-tlsv1-1+)
                  :options (list cl+ssl::+ssl-op-all+
                                 *ssl-op-no-compression*
                                 *ssl-op-no-renegotiation*)
                  :verify-mode cl+ssl:+ssl-verify-none+
                  :cipher-list *tls-1.2-ciphers*)))
    (%ssl-ctx-set-alpn-select-cb context (cffi:callback pazuzu-alpn-select)
                                  (cffi:null-pointer))
    context))

(defun listen-socket (address port &key (backlog 128))
  "A non-blocking listener. socket-accept returns NIL on EAGAIN, so several
workers can share it and STOP never blocks inside accept."
  (let ((socket (usocket:socket-listen address port
                                       :reuse-address t
                                       :backlog backlog
                                       :element-type '(unsigned-byte 8))))
    (setf (sb-bsd-sockets:non-blocking-mode (usocket:socket socket)) t)
    socket))

(defun spawn-acceptor (server id)
  (let ((thread (bt:make-thread
                 (lambda ()
                   (accept-loop server (server-main-listener server)
                                :tls (server-main-tls server)
                                :id id))
                 :name (format nil "pazuzu-accept-~d" id))))
    (push thread (server-threads server))
    (push (cons id thread) (server-acceptors server))
    thread))

(defun ensure-acceptors (server)
  "Start any missing accept workers. Workers above the target leave on their own."
  (bt:with-lock-held ((server-lock server))
    (setf (server-acceptors server)
          (remove-if-not (lambda (pair) (bt:thread-alive-p (cdr pair)))
                         (server-acceptors server)))
    (loop for id below (server-worker-target server)
          unless (assoc id (server-acceptors server))
            do (spawn-acceptor server id))))

(defun worker-count (server)
  "The configured number of accept workers."
  (server-worker-target server))

(defun set-workers (server count)
  "Change how many threads accept on the main listener. The change is live:
extra workers exit after their current poll, and missing workers are started."
  (unless (and (integerp count) (plusp count))
    (error "workers must be a positive integer, not ~s" count))
  (setf (server-worker-target server) count)
  (when (and (server-running server) (server-main-listener server))
    (ensure-acceptors server))
  count)

(defun metrics-loop (server listener)
  (let ((fd (usocket-fd listener)))
    (loop while (server-running server)
          for ready = (poll-fds (list (list fd +pollin+)) 200)
          when (and ready (logtest (or (first ready) 0) +pollin+)
                     (server-running server))
            do (let ((client (ignore-errors
                              (usocket:socket-accept listener
                                                     :element-type '(unsigned-byte 8)))))
                 (when client
                   (set-blocking (usocket-fd client))
                   (unwind-protect (ignore-errors (serve-metrics-client server client))
                     (ignore-errors (usocket:socket-close client))))))))

(defun read-metrics-request (stream)
  (let ((buffer (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (handler-case
        (sb-sys:with-deadline (:seconds 2)
          (loop for byte = (read-byte stream nil :eof)
                until (eq byte :eof)
                do (vector-push-extend byte buffer)
                   (when (and (>= (length buffer) 4)
                              (search #(13 10 13 10) buffer))
                     (return))))
      (sb-sys:deadline-timeout () nil))
    (babel:octets-to-string buffer :encoding :iso-8859-1)))

(defun write-latin1 (stream text)
  (write-sequence (babel:string-to-octets text :encoding :iso-8859-1) stream))

(defun metrics-authorized-p (server head)
  "True when no metrics token is configured, or HEAD carries that bearer token."
  (let ((token (server-metrics-token server)))
    (or (null token)
        (let ((expected (concatenate 'string "Bearer " token)))
          (loop for start = 0 then (1+ newline)
                for newline = (position #\Newline head :start start)
                for line = (string-right-trim '(#\Return #\Space #\Tab)
                                              (subseq head start (or newline (length head))))
                while (< start (length head))
                thereis (and (>= (length line) 14)
                             (string-equal line "authorization:" :end1 14)
                             (constant-time-equal
                              (string-left-trim '(#\Space #\Tab) (subseq line 14))
                              expected))
                when (or (null newline) (zerop (length line)))
                  return nil)))))

(defun serve-metrics-client (server client)
  (let* ((stream (usocket:socket-stream client))
         (head (read-metrics-request stream))
         (authorized (metrics-authorized-p server head))
         (wanted (and authorized
                      (>= (length head) 13)
                      (string= head "GET /metrics " :end1 13)))
         (payload (cond ((not authorized) "unauthorized")
                        (wanted (metrics-text (server-metrics server)
                                              :active (bt:with-lock-held ((server-lock server))
                                                       (connection-count server))
                                              :workers (server-worker-target server)))
                        (t "not found")))
         (body (babel:string-to-octets payload :encoding :utf-8))
         (status (cond ((not authorized) "401 Unauthorized")
                       (wanted "200 OK")
                       (t "404 Not Found"))))
    (write-latin1 stream (format nil "HTTP/1.1 ~a~c~c" status #\Return #\Newline))
    (unless authorized
      (write-latin1 stream (format nil "WWW-Authenticate: Bearer realm=\"metrics\"~c~c"
                                 #\Return #\Newline)))
    (write-latin1 stream "Content-Type: text/plain; version=0.0.4; charset=utf-8")
    (write-latin1 stream (format nil "~c~cContent-Length: ~d~c~c~c~c"
                                 #\Return #\Newline (length body)
                                 #\Return #\Newline #\Return #\Newline))
    (write-sequence body stream)
    (finish-output stream)))

(defun bind-metrics (server address port)
  (let ((listener (listen-socket address port :backlog (server-backlog server))))
    (setf (server-metrics-listener server) listener
          (server-metrics-port server) (usocket:get-local-port listener))
    listener))

(defun serve-metrics (server)
  (when (server-metrics-listener server)
    (note-thread server
                 (bt:make-thread
                  (lambda () (metrics-loop server (server-metrics-listener server)))
                  :name "pazuzu-metrics"))))

(cffi:defcfun ("initgroups" %initgroups) :int
  (user :string)
  (group :unsigned-int))

(defun drop-privileges (user group)
  "Give up the startup uid and gid after the sockets are bound.
initgroups runs only as root. A later setuid cannot regain that uid."
  (unless (or user group)
    (return-from drop-privileges nil))
  (let* ((passwd (and user (or (sb-posix:getpwnam user)
                               (error "Unknown user ~a" user))))
         (uid (and passwd (sb-posix:passwd-uid passwd)))
         (gid (cond (group (or (ignore-errors (sb-posix:group-gid (sb-posix:getgrnam group)))
                               (error "Unknown group ~a" group)))
                    (passwd (sb-posix:passwd-gid passwd)))))
    (when (and user (zerop (sb-posix:geteuid)))
      (unless (zerop (%initgroups user (or gid (sb-posix:passwd-gid passwd))))
        (error "initgroups failed for ~a" user)))
    (when gid
      (sb-posix:setgid gid))
    (when uid
      (sb-posix:setuid uid))))

(defun fd-domain (fd)
  "SO_DOMAIN (39). AF_INET is 2 and AF_INET6 is 10."
  (cffi:with-foreign-objects ((value :int) (length :unsigned-int))
    (setf (cffi:mem-ref length :unsigned-int) (cffi:foreign-type-size :int))
    (if (zerop (%getsockopt fd 1 39 value length))
        (cffi:mem-ref value :int)
        2)))

(defun listener-from-fd (fd)
  "Adopt a listening socket. Linux accept does not copy O_NONBLOCK, and
sd_listen_fds sets FD_CLOEXEC on the passed descriptors."
  (set-nonblock fd)
  (%fcntl fd 2 1)
  (let ((sock (make-instance (if (= (fd-domain fd) 10)
                                 'sb-bsd-sockets:inet6-socket
                                 'sb-bsd-sockets:inet-socket)
                             :type :stream :protocol :tcp :descriptor fd)))
    (usocket::make-stream-server-socket sock :element-type '(unsigned-byte 8))))

(defun split-colon-names (text)
  (when (and text (plusp (length text)))
    (loop for start = 0 then (1+ colon)
          for colon = (position #\: text :start start)
          collect (subseq text start (or colon (length text)))
          while colon)))

(defun take-activated-listeners ()
  "Systemd socket activation (sd_listen_fds). Returns the main, metrics, and
redirect listeners when LISTEN_PID is this process. The LISTEN_* environment
is cleared so a child does not claim the same descriptors. FileDescriptorName
values http, https, and web are the main listener. metrics and redirect select
the other two. With no names, the first descriptor is the main listener."
  (let ((pid-text (sb-ext:posix-getenv "LISTEN_PID"))
        (count-text (sb-ext:posix-getenv "LISTEN_FDS")))
    (unless (and pid-text count-text
                 (string= pid-text (princ-to-string (sb-posix:getpid))))
      (return-from take-activated-listeners (values nil nil nil)))
    (let ((count (parse-integer count-text :junk-allowed t))
          (names (split-colon-names (sb-ext:posix-getenv "LISTEN_FDNAMES")))
          (main nil)
          (metrics nil)
          (redirect nil))
      (sb-posix:unsetenv "LISTEN_PID")
      (sb-posix:unsetenv "LISTEN_FDS")
      (sb-posix:unsetenv "LISTEN_FDNAMES")
      (sb-posix:unsetenv "LISTEN_PIDFDID")
      (unless (and count (plusp count))
        (return-from take-activated-listeners (values nil nil nil)))
      (loop for index below count
            for fd = (+ 3 index)
            for name = (nth index names)
            for listener = (listener-from-fd fd)
            do (cond ((member name '("metrics") :test #'string=)
                      (setf metrics listener))
                     ((member name '("redirect") :test #'string=)
                      (setf redirect listener))
                     ((or (null name) (string= name "")
                          (member name '("http" "https" "web") :test #'string=))
                      (if main
                          (ignore-errors (usocket:socket-close listener))
                          (setf main listener)))
                     (t
                      (if main
                          (ignore-errors (usocket:socket-close listener))
                          (setf main listener)))))
      (values main metrics redirect))))

(defun parse-ipv4-host (text)
  "Four decimal octets, 0-255, with no leading zero. NIL otherwise."
  (let ((parts (uiop:split-string text :separator '(#\.))))
    (when (= (length parts) 4)
      (let ((octets (make-array 4 :element-type '(unsigned-byte 8))))
        (loop for part in parts
              for index from 0
              do (unless (and (plusp (length part))
                              (<= (length part) 3)
                              (every #'digit-char-p part)
                              (or (= (length part) 1)
                                  (char/= (char part 0) #\0)))
                   (return-from parse-ipv4-host nil))
                 (let ((number (parse-integer part)))
                   (unless (<= 0 number 255)
                     (return-from parse-ipv4-host nil))
                   (setf (aref octets index) number)))
        octets))))

(defun classify-certificate-name (text)
  "One SAN or CN string. :ip with a 4- or 16-byte vector, or :dns."
  (let ((name (string-downcase
               (string-right-trim "." (string-trim '(#\Space #\Tab) (or text ""))))))
    (cond ((zerop (length name)) nil)
          ((find #\: name)
           (let ((ip (ignore-errors (usocket:ipv6-host-to-vector name))))
             (and ip (cons :ip ip))))
          (t (let ((ip (parse-ipv4-host name)))
               (if ip
                   (cons :ip ip)
                   (cons :dns name)))))))

(defun classify-certificate-names (texts)
  "Split identity strings into a DNS list and an IP-vector list."
  (let ((dns nil)
        (ips nil))
    (dolist (text texts)
      (let ((named (classify-certificate-name text)))
        (case (car named)
          (:dns (push (cdr named) dns))
          (:ip (push (cdr named) ips)))))
    (values (nreverse dns) (nreverse ips))))

(defun certificate-identities (path)
  "DNS names and IP addresses the leaf certificate is valid for.
subjectAltName dNSName and iPAddress are that set. A certificate with
neither uses the subject CN, which is how a name-only self-signed
certificate identifies its origin."
  (cl+ssl:ensure-initialized)
  (let ((cert (cl+ssl::x509-cert-from-pem (uiop:read-file-string path))))
    (when (or (null cert) (cffi:null-pointer-p cert))
      (error "Could not read certificate ~a" path))
    (unwind-protect
         (let ((alts (remove-if-not #'stringp
                                    (cl+ssl::certificate-dns-alt-names cert))))
           (classify-certificate-names
            (if alts
                alts
                (cl+ssl:certificate-subject-common-names cert))))
      (cl+ssl:x509-free cert))))

(defvar *certificate-names* (make-hash-table :test #'eq :weakness :key)
  "Leaf identities for each server, (dns-names . ip-vectors). The table is
weak on the server so a stopped server does not keep the names alive.
The pair is replaced as a whole, so a reader sees one consistent set.")

(defun server-certificate-names (server)
  (gethash server *certificate-names*))

(defun (setf server-certificate-names) (value server)
  (setf (gethash server *certificate-names*) value))

(defun remember-certificate-names (server path)
  (multiple-value-bind (dns ips) (certificate-identities path)
    (setf (server-certificate-names server) (cons dns ips))))

(defun dns-name-covered-p (host patterns)
  "Exact match, or one leftmost-label wildcard (RFC 9525)."
  (let ((name (string-right-trim "." host)))
    (dolist (pattern patterns)
      (when (or (string= pattern name)
                (and (> (length pattern) 2)
                     (string= pattern "*." :end1 2)
                     (not (find #\* pattern :start 2))
                     (let ((suffix (subseq pattern 1)))
                       (and (> (length name) (length suffix))
                            (string= name suffix
                                     :start1 (- (length name) (length suffix)))
                            (not (position #\. name
                                           :end (- (length name)
                                                   (length suffix))))))))
        (return t)))))

(defun certificate-covers-p (names host)
  "True when NAMES covers the host in HOST, ignoring any port.
An IP reference matches only an iPAddress. A DNS name matches dNSName."
  (unless names
    (return-from certificate-covers-p nil))
  (multiple-value-bind (bare port) (split-authority (or host ""))
    (declare (ignore port))
    (unless (and bare (plusp (length bare)))
      (return-from certificate-covers-p nil))
    (let ((address (if (char= (char bare 0) #\[)
                       (ignore-errors
                        (usocket:ipv6-host-to-vector
                         (subseq bare 1 (1- (length bare)))))
                       (parse-ipv4-host bare))))
      (if address
          (member address (cdr names) :test #'equalp)
          (dns-name-covered-p bare (car names))))))

(defun https-origin-rejected (server request)
  "RFC 9110 §7.4. Reject an https target unless this certificate is valid
for that origin (§4.2.2). Cleartext is not this check. The handshake is
left alone: a missing SNI is not refused here. The body is the reason
phrase, not the target representation."
  (when (string= (or (request-scheme request) "") "https")
    (unless (certificate-covers-p (server-certificate-names server)
                                  (request-host request))
      (plain-error 421))))

(defun reload-certificates (server)
  "Load the certificate chain and private key into new TLS contexts.
OpenSSL copies the chain into each SSL object at SSL_new. The server drops
its own reference on the previous context here. A handshake that already
borrowed that context, and every SSL created from it, still holds a
reference, so the context is freed when the last of those closes."
  (let ((certificate (server-certificate server))
        (key (server-private-key server)))
    (unless (and certificate key)
      (return-from reload-certificates nil))
    (let ((https nil)
          (h3 nil))
      (unwind-protect
           (progn
             (setf https (make-https-context certificate key)
                   h3 (make-h3-context certificate key))
             (multiple-value-bind (dns ips) (certificate-identities certificate)
               (let ((old-https nil)
                     (old-h3 nil))
                 (bt:with-lock-held ((server-lock server))
                   (setf old-https (server-ssl-context server)
                         old-h3 (server-h3-context server)
                         (server-ssl-context server) https
                         (server-h3-context server) h3
                         (server-certificate-names server) (cons dns ips)
                         https nil
                         h3 nil)
                   (when (server-endpoint server)
                     (setf (h3-endpoint-context (server-endpoint server))
                           (server-h3-context server))))
                 (release-context old-https)
                 (release-context old-h3))))
        (release-context https)
        (release-context h3)))
    (error-log (server-logger server) "notice" "reloaded certificates from ~a" certificate)
    t))

(defun start (&key (address "127.0.0.1") (port 8080)
                   certificate private-key
                   hsts-max-age hsts-include-subdomains
                   redirect-port
                   (max-body (* 1024 1024))
                   (max-connections 128)
                   (max-connections-per-peer 32)
                   (read-timeout 30)
                   (workers 2)
                   (backlog 128)
                   access-log error-log
                   (metrics-address "127.0.0.1")
                   metrics-port
                   metrics-token
                   request-rate
                   user group
                   cors)
  "Start an origin server. With CERTIFICATE and PRIVATE-KEY the TCP listener is
HTTPS (TLS 1.2 minimum, ALPN h2 then http/1.1) and a UDP listener on the same
port speaks HTTP/3. REDIRECT-PORT, when given, is a cleartext listener that
redirects to HTTPS and does not send Strict-Transport-Security.
ADDRESS may be an IPv4 or IPv6 literal. WORKERS is how many threads accept on
the main listener. MAX-CONNECTIONS is the global cap and
MAX-CONNECTIONS-PER-PEER is the cap for one client address. Either cap refuses
a TCP connection with 503 and an HTTP/3 connection with CONNECTION_REFUSED.
READ-TIMEOUT is the per-request read deadline in seconds; NIL waits without a
deadline. REQUEST-RATE is how many requests one peer may send in one second.
Past that the response is 429. USER and GROUP are applied after the sockets
are bound. When LISTEN_PID names this process, LISTEN_FDS supplies the
listeners (sd_listen_fds) and those roles are not bound again. ACCESS-LOG and
ERROR-LOG are pathnames. METRICS-PORT, when set, serves Prometheus text at
/metrics. METRICS-TOKEN, when set, requires Authorization: Bearer. STOP sends
HTTP/2 GOAWAY and HTTP/3 H3_NO_ERROR before it closes sockets."
  (when (or (and certificate (not private-key))
            (and private-key (not certificate)))
    (error "HTTPS needs both a certificate chain and a private key."))
  (when (and redirect-port (not certificate))
    (error "redirect-port requires an HTTPS listener."))
  (unless (and (integerp workers) (plusp workers))
    (error "workers must be a positive integer, not ~s" workers))
  (unless (and (integerp max-connections) (>= max-connections 0))
    (error "max-connections must be a non-negative integer"))
  (unless (and (integerp max-connections-per-peer) (>= max-connections-per-peer 0))
    (error "max-connections-per-peer must be a non-negative integer"))
  (when (and metrics-token (not (stringp metrics-token)))
    (error "metrics-token must be a string, not ~s" metrics-token))
  (when (and request-rate (not (and (integerp request-rate) (>= request-rate 0))))
    (error "request-rate must be a non-negative integer or nil, not ~s" request-rate))
  (when (and user (not (stringp user)))
    (error "user must be a string, not ~s" user))
  (when (and group (not (stringp group)))
    (error "group must be a string, not ~s" group))
  (let* ((https (and certificate t))
         (server (%make-server :address address
                               :port port
                               :max-body max-body
                               :max-connections max-connections
                               :max-connections-per-peer max-connections-per-peer
                               :read-timeout read-timeout
                               :worker-target workers
                               :backlog backlog
                               :certificate (and certificate (pathname certificate))
                               :private-key (and private-key (pathname private-key))
                               :hsts-max-age hsts-max-age
                               :hsts-include-subdomains hsts-include-subdomains
                               :cors cors
                               :logger (open-logger :access-log access-log :error-log error-log)
                               :metrics-address metrics-address
                               :metrics-token metrics-token
                               :request-rate (and request-rate (plusp request-rate) request-rate)
                               :user user
                               :group group
                               :https-port (if https port nil))))
    (when https
      (setf (server-ssl-context server)
            (make-https-context certificate private-key)))
    (handler-case
        (progn
          (when https
            (remember-certificate-names server certificate))
          (multiple-value-bind (given-main given-metrics given-redirect)
              (take-activated-listeners)
            (let* ((listener (or given-main
                                 (listen-socket address port :backlog backlog)))
                   (redirect-listener nil))
              (setf (server-port server) (usocket:get-local-port listener)
                    (server-main-listener server) listener
                    (server-main-tls server) https)
              (push listener (server-listeners server))
              (when https
                (setf (server-https-port server) (server-port server)
                      (server-h3-context server) (make-h3-context certificate private-key)
                      (server-quic-socket server)
                      (http3-bind (usocket:get-local-address listener) (server-port server))))
              (when (and given-redirect (not https))
                (error "redirect requires an HTTPS listener."))
              (when (or redirect-port given-redirect)
                (setf redirect-listener
                      (or given-redirect
                          (listen-socket address redirect-port :backlog backlog)))
                (setf (server-clear-port server) (usocket:get-local-port redirect-listener))
                (push redirect-listener (server-listeners server)))
              (when given-metrics
                (setf (server-metrics-listener server) given-metrics
                      (server-metrics-port server) (usocket:get-local-port given-metrics)))
              (when (and metrics-port (not given-metrics))
                (bind-metrics server metrics-address metrics-port))
              (drop-privileges user group)
              (when (server-quic-socket server)
                (setf (server-endpoint server)
                      (start-http3 server (server-quic-socket server))))
              (ensure-acceptors server)
              (when redirect-listener
                (note-thread server
                             (bt:make-thread
                              (lambda () (accept-loop server redirect-listener :redirect t))
                              :name "pazuzu-redirect")))
              (serve-metrics server)))
          server)
      (error (condition)
        (stop server)
        (error condition)))))

(defun stop (server)
  "GOAWAY HTTP/2, close HTTP/3 with H3_NO_ERROR, then close sockets and join."
  (let ((endpoint (server-endpoint server)))
    (when endpoint
      (setf (h3-endpoint-draining endpoint) t)
      (eventfd-write (h3-endpoint-wake endpoint)))
    (setf (server-running server) nil)
    (dolist (listener (server-listeners server))
      (ignore-errors (usocket:socket-close listener)))
    (dolist (conn (bt:with-lock-held ((server-lock server))
                    (copy-list (server-h2-conns server))))
      (eventfd-write (h2-conn-wake conn)))
    (wait-for (lambda ()
                (and (null (bt:with-lock-held ((server-lock server))
                              (server-h2-conns server)))
                     (or (null endpoint) (h3-endpoint-drained endpoint))))
              2))
  ;; shutdown wakes a peer blocked in poll. close() from another thread
  ;; does not, on Linux, so join would wait out the read deadline.
  (dolist (client (copy-list (server-clients server)))
    (ignore-errors (usocket:socket-shutdown client :io))
    (ignore-errors (usocket:socket-close client)))
  (when (server-endpoint server)
    (http3-shutdown (server-endpoint server))
    (setf (server-endpoint server) nil))
  (when (server-quic-socket server)
    (ignore-errors (sb-bsd-sockets:socket-close (server-quic-socket server)))
    (setf (server-quic-socket server) nil))
  (when (server-metrics-listener server)
    (ignore-errors (usocket:socket-close (server-metrics-listener server)))
    (setf (server-metrics-listener server) nil))
  ;; Re-read the thread list. A reload in progress can spawn an acceptor
  ;; after a one-shot copy, and that acceptor must be joined too.
  (loop for guard below 1000
        for thread = (find-if (lambda (candidate)
                                (and (bt:thread-alive-p candidate)
                                     (not (eq candidate (bt:current-thread)))))
                              (server-threads server))
        while thread
        do (handler-case (sb-thread:join-thread thread :timeout 2)
             (error ()
               (error-log (server-logger server) "error"
                          "thread ~a did not exit during stop"
                          (ignore-errors (bt:thread-name thread)))
               (bt:with-lock-held ((server-lock server))
                 (setf (server-threads server)
                       (remove thread (server-threads server)))))))
  (close-logger (server-logger server))
  (setf (server-logger server) nil)
  (let ((https nil)
        (h3 nil)
        (retired nil))
    (bt:with-lock-held ((server-lock server))
      (setf https (shiftf (server-ssl-context server) nil)
            h3 (shiftf (server-h3-context server) nil)
            retired (shiftf (server-retired-contexts server) nil))
      (when (server-endpoint server)
        (setf (h3-endpoint-context (server-endpoint server)) nil)))
    (dolist (context (cons https (cons h3 retired)))
      (release-context context)))
  server)

(defparameter *mime-types*
  '(("html" . "text/html; charset=utf-8")
    ("htm" . "text/html; charset=utf-8")
    ("txt" . "text/plain; charset=utf-8")
    ("css" . "text/css; charset=utf-8")
    ("js" . "text/javascript; charset=utf-8")
    ("json" . "application/json")
    ("xml" . "application/xml")
    ("svg" . "image/svg+xml")
    ("png" . "image/png")
    ("jpg" . "image/jpeg")
    ("jpeg" . "image/jpeg")
    ("gif" . "image/gif")
    ("webp" . "image/webp")
    ("pdf" . "application/pdf")
    ("wasm" . "application/wasm")
    ("woff" . "font/woff")
    ("woff2" . "font/woff2")))

(defun mime-type (pathname)
  (or (cdr (assoc (string-downcase (or (pathname-type pathname) ""))
                  *mime-types* :test #'string=))
      "application/octet-stream"))

(defun directory-child (root relative)
  (let* ((root-dir (uiop:ensure-directory-pathname root))
         (merged (merge-pathnames relative root-dir))
         (probed (probe-file merged)))
    (when (and probed
               (ignore-errors
                 (let ((root-true (truename root-dir))
                       (file-true (truename probed)))
                   (equal (pathname-directory root-true)
                          (subseq (pathname-directory file-true)
                                  0
                                  (length (pathname-directory root-true)))))))
      probed)))

(defun static-file (root prefix request)
  (let* ((path (request-path request))
         (base (if (string= prefix "/")
                   path
                   (subseq path (length prefix))))
         (relative (if (or (string= base "") (string= base "/"))
                       "index.html"
                       (string-left-trim "/" base))))
    (when (find #\\ relative)
      (return-from static-file nil))
    (let ((candidate (directory-child root relative)))
      (cond ((and candidate (uiop:directory-pathname-p candidate))
             (directory-child root (merge-pathnames "index.html" candidate)))
            (candidate candidate)))))

(defun read-file-octets (pathname)
  (with-open-file (in pathname :element-type '(unsigned-byte 8))
    (let ((buffer (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence buffer in)
      buffer)))

(defun static-validator (root prefix request)
  "Return (mtime . length) for the file this request selects, or NIL.
The body is not read. A false If-None-Match can be decided from this
pair before the method (RFC 9110 §13.1.2)."
  (let ((file (static-file root prefix request)))
    (when (and file (probe-file file) (not (uiop:directory-pathname-p file)))
      (ignore-errors
        (with-open-file (in file :element-type '(unsigned-byte 8))
          (cons (min (or (file-write-date file) 0) (get-universal-time))
                (file-length in)))))))

(defun static-etag (mtime length)
  ;; Length plus a one-second modification time does not change for every
  ;; change to the bytes, so this is not a strong validator (RFC 9110
  ;; §§8.8.1 and 8.8.3).
  (format nil "W/\"~x-~x\"" length mtime))

(defun static-response (root prefix request)
  (let ((file (static-file root prefix request))
        (validator (static-validator root prefix request)))
    (unless (and file validator)
      (return-from static-response (plain-error 404)))
    (make-response :status 200
                   :body (read-file-octets file)
                   :content-type (mime-type file)
                   :etag (static-etag (car validator) (cdr validator))
                   :last-modified (car validator)
                   :headers '(("accept-ranges" . "bytes")))))

(defun make-static-route (url-prefix directory &key host config)
  "A GET and HEAD route that serves DIRECTORY at URL-PREFIX.
HOST nil answers every host. CONFIG is :directory or :host for a file route."
  (let ((prefix (if (string= url-prefix "/")
                    "/"
                    (string-right-trim "/" url-prefix)))
        (root directory))
    (make-route :methods '("GET" "HEAD")
                :path prefix
                :prefix t
                :host host
                :config config
                :handler (lambda (request) (static-response root prefix request))
                :etag (lambda (request)
                        (let ((validator (static-validator root prefix request)))
                          (when validator
                            (static-etag (car validator) (cdr validator)))))
                :last-modified (lambda (request)
                                 (let ((validator (static-validator root prefix request)))
                                   (and validator (car validator)))))))

(defun replace-config-routes (server kind routes)
  "Drop file routes tagged KIND and install ROUTES. Other routes stay."
  (bt:with-lock-held ((server-lock server))
    (setf (server-routes server)
          (append routes
                  (remove kind (server-routes server) :key #'route-config))))
  routes)

(defun serve-directory (server url-prefix directory)
  "Serve files under DIRECTORY at URL-PREFIX. Paths that escape the directory are 404."
  (let ((route (make-static-route url-prefix directory)))
    (bt:with-lock-held ((server-lock server))
      (setf (server-routes server)
            (cons route
                  (remove-if (lambda (old)
                               (route-replaces-p old (route-path route)))
                             (server-routes server)))))
    route))

(defun sse-response (function)
  "Stream text/event-stream. FUNCTION is called with a sender of one argument,
the event data, and keyword arguments EVENT and ID."
  (make-response :status 200
                 :content-type "text/event-stream"
                 :cache-control "no-cache"
                 :body (lambda (send)
                         (flet ((emit (data &key event id)
                                  (let ((text (with-output-to-string (out)
                                                (when id
                                                  (format out "id: ~a~%" id))
                                                (when event
                                                  (format out "event: ~a~%" event))
                                                (dolist (line (uiop:split-string
                                                               (substitute #\Newline #\Return data)
                                                               :separator '(#\Newline)))
                                                  (format out "data: ~a~%" line))
                                                (write-char #\Newline out))))
                                    (funcall send (utf8-octets text)))))
                           (funcall function #'emit)))))
