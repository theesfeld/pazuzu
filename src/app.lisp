(in-package #:pazuzu)

(defmacro defroute (server methods path handler &rest rest &key prefix etag
                          last-modified middleware)
  "Register HANDLER with ADD-ROUTE.
A symbol is quoted, so the route keeps the name and a later DEFUN is live.
A lambda or other form is stored as that function."
  (declare (ignore prefix etag last-modified middleware))
  `(add-route ,server ,methods ,path
              ,(cond ((and (consp handler)
                           (eq (first handler) 'quote))
                      handler)
                     ((symbolp handler) `',handler)
                     (t handler))
              ,@rest))

(defun localhost-address-p (address)
  (member address '("127.0.0.1" "::1" "localhost") :test #'string=))

(defvar *lisp-listeners* nil
  "((interface . port) ...) already started in this image.")

(defun ensure-listener-system (system package)
  (unless (find-package package)
    (unless (asdf:find-system system nil)
      (error "~a is not available. Install it before opening a listener." system))
    (asdf:load-system system)))

(defun start-listener (&key (interface :swank) port (address "127.0.0.1"))
  "Start a Swank or Slynk server on ADDRESS and PORT.
ADDRESS must be localhost. The call does nothing when that interface and
port are already open. Neither listener starts unless something calls this."
  (unless (and (integerp port) (<= 1 port 65535))
    (error "Listener port must be an integer from 1 to 65535, not ~s" port))
  (unless (localhost-address-p address)
    (error "The Lisp listener binds to localhost only, not ~a." address))
  (let ((key (cons interface port)))
    (when (member key *lisp-listeners* :test #'equal)
      (return-from start-listener port))
    (ecase interface
      (:swank
       (ensure-listener-system :swank :swank)
       (uiop:symbol-call :swank :create-server
                         :port port :dont-close t :interface address))
      (:slynk
       (ensure-listener-system :slynk :slynk)
       (uiop:symbol-call :slynk :create-server
                         :port port :dont-close t :interface address)))
    (push key *lisp-listeners*)
    port))

(defclass lack-body (sb-gray:fundamental-binary-input-stream)
  ((data :initarg :data :reader lack-body-data)
   (pos :initform 0 :accessor lack-body-pos)))

(defmethod stream-element-type ((stream lack-body))
  '(unsigned-byte 8))

(defmethod sb-gray:stream-read-byte ((stream lack-body))
  (if (< (lack-body-pos stream) (length (lack-body-data stream)))
      (prog1 (aref (lack-body-data stream) (lack-body-pos stream))
        (incf (lack-body-pos stream)))
      :eof))

(defmethod sb-gray:stream-read-sequence ((stream lack-body) sequence
                                         &optional (start 0) end)
  (let ((end (or end (length sequence)))
        (data (lack-body-data stream)))
    (loop while (and (< start end)
                     (< (lack-body-pos stream) (length data)))
          do (setf (elt sequence start) (aref data (lack-body-pos stream)))
             (incf start)
             (incf (lack-body-pos stream)))
    start))

(defun lack-host (host)
  "Hostname from a Host header, without the port."
  (cond ((or (null host) (zerop (length host))) "")
        ((char= (char host 0) #\[)
         (subseq host 1 (or (position #\] host) (length host))))
        (t (subseq host 0 (or (position #\: host) (length host))))))

(defun lack-headers (request)
  (let ((table (make-hash-table :test #'equal)))
    (dolist (pair (request-headers request))
      (let ((name (string-downcase (car pair))))
        (setf (gethash name table)
              (if (gethash name table)
                  (format nil "~a, ~a" (gethash name table) (cdr pair))
                  (cdr pair)))))
    table))

(defun request-to-lack (request)
  "A Lack environment for REQUEST. :raw-body is a binary stream over the
buffered body. :headers is a hash table of lowercase names."
  (let ((body (request-body request)))
    (list :request-method (intern (string-upcase (request-method request)) :keyword)
          :request-uri (or (request-target request) (request-path request))
          :script-name ""
          :path-info (request-path request)
          :query-string (or (request-query request) "")
          :server-name (lack-host (request-host request))
          :server-port 80
          :server-protocol (if (= (request-http-version request) 20) :http/2 :http/1.1)
          :url-scheme (intern (string-downcase (or (request-scheme request) "http")) :keyword)
          :remote-addr (or (request-peer request) "")
          :content-type (request-header request "content-type")
          :content-length (and body (length body))
          :headers (lack-headers request)
          :raw-body (make-instance 'lack-body
                                  :data (or body (ascii-octets ""))))))

(defun lack-header-alist (headers)
  (loop for (name value) on headers by #'cddr
        collect (cons (string-downcase (string name))
                      (if (stringp value) value (princ-to-string value)))))

(defun lack-response-body (body)
  (cond ((or (null body) (and (consp body) (null (first body)))) "")
        ((stringp body) body)
        ((pathnamep body) body)
        ((typep body '(vector (unsigned-byte 8))) body)
        ((and (consp body) (every #'stringp body))
         (apply #'concatenate 'string body))
        ((and (consp body)
              (every (lambda (part) (typep part '(vector (unsigned-byte 8)))) body))
         (apply #'concatenate '(vector (unsigned-byte 8)) body))
        (t (error "Lack response body ~s is not a string, octets, pathname, or list of those."
                  body))))

(defun lack-response (result)
  "Turn a Lack (status headers body) list into a pazuzu response."
  (unless (and (listp result) (>= (length result) 3) (integerp (first result)))
    (error "Lack app returned ~s, not (status headers body)." result))
  (make-response :status (first result)
                 :headers (lack-header-alist (second result))
                 :body (lack-response-body (third result))))

(defun mount-lack (server app &key (path "/") methods middleware)
  "Route PATH, and paths under it, to a Lack application.
APP is a function of a Lack environment and returns (status headers body).
No Clack system is loaded. The calling convention is Lack's."
  (add-route server
             (or methods '(:get :head :post :put :delete :patch :options))
             path
             (lambda (request)
               (lack-response (funcall app (request-to-lack request))))
             :prefix t
             :middleware middleware))
