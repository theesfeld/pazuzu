(in-package #:pazuzu)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-posix))

(defvar *reload-flag* nil
  "Set from the SIGHUP handler. The reload thread applies it.")

(defvar *shutdown-flag* nil
  "Set from SIGINT and SIGTERM. MAIN returns after STOP.")

(defvar *signals-installed* nil)

(defun read-config (path)
  "Read one property list from PATH. The file is data: *read-eval* is nil.
WITH-STANDARD-IO-SYNTAX binds *read-eval* to true, so the nil binding is inside it."
  (with-open-file (in path)
    (with-standard-io-syntax
      (let ((*read-eval* nil)
            (*package* (find-package :keyword)))
        (let ((form (read in nil :eof)))
          (unless (and (listp form) (not (eq form :eof)) (evenp (length form)))
            (error "Configuration ~a must be a property list." path))
          form)))))

(defun config-value (plist key)
  (getf plist key))

(defun config-cors (value)
  (when value
    (apply #'make-cors-policy value)))

(defun config-path (value)
  (when value
    (pathname value)))

(defun known-config-key-p (key)
  (member key '(:address :port :workers :backlog
                :max-connections :max-connections-per-peer
                :read-timeout :max-body
                :certificate :private-key
                :hsts-max-age :hsts-include-subdomains
                :redirect-port :access-log :error-log
                :metrics-address :metrics-port :metrics-token
                :request-rate :user :group :cors
                :root :directories :hosts)
          :test #'eq))

(defun check-config-keys (plist)
  (loop for tail on plist by #'cddr
        for key = (car tail)
        unless (known-config-key-p key)
          do (error "Unknown configuration key ~s" key)))

(defun plist-key-p (plist key)
  (loop for tail on plist by #'cddr
        thereis (eq (car tail) key)))

(defun mapping-list (value what)
  "Nil, one entry property list, or a list of entry property lists."
  (cond ((null value) nil)
        ((not (listp value))
         (error "~a must be a list of entries, not ~s" what value))
        ((keywordp (first value))
         (list value))
        (t value)))

(defun absolute-url-prefix (value)
  (unless (and (stringp value)
               (plusp (length value))
               (char= (char value 0) #\/))
    (error "Directory :prefix must be an absolute URL path, not ~s" value))
  (when (or (find #\\ value) (find #\? value) (find #\# value) (search "//" value))
    (error "Directory :prefix ~s is not a literal URL path" value))
  (let ((prefix (if (string= value "/")
                    "/"
                    (string-right-trim "/" value))))
    (when (zerop (length prefix))
      (error "Directory :prefix ~s is empty" value))
    (dolist (segment (uiop:split-string prefix :separator '(#\/)))
      (when (or (string= segment ".") (string= segment ".."))
        (error "Directory :prefix ~s cannot contain ~a" value segment)))
    prefix))

(defun default-file-root ()
  "The base directory used when the file omits :root."
  (file-root-pathname "/var/www"))

(defun literal-directory (pathname)
  "PATHNAME as a directory, with . and .. collapsed. The directory need not exist."
  (let* ((ensured (uiop:ensure-directory-pathname pathname))
         (directory (pathname-directory ensured))
         (stack nil))
    (unless (consp directory)
      (error "A file root must be a literal directory, not ~s" pathname))
    (dolist (part (rest directory))
      (cond ((or (eq part :up) (eq part :back)
                 (and (stringp part) (string= part "..")))
             (when stack
               (pop stack)))
            ((and (stringp part) (string= part "."))
             nil)
            ((stringp part)
             (push part stack))
            (t
             (error "A file root must be a literal directory, not ~s" pathname))))
    (make-pathname :directory (cons (first directory) (nreverse stack))
                   :name nil :type nil :version nil
                   :defaults ensured)))

(defun file-root-pathname (value)
  "The :root base. It must be an absolute path."
  (unless (or (stringp value) (pathnamep value))
    (error ":root must be an absolute directory, not ~s" value))
  (let ((directory (literal-directory (pathname value))))
    (unless (uiop:absolute-pathname-p directory)
      (error ":root must be an absolute directory, not ~s" value))
    directory))

(defun resolve-file-root (value base)
  "An absolute entry root is used as written. A relative one is under BASE.
. is BASE itself."
  (unless (or (stringp value) (pathnamep value))
    (error "A file root must be a path, not ~s" value))
  (let ((path (pathname value)))
    (literal-directory
     (if (uiop:absolute-pathname-p path)
         path
         (merge-pathnames path (uiop:ensure-directory-pathname base))))))

(defun config-host-name (value)
  "A hostname with no port. Comparison ignores case and a trailing dot."
  (unless (and (stringp value) (plusp (length value)))
    (error "Host :host must be a name, not ~s" value))
  (when (or (find #\/ value) (find #\\ value) (find #\Space value)
            (find #\@ value) (find #\: value) (find #\? value) (find #\# value))
    (error "Host :host must be a hostname without a port, not ~s" value))
  (let ((name (string-right-trim "." (string-downcase value))))
    (when (zerop (length name))
      (error "Host :host must be a name, not ~s" value))
    name))

(defun parse-directory-entry (entry base)
  (unless (and (listp entry) (evenp (length entry)) (keywordp (first entry)))
    (error "A directory entry must be a :prefix and :root property list, not ~s" entry))
  (let ((prefix nil)
        (root nil)
        (saw-prefix nil)
        (saw-root nil))
    (loop for (key value) on entry by #'cddr
          do (case key
               (:prefix (setf prefix value saw-prefix t))
               (:root (setf root value saw-root t))
               (t (error "Unknown directory key ~s" key))))
    (unless saw-prefix
      (error "A directory entry needs :prefix, not ~s" entry))
    (unless saw-root
      (error "A directory entry needs :root, not ~s" entry))
    (cons (absolute-url-prefix prefix) (resolve-file-root root base))))

(defun parse-host-entry (entry base)
  (unless (and (listp entry) (evenp (length entry)) (keywordp (first entry)))
    (error "A host entry must be a :host and :root property list, not ~s" entry))
  (let ((host nil)
        (root nil)
        (saw-host nil)
        (saw-root nil))
    (loop for (key value) on entry by #'cddr
          do (case key
               (:host (setf host value saw-host t))
               (:root (setf root value saw-root t))
               (t (error "Unknown host key ~s" key))))
    (unless saw-host
      (error "A host entry needs :host, not ~s" entry))
    (unless saw-root
      (error "A host entry needs :root, not ~s" entry))
    (cons (config-host-name host) (resolve-file-root root base))))

(defun reject-duplicate-keys (entries what)
  (let ((seen nil))
    (dolist (entry entries entries)
      (when (member (car entry) seen :test #'string=)
        (error "Duplicate ~a ~s" what (car entry)))
      (push (car entry) seen))))

(defun directory-config-routes (value base)
  (mapcar (lambda (entry)
            (make-static-route (car entry) (cdr entry) :config :directory))
          (reject-duplicate-keys
           (mapcar (lambda (entry) (parse-directory-entry entry base))
                   (mapping-list value "directories"))
           "directory prefix")))

(defun host-config-routes (value base)
  (mapcar (lambda (entry)
            (make-static-route "/" (cdr entry) :host (car entry) :config :host))
          (reject-duplicate-keys
           (mapcar (lambda (entry) (parse-host-entry entry base))
                   (mapping-list value "hosts"))
           "host")))

(defstruct file-plan
  base
  (base-p nil)
  directory-spec
  (directories-p nil)
  directory-routes
  host-spec
  (hosts-p nil)
  host-routes)

(defun mapping-spec (value what)
  "The raw mapping to store. NIL when the mapping is empty."
  (and (mapping-list value what) value))

(defun plan-one-mapping (present value saved root-p missing-clears base builder label)
  "Resolve one mapping before any slot changes.
A present key replaces it. Start with the key omitted installs nothing.
A root change resolves a saved mapping again."
  (let ((install (or present missing-clears (and root-p saved))))
    (if install
        (let ((chosen (if present value (if missing-clears nil saved))))
          (values (mapping-spec chosen label)
                  t
                  (funcall builder chosen base)))
        (values nil nil nil))))

(defun plan-file-mappings (server plist &key missing-clears)
  "Resolve :root, :directories, and :hosts before any slot changes."
  (let* ((root-p (plist-key-p plist :root))
         (base (cond (root-p (file-root-pathname (getf plist :root)))
                     (missing-clears (default-file-root))
                     (t (or (server-file-root server) (default-file-root)))))
         (base-p (or root-p missing-clears)))
    (multiple-value-bind (directory-spec directories-p directory-routes)
        (plan-one-mapping (plist-key-p plist :directories)
                          (getf plist :directories)
                          (server-directory-spec server)
                          root-p missing-clears base
                          #'directory-config-routes "directories")
      (multiple-value-bind (host-spec hosts-p host-routes)
          (plan-one-mapping (plist-key-p plist :hosts)
                            (getf plist :hosts)
                            (server-host-spec server)
                            root-p missing-clears base
                            #'host-config-routes "hosts")
        (make-file-plan :base base
                        :base-p base-p
                        :directory-spec directory-spec
                        :directories-p directories-p
                        :directory-routes directory-routes
                        :host-spec host-spec
                        :hosts-p hosts-p
                        :host-routes host-routes)))))

(defun commit-file-mappings (server plan)
  (when (file-plan-base-p plan)
    (setf (server-file-root server) (file-plan-base plan)))
  (when (file-plan-directories-p plan)
    (setf (server-directory-spec server) (file-plan-directory-spec plan))
    (replace-config-routes server :directory (file-plan-directory-routes plan)))
  (when (file-plan-hosts-p plan)
    (setf (server-host-spec server) (file-plan-host-spec plan))
    (replace-config-routes server :host (file-plan-host-routes plan))))

(defun apply-file-mappings (server plist &key missing-clears)
  "Mount :directories and :hosts under :root.
A present key replaces that whole mapping.
An omitted key stays as it is, unless MISSING-CLEARS, which is start.
A present :root resolves saved relative paths again."
  (commit-file-mappings
   server (plan-file-mappings server plist :missing-clears missing-clears)))

(defun start-arguments (plist)
  "Keyword arguments for START. A listen port in the file is used only at start.
Every present key is passed, including an explicit NIL such as :read-timeout.
:root, directory, and host mappings are applied by START-FROM-CONFIG, not by START."
  (check-config-keys plist)
  (let ((args nil))
    (loop for (key value) on plist by #'cddr
          do (case key
               (:address (setf (getf args :address) value))
               (:port (setf (getf args :port) value))
               (:workers (setf (getf args :workers) value))
               (:backlog (setf (getf args :backlog) value))
               (:max-connections (setf (getf args :max-connections) value))
               (:max-connections-per-peer
                (setf (getf args :max-connections-per-peer) value))
               (:read-timeout (setf (getf args :read-timeout) value))
               (:max-body (setf (getf args :max-body) value))
               (:certificate (setf (getf args :certificate) (config-path value)))
               (:private-key (setf (getf args :private-key) (config-path value)))
               (:hsts-max-age (setf (getf args :hsts-max-age) value))
               (:hsts-include-subdomains
                (setf (getf args :hsts-include-subdomains) value))
               (:redirect-port (setf (getf args :redirect-port) value))
               (:access-log (setf (getf args :access-log) (config-path value)))
               (:error-log (setf (getf args :error-log) (config-path value)))
               (:metrics-address (setf (getf args :metrics-address) value))
               (:metrics-port (setf (getf args :metrics-port) value))
               (:metrics-token (setf (getf args :metrics-token) value))
               (:request-rate (setf (getf args :request-rate) value))
               (:user (setf (getf args :user) value))
               (:group (setf (getf args :group) value))
               (:cors (setf (getf args :cors) (config-cors value)))
               ((:root :directories :hosts))
               (t (error "Unknown configuration key ~s" key))))
    args))

(defun start-from-config (path)
  "Start a server from the property list in PATH."
  (let ((plist (read-config path))
        (server nil))
    (setf server (apply #'start (start-arguments plist)))
    (setf (server-config-path server) (pathname path))
    (handler-case (apply-file-mappings server plist :missing-clears t)
      (error (condition)
        (ignore-errors (stop server))
        (error condition)))
    server))

(defun apply-runtime-config (server plist)
  "Apply the keys that can change without binding a new socket.
File mappings are parsed before any slot changes, so a bad :root leaves
workers and routes as they were."
  (check-config-keys plist)
  (let ((plan (plan-file-mappings server plist)))
    (apply-runtime-keys server plist)
    (commit-file-mappings server plan))
  (when (server-logger server)
    (reopen-logger (server-logger server))))

(defun apply-runtime-keys (server plist)
  (loop for (key value) on plist by #'cddr
        do (case key
             (:workers (set-workers server value))
             (:max-connections
              (unless (and (integerp value) (>= value 0))
                (error "max-connections must be a non-negative integer"))
              (setf (server-max-connections server) value))
             (:max-connections-per-peer
              (unless (and (integerp value) (>= value 0))
                (error "max-connections-per-peer must be a non-negative integer"))
              (setf (server-max-connections-per-peer server) value))
             (:read-timeout (setf (server-read-timeout server) value))
             (:max-body (setf (server-max-body server) value))
             (:hsts-max-age (setf (server-hsts-max-age server) value))
             (:hsts-include-subdomains
              (setf (server-hsts-include-subdomains server) value))
             (:certificate (setf (server-certificate server) (config-path value)))
             (:private-key (setf (server-private-key server) (config-path value)))
             (:metrics-token
              (unless (or (null value) (stringp value))
                (error "metrics-token must be a string or nil"))
              (setf (server-metrics-token server) value))
             (:request-rate
              (unless (or (null value) (and (integerp value) (>= value 0)))
                (error "request-rate must be a non-negative integer or nil"))
              (setf (server-request-rate server) (and value (plusp value) value)))
             ((:user :group)
              (error-log (server-logger server) "notice"
                         "ignored ~s on reload; restart to change the account" key))
             ((:address :port :redirect-port :backlog :metrics-address :metrics-port)
              (error-log (server-logger server) "notice"
                         "ignored ~s on reload; restart to change the listener" key))
             (:access-log
              (when (server-logger server)
                (setf (logger-access-path (server-logger server)) (config-path value))))
             (:error-log
              (when (server-logger server)
                (setf (logger-error-path (server-logger server)) (config-path value))))
             (:cors (setf (server-cors server) (config-cors value)))
             ((:root :directories :hosts)))))

(defun reload (server)
  "Re-read the configuration file when the server was started from one,
reopen the logs, and load the certificate chain again."
  (when (server-config-path server)
    (apply-runtime-config server (read-config (server-config-path server))))
  (reload-certificates server)
  server)

(defparameter +pazuzu-version+ "0.1.0")

(defvar *shutdown-drain-seconds* 2)

(defparameter *usage*
  "Usage: pazuzu --config PATH [--log-level notice|error]
       pazuzu --check-config PATH
       pazuzu --version

--config PATH        Configuration file. A bare path is also accepted.
--check-config PATH  Read the file and exit. No sockets are opened.
--version            Print the version and exit.
--log-level LEVEL    notice (default) or error. error hides notice lines.
--help               Print this text and exit.

SIGINT and SIGTERM stop accepting, drain in-flight connections, then exit.
SIGHUP reloads workers, limits, timeouts, HSTS, CORS, log paths, the metrics
token, the certificate chain, and the file mappings. The listen address,
ports, backlog, and the process account stay as they were at start.
Restart the process to change those.
")

(defun pazuzu-init-library-path ()
  "Search the install lib directory before foreign libraries are reopened.
The directory sits next to the executable: ../lib/pazuzu."
  (let* ((runtime sb-ext:*runtime-pathname*)
         (dir (ignore-errors
                (merge-pathnames "../lib/pazuzu/"
                                 (make-pathname :directory (pathname-directory
                                                            (truename runtime)))))))
    (when (and dir (probe-file dir))
      (pushnew dir cffi:*foreign-library-directories* :test #'equal))))

(pushnew 'pazuzu-init-library-path sb-ext:*init-hooks*)

(cffi:defcfun ("socket" %notify-socket) :int
  (domain :int) (type :int) (protocol :int))

(cffi:defcfun ("sendto" %notify-sendto) :long
  (fd :int) (buffer :pointer) (length :unsigned-long) (flags :int)
  (address :pointer) (address-length :unsigned-int))

(defun sd-notify (state)
  "Tell systemd the service state when NOTIFY_SOCKET is set.
The message is one datagram, which is the sd_notify protocol. A missing
variable does nothing, so a process started by hand is unchanged."
  (let ((name (sb-ext:posix-getenv "NOTIFY_SOCKET")))
    (unless (and name (plusp (length name)))
      (return-from sd-notify nil))
    (let* ((abstract (char= (char name 0) #\@))
           (path (if abstract (subseq name 1) name))
           (fd (%notify-socket 1 2 0)))
      (when (< fd 0)
        (return-from sd-notify nil))
      (unwind-protect
           (cffi:with-foreign-object (addr :uint8 110)
             (foreign-zero addr 110)
             (setf (cffi:mem-ref addr :uint16) 1)
             (if abstract
                 (setf (cffi:mem-ref addr :uint8 2) 0)
                 nil)
             (loop for index below (min (length path) 100)
                   for byte = (char-code (char path index))
                   do (setf (cffi:mem-ref addr :uint8
                                          (+ index (if abstract 3 2)))
                            byte))
             (let* ((octets (babel:string-to-octets state :encoding :utf-8))
                    (addrlen (if abstract
                                 (+ 3 (length path))
                                 (+ 2 (length path) 1))))
               (cffi:with-pointer-to-vector-data (pointer octets)
                 (%notify-sendto fd pointer (length octets) 0 addr addrlen))))
        (ignore-errors (posix-close fd))))))

(defun check-config-file (path)
  "Read PATH and reject a bad key or a bad file mapping. No socket is opened."
  (let ((plist (read-config path)))
    (check-config-keys plist)
    (start-arguments plist)
    (let ((base (if (plist-key-p plist :root)
                    (file-root-pathname (getf plist :root))
                    (default-file-root))))
      (when (plist-key-p plist :directories)
        (directory-config-routes (getf plist :directories) base))
      (when (plist-key-p plist :hosts)
        (host-config-routes (getf plist :hosts) base)))
    t))

(defun parse-command (argv)
  "Plist of :config :check :version :help :log-level from ARGV."
  (let ((config nil)
        (check nil)
        (version nil)
        (help nil)
        (level nil))
    (loop for rest = argv then (cdr rest)
          while rest
          for arg = (first rest)
          do (cond
               ((or (string= arg "--help") (string= arg "-h"))
                (setf help t))
               ((string= arg "--version")
                (setf version t))
               ((string= arg "--config")
                (unless (second rest)
                  (error "missing path after --config~%~a" *usage*))
                (setf config (second rest)
                      rest (cdr rest)))
               ((string= arg "--check-config")
                (setf check t)
                (when (and (second rest)
                           (plusp (length (second rest)))
                           (char/= (char (second rest) 0) #\-))
                  (setf config (second rest)
                        rest (cdr rest))))
               ((string= arg "--log-level")
                (unless (second rest)
                  (error "missing level after --log-level~%~a" *usage*))
                (setf level (second rest)
                      rest (cdr rest)))
               ((and (plusp (length arg)) (char/= (char arg 0) #\-))
                (when config
                  (error "unexpected argument ~a~%~a" arg *usage*))
                (setf config arg))
               (t (error "unknown argument ~a~%~a" arg *usage*))))
    (list :config config :check check :version version :help help :log-level level)))

(defun install-signals ()
  (unless *signals-installed*
    (setf *signals-installed* t)
    (sb-sys:enable-interrupt sb-posix:sighup
                             (lambda (signal info context)
                               (declare (ignore signal info context))
                               (setf *reload-flag* t)))
    (flet ((shutdown (signal info context)
             (declare (ignore signal info context))
             (setf *shutdown-flag* t)))
      (sb-sys:enable-interrupt sb-posix:sigterm #'shutdown)
      (sb-sys:enable-interrupt sb-posix:sigint #'shutdown))))

(defun enable-reload (server)
  "Arrange for SIGHUP to reload SERVER and for SIGINT and SIGTERM to stop MAIN.
A thread owned by SERVER performs the reload, because the signal handler only
sets a flag."
  (install-signals)
  (note-thread server
               (bt:make-thread
                (lambda ()
                  (loop while (server-running server)
                        do (when *reload-flag*
                             (setf *reload-flag* nil)
                             (handler-case (reload server)
                               (error (condition)
                                 (error-log (server-logger server) "error"
                                            "reload failed: ~a" condition))))
                           (sleep 0.1)))
                :name "pazuzu-reload")))

(defun command-config-path (argv)
  "The configuration file named by --config, or the first argument that is a file."
  (loop for rest on argv
        when (and (string= (first rest) "--config") (second rest))
          return (second rest)
        when (and (plusp (length (first rest)))
                  (char/= (char (first rest) 0) #\-)
                  (probe-file (first rest)))
          return (first rest)))

(defun main (&optional (argv (rest sb-ext:*posix-argv*)))
  "Run the server in the foreground from a configuration file.
--check-config and --version do not listen. SIGINT and SIGTERM drain
connections and stop the process. SIGHUP reloads the runtime keys."
  (let ((command (parse-command argv)))
    (when (getf command :log-level)
      (set-log-level (getf command :log-level)))
    (cond
      ((getf command :help)
       (write-string *usage* *standard-output*)
       (finish-output *standard-output*))
      ((getf command :version)
       (format t "pazuzu ~a~%" +pazuzu-version+)
       (finish-output *standard-output*))
      ((getf command :check)
       (let ((path (getf command :config)))
         (unless path
           (error "missing configuration path~%~a" *usage*))
         (check-config-file path)
         (format t "configuration ok~%")
         (finish-output *standard-output*)))
      (t
       (let ((path (getf command :config)))
         (unless path
           (error "missing configuration path~%~a" *usage*))
         (setf *shutdown-flag* nil
               *shutdown-drain-seconds* 10
               *access-on-stdout* t)
         (let ((server (start-from-config path)))
           (enable-reload server)
           (error-log (server-logger server) "notice"
                      "listening on ~a port ~d with ~d workers"
                      (server-address server) (server-port server)
                      (worker-count server))
           (sd-notify "READY=1")
           (unwind-protect
                (loop until *shutdown-flag*
                      do (sleep 0.2))
             (sd-notify "STOPPING=1")
             (stop server :drain-seconds *shutdown-drain-seconds*))))))))
