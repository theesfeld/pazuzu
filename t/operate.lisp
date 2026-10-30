;;; Configuration, production, and account checks.

(in-package #:pazuzu/tests)

(defun ipv6-tests (certificate private-key)
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "IPv6 HTTP/1.1"
       (multiple-value-bind (version body)
           (curl-version (format nil "http://[::1]:~d/" (pazuzu::server-port server))
                         "--http1.1" "-g")
         (unless (string= version "1.1")
           (fail "version ~s body ~s" version body))
         (unless (and body (search "pazuzu" body))
           (fail "body ~s" body)))))
   :address "::1")
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "IPv6 HTTP/3"
       (multiple-value-bind (version body)
           (curl-version (format nil "https://[::1]:~d/" (pazuzu::server-port server))
                         "--http3-only" "-k" "-g")
         (unless (string= version "3")
           (fail "version ~s body ~s" version body))
         (unless (and body (search "pazuzu" body))
           (fail "body ~s" body))))
     (quic-dont-fragment-test server))
   :address "::1" :certificate certificate :private-key private-key))

(defun accept-thread-count ()
  (count-if (lambda (thread)
              (let ((name (ignore-errors (bt:thread-name thread))))
                (and name
                     (search "pazuzu-accept-" name)
                     (bt:thread-alive-p thread))))
            (bt:all-threads)))

(defun wait-until (predicate)
  (loop repeat 40
        when (funcall predicate)
          do (return t)
        do (sleep 0.05)))

(defun write-config (path plist)
  (with-open-file (out path :direction :output :if-exists :supersede :if-does-not-exist :create)
    (let ((*print-case* :downcase))
      (prin1 plist out))
    (terpri out)))

(defun file-text (path)
  (alexandria:read-file-into-string path))

(defun file-octets (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((buffer (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence buffer in)
      buffer)))

(defun expect-file (reply path)
  (expect-status reply 200)
  (unless (equalp (reply-body reply) (file-octets path))
    (fail "body ~s is not ~a" (ignore-errors (body-text reply)) path))
  (let ((type (pazuzu::mime-type path)))
    (unless (string= (or (header reply "content-type") "") type)
      (fail "content-type ~s for ~a" (header reply "content-type") path))))

(defun write-utf8 (path text)
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :if-exists :supersede
                       :if-does-not-exist :create
                       :element-type '(unsigned-byte 8))
    (write-sequence (octets text) out)))

(defun logged-listen-port (text)
  (let ((mark (search "listening on" text :from-end t)))
    (when mark
      (let ((at (search " port " text :start2 mark)))
        (when at
          (parse-integer text :start (+ at 6) :junk-allowed t))))))

(defun exercise-config-main (config log file host path)
  (setf pazuzu::*shutdown-flag* nil)
  (let ((done nil)
        (err nil))
    (bt:make-thread
     (lambda ()
       (handler-case (pazuzu:main (list config))
         (error (condition) (setf err condition)))
       (setf done t))
     :name "pazuzu-config-main")
    (unless (wait-until (lambda ()
                          (and (probe-file log)
                               (search "listening on" (file-text log)))))
      (fail "no listener ~s" (ignore-errors (file-text log))))
    (let ((port (logged-listen-port (file-text log))))
      (unless port
        (fail "port ~s" (file-text log)))
      (expect-file (exchange port
                             (request-text (format nil "GET ~a HTTP/1.1" path)
                                           (format nil "Host: ~a" host)))
                   file))
    (require :sb-posix)
    (sb-posix:kill (sb-posix:getpid) sb-posix:sigterm)
    (unless (wait-until (lambda () done))
      (fail "main did not return, shutdown ~s" pazuzu::*shutdown-flag*))
    (when err
      (fail "main error ~a" err))))

(defun cli-tests ()
  (check "the version line names pazuzu"
    (let ((text (with-output-to-string (*standard-output*)
                  (pazuzu:main '("--version")))))
      (unless (and (search "pazuzu" text) (search "0.1.0" text))
        (fail "version ~s" text))))
  (check "check-config accepts a file and rejects an unknown key"
    (let ((path "/tmp/pazuzu-check-config.lisp"))
      (write-config path '(:address "127.0.0.1" :port 9 :workers 1))
      (let ((text (with-output-to-string (*standard-output*)
                    (pazuzu:main (list "--check-config" path)))))
        (unless (search "configuration ok" text)
          (fail "check ~s" text)))
      (write-config path '(:nope t))
      (handler-case
          (progn (pazuzu:main (list "--check-config" path))
                 (fail "unknown key accepted"))
        (error () nil))))
  (check "an unknown command line flag is rejected"
    (handler-case
        (progn (pazuzu:main '("--not-a-flag"))
               (fail "accepted an unknown flag"))
      (error () nil)))
  (check "log level error hides a notice"
    (let ((pazuzu::*log-level* :error)
          (lines nil))
      (let ((*error-output* (make-string-output-stream)))
        (pazuzu::error-log nil "notice" "hidden-notice")
        (pazuzu::error-log nil "error" "shown-error")
        (setf lines (get-output-stream-string *error-output*)))
      (when (search "hidden-notice" lines)
        (fail "notice leaked ~s" lines))
      (unless (search "shown-error" lines)
        (fail "error missing ~s" lines))))
  (check "sd_notify sends READY to NOTIFY_SOCKET"
    (let* ((path "/tmp/pazuzu-notify.sock")
           (sock (make-instance 'sb-bsd-sockets:local-socket :type :datagram)))
      (ignore-errors (delete-file path))
      (unwind-protect
           (progn
             (sb-bsd-sockets:socket-bind sock path)
             (sb-posix:setenv "NOTIFY_SOCKET" path 1)
             (pazuzu::sd-notify "READY=1")
             (let ((buf (make-array 32 :element-type '(unsigned-byte 8))))
               (multiple-value-bind (got len)
                   (sb-bsd-sockets:socket-receive sock buf nil)
                 (declare (ignore got))
                 (unless (string= (babel:octets-to-string (subseq buf 0 len)
                                                          :encoding :utf-8)
                                  "READY=1")
                   (fail "notify ~s" (subseq buf 0 len))))))
        (sb-posix:unsetenv "NOTIFY_SOCKET")
        (ignore-errors (sb-bsd-sockets:socket-close sock))
        (ignore-errors (delete-file path))))))

(defun config-file-tests ()
  (check "the example configuration shows file mappings and serves none"
    (let* ((example (asdf:system-relative-pathname :pazuzu "examples/config.lisp"))
           (readme (asdf:system-relative-pathname :pazuzu "README.md"))
           (text (file-text example))
           (plist (pazuzu:read-config example)))
      (unless (and (search ":directories" text) (search ":hosts" text)
                   (search ":prefix" text) (search ":root" text)
                   (search ":root \"html\"" text) (search ":root \"docs\"" text)
                   (search ":root \"www\"" text) (search ":root \"blog\"" text))
        (fail "example does not show the file keys"))
      (when (search "/var/www/" text)
        (fail "example hardcodes a directory under /var/www"))
      (unless (equal (getf plist :root) "/var/www")
        (fail "example root ~s" (getf plist :root)))
      (when (or (getf plist :directories) (getf plist :hosts))
        (fail "example mounts directories ~s hosts ~s"
              (getf plist :directories) (getf plist :hosts)))
      (let ((keys (file-text readme)))
        (unless (and (search ":directories" keys) (search ":hosts" keys)
                     (search "The default is `/var/www`." keys))
          (fail "documented key list omits the file root")))))
  (check "a configuration #. form does not run"
    (let ((path "/tmp/pazuzu-config-eval.lisp"))
      (write-lines path '("(:directories #.(error \"eval\"))"))
      (handler-case
          (progn (pazuzu:read-config path) (fail "read-eval ran"))
        (error () nil))))
  (check "an unknown configuration key is rejected"
    (let ((path "/tmp/pazuzu-config-unknown.lisp"))
      (write-config path '(:directories () :nope t))
      (handler-case
          (progn (pazuzu:start-from-config path) (fail "unknown key was accepted"))
        (error () nil))))
  (check "a configuration root must be an absolute directory"
    (let ((path "/tmp/pazuzu-config-relative-root.lisp"))
      (dolist (root '("site" nil))
        (write-config path `(:address "127.0.0.1" :port 0 :workers 1 :root ,root))
        (handler-case
            (progn (pazuzu:start-from-config path)
                   (fail "root ~s was accepted" root))
          (error () nil)))))
  (check "a configuration file with no directory or host answers 404"
    (let ((path "/tmp/pazuzu-config-empty.lisp"))
      (write-config path '(:address "127.0.0.1" :port 0 :workers 1))
      (let ((server (pazuzu:start-from-config path)))
        (unwind-protect
             (progn
               (unless (equal (pathname-directory (pazuzu::server-file-root server))
                              '(:absolute "var" "www"))
                 (fail "file root ~s" (pazuzu::server-file-root server)))
               (expect-status (exchange (pazuzu:server-port server)
                                        (request-text "GET / HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              404))
          (ignore-errors (pazuzu:stop server))))))
  (check "a configuration root resolves relative files and a root-only reload keeps the port"
    (let* ((base #p"/tmp/pazuzu-config-base/")
           (first-root (merge-pathnames "a/" base))
           (second-root (merge-pathnames "b/" base))
           (absolute (merge-pathnames "abs/" base))
           (config "/tmp/pazuzu-config-base.lisp"))
      (write-utf8 (merge-pathnames "site/hello.txt" first-root) "base-a-hello")
      (write-utf8 (merge-pathnames "here.txt" first-root) "base-a-here")
      (write-utf8 (merge-pathnames "www/page.txt" first-root) "base-a-page")
      (write-utf8 (merge-pathnames "site/hello.txt" second-root) "base-b-hello")
      (write-utf8 (merge-pathnames "here.txt" second-root) "base-b-here")
      (write-utf8 (merge-pathnames "www/page.txt" second-root) "base-b-page")
      (write-utf8 (merge-pathnames "hello.txt" absolute) "base-abs-hello")
      (write-config config
                    `(:address "127.0.0.1"
                      :port 0
                      :workers 1
                      :root ,(namestring first-root)
                      :directories ((:prefix "/site" :root "site")
                                    (:prefix "/here" :root "."))
                      :hosts ((:host "www.example.test" :root "www/")
                              (:host "abs.example.test" :root ,(namestring absolute)))))
      (let ((server (pazuzu:start-from-config config)))
        (unwind-protect
             (let ((port (pazuzu:server-port server)))
               (unless (equal (pathname-directory (pazuzu::server-file-root server))
                              '(:absolute "tmp" "pazuzu-config-base" "a"))
                 (fail "file root ~s" (pazuzu::server-file-root server)))
               (expect-status (exchange port
                                        (request-text "GET / HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              404)
               (expect-status (exchange port
                                        (request-text "GET /here.txt HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              404)
               (expect-file (exchange port
                                      (request-text "GET /site/hello.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                            (merge-pathnames "site/hello.txt" first-root))
               (expect-file (exchange port
                                      (request-text "GET /here/here.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                            (merge-pathnames "here.txt" first-root))
               (expect-file (exchange port
                                      (request-text "GET /page.txt HTTP/1.1"
                                                    "Host: www.example.test"))
                            (merge-pathnames "www/page.txt" first-root))
               (expect-file (exchange port
                                      (request-text "GET /hello.txt HTTP/1.1"
                                                    "Host: abs.example.test"))
                            (merge-pathnames "hello.txt" absolute))
               (write-config config `(:root ,(namestring second-root)))
               (pazuzu:reload server)
               (unless (= (pazuzu:server-port server) port)
                 (fail "port changed from ~d to ~d" port (pazuzu:server-port server)))
               (unless (equal (pathname-directory (pazuzu::server-file-root server))
                              '(:absolute "tmp" "pazuzu-config-base" "b"))
                 (fail "reloaded root ~s" (pazuzu::server-file-root server)))
               (expect-file (exchange port
                                      (request-text "GET /site/hello.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                            (merge-pathnames "site/hello.txt" second-root))
               (expect-file (exchange port
                                      (request-text "GET /here/here.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                            (merge-pathnames "here.txt" second-root))
               (expect-file (exchange port
                                      (request-text "GET /page.txt HTTP/1.1"
                                                    "Host: www.example.test"))
                            (merge-pathnames "www/page.txt" second-root))
               (expect-file (exchange port
                                      (request-text "GET /hello.txt HTTP/1.1"
                                                    "Host: abs.example.test"))
                            (merge-pathnames "hello.txt" absolute))
               (write-config config '(:workers 1))
               (pazuzu:reload server)
               (unless (and (= (pazuzu:server-port server) port)
                            (equal (pathname-directory (pazuzu::server-file-root server))
                                   '(:absolute "tmp" "pazuzu-config-base" "b")))
                 (fail "omitted root ~s port ~d"
                       (pazuzu::server-file-root server)
                       (pazuzu:server-port server)))
               (expect-file (exchange port
                                      (request-text "GET /site/hello.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                            (merge-pathnames "site/hello.txt" second-root)))
          (ignore-errors (pazuzu:stop server))))))
  (let* ((root #p"/tmp/pazuzu-config-serve/")
         (site (merge-pathnames "site/" root))
         (site-sub (merge-pathnames "sub/" site))
         (assets (merge-pathnames "assets/" root))
         (site-next (merge-pathnames "site-next/" root))
         (www (merge-pathnames "www/" root))
         (blog (merge-pathnames "blog/" root))
         (www-next (merge-pathnames "www-next/" root))
         (secret (merge-pathnames "secret.txt" root))
         (config "/tmp/pazuzu-config-serve.lisp"))
    (write-utf8 (merge-pathnames "hello.txt" site) "site-hello")
    (write-utf8 (merge-pathnames "index.html" site) "site-index")
    (write-utf8 (merge-pathnames "style.css" site) "site-css")
    (write-utf8 (merge-pathnames "index.html" site-sub) "site-sub-index")
    (write-utf8 (merge-pathnames "other.txt" assets) "assets-other")
    (write-utf8 (merge-pathnames "hello.txt" site-next) "site-next-hello")
    (write-utf8 (merge-pathnames "page.txt" www) "www-page")
    (write-utf8 (merge-pathnames "page.txt" blog) "blog-page")
    (write-utf8 (merge-pathnames "page.txt" www-next) "www-next-page")
    (write-utf8 secret "SECRET-BYTES")
    (write-config config
                  `(:address "127.0.0.1"
                    :port 0
                    :workers 2
                    :backlog 16
                    :max-connections 40
                    :max-connections-per-peer 4
                    :read-timeout 12
                    :directories ((:prefix "/site" :root ,(namestring site))
                                  (:prefix "/assets" :root ,(namestring assets)))
                    :hosts ((:host "www.example.test" :root ,(namestring www))
                            (:host "blog.example.test" :root ,(namestring blog)))))
    (let ((server (pazuzu:start-from-config config)))
      (unwind-protect
           (progn
             (pazuzu:add-route server :get "/app"
                               (lambda (request)
                                 (declare (ignore request))
                                 (pazuzu:text-response "from-lisp")))
             (check "configuration listener keys are honored"
               (unless (and (= (pazuzu:worker-count server) 2)
                            (= (pazuzu::server-backlog server) 16)
                            (= (pazuzu::server-max-connections server) 40)
                            (= (pazuzu::server-max-connections-per-peer server) 4)
                            (= (pazuzu::server-read-timeout server) 12)
                            (string= (pazuzu:server-address server) "127.0.0.1"))
                 (fail "workers ~d backlog ~d address ~s"
                       (pazuzu:worker-count server)
                       (pazuzu::server-backlog server)
                       (pazuzu:server-address server))))
             (check "a configuration file serves directory prefixes"
               (let ((port (pazuzu:server-port server)))
                 (expect-file (exchange port
                                        (request-text "GET /site/hello.txt HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "hello.txt" site))
                 (expect-file (exchange port
                                        (request-text "GET /site/style.css HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "style.css" site))
                 (expect-file (exchange port
                                        (request-text "GET /assets/other.txt HTTP/1.1"
                                                      "Host: blog.example.test"))
                              (merge-pathnames "other.txt" assets))))
             (check "a directory URL returns that directory's index.html"
               (let ((port (pazuzu:server-port server)))
                 (expect-file (exchange port
                                        (request-text "GET /site HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "index.html" site))
                 (expect-file (exchange port
                                        (request-text "GET /site/ HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "index.html" site))
                 (expect-file (exchange port
                                        (request-text "GET /site/sub/ HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "index.html" site-sub))))
             (check "a path that escapes a configured directory is 404"
               (let ((reply (exchange (pazuzu:server-port server)
                                      (request-text "GET /site/../secret.txt HTTP/1.1"
                                                    "Host: 127.0.0.1"))))
                 (expect-status reply 404)
                 (when (search "SECRET-BYTES"
                               (or (ignore-errors (body-text reply)) ""))
                   (fail "escaped body ~s" (body-text reply)))))
             (check "each configured host serves only its own files"
               (let ((port (pazuzu:server-port server)))
                 (expect-file (exchange port
                                        (request-text "GET /page.txt HTTP/1.1"
                                                      "Host: www.example.test"))
                              (merge-pathnames "page.txt" www))
                 (expect-file (exchange port
                                        (request-text "GET /page.txt HTTP/1.1"
                                                      "Host: WWW.Example.Test:9"))
                              (merge-pathnames "page.txt" www))
                 (expect-file (exchange port
                                        (request-text "GET /page.txt HTTP/1.1"
                                                      "Host: blog.example.test"))
                              (merge-pathnames "page.txt" blog))
                 (let ((crossed (exchange port
                                          (request-text "GET /page.txt HTTP/1.1"
                                                        "Host: blog.example.test"))))
                   (when (search "www-page" (or (ignore-errors (body-text crossed)) ""))
                     (fail "blog received www ~s" (body-text crossed))))))
             (check "an unnamed host does not receive a configured host's file"
               (let ((reply (exchange (pazuzu:server-port server)
                                      (request-text "GET /page.txt HTTP/1.1"
                                                    "Host: other.example.test"))))
                 (expect-status reply 404)
                 (let ((text (or (ignore-errors (body-text reply)) "")))
                   (when (or (search "www-page" text) (search "blog-page" text))
                     (fail "unnamed body ~s" text)))))
             (check "reloading a configuration file switches served files and keeps the port"
               (let ((port (pazuzu:server-port server)))
                 (write-config config
                               `(:address "127.0.0.2"
                                 :port 1
                                 :workers 3
                                 :backlog 99
                                 :max-connections 40
                                 :max-connections-per-peer 4
                                 :read-timeout 12
                                 :directories ((:prefix "/site" :root ,(namestring site-next))
                                               (:prefix "/assets" :root ,(namestring assets)))
                                 :hosts ((:host "www.example.test" :root ,(namestring www-next))
                                         (:host "blog.example.test" :root ,(namestring blog)))))
                 (pazuzu:reload server)
                 (unless (= (pazuzu:server-port server) port)
                   (fail "port changed from ~d to ~d" port (pazuzu:server-port server)))
                 (unless (and (= (pazuzu:worker-count server) 3)
                              (= (pazuzu::server-backlog server) 16)
                              (string= (pazuzu:server-address server) "127.0.0.1"))
                   (fail "workers ~d backlog ~d address ~s"
                         (pazuzu:worker-count server)
                         (pazuzu::server-backlog server)
                         (pazuzu:server-address server)))
                 (expect-file (exchange port
                                        (request-text "GET /site/hello.txt HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "hello.txt" site-next))
                 (expect-file (exchange port
                                        (request-text "GET /page.txt HTTP/1.1"
                                                      "Host: www.example.test"))
                              (merge-pathnames "page.txt" www-next))
                 (let ((lisp (exchange port
                                       (request-text "GET /app HTTP/1.1"
                                                     "Host: 127.0.0.1"))))
                   (expect-status lisp 200)
                   (unless (string= (body-text lisp) "from-lisp")
                     (fail "lisp route ~s" (body-text lisp))))
                 (write-config config
                               `(:workers 2
                                 :max-connections 40))
                 (pazuzu:reload server)
                 (unless (= (pazuzu:server-port server) port)
                   (fail "port changed from ~d to ~d" port (pazuzu:server-port server)))
                 (expect-file (exchange port
                                        (request-text "GET /site/hello.txt HTTP/1.1"
                                                      "Host: 127.0.0.1"))
                              (merge-pathnames "hello.txt" site-next))
                 (expect-file (exchange port
                                        (request-text "GET /page.txt HTTP/1.1"
                                                      "Host: blog.example.test"))
                              (merge-pathnames "page.txt" blog)))))
        (ignore-errors (pazuzu:stop server)))))
  (let* ((root #p"/tmp/pazuzu-config-https/")
         (covered (merge-pathnames "covered/" root))
         (rejected (merge-pathnames "rejected/" root))
         (config "/tmp/pazuzu-config-https.lisp"))
    (write-utf8 (merge-pathnames "page.txt" covered) "covered-page")
    (write-utf8 (merge-pathnames "page.txt" rejected) "rejected-page")
    (multiple-value-bind (cert key) (make-cert #p"/tmp/pazuzu-config-cert/" "config")
      (write-config config
                    `(:address "127.0.0.1"
                      :port 0
                      :workers 1
                      :certificate ,(namestring cert)
                      :private-key ,(namestring key)
                      :hosts ((:host "example.com" :root ,(namestring covered))
                              (:host "other.example" :root ,(namestring rejected)))))
      (let ((server (pazuzu:start-from-config config)))
        (unwind-protect
             (check "a host the certificate does not cover is still 421"
               (let ((port (pazuzu:server-port server)))
                 (expect-file (https-request port
                                             (request-text "GET /page.txt HTTP/1.1"
                                                           "Host: example.com"))
                              (merge-pathnames "page.txt" covered))
                 (let ((reply (https-request port
                                             (request-text "GET /page.txt HTTP/1.1"
                                                           "Host: other.example"))))
                   (expect-status reply 421)
                   (when (search "rejected-page"
                                 (or (ignore-errors (body-text reply)) ""))
                     (fail "421 body ~s" (body-text reply))))))
          (ignore-errors (pazuzu:stop server))))))
  (let ((root #p"/tmp/pazuzu-config-main/")
        (first-config "/tmp/pazuzu-config-main-1.lisp")
        (second-config "/tmp/pazuzu-config-main-2.lisp")
        (first-log "/tmp/pazuzu-config-main-1.log")
        (second-log "/tmp/pazuzu-config-main-2.log"))
    (let ((first-file (merge-pathnames "one/only.txt" root))
          (second-file (merge-pathnames "two/only.txt" root)))
      (write-utf8 first-file "main-one")
      (write-utf8 second-file "main-two")
      (ignore-errors (delete-file first-log))
      (ignore-errors (delete-file second-log))
      (write-config first-config
                    `(:address "127.0.0.1" :port 0 :workers 1
                      :error-log ,first-log
                      :directories ((:prefix "/m" :root ,(namestring (merge-pathnames "one/" root))))))
      (write-config second-config
                    `(:address "127.0.0.1" :port 0 :workers 1
                      :error-log ,second-log
                      :directories ((:prefix "/m" :root ,(namestring (merge-pathnames "two/" root))))))
      (check "main serves a configured directory"
        (exercise-config-main first-config first-log first-file "127.0.0.1" "/m/only.txt"))
      (check "a second main serves a configured directory"
        (exercise-config-main second-config second-log second-file "127.0.0.1" "/m/only.txt")))))

(defun production-tests ()
  (check "configuration is data"
    (let ((path "/tmp/pazuzu-not-code.lisp"))
      (write-lines path '("(:port #.(error \"eval\"))"))
      (handler-case
          (progn (pazuzu:read-config path) (fail "read-eval ran"))
        (error () nil))
      (write-config path '(:nope t))
      (handler-case
          (progn (pazuzu:start-from-config path) (fail "unknown key was accepted"))
        (error () nil))))
  (let ((access "/tmp/pazuzu-access.log")
        (error-log "/tmp/pazuzu-error.log")
        (config "/tmp/pazuzu-config.lisp"))
    (ignore-errors (delete-file access))
    (ignore-errors (delete-file error-log))
    (write-config config
                  `(:address "127.0.0.1"
                    :port 0
                    :workers 2
                    :backlog 64
                    :max-connections 40
                    :max-connections-per-peer 4
                    :read-timeout 12
                    :max-body 1048576
                    :access-log ,access
                    :error-log ,error-log
                    :metrics-address "127.0.0.1"
                    :metrics-port 0))
    (let ((server (pazuzu:start-from-config config)))
      (unwind-protect
           (progn
             (pazuzu:add-route server :get "/"
                               (lambda (request)
                                 (declare (ignore request))
                                 (pazuzu:text-response "pazuzu")))
             (check "configuration file starts the server"
               (unless (and (= (pazuzu:worker-count server) 2)
                            (= (pazuzu::server-max-connections server) 40)
                            (= (pazuzu::server-max-connections-per-peer server) 4)
                            (= (pazuzu::server-read-timeout server) 12)
                            (plusp (pazuzu:server-metrics-port server)))
                 (fail "workers ~d metrics ~d"
                       (pazuzu:worker-count server)
                       (pazuzu:server-metrics-port server)))
               (let ((reply (exchange (pazuzu:server-port server)
                                      (request-text "GET / HTTP/1.1"
                                                    "Host: 127.0.0.1"
                                                    "User-Agent: a\"b"
                                                    "Referer: http://example.test/"))))
                 (expect-status reply 200)))
             (check "combined access log"
               (let ((text (file-text access)))
                 (unless (search "127.0.0.1 - - " text)
                   (fail "log ~s" text))
                 (unless (search "\"GET / HTTP/1.1\" 200 " text)
                   (fail "log ~s" text))
                 (unless (search "a\\\"b" text)
                   (fail "user-agent ~s" text))
                 (unless (search "http://example.test/" text)
                   (fail "referer ~s" text))))
             (check "Prometheus /metrics"
               (let* ((before (exchange (pazuzu:server-metrics-port server)
                                        (request-text "GET /metrics HTTP/1.1"
                                                      "Host: 127.0.0.1")))
                      (other (exchange (pazuzu:server-metrics-port server)
                                       (request-text "GET /other HTTP/1.1"
                                                     "Host: 127.0.0.1"))))
                 (expect-status before 200)
                 (expect-status other 404)
                 (unless (search "text/plain; version=0.0.4"
                                 (header before "content-type"))
                   (fail "content-type ~s" (header before "content-type")))
                 (let ((body (body-text before))
                       (type-at (search "# TYPE pazuzu_requests_total counter"
                                        (body-text before)))
                       (sample-at (search "pazuzu_requests_total{"
                                          (body-text before))))
                   (unless (and type-at sample-at (< type-at sample-at))
                     (fail "exposition ~s" body))
                   (unless (search "pazuzu_request_duration_seconds_bucket{le=\"+Inf\"}"
                                   body)
                     (fail "histogram ~s" body))
                   (unless (search "# TYPE pazuzu_connections_active gauge" body)
                     (fail "gauge ~s" body))
                   (unless (search "pazuzu_workers 2" body)
                     (fail "workers ~s" body)))))
             (check "reload changes workers and ignores the listen port"
               (write-config config
                             `(:address "127.0.0.1"
                               :port 1
                               :workers 4
                               :max-connections 40
                               :max-connections-per-peer 4
                               :read-timeout 12
                               :access-log ,access
                               :error-log ,error-log
                               :metrics-port 9))
               (let ((port (pazuzu:server-port server)))
                 (pazuzu:reload server)
                 (unless (= (pazuzu:worker-count server) 4)
                   (fail "workers ~d" (pazuzu:worker-count server)))
                 (unless (= (pazuzu:server-port server) port)
                   (fail "port changed from ~d to ~d" port (pazuzu:server-port server)))
                 (unless (wait-until (lambda () (= (accept-thread-count) 4)))
                   (fail "acceptors ~d" (accept-thread-count)))
                 (unless (search "ignored :PORT" (file-text error-log))
                   (fail "error log ~s" (file-text error-log)))
                 (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                             "Host: 127.0.0.1"))
                                200)))
             (check "SIGHUP reloads the configuration file"
               (write-config config
                             `(:workers 1
                               :max-connections 40
                               :max-connections-per-peer 4
                               :access-log ,access
                               :error-log ,error-log))
               (pazuzu:enable-reload server)
               (require :sb-posix)
               (sb-posix:kill (sb-posix:getpid) sb-posix:sighup)
               (unless (wait-until (lambda () (= (pazuzu:worker-count server) 1)))
                 (fail "workers ~d" (pazuzu:worker-count server)))
               (unless (wait-until (lambda () (= (accept-thread-count) 1)))
                 (fail "acceptors ~d" (accept-thread-count)))))
        (ignore-errors (pazuzu:stop server)))))
  (check "main returns on SIGTERM"
    (let ((path "/tmp/pazuzu-main.lisp")
          (log "/tmp/pazuzu-main-error.log")
          (done nil)
          (err nil))
      (ignore-errors (delete-file log))
      (write-config path
                    `(:address "127.0.0.1" :port 0 :workers 1 :error-log ,log))
      (setf pazuzu::*shutdown-flag* nil)
      (bt:make-thread
       (lambda ()
         (handler-case (pazuzu:main (list path))
           (error (condition) (setf err condition)))
         (setf done t))
       :name "pazuzu-main-test")
      (unless (wait-until (lambda () (and (probe-file log)
                                          (search "listening on" (file-text log)))))
        (fail "no listener log ~s" (ignore-errors (file-text log))))
      (require :sb-posix)
      (sb-posix:kill (sb-posix:getpid) sb-posix:sigterm)
      (unless (wait-until (lambda () done))
        (fail "main did not return, shutdown ~s" pazuzu::*shutdown-flag*))
      (when err
        (fail "main error ~a" err))))
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "per-peer connection cap answers 503"
       (let ((held (connect (pazuzu:server-port server))))
         (unwind-protect
              (let ((stream (usocket:socket-stream held)))
                (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                                stream)
                (finish-output stream)
                (expect-status (read-reply stream) 200)
                (expect-status (exchange (pazuzu:server-port server)
                                         (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                               503))
           (ignore-errors (usocket:socket-close held)))))
     (check "set-workers grows and shrinks the accept pool"
       (pazuzu:set-workers server 3)
       (unless (wait-until (lambda () (= (accept-thread-count) 3)))
         (fail "grow ~d" (accept-thread-count)))
       (expect-status (exchange (pazuzu:server-port server)
                                (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                      200)
       (pazuzu:set-workers server 1)
       (unless (wait-until (lambda () (= (accept-thread-count) 1)))
         (fail "shrink ~d" (accept-thread-count)))))
   :workers 1
   :max-connections-per-peer 1)
  (call-with-server
   (lambda (server)
     (check "per-peer cap of zero rejects the first connection"
       (expect-status (exchange (pazuzu:server-port server)
                                (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                      503)))
   :max-connections-per-peer 0)
  (call-with-server
   (lambda (server)
     (check "metrics token requires the bearer"
       (let ((missing (exchange (pazuzu:server-metrics-port server)
                                (request-text "GET /metrics HTTP/1.1"
                                              "Host: 127.0.0.1")))
             (wrong (exchange (pazuzu:server-metrics-port server)
                              (request-text "GET /metrics HTTP/1.1"
                                            "Host: 127.0.0.1"
                                            "Authorization: Bearer nope")))
             (ok (exchange (pazuzu:server-metrics-port server)
                           (request-text "GET /metrics HTTP/1.1"
                                         "Host: 127.0.0.1"
                                         "Authorization: Bearer secret-token"))))
         (expect-status missing 401)
         (expect-status wrong 401)
         (expect-status ok 200)
         (let ((challenge (or (header missing "www-authenticate") ""))
               (again (exchange (pazuzu:server-metrics-port server)
                                (request-text "GET /metrics HTTP/1.1"
                                              "Host: 127.0.0.1"))))
           (expect-status again 401)
           (unless (and (>= (length challenge) 7)
                        (string-equal challenge "Bearer" :end1 6)
                        (char= (char challenge 6) #\Space)
                        (search "realm=" challenge))
             (fail "www-authenticate ~s" challenge))
           (unless (string= challenge (or (header again "www-authenticate") ""))
             (fail "second challenge ~s" (header again "www-authenticate")))))))
   :metrics-port 0
   :metrics-token "secret-token"))

(defun tls-subject (port)
  (command-text "timeout" "3" "openssl" "s_client" "-connect"
                (format nil "127.0.0.1:~d" port)
                "-servername" "127.0.0.1"))

(defun http3-connection-cap-test (cert key)
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "HTTP/3 shares the connection cap"
       (multiple-value-bind (out err code)
           (uiop:run-program
            (list "curl" "-sS" "--http3-only" "-k"
                  "--max-time" "4" "--connect-timeout" "2"
                  "-o" "/tmp/pazuzu-h3cap-body" "-w" "%{http_version}"
                  (format nil "https://127.0.0.1:~d/" (pazuzu:server-port server)))
            :output :string :error-output :string :ignore-error-status t)
         (when (string= (string-trim '(#\Newline #\Return #\Space) out) "3")
           (fail "http3 admitted under a zero cap exit ~s out ~s err ~s" code out err)))))
   :certificate cert
   :private-key key
   :max-connections 0))

(defun certificate-reload-test (cert key)
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "certificate reload keeps the live session and serves the new chain"
       (let ((before (tls-subject (pazuzu:server-port server))))
         (unless (search "subject=CN=before" before)
           (fail "subject before reload ~s" before)))
       (multiple-value-bind (ssl reply socket)
           (https-exchange (pazuzu:server-port server))
         (expect-status reply 200)
         (unwind-protect
              (progn
                (make-cert #p"/tmp/pazuzu-cert/" "after")
                (pazuzu:reload server)
                (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                                ssl)
                (finish-output ssl)
                (expect-status (read-reply ssl) 200))
           (ignore-errors (close ssl))
           (ignore-errors (usocket:socket-close socket))))
       (let ((after (tls-subject (pazuzu:server-port server))))
         (unless (search "subject=CN=after" after)
           (fail "subject after reload ~s" after)))
       (multiple-value-bind (version body)
           (curl-version (format nil "https://127.0.0.1:~d/" (pazuzu:server-port server))
                         "--http3-only" "-k")
         (unless (and (string= version "3") body (search "pazuzu" body))
           (fail "http3 after reload version ~s body ~s" version body)))
       (let ((subject (h3-peer-subject (pazuzu:server-port server))))
         (unless (search "CN=after" subject)
           (fail "http3 subject ~s" subject)))))
   :certificate cert :private-key key))

(defun https-exchange (port)
  (let* ((socket (connect port))
         (ssl (cl+ssl:make-ssl-client-stream (usocket:socket-stream socket)
                                             :verify nil
                                             :hostname "127.0.0.1"
                                             :external-format nil
                                             :alpn-protocols '("http/1.1"))))
    (write-sequence (octets (request-text "GET / HTTP/1.1" "Host: 127.0.0.1")) ssl)
    (finish-output ssl)
    (values ssl (read-reply ssl) socket)))

(defun https-request (port text)
  (let* ((socket (connect port))
         (ssl (cl+ssl:make-ssl-client-stream (usocket:socket-stream socket)
                                             :verify nil
                                             :hostname "127.0.0.1"
                                             :external-format nil
                                             :alpn-protocols '("http/1.1"))))
    (unwind-protect
         (progn
           (write-sequence (octets text) ssl)
           (finish-output ssl)
           (read-reply ssl))
      (ignore-errors (close ssl))
      (ignore-errors (usocket:socket-close socket)))))

(defun websocket-tls-test (port)
  "RFC 6455 §4.2.2. On an HTTPS port the opening handshake and the
following data frame run through the TLS tunnel."
  (check "a WebSocket on HTTPS stays inside TLS"
    (let* ((socket (connect port))
           (ssl (cl+ssl:make-ssl-client-stream (usocket:socket-stream socket)
                                              :verify nil
                                              :hostname "127.0.0.1"
                                              :external-format nil
                                              :alpn-protocols '("http/1.1"))))
      (unwind-protect
           (progn
             (write-sequence
              (octets (request-text
                       "GET /ws HTTP/1.1"
                       "Host: 127.0.0.1"
                       "Upgrade: websocket"
                       "Connection: Upgrade"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
                       "Sec-WebSocket-Version: 13"))
              ssl)
             (finish-output ssl)
             (let ((reply (read-reply-headers-only ssl)))
               (unless (= (reply-status reply) 101)
                 (fail "status ~d" (reply-status reply)))
               (unless (string= (header reply "sec-websocket-accept")
                                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                 (fail "accept ~s" (header reply "sec-websocket-accept"))))
             (write-masked-frame ssl 1 "hi")
             (let ((echo (read-server-text ssl)))
               (unless (string= echo "hi")
                 (fail "echo ~s" echo))))
        (ignore-errors (close ssl))
        (ignore-errors (usocket:socket-close socket))))))

(defun mixed-coding-test (port)
  "RFC 9113 §10.6 and RFC 9114 §10.6. On a secure connection a body that
mixes confidential and attacker-controlled data is not content-coded.
An ordinary compressible body on the same listener still may be."
  (check "a mixed secure body is not content-coded"
    (let ((mixed (https-request port (request-text "GET /mixed?user=attacker HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Accept-Encoding: gzip")))
          (plain (https-request port (request-text "GET /flow-body HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "Accept-Encoding: gzip"))))
      (expect-status mixed 200)
      (when (header mixed "content-encoding")
        (fail "mixed coding ~s" (header mixed "content-encoding")))
      (when (header mixed "pazuzu-mixed")
        (fail "marker ~s" (header mixed "pazuzu-mixed")))
      (unless (search "secret-value:user=attacker" (body-text mixed))
        (fail "mixed body ~s" (body-text mixed)))
      (expect-status plain 200)
      (unless (string-equal (or (header plain "content-encoding") "") "gzip")
        (fail "ordinary coding ~s" (header plain "content-encoding"))))))

(defun certificate-origin-test (port)
  "RFC 9110 §7.4. The certificate covers 127.0.0.1. other.example is a
different origin, so that representation is not returned. A second
connection sees the same rejection. SNI stays 127.0.0.1; the handshake
is not refused for the Host value."
  (check "an https origin the certificate does not cover is 421"
    (let ((matched (https-request port (request-text "GET / HTTP/1.1"
                                                     "Host: 127.0.0.1")))
          (rejected (https-request port (request-text "GET / HTTP/1.1"
                                                      "Host: other.example")))
          (again (https-request port (request-text "GET / HTTP/1.1"
                                                   "Host: other.example"))))
      (expect-status matched 200)
      (unless (search "pazuzu" (body-text matched))
        (fail "matched body ~s" (body-text matched)))
      (expect-status rejected 421)
      (when (search "pazuzu" (or (ignore-errors (body-text rejected)) ""))
        (fail "rejected body ~s" (body-text rejected)))
      (expect-status again 421)
      (unless (= (reply-status rejected) (reply-status again))
        (fail "second status ~d" (reply-status again)))
      (when (search "pazuzu" (or (ignore-errors (body-text again)) ""))
        (fail "second body ~s" (body-text again))))))

(defun https-empty-host-test (port)
  "RFC 9110 §4.2.2. An https URI with an empty host is invalid."
  (check "an empty https host identifier is rejected"
    (expect-status (https-request port (request-text "GET https:/// HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                   400)
    (expect-status (https-request port (request-text "GET / HTTP/1.1"
                                                    "Host:"))
                   400)))

(defun aioquic-python ()
  (let ((python "/tmp/pazuzu-h3venv/bin/python"))
    (unless (probe-file python)
      (fail "aioquic interpreter ~a is missing" python))
    python))

(defun aioquic-continue (port)
  "HTTP/3 Expect: 100-continue. The body is withheld until status 100.
A missing target is 404 with no body."
  (let ((script "/tmp/pazuzu-h3-continue.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, HeadersState"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._events = {}"
                   "        self._waiters = {}"
                   "        self._continues = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        for http_event in self._http.handle_event(event):"
                   "            stream_id = getattr(http_event, 'stream_id', None)"
                   "            if stream_id is None:"
                   "                continue"
                   "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b'', 'continued': False, 'www': b''})"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                status = None"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        status = int(value)"
                   "                    elif name == b'www-authenticate':"
                   "                        bucket['www'] = value"
                   "                if status == 100 and not http_event.stream_ended:"
                   "                    bucket['continued'] = True"
                   "                    # aioquic 1.2 records the first HEADERS as the"
                   "                    # final response and then rejects :status on the"
                   "                    # real one. 100 is not final (RFC 9110 §15.2)."
                   "                    state = self._http._get_or_create_stream(stream_id)"
                   "                    state.headers_recv_state = HeadersState.INITIAL"
                   "                    state.content_length = 0"
                   "                    state.expected_content_length = None"
                   "                    waiter = self._continues.get(stream_id)"
                   "                    if waiter is not None and not waiter.done():"
                   "                        waiter.set_result(True)"
                   "                else:"
                   "                    bucket['status'] = status"
                   "                    if http_event.stream_ended:"
                   "                        self._finish(stream_id)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                bucket['data'] += http_event.data"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   ""
                   "    def _finish(self, stream_id):"
                   "        waiter = self._waiters.get(stream_id)"
                   "        if waiter is not None and not waiter.done():"
                   "            waiter.set_result(self._events[stream_id])"
                   ""
                   "    def _open(self, path, extra, method=b'POST'):"
                   "        stream_id = self._quic.get_next_available_stream_id()"
                   "        done = self._loop.create_future()"
                   "        cont = self._loop.create_future()"
                   "        self._waiters[stream_id] = done"
                   "        self._continues[stream_id] = cont"
                   "        headers = ["
                   "            (b':method', method),"
                   "            (b':scheme', b'https'),"
                   "            (b':authority', f'127.0.0.1:{sys.argv[1]}'.encode()),"
                   "            (b':path', path),"
                   "        ] + extra"
                   "        self._http.send_headers(stream_id, headers, end_stream=False)"
                   "        self.transmit()"
                   "        return stream_id, done, cont"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "        sid, done, cont = client._open(b'/no-such-continue', ["
                   "            (b'content-length', b'4'),"
                   "            (b'expect', b'100-continue'),"
                   "        ])"
                   "        missing = await asyncio.wait_for(done, 4)"
                   "        print(f'MISS {missing[\"status\"]} continued={missing[\"continued\"]}')"
                   "        sid, done, cont = client._open(b'/echo', ["
                   "            (b'content-length', b'4'),"
                   "            (b'expect', b'100-continue'),"
                   "        ])"
                   "        await asyncio.wait_for(cont, 4)"
                   "        client._http.send_data(sid, b'echo', end_stream=True)"
                   "        client.transmit()"
                   "        echoed = await asyncio.wait_for(done, 4)"
                   "        print(f'ECHO {echoed[\"status\"]} {echoed[\"data\"].decode()} continued={echoed[\"continued\"]}')"
                   "        sid, done, cont = client._open(b'/basic-continue', ["
                   "            (b'content-length', b'4'),"
                   "            (b'expect', b'100-continue'),"
                   "        ])"
                   "        auth = await asyncio.wait_for(done, 4)"
                   "        print(f'AUTH {auth[\"status\"]} continued={auth[\"continued\"]} www={auth[\"www\"].decode()}')"
                   "        sid, done, cont = client._open(b'/basic-continue', ["
                   "            (b'content-length', b'4'),"
                   "            (b'expect', b'100-continue'),"
                   "            (b'authorization', b'Basic YWRhOnNlY3JldA=='),"
                   "        ])"
                   "        await asyncio.wait_for(cont, 4)"
                   "        client._http.send_data(sid, b'ping', end_stream=True)"
                   "        client.transmit()"
                   "        authed = await asyncio.wait_for(done, 4)"
                   "        print(f'AUTHED {authed[\"status\"]} {authed[\"data\"].decode()} continued={authed[\"continued\"]}')"
                   "        sid, done, cont = client._open(b'/item', ["
                   "            (b'content-length', b'4'),"
                   "            (b'expect', b'100-continue'),"
                   "            (b'if-match', b'\"no\"'),"
                   "        ], b'PUT')"
                   "        matched = await asyncio.wait_for(done, 4)"
                   "        print(f'MATCH {matched[\"status\"]} continued={matched[\"continued\"]}')"
                   "        sid, done, cont = client._open(b'/echo', ["
                   "            (b'content-length', b'4'),"
                   "            (b'expect', b'100-continue'),"
                   "            (b'content-encoding', b'nosuch'),"
                   "        ])"
                   "        coded = await asyncio.wait_for(done, 4)"
                   "        print(f'CODE {coded[\"status\"]} continued={coded[\"continued\"]}')"
                   "        client.close()"
                   ""
                   "asyncio.run(main())"))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string
                          :error-output :string
                          :ignore-error-status t)
      (unless (and code (zerop code)
                   (search "MISS 404" out)
                   (search "ECHO 200 echo" out)
                   (search "AUTH 401 continued=False" out)
                   (search "Basic" out)
                   (search "AUTHED 200 ping continued=True" out)
                   (search "MATCH 412 continued=False" out)
                   (search "CODE 415 continued=False" out))
        (fail "exit ~s out ~s err ~s" code out err)))))

(defun h3-informational-length-test (port)
  "RFC 9110 §8.6. An informational response must not send Content-Length.
The HTTP/3 100 for Expect: 100-continue omits it. The client sends the
body only after that 100, and the final response returns the content."
  (check "an HTTP/3 100 omits content-length"
    (let ((script "/tmp/pazuzu-h3-100-length.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection, HeadersState"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     "        self._continues = {}"
                     ""
                     "    def quic_event_received(self, event):"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b'', 'continued': False, 'ilen': None})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                status = None"
                     "                length = None"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        status = int(value)"
                     "                    elif name == b'content-length':"
                     "                        length = value"
                     "                if status == 100 and not http_event.stream_ended:"
                     "                    bucket['continued'] = True"
                     "                    bucket['ilen'] = b'' if length is None else length"
                     "                    state = self._http._get_or_create_stream(stream_id)"
                     "                    state.headers_recv_state = HeadersState.INITIAL"
                     "                    state.content_length = 0"
                     "                    state.expected_content_length = None"
                     "                    waiter = self._continues.get(stream_id)"
                     "                    if waiter is not None and not waiter.done():"
                     "                        waiter.set_result(True)"
                     "                else:"
                     "                    bucket['status'] = status"
                     "                    if http_event.stream_ended:"
                     "                        self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events[stream_id])"
                     ""
                     "    def _open(self, path, extra):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        done = self._loop.create_future()"
                     "        cont = self._loop.create_future()"
                     "        self._waiters[stream_id] = done"
                     "        self._continues[stream_id] = cont"
                     "        headers = ["
                     "            (b':method', b'POST'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', f'127.0.0.1:{sys.argv[1]}'.encode()),"
                     "            (b':path', path),"
                     "        ] + extra"
                     "        self._http.send_headers(stream_id, headers, end_stream=False)"
                     "        self.transmit()"
                     "        return stream_id, done, cont"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "        sid, done, cont = client._open(b'/echo', ["
                     "            (b'content-length', b'4'),"
                     "            (b'expect', b'100-continue'),"
                     "        ])"
                     "        await asyncio.wait_for(cont, 4)"
                     "        client._http.send_data(sid, b'echo', end_stream=True)"
                     "        client.transmit()"
                     "        echoed = await asyncio.wait_for(done, 4)"
                     "        stream_id = client._quic.get_next_available_stream_id()"
                     "        waiter = client._loop.create_future()"
                     "        client._waiters[stream_id] = waiter"
                     "        client._http.send_headers(stream_id, ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', f'127.0.0.1:{port}'.encode()),"
                     "            (b':path', b'/'),"
                     "        ], end_stream=True)"
                     "        client.transmit()"
                     "        got = await asyncio.wait_for(waiter, 4)"
                     "        ilen = echoed['ilen']"
                     "        ilen_text = 'MISSING' if ilen is None else ilen.decode()"
                     "        print(f'RESULT saw={1 if echoed[\"continued\"] else 0} ilen={ilen_text} status={echoed[\"status\"]} body={echoed[\"data\"].decode()} get={got[\"status\"]} gtext={got[\"data\"].decode()}')"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (let ((mark (search "ilen=" out)))
          (unless (and code (zerop code)
                       (search "RESULT saw=1 " out)
                       (search " status=200 " out)
                       (search " body=echo " out)
                       (search " get=200 " out)
                       (search " gtext=pazuzu" out)
                       mark
                       (< (+ mark 5) (length out))
                       (char= (char out (+ mark 5)) #\Space))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun aioquic-http3 (port)
  (let ((script "/tmp/pazuzu-h3-aioquic.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from urllib.parse import urlparse"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._events = {}"
                   "        self._waiters = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        for http_event in self._http.handle_event(event):"
                   "            stream_id = getattr(http_event, 'stream_id', None)"
                   "            if stream_id is None:"
                   "                continue"
                   "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        bucket['status'] = int(value)"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                bucket['data'] += http_event.data"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   ""
                   "    def _finish(self, stream_id):"
                   "        waiter = self._waiters.get(stream_id)"
                   "        if waiter is not None and not waiter.done():"
                   "            waiter.set_result(self._events[stream_id])"
                   ""
                   "    async def request(self, method, url, data=None):"
                   "        parsed = urlparse(url)"
                   "        path = parsed.path or '/'"
                   "        if parsed.query:"
                   "            path += '?' + parsed.query"
                   "        stream_id = self._quic.get_next_available_stream_id()"
                   "        waiter = self._loop.create_future()"
                   "        self._waiters[stream_id] = waiter"
                   "        headers = ["
                   "            (b':method', method.encode()),"
                   "            (b':scheme', b'https'),"
                   "            (b':authority', parsed.netloc.encode()),"
                   "            (b':path', path.encode()),"
                   "            (b'user-agent', b'aioquic-pazuzu'),"
                   "        ]"
                   "        if data is not None:"
                   "            headers.append((b'content-type', b'text/plain'))"
                   "            headers.append((b'content-length', str(len(data)).encode()))"
                   "        self._http.send_headers(stream_id, headers, end_stream=data is None)"
                   "        if data is not None:"
                   "            self._http.send_data(stream_id, data, end_stream=True)"
                   "        self.transmit()"
                   "        return await asyncio.wait_for(waiter, 5)"
                   ""
                   "async def main():"
                   "    port = sys.argv[1]"
                   "    base = f'https://127.0.0.1:{port}'"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                   "        got, posted, missing, again = await asyncio.gather("
                   "            client.request('GET', base + '/'),"
                   "            client.request('POST', base + '/echo', b'hello-aioquic'),"
                   "            client.request('GET', base + '/missing'),"
                   "            client.request('GET', base + '/q?a=1&c=2'),"
                   "        )"
                   "        print(f'GET {got[\"status\"]} {got[\"data\"].decode()}')"
                   "        print(f'POST {posted[\"status\"]} {posted[\"data\"].decode()}')"
                   "        print(f'MISS {missing[\"status\"]}')"
                   "        print(f'QUERY {again[\"status\"]} {again[\"data\"].decode()}')"
                   "        client.close()"
                   ""
                   "asyncio.run(main())"))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string
                          :error-output :string
                          :ignore-error-status t)
      (unless (and code (zerop code)
                   (search "GET 200 pazuzu" out)
                   (search "POST 200 hello-aioquic" out)
                   (search "MISS 404" out)
                   (search "QUERY 200 a=1;c=2" out))
        (fail "exit ~s out ~s err ~s" code out err)))))

(defun blocked-handler-test ()
  "A handler that has not returned still leaves another connection able
to read the normal successful body. Each connection runs on its own thread."
  (call-with-server
   (lambda (server)
     (let ((gate (bt:make-lock "pazuzu-block"))
           (entered nil))
       (bt:acquire-lock gate)
       (pazuzu:add-route server :get "/"
                         (lambda (request)
                           (declare (ignore request))
                           (pazuzu:text-response "pazuzu")))
       (pazuzu:add-route server :get "/block"
                         (lambda (request)
                           (declare (ignore request))
                           (setf entered t)
                           (bt:acquire-lock gate)
                           (bt:release-lock gate)
                           (pazuzu:text-response "done")))
       (unwind-protect
            (check "a blocked handler still serves another connection"
              (bt:make-thread
               (lambda ()
                 (ignore-errors
                   (exchange (pazuzu:server-port server)
                             (request-text "GET /block HTTP/1.1"
                                           "Host: 127.0.0.1"))))
               :name "pazuzu-blocked-handler")
              (unless (wait-until (lambda () entered))
                (fail "handler did not start"))
              (let ((reply (exchange (pazuzu:server-port server)
                                     (request-text "GET / HTTP/1.1"
                                                   "Host: 127.0.0.1"))))
                (expect-status reply 200)
                (unless (search "pazuzu" (body-text reply))
                  (fail "body ~s" (body-text reply)))))
         (ignore-errors (bt:release-lock gate)))))
   :workers 1))

(defun rate-limit-test ()
  (call-with-server
   (lambda (server)
     (pazuzu:add-route server :get "/"
                       (lambda (request)
                         (declare (ignore request))
                         (pazuzu:text-response "pazuzu")))
     (check "request rate answers 429"
       (let ((socket (connect (pazuzu:server-port server))))
         (unwind-protect
              (let ((stream (usocket:socket-stream socket)))
                (dotimes (ignored 6)
                  (write-sequence (octets (request-text "GET / HTTP/1.1"
                                                        "Host: 127.0.0.1"))
                                  stream))
                (finish-output stream)
                (let ((replies (loop repeat 6 collect (read-reply stream))))
                  (unless (and (find 200 replies :key #'reply-status)
                               (>= (count 429 replies :key #'reply-status) 4))
                    (fail "statuses ~s" (mapcar #'reply-status replies)))
                  (let ((limited (find 429 replies :key #'reply-status)))
                    (unless (and limited (string= (header limited "retry-after") "1"))
                      (fail "retry-after ~s" (and limited (header limited "retry-after")))))))
           (ignore-errors (usocket:socket-close socket))))))
   :request-rate 1))

(defun account-and-activation-tests ()
  (require :sb-posix)
  (check "unknown user is refused"
    (handler-case
        (let ((server (pazuzu:start :address "127.0.0.1" :port 0
                                    :user "no-such-pazuzu-user")))
          (ignore-errors (pazuzu:stop server))
          (fail "server started"))
      (error () nil)))
  (let ((name (sb-posix:passwd-name (sb-posix:getpwuid (sb-posix:getuid)))))
    (call-with-server
     (lambda (server)
       (pazuzu:add-route server :get "/"
                         (lambda (request)
                           (declare (ignore request))
                           (pazuzu:text-response "pazuzu")))
       (check "current user keeps serving after the account drop"
         (expect-status (exchange (pazuzu:server-port server)
                                  (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))
                        200)))
     :user name))
  ;; Stop runs outside the check deadline. A deadline that fires while
  ;; stop is joining a client aborts the process instead of recording FAIL.
  (let* ((raw (usocket:socket-listen "127.0.0.1" 0
                                     :reuse-address t
                                     :backlog 16
                                     :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port raw))
         (fd (pazuzu::usocket-fd raw))
         (saved (handler-case (sb-posix:dup 3) (error () nil)))
         (same (= fd 3))
         (server nil))
    (unwind-protect
         (progn
           ;; One owner of the listening fd. A second sb-bsd-sockets object
           ;; finalizes by closing that descriptor.
           (let ((sock (usocket:socket raw)))
             (sb-ext:cancel-finalization sock)
             (setf (slot-value sock 'sb-bsd-sockets::file-descriptor) -1))
           (sb-posix:dup2 fd 3)
           (unless same
             (sb-posix:close fd))
           (sb-posix:setenv "LISTEN_PID" (princ-to-string (sb-posix:getpid)) 1)
           (sb-posix:setenv "LISTEN_FDS" "1" 1)
           (sb-posix:unsetenv "LISTEN_FDNAMES")
           (check "socket activation serves the passed listener"
             (setf server (pazuzu:start :address "127.0.0.1" :port 9 :workers 1))
             (unless (= (pazuzu:server-port server) port)
               (fail "activated port ~d, listener was ~d"
                     (pazuzu:server-port server) port))
             (pazuzu:add-route server :get "/"
                               (lambda (request)
                                 (declare (ignore request))
                                 (pazuzu:text-response "activated")))
             (let ((reply (exchange port (request-text "GET / HTTP/1.1"
                                                       "Host: 127.0.0.1"))))
               (expect-status reply 200)
               (unless (search "activated" (body-text reply))
                 (fail "body ~s" (body-text reply))))))
      (when server
        (ignore-errors (pazuzu:stop server)))
      (sb-posix:unsetenv "LISTEN_PID")
      (sb-posix:unsetenv "LISTEN_FDS")
      (sb-posix:unsetenv "LISTEN_FDNAMES")
      (cond ((and saved (not same))
             (ignore-errors (sb-posix:dup2 saved 3))
             (ignore-errors (sb-posix:close saved)))
            (saved
             (ignore-errors (sb-posix:close saved))))
      (ignore-errors (usocket:socket-close raw)))))

(defun h3-peer-subject (port)
  "The peer certificate subject from a new HTTP/3 connection."
  (let ((script "/tmp/pazuzu-h3-subject.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    async with connect('127.0.0.1', port, configuration=configuration) as client:"
                   "        cert = client._quic.tls._peer_certificate"
                   "        print(cert.subject.rfc4514_string() if cert is not None else 'NONE')"
                   "        client.close()"
                   ""
                   "asyncio.run(main())"))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (unless (and code (zerop code))
        (fail "subject exit ~s out ~s err ~s" code out err))
      out)))

(defun http3-websocket-test (port)
  (check "HTTP/3 extended CONNECT"
    (let ((script "/tmp/pazuzu-h3-ws.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._status = None"
                     "        self._accept = None"
                     "        self._upgrade = None"
                     "        self._length = None"
                     "        self._te = None"
                     "        self._data = b''"
                     "        self._waiter = None"
                     "        self._until_end = False"
                     ""
                     "    def quic_event_received(self, event):"
                     "        for http_event in self._http.handle_event(event):"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        self._status = int(value)"
                     "                    elif name == b'sec-websocket-accept':"
                     "                        self._accept = value.decode()"
                     "                    elif name == b'upgrade':"
                     "                        self._upgrade = value.decode()"
                     "                    elif name == b'content-length':"
                     "                        self._length = value.decode()"
                     "                    elif name == b'transfer-encoding':"
                     "                        self._te = value.decode()"
                     "                if http_event.stream_ended:"
                     "                    self._finish()"
                     "            elif isinstance(http_event, DataReceived):"
                     "                self._data += http_event.data"
                     "                if http_event.stream_ended or (not self._until_end and len(self._data) >= 4):"
                     "                    self._finish()"
                     ""
                     "    def _finish(self):"
                     "        if self._waiter is not None and not self._waiter.done():"
                     "            self._waiter.set_result(True)"
                     ""
                     "    async def get_ws(self, authority):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        self._waiter = self._loop.create_future()"
                     "        self._status = None"
                     "        self._upgrade = None"
                     "        self._data = b''"
                     "        self._until_end = True"
                     "        self._http.send_headers(stream_id, ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':path', b'/ws'),"
                     "            (b':authority', authority.encode()),"
                     "        ], end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(self._waiter, 5)"
                     ""
                     "    async def open_socket(self, authority):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        self._waiter = self._loop.create_future()"
                     "        self._status = None"
                     "        self._accept = None"
                     "        self._length = None"
                     "        self._te = None"
                     "        self._data = b''"
                     "        self._until_end = False"
                     "        self._http.send_headers(stream_id, ["
                     "            (b':method', b'CONNECT'),"
                     "            (b':protocol', b'websocket'),"
                     "            (b':scheme', b'https'),"
                     "            (b':path', b'/ws'),"
                     "            (b':authority', authority.encode()),"
                     "            (b'sec-websocket-version', b'13'),"
                     "            (b'sec-websocket-key', b'dGhlIHNhbXBsZSBub25jZQ=='),"
                     "        ], end_stream=False)"
                     "        self._http.send_data(stream_id, bytes(["
                     "            0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 0x69, 0x6b"
                     "        ]), end_stream=False)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(self._waiter, 5)"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "        await client.get_ws(f'127.0.0.1:{port}')"
                     "        print(f'GET {client._status} UPGRADE {client._upgrade}')"
                     "        await client.open_socket(f'127.0.0.1:{port}')"
                     "        print(f'STATUS {client._status}')"
                     "        print(f'LENGTH {client._length} TE {client._te}')"
                     "        print(f'ACCEPT {client._accept}')"
                     "        print('ECHO ' + client._data[:4].hex())"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET 400 UPGRADE None" out)
                     (search "STATUS 200" out)
                     (search "LENGTH None TE None" out)
                     (search "ACCEPT s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" out)
                     (search "ECHO 81026869" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-field-value-del-test (port)
  "RFC 9114 §10.3. field-content is field-vchar, which is VCHAR or
obs-text. DEL (octet 127) is neither. A request that contains it is
malformed, a stream error H3_MESSAGE_ERROR (0x010e). The next GET /
still returns pazuzu."
  (check "an HTTP/3 field value containing DEL is malformed"
    (let ((script "/tmp/pazuzu-h3-field-del.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     "        self._resets = {}"
                     "        self._terminated = None"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "            for stream_id, waiter in list(self._waiters.items()):"
                     "                if not waiter.done():"
                     "                    waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     "            return"
                     "        if isinstance(event, (StreamReset, StopSendingReceived)):"
                     "            self._resets[event.stream_id] = event.error_code"
                     "            self._finish(event.stream_id)"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(waiter, 4)"
                     "        return stream_id"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    authority = f'127.0.0.1:{port}'.encode()"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "        base = ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ]"
                     "        sid = await client.request(base)"
                     "        got = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print(f'GET status={got[\"status\"]} body={got[\"data\"].decode(errors=\"replace\")} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-del', b'a\\x7fb')])"
                     "        print(f'DEL reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base)"
                     "        later = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print(f'LATER status={later[\"status\"]} body={later[\"data\"].decode(errors=\"replace\")} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu reset=None closed=None" out)
                     (search "DEL reset=270 closed=None" out)
                     (search "LATER status=200 body=pazuzu reset=None closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun malformed-http3-test (port)
  "RFC 9114 §4.1.2: a malformed request is a stream error H3_MESSAGE_ERROR
(0x10e). A later request on the same connection still completes."
  (check "HTTP/3 malformed message is a stream error"
    (let ((script "/tmp/pazuzu-h3-malformed.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "import aioquic.h3.connection as h3mod"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     "        self._resets = {}"
                     "        self._terminated = None"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "            for stream_id, waiter in list(self._waiters.items()):"
                     "                if not waiter.done():"
                     "                    waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     "            return"
                     "        if isinstance(event, (StreamReset, StopSendingReceived)):"
                     "            self._resets[event.stream_id] = event.error_code"
                     "            self._finish(event.stream_id)"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     ""
                     "    async def request(self, headers, data=None):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=data is None)"
                     "        if data is not None:"
                     "            self._http.send_data(stream_id, data, end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(waiter, 4)"
                     "        return stream_id"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    authority = f'127.0.0.1:{port}'.encode()"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "        base = ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ]"
                     "        forbidden = ["
                     "            (b'connection', b'close'),"
                     "            (b'keep-alive', b'timeout=5'),"
                     "            (b'proxy-connection', b'keep-alive'),"
                     "            (b'transfer-encoding', b'chunked'),"
                     "            (b'upgrade', b'websocket'),"
                     "            (b'te', b'gzip'),"
                     "        ]"
                     "        for name, value in forbidden:"
                     "            sid = await client.request(base + [(name, value)])"
                     "            print(f'BAD {name.decode()} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'te', b'trailers')])"
                     "        trailed = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print(f'TE status={trailed[\"status\"]} body={trailed[\"data\"].decode(errors=\"replace\")} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(["
                     "            (b':method', b'POST'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/echo'),"
                     "            (b'content-length', b'5'),"
                     "        ], b'ab')"
                     "        print(f'LEN reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        h3mod.validate_header_value = lambda key, value: None"
                     "        sid = await client.request(base + [(b'x-pad', b'value ')])"
                     "        print(f'PAD reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-nul', b'a\\x00b')])"
                     "        print(f'NUL reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-lf', b'a\\nb')])"
                     "        print(f'LF reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-cr', b'a\\rb')])"
                     "        print(f'CR reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-lsp', b' a')])"
                     "        print(f'LSP reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-lht', b'\\ta')])"
                     "        print(f'LHT reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x-tht', b'a\\t')])"
                     "        print(f'THT reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        h3mod.validate_header_name = lambda key: None"
                     "        sid = await client.request(base + [(b'Accept', b'text/plain')])"
                     "        print(f'UP reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x y', b'z')])"
                     "        print(f'SPN reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x:y', b'z')])"
                     "        print(f'COL reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'x\\x7fy', b'z')])"
                     "        print(f'DELN reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'\\xff', b'z')])"
                     "        print(f'HIGH reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'host', b'other.example')])"
                     "        hosted = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print(f'HOST status={hosted[\"status\"]} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base + [(b'host', authority), (b'host', authority)])"
                     "        print(f'HOST2 status={client._events.get(sid, {\"status\": None})[\"status\"]} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', b'Example.COM'),"
                     "            (b':path', b'/'),"
                     "            (b'host', b'example.com:443'),"
                     "        ])"
                     "        same = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print(f'SAME status={same[\"status\"]} body={same[\"data\"].decode(errors=\"replace\")} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        sid = await client.request(base)"
                     "        got = client._events.get(sid, {'status': None, 'data': b''})"
                     "        body = got['data'].decode(errors='replace')"
                     "        print(f'GET status={got[\"status\"]} body={body} reset={client._resets.get(sid)} closed={client._terminated}')"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "BAD connection reset=270 closed=None" out)
                     (search "BAD keep-alive reset=270 closed=None" out)
                     (search "BAD proxy-connection reset=270 closed=None" out)
                     (search "BAD transfer-encoding reset=270 closed=None" out)
                     (search "BAD upgrade reset=270 closed=None" out)
                     (search "BAD te reset=270 closed=None" out)
                     (search "TE status=200 body=pazuzu reset=None closed=None" out)
                     (search "LEN reset=270 closed=None" out)
                     (search "PAD reset=270 closed=None" out)
                     (search "NUL reset=270 closed=None" out)
                     (search "LF reset=270 closed=None" out)
                     (search "CR reset=270 closed=None" out)
                     (search "LSP reset=270 closed=None" out)
                     (search "LHT reset=270 closed=None" out)
                     (search "THT reset=270 closed=None" out)
                     (search "UP reset=270 closed=None" out)
                     (search "SPN reset=270 closed=None" out)
                     (search "COL reset=270 closed=None" out)
                     (search "DELN reset=270 closed=None" out)
                     (search "HIGH reset=270 closed=None" out)
                     (search "HOST status=400 reset=None closed=None" out)
                     (search "HOST2 status=None reset=270 closed=None" out)
                     (search "SAME status=200 body=pazuzu reset=None closed=None" out)
                     (search "GET status=200 body=pazuzu reset=None closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-second-encoder-test (port)
  "RFC 9204 §4.2. A second QPACK encoder stream is a connection error of
type H3_STREAM_CREATION_ERROR (0x0103)."
  (check "a second QPACK encoder stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "if sys.argv[2] == 'grease-setting':"
                     "    _orig_settings = H3Connection._get_local_settings"
                     "    def _with_grease(self):"
                     "        settings = _orig_settings(self)"
                     "        settings[0x21] = 9"
                     "        return settings"
                     "    H3Connection._get_local_settings = _with_grease"
                     "elif sys.argv[2] == 'h2-setting':"
                     "    _orig_settings = H3Connection._get_local_settings"
                     "    def _with_h2_push(self):"
                     "        settings = _orig_settings(self)"
                     "        settings[0x02] = 0"
                     "        return settings"
                     "    H3Connection._get_local_settings = _with_h2_push"
                     "elif sys.argv[2] == 'missing-settings':"
                     "    def _bad_init(self):"
                     "        self._local_control_stream_id = self._create_uni_stream(0)"
                     "        self._quic.send_stream_data(self._local_control_stream_id, bytes([0, 1, 90]))"
                     "        self._sent_settings = {}"
                     "        self._local_encoder_stream_id = self._create_uni_stream(2)"
                     "        self._local_decoder_stream_id = self._create_uni_stream(3)"
                     "    H3Connection._init_connection = _bad_init"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     "        self._terminated = None"
                     "        self._resets = {}"
                     "        self._done = self._loop.create_future()"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "            if not self._done.done():"
                     "                self._done.set_result(event.error_code)"
                     "            for stream_id, waiter in list(self._waiters.items()):"
                     "                if not waiter.done():"
                     "                    waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     "            return"
                     "        if isinstance(event, (StreamReset, StopSendingReceived)):"
                     "            self._resets[event.stream_id] = event.error_code"
                     "            self._finish(event.stream_id)"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                    elif name == b'allow':"
                     "                        bucket['allow'] = value.decode()"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(waiter, 4)"
                     "        return stream_id"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    authority = f'127.0.0.1:{port}'.encode()"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    try:"
                     "        async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "            if sys.argv[2] == 'h2-setting':"
                     "                print('SETTING 2=%s' % client._http._sent_settings.get(2))"
                     "            if sys.argv[2] in ('h2-setting', 'missing-settings'):"
                     "                try:"
                     "                    code = await asyncio.wait_for(client._done, 4)"
                     "                except TimeoutError:"
                     "                    code = client._terminated"
                     "                print('SECOND closed=%s' % code)"
                     "                return"
                     "            sid = await client.request(["
                     "                (b':method', b'GET'),"
                     "                (b':scheme', b'https'),"
                     "                (b':authority', authority),"
                     "                (b':path', b'/'),"
                     "            ])"
                     "            got = client._events.get(sid, {'status': None, 'data': b''})"
                     "            print('GET status=%s body=%s' % (got['status'], got['data'].decode(errors='replace')))"
                     "            if sys.argv[2] == 'twice':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                req = ["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ]"
                     "                client._http.send_headers(stream_id, req, end_stream=False)"
                     "                client._http.send_headers(stream_id, ["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/again'),"
                     "                ], end_stream=False)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                print('SECOND reset=%s closed=%s' % (client._resets.get(stream_id), client._terminated))"
                     "                sid = await client.request(req)"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'close':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, b'', end_stream=True)"
                     "            elif sys.argv[2] == 'close-decoder':"
                     "                client._quic.send_stream_data(client._http._local_decoder_stream_id, b'', end_stream=True)"
                     "            elif sys.argv[2] == 'close-control':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, b'', end_stream=True)"
                     "            elif sys.argv[2] == 'data-control':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([0, 1, 90]), end_stream=False)"
                     "            elif sys.argv[2] == 'headers-control':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([1, 2, 0, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'settings-control':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([4, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'settings-bidi':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([4, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'cancel-bidi':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([3, 1, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'max-push-bidi':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([13, 1, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'max-push-long':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([13, 2, 0, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'cancel-unknown':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([3, 1, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'control2':"
                     "                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)"
                     "                client._quic.send_stream_data(stream_id, bytes([0]), end_stream=False)"
                     "            elif sys.argv[2] == 'push-uni':"
                     "                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)"
                     "                client._quic.send_stream_data(stream_id, bytes([1]), end_stream=False)"
                     "            elif sys.argv[2] == 'goaway-empty':"
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([7, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'goaway-increase':"
                     "                # Push ID 0, then push ID 1. The second identifier is larger."
                     "                client._quic.send_stream_data(client._http._local_control_stream_id, bytes([7, 1, 0, 7, 1, 1]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-cap':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0x21]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-inc':"
                     "                client._quic.send_stream_data(client._http._local_decoder_stream_id, bytes([0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-ack':"
                     "                client._quic.send_stream_data(client._http._local_decoder_stream_id, bytes([0x80]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-inc1':"
                     "                client._quic.send_stream_data(client._http._local_decoder_stream_id, bytes([1]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-ric':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 2, 1, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-static':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 4, 0, 0, 0xFF, 0x24]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-big':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0xC0, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-post':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 3, 0, 0, 0x10]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-estatic':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0xFF, 0x24, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-base':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 2, 0, 0x80]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-dup':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-huff':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 5, 0, 0, 0x29, 0xFF, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-eos':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 8, 0, 0, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-ehuff':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0x61, 0xFF, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-eeos':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0x64, 0xFF, 0xFF, 0xFF, 0xFF, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-int':"
                     "                client._quic.send_stream_data(client._http._local_encoder_stream_id, bytes([0x5F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-rint':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([1, 13, 0, 0, 0x27] + [0x80] * 10), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-dint':"
                     "                client._quic.send_stream_data(client._http._local_decoder_stream_id, bytes([0xFF] + [0x80] * 10), end_stream=False)"
                     "            elif sys.argv[2] == 'qpack-wide':"
                     "                delta = bytes([0x7F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F])"
                     "                path = b'/'"
                     "                block = bytes([0]) + delta + bytes([0xD1, 0xD7, 0x51, len(path)]) + path + bytes([0x50, len(authority)]) + authority"
                     "                blen = len(block)"
                     "                length = bytes([blen]) if blen < 64 else bytes([(blen >> 8) | 0x40, blen & 0xFF])"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1]) + length + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                wide = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('WIDE status=%s body=%s closed=%s' % (wide['status'], wide['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-order':"
                     "                path = b'/horder'"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x51, len(path)]) + path + bytes([0x50, len(authority)]) + authority + bytes([0x23]) + b'x-b' + bytes([1, 50, 0x23]) + b'x-a' + bytes([1, 49, 0x23]) + b'x-c' + bytes([1, 51])"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                ordered = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('ORDER status=%s body=%s closed=%s' % (ordered['status'], ordered['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-late':"
                     "                block = bytes([0, 0, 0x23]) + b'x-a' + bytes([1, 49, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('LATE reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-twomethod':"
                     "                block = bytes([0, 0, 0xD1, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                twice = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('TWO reset=%s status=%s closed=%s' % (client._resets.get(stream_id), twice['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-status':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0xD9, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('STATUS reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-epath':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x51, 0, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('EPATH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-eauth':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, 0])"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('EAUTH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-nslash':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x51, 7]) + b'noslash' + bytes([0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('NSLASH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-star':"
                     "                block = bytes([0, 0, 0xD3, 0xD7, 0x51, 1]) + b'*' + bytes([0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('STAR status=%s bodylen=%s allow=%s reset=%s closed=%s' % (late['status'], len(late['data']), late.get('allow', ''), client._resets.get(stream_id), client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-getstar':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x51, 1]) + b'*' + bytes([0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('GETSTAR reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-tpseudo':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block + bytes([1, 3, 0, 0, 0xD1]), end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('TPSEUDO reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-nomethod':"
                     "                block = bytes([0, 0, 0xD7, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('NOMETHOD reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-noscheme':"
                     "                block = bytes([0, 0, 0xD1, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('NOSCHEME reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-nopath':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('NOPATH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-noauth':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1])"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('NOAUTH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-ehost':"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority + bytes([0x24]) + b'host' + bytes([0])"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('EHOST reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-hostonly':"
                     "                path = b'/who'"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x51, len(path)]) + path + bytes([0x24]) + b'host' + bytes([len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('HOSTONLY reset=%s status=%s body=%s closed=%s' % (client._resets.get(stream_id), late['status'], late['data'].decode(errors='replace'), client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-hostdiff':"
                     "                other = b'other.example'"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority + bytes([0x24]) + b'host' + bytes([len(other)]) + other"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('HOSTDIFF reset=%s status=%s body=%s closed=%s' % (client._resets.get(stream_id), late['status'], late['data'].decode(errors='replace'), client._terminated))"
                     "                same = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority + bytes([0x24]) + b'host' + bytes([len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(same)]) + same, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                matched = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('HOSTSAME reset=%s status=%s body=%s closed=%s' % (client._resets.get(stream_id), matched['status'], matched['data'].decode(errors='replace'), client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-cpath':"
                     "                block = bytes([0, 0, 0xCF, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('CPATH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-cscheme':"
                     "                block = bytes([0, 0, 0xCF, 0xD7, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('CSCHEME reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-cauth':"
                     "                block = bytes([0, 0, 0xCF])"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('CAUTH reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-uinfo':"
                     "                userinfo = b'user@' + authority"
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, len(userinfo)]) + userinfo"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('UINFO reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-mmethod':"
                     "                # Static index 17 is :method. 4-bit prefix, remainder 2."
                     "                # Value is G, 0xE9, T: not a token (RFC 9110 §5.6.2)."
                     "                block = bytes([0, 0, 0x5F, 0x02, 0x03, 71, 233, 84, 0xD7, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('MMETHOD reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-ischeme':"
                     "                # Static index 22 is :scheme. 4-bit prefix, remainder 7."
                     "                # Value 0x39 is '9', which is not a URI scheme."
                     "                block = bytes([0, 0, 0xD1, 0x5F, 0x07, 0x01, 0x39, 0xC1, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('ISCHEME reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'qpack-frag':"
                     "                # Literal :path index 1. Value is slash, hash."
                     "                block = bytes([0, 0, 0xD1, 0xD7, 0x51, 0x02, 0x2F, 0x23, 0x50, len(authority)]) + authority"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                waiter = client._loop.create_future()"
                     "                client._waiters[stream_id] = waiter"
                     "                client._quic.send_stream_data(stream_id, bytes([1, len(block)]) + block, end_stream=True)"
                     "                client.transmit()"
                     "                try:"
                     "                    await asyncio.wait_for(waiter, 4)"
                     "                except TimeoutError:"
                     "                    pass"
                     "                late = client._events.get(stream_id, {'status': None, 'data': b''})"
                     "                print('FRAG reset=%s status=%s closed=%s' % (client._resets.get(stream_id), late['status'], client._terminated))"
                     "                sid = await client.request(["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ])"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'grease-setting':"
                     "                print('SETTING 33=%s' % client._http._sent_settings.get(0x21))"
                     "                await asyncio.sleep(0.5)"
                     "                print('STILL closed=%s' % client._terminated)"
                     "            elif sys.argv[2] == 'empty-uni':"
                     "                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)"
                     "                client._quic.send_stream_data(stream_id, b'', end_stream=True)"
                     "                client.transmit()"
                     "                await asyncio.sleep(0.5)"
                     "                req = ["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ]"
                     "                sid = await client.request(req)"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'reset-uni':"
                     "                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)"
                     "                client._quic.reset_stream(stream_id, 0x100)"
                     "                client.transmit()"
                     "                await asyncio.sleep(0.5)"
                     "                req = ["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ]"
                     "                sid = await client.request(req)"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'h2-priority':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([2, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'push-promise':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([5, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'h2-ping':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([6, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'h2-window':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([8, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'h2-continuation':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([9, 0]), end_stream=False)"
                     "            elif sys.argv[2] == 'truncated':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([0x21, 5, 90]), end_stream=True)"
                     "            elif sys.argv[2] == 'grease':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([0x21, 1, 90]), end_stream=False)"
                     "                client.transmit()"
                     "                await asyncio.sleep(0.5)"
                     "                req = ["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ]"
                     "                sid = await client.request(req)"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'unknown-uni':"
                     "                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)"
                     "                client._quic.send_stream_data(stream_id, bytes([0x21, 9, 9, 9]), end_stream=False)"
                     "                client.transmit()"
                     "                await asyncio.sleep(0.5)"
                     "                req = ["
                     "                    (b':method', b'GET'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/'),"
                     "                ]"
                     "                sid = await client.request(req)"
                     "                later = client._events.get(sid, {'status': None, 'data': b''})"
                     "                print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "            elif sys.argv[2] == 'data':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._quic.send_stream_data(stream_id, bytes([0, 1, 90]), end_stream=False)"
                     "            elif sys.argv[2] == 'after':"
                     "                stream_id = client._quic.get_next_available_stream_id()"
                     "                client._http.send_headers(stream_id, ["
                     "                    (b':method', b'POST'),"
                     "                    (b':scheme', b'https'),"
                     "                    (b':authority', authority),"
                     "                    (b':path', b'/echo'),"
                     "                ], end_stream=False)"
                     "                client._http.send_data(stream_id, b'hi', end_stream=False)"
                     "                client._http.send_headers(stream_id, [(b'x-checksum', b'abc')], end_stream=False)"
                     "                client._quic.send_stream_data(stream_id, bytes([0, 1, 90]), end_stream=False)"
                     "            else:"
                     "                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)"
                     "                client._quic.send_stream_data(stream_id, bytes([int(sys.argv[2])]), end_stream=False)"
                     "            if sys.argv[2] not in ('twice', 'unknown-uni', 'grease', 'empty-uni', 'grease-setting', 'reset-uni', 'qpack-wide', 'qpack-order', 'qpack-late', 'qpack-twomethod', 'qpack-status', 'qpack-epath', 'qpack-eauth', 'qpack-nslash', 'qpack-star', 'qpack-getstar', 'qpack-tpseudo', 'qpack-nomethod', 'qpack-noscheme', 'qpack-nopath', 'qpack-noauth', 'qpack-ehost', 'qpack-hostonly', 'qpack-hostdiff', 'qpack-cpath', 'qpack-cscheme', 'qpack-cauth', 'qpack-uinfo', 'qpack-mmethod', 'qpack-ischeme', 'qpack-frag'):"
                     "                client.transmit()"
                     "                try:"
                     "                    code = await asyncio.wait_for(client._done, 4)"
                     "                except TimeoutError:"
                     "                    code = client._terminated"
                     "                print('SECOND closed=%s' % code)"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "2")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=259" out))
          (fail "exit ~s out ~s err ~s" code out err)))
    (check "a second QPACK decoder stream is a connection error"
      ;; RFC 9204 §4.2. Stream type 0x03 is the QPACK decoder stream.
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "3")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=259" out))
          (fail "exit ~s out ~s err ~s" code out err))))
    (check "closing the QPACK encoder stream is a connection error"
      ;; RFC 9204 §4.2. The sender MUST NOT close the encoder stream.
      ;; Closure is H3_CLOSED_CRITICAL_STREAM (0x0104).
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "close")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=260" out))
          (fail "exit ~s out ~s err ~s" code out err))))
    (check "closing the QPACK decoder stream is a connection error"
      ;; RFC 9204 §4.2. Closing the decoder stream is the same connection error.
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "close-decoder")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=260" out))
          (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h3-close-control-test (port)
  "RFC 9114 §6.2.1. Closing the control stream is a connection error of
type H3_CLOSED_CRITICAL_STREAM (0x0104)."
  (check "closing the HTTP/3 control stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "close-control")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=260" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-data-before-headers-test (port)
  "RFC 9114 §4.1. A DATA frame before HEADERS is a connection error of
type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a DATA frame before HEADERS is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "data")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-frame-after-trailers-test (port)
  "RFC 9114 §4.1. A DATA frame after the trailing HEADERS is a connection
error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a frame after the trailing HEADERS is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "after")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-truncated-frame-test (port)
  "RFC 9114 §7.1. A request stream that ends in the middle of a frame is
a connection error of type H3_FRAME_ERROR (0x0106)."
  (check "a truncated HTTP/3 frame is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "truncated")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=262" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-unknown-uni-test (port)
  "RFC 9114 §6.2 and §6.2.3. An unknown unidirectional stream type,
including the reserved type 0x21, is not a connection error. A later
GET on that connection still returns the resource."
  (check "an unknown HTTP/3 unidirectional stream type is not a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "unknown-uni")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-grease-frame-test (port)
  "RFC 9114 §7.2.8 and §9. A complete reserved frame (type 0x21) has no
meaning. The connection stays open and a later GET still returns the
resource."
  (check "a reserved HTTP/3 frame is ignored"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "grease")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-client-push-stream-test (port)
  "RFC 9114 §6.2.2. A client-initiated push stream is a connection error
of type H3_STREAM_CREATION_ERROR (0x0103)."
  (check "a client push stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "push-uni")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=259" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-empty-uni-test (port)
  "RFC 9114 §6.2. A unidirectional stream that closes before its type
byte is not a connection error. A later GET still returns the resource."
  (check "an HTTP/3 unidirectional stream closed before its type is tolerated"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "empty-uni")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-reset-uni-test (port)
  "RFC 9114 §6.2. A unidirectional stream reset before its type byte is
not a connection error. A later GET still returns the resource."
  (check "an HTTP/3 unidirectional stream reset before its type is tolerated"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "reset-uni")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-unknown-error-code-test (port)
  "RFC 9114 §8. An application error code the peer has not defined,
including the reserved code 0x21, is equivalent to H3_NO_ERROR. Resetting
a request stream with that code does not close the connection."
  (check "an unknown HTTP/3 error code is H3_NO_ERROR"
    (let ((script "/tmp/pazuzu-h3-unknown-error.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     "        self._terminated = None"
                     "        self._resets = {}"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "            for stream_id, waiter in list(self._waiters.items()):"
                     "                if not waiter.done():"
                     "                    waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     "            return"
                     "        if isinstance(event, (StreamReset, StopSendingReceived)):"
                     "            self._resets[event.stream_id] = event.error_code"
                     "            self._finish(event.stream_id)"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(waiter, 4)"
                     "        return stream_id"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    authority = ('127.0.0.1:%s' % port).encode()"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "        req = ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ]"
                     "        sid = await client.request(req)"
                     "        got = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print('GET status=%s body=%s closed=%s' % (got['status'], got['data'].decode(errors='replace'), client._terminated))"
                     "        stream_id = client._quic.get_next_available_stream_id()"
                     "        client._http.send_headers(stream_id, req, end_stream=False)"
                     "        client._quic.reset_stream(stream_id, 0x21)"
                     "        client._quic.stop_stream(stream_id, 0x21)"
                     "        client.transmit()"
                     "        await asyncio.sleep(0.5)"
                     "        sid = await client.request(req)"
                     "        later = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-id-reuse-test (port)
  "RFC 9000 §2.1. A stream ID is unique for the connection. The server
opens its control stream and its two QPACK streams as 3, 7, and 11, and
a second request does not open another stream with one of those IDs."
  (check "a server stream id is not reused"
    (let ((script "/tmp/pazuzu-h3-stream-id.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     "        self._terminated = None"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "            for stream_id, waiter in list(self._waiters.items()):"
                     "                if not waiter.done():"
                     "                    waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     "            return"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events.get(stream_id, {'status': None, 'data': b''}))"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        await asyncio.wait_for(waiter, 4)"
                     "        return stream_id"
                     ""
                     "def snap(client):"
                     "    ids = [client._http._peer_control_stream_id,"
                     "           client._http._peer_encoder_stream_id,"
                     "           client._http._peer_decoder_stream_id]"
                     "    if any(i is None for i in ids):"
                     "        return 'missing'"
                     "    return ','.join(str(i) for i in sorted(ids))"
                     ""
                     "async def main():"
                     "    port = sys.argv[1]"
                     "    authority = ('127.0.0.1:%s' % port).encode()"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', int(port), configuration=configuration, create_protocol=Client) as client:"
                     "        req = ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ]"
                     "        sid = await client.request(req)"
                     "        got = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print('GET status=%s body=%s closed=%s' % (got['status'], got['data'].decode(errors='replace'), client._terminated))"
                     "        print('IDS %s' % snap(client))"
                     "        sid = await client.request(req)"
                     "        later = client._events.get(sid, {'status': None, 'data': b''})"
                     "        print('LATER status=%s body=%s closed=%s' % (later['status'], later['data'].decode(errors='replace'), client._terminated))"
                     "        print('AGAIN %s' % snap(client))"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out)
                     (search "IDS 3,7,11" out)
                     (search "AGAIN 3,7,11" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-goaway-increase-test (port)
  "RFC 9114 §5.2. A GOAWAY whose identifier is larger than one already
received is a connection error of type H3_ID_ERROR (0x0108). The
client sends push ID 0 and then push ID 1."
  (check "a larger HTTP/3 GOAWAY identifier is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "goaway-increase")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=264" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-split-cookie-test (port)
  "RFC 9114 §4.2.1. Several Cookie field lines become one field joined
by \"; \" before the application sees the request."
  (check "HTTP/3 split Cookie fields are one field"
    (let ((script "/tmp/pazuzu-h3-cookie.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     ""
                     "    def quic_event_received(self, event):"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events[stream_id])"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        return await asyncio.wait_for(waiter, 4)"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "        got = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', f'127.0.0.1:{port}'.encode()),"
                     "            (b':path', b'/cookie-header'),"
                     "            (b'cookie', b'a=b'),"
                     "            (b'cookie', b'c=d'),"
                     "        ])"
                     "        print('COOKIE status=%s body=%s' % (got['status'], got['data'].decode(errors='replace')))"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "COOKIE status=200 body=a=b; c=d" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-empty-goaway-test (port)
  "RFC 9114 §7.1. A GOAWAY payload that ends before the push ID is a
connection error of type H3_FRAME_ERROR (0x0106)."
  (check "a GOAWAY frame with an empty payload is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "goaway-empty")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=262" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-capacity-test (port)
  "RFC 9204 §4.3.1. A Set Dynamic Table Capacity above
SETTINGS_QPACK_MAX_TABLE_CAPACITY is QPACK_ENCODER_STREAM_ERROR (0x0201).
The server limit is the default, zero."
  (check "a QPACK dynamic table capacity above the limit is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-cap")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-increment-test (port)
  "RFC 9204 §4.4.3. An Insert Count Increment of zero is a connection
error of type QPACK_DECODER_STREAM_ERROR (0x0202)."
  (check "a QPACK insert count increment of zero is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-inc")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=514" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-section-ack-test (port)
  "RFC 9204 §4.4.1. A Section Acknowledgment for a stream whose field
sections had a Required Insert Count of zero is
QPACK_DECODER_STREAM_ERROR (0x0202)."
  (check "a QPACK section acknowledgment with nothing to acknowledge is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-ack")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=514" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-increment-past-test (port)
  "RFC 9204 §4.4.3. An Insert Count Increment that moves Known Received
Count past the inserts the encoder has sent is
QPACK_DECODER_STREAM_ERROR (0x0202)."
  (check "a QPACK insert count past the encoder inserts is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-inc1")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=514" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-insert-count-test (port)
  "RFC 9204 §4.5.1.1. With a maximum dynamic table capacity of zero, an
Encoded Insert Count other than zero cannot be produced by a conformant
encoder. That is QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK encoded insert count above the table capacity is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-ric")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-static-index-test (port)
  "RFC 9204 §3.1. The static table is indices 0 through 98. An index of
99 in a field line cannot name an entry. That is
QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK static index past the static table is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-static")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-insert-too-big-test (port)
  "RFC 9204 §3.2.2. The dynamic table capacity is zero. Inserting static
index 0 with an empty value is still larger than that capacity. That is
QPACK_ENCODER_STREAM_ERROR (0x0201)."
  (check "a QPACK insert larger than the dynamic table capacity is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-big")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-post-base-test (port)
  "RFC 9204 §2.2.3. Post-Base index 0 with Base 0 names absolute index 0.
The Required Insert Count is 0, so that index is not below the required
count. That is QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK dynamic reference at the required insert count is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-post")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-encoder-static-test (port)
  "RFC 9204 §3.1. Static index 99 on the encoder stream, in an Insert
With Name Reference, cannot name an entry. That is
QPACK_ENCODER_STREAM_ERROR (0x0201)."
  (check "a QPACK static index on the encoder stream past the static table is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-estatic")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-negative-base-test (port)
  "RFC 9204 §4.5.1.2. A Sign bit of 1 is invalid when the Required Insert
Count is less than or equal to Delta Base. Count 0 and Delta Base 0
make Base negative. That is QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK base below zero is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-base")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-duplicate-test (port)
  "RFC 9204 §2.2.3. A Duplicate instruction names a dynamic table entry.
Relative index 0 on an empty table does not name a live entry. That is
QPACK_ENCODER_STREAM_ERROR (0x0201)."
  (check "a QPACK duplicate of a missing dynamic entry is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-dup")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-huffman-test (port)
  "RFC 9204 §4.1.2 uses the HPACK Huffman format. Padding longer than
seven bits is a decoding error (RFC 7541 §5.2). On a field section that
is QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK Huffman string padded by more than seven bits is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-huff")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-huffman-eos-test (port)
  "RFC 9204 §4.1.2 uses the HPACK Huffman format. A string that contains
the EOS symbol is a decoding error (RFC 7541 §5.2). On a field section
that is QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK Huffman string that contains the EOS symbol is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-eos")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-encoder-huffman-test (port)
  "RFC 9204 §4.1.2 and §6. Huffman padding longer than seven bits on an
encoder instruction is QPACK_ENCODER_STREAM_ERROR (0x0201)."
  (check "a QPACK Huffman string on the encoder stream padded by more than seven bits is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-ehuff")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-encoder-eos-test (port)
  "RFC 9204 §4.1.2 and §6. The Huffman EOS symbol in an encoder
instruction is a decoding error. That is QPACK_ENCODER_STREAM_ERROR
(0x0201)."
  (check "a QPACK Huffman EOS symbol on the encoder stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-eeos")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-integer-test (port)
  "RFC 9204 §4.1.1 and §7.4. A prefixed integer that shifts past 62 bits
cannot be decoded. On the encoder stream that is
QPACK_ENCODER_STREAM_ERROR (0x0201)."
  (check "a QPACK integer past 62 bits on the encoder stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-int")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=513" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-request-integer-test (port)
  "RFC 9204 §4.1.1 and §7.4. A prefixed integer that shifts past 62 bits
in a field section cannot be decoded. That is
QPACK_DECOMPRESSION_FAILED (0x0200)."
  (check "a QPACK integer past 62 bits in a field section is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-rint")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=512" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-wide-integer-test (port)
  "RFC 9204 §4.1.1. A prefixed integer of 62 bits is decoded. A field
section whose Required Insert Count is 0 and whose Delta Base is
2^62-1 uses only the static table, and that request is still served."
  (check "a 62-bit QPACK integer is decoded"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-wide")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "WIDE status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-decoder-integer-test (port)
  "RFC 9204 §4.1.1 and §7.4. A prefixed integer that shifts past 62 bits
on the decoder stream cannot be decoded. That is
QPACK_DECODER_STREAM_ERROR (0x0202)."
  (check "a QPACK integer past 62 bits on the decoder stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-dint")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=514" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-qpack-field-order-test (port)
  "RFC 9204 §2.2. The decoder emits field lines in the order their
representations appear in the encoded field section."
  (check "QPACK field lines are emitted in representation order"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-order")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "ORDER status=200 body=x-b,x-a,x-c closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-pseudo-after-regular-test (port)
  "RFC 9114 §4.3. A pseudo-header after a regular field is malformed.
That is a stream error H3_MESSAGE_ERROR (0x010e), and the connection
stays open."
  (check "a pseudo-header after a regular field is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-late")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "LATE reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-repeated-pseudo-test (port)
  "RFC 9114 §4.3.1. A request has exactly one :method. A second :method
is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "a repeated HTTP/3 pseudo-header is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-twomethod")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "TWO reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-response-pseudo-test (port)
  "RFC 9114 §4.3. :status is defined for responses. A request that
carries it is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "a response pseudo-header on a request is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-status")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "STATUS reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-empty-path-test (port)
  "RFC 9114 §4.3.1. :path must not be empty for an https URI. That
request is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an empty HTTP/3 :path is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-epath")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "EPATH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-empty-authority-test (port)
  "RFC 9114 §4.3.1. :authority must not be empty when it is present.
That request is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an empty HTTP/3 :authority is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-eauth")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "EAUTH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-relative-path-test (port)
  "RFC 9114 §4.3.1. :path for https is path-absolute or *. A value
with no leading slash is malformed, a stream error H3_MESSAGE_ERROR."
  (check "an HTTP/3 :path without a leading slash is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-nslash")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "NSLASH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-asterisk-path-test (port)
  "RFC 9114 §4.3.1. OPTIONS with :path * applies to the server.
The raw QPACK path accepts * before the shared path parser. Allow
includes PUT. A later GET / returns pazuzu. Rejecting * is
H3_MESSAGE_ERROR."
  (check "HTTP/3 accepts an OPTIONS asterisk path"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-star")
                            :output :string :error-output :string :ignore-error-status t)
        (let* ((star (search "STAR " out))
               (allow-at (and star (search "allow=" out :start2 star)))
               (reset-at (and allow-at (search " reset=" out :start2 allow-at)))
               (allow (and allow-at reset-at
                           (subseq out (+ allow-at 6) reset-at))))
          (unless (and code (zerop code)
                       (search "GET status=200 body=pazuzu" out)
                       (search "STAR status=200 bodylen=0 " out)
                       allow
                       (search "PUT" allow)
                       (search "DELETE" allow)
                       (search " reset=None" (and star (subseq out star)))
                       (search "LATER status=200 body=pazuzu closed=None" out))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun h3-get-asterisk-path-test (port)
  "RFC 9110 §7.1 and RFC 9114 §§4.3.1 and 4.1.2. Asterisk-form is only
for OPTIONS. GET with :path * is an invalid pseudo-header value, a
stream error H3_MESSAGE_ERROR (0x010e). A later GET / returns pazuzu."
  (check "HTTP/3 rejects GET with an asterisk path"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-getstar")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "GETSTAR reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-trailer-pseudo-test (port)
  "RFC 9114 §4.3. A pseudo-header in a trailer section is malformed.
That is a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 pseudo-header in trailers is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-tpseudo")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "TPSEUDO reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-trailer-separate-test (port)
  "RFC 9110 §6.5.1. A retained trailer is stored apart from the header
section. Merging it would make request-header see x-checksum. The
following GET still returns the whole representation."
  (check "an HTTP/3 trailer stays out of the header section"
    (let ((script "/tmp/pazuzu-h3-trailer-sep.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     ""
                     "    def quic_event_received(self, event):"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events[stream_id])"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    authority = f'127.0.0.1:{port}'.encode()"
                     "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "        stream_id = client._quic.get_next_available_stream_id()"
                     "        done = client._loop.create_future()"
                     "        client._waiters[stream_id] = done"
                     "        client._http.send_headers(stream_id, ["
                     "            (b':method', b'POST'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/trailers'),"
                     "            (b'content-length', b'5'),"
                     "            (b'x-note', b'head'),"
                     "        ], end_stream=False)"
                     "        client._http.send_data(stream_id, b'hello', end_stream=False)"
                     "        client._http.send_headers(stream_id, ["
                     "            (b'x-checksum', b'abc'),"
                     "        ], end_stream=True)"
                     "        client.transmit()"
                     "        posted = await asyncio.wait_for(done, 4)"
                     "        later_id = client._quic.get_next_available_stream_id()"
                     "        waiter = client._loop.create_future()"
                     "        client._waiters[later_id] = waiter"
                     "        client._http.send_headers(later_id, ["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ], end_stream=True)"
                     "        client.transmit()"
                     "        got = await asyncio.wait_for(waiter, 4)"
                     "        print('RESULT status=%s body=%s get=%s gtext=%s' % (posted['status'], posted['data'].decode(), got['status'], got['data'].decode()))"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 " out)
                     (search " body=x-checksum=abc " out)
                     (not (search "body=merged" out))
                     (search " get=200 " out)
                     (search " gtext=pazuzu" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-missing-method-test (port)
  "RFC 9114 §4.3.1. A request includes exactly one :method. Omitting it
is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 request without :method is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-nomethod")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "NOMETHOD reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-missing-scheme-test (port)
  "RFC 9114 §4.3.1. A non-CONNECT request includes exactly one :scheme.
Omitting it is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 request without :scheme is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-noscheme")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "NOSCHEME reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-missing-path-test (port)
  "RFC 9114 §4.3.1. A non-CONNECT request includes exactly one :path.
Omitting it is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 request without :path is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-nopath")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "NOPATH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-missing-authority-test (port)
  "RFC 9114 §4.3.1. An https request includes :authority or Host.
Omitting both is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 request without :authority or Host is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-noauth")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "NOAUTH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-empty-host-test (port)
  "RFC 9114 §4.3.1. Host, when present, is not empty. An empty value is
malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 request with an empty Host is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-ehost")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "EHOST reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-host-authority-test (port)
  "RFC 9114 §4.3.1. An https request may name its authority with Host and
omit :authority. GET /who returns that host. The next GET / returns pazuzu."
  (check "an HTTP/3 request with Host and no :authority is served"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-hostonly")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search (format nil "HOSTONLY reset=None status=200 body=127.0.0.1:~d closed=None" port) out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-host-differs-test (port)
  "RFC 9114 §4.3.1. When an https request carries both :authority and Host,
those fields contain the same value. A different Host is a 400. The same
value is served, and a later GET still returns pazuzu."
  (check "an HTTP/3 Host that differs from :authority is rejected"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-hostdiff")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "HOSTDIFF reset=None status=400 body=Bad Request closed=None" out)
                     (search "HOSTSAME reset=None status=200 body=pazuzu closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-noauth-scheme-test (port)
  "RFC 9114 §4.3.1. A scheme without a mandatory authority, and with none
in the request target, does not also carry :authority or Host. :scheme
about with either field is 400. A surrounding GET still returns pazuzu."
  (check "an HTTP/3 scheme without authority does not carry :authority"
    (let ((script "/tmp/pazuzu-h3-noauth-scheme.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, StreamReset):"
                     "            bucket = self._events.setdefault(event.stream_id, {'status': None, 'data': b'', 'reset': None})"
                     "            bucket['reset'] = event.error_code"
                     "            self._finish(event.stream_id)"
                     "            return"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b'', 'reset': None})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events[stream_id])"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        return await asyncio.wait_for(waiter, 4)"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    authority = f'127.0.0.1:{port}'.encode()"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "        got = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ])"
                     "        print('GET status=%s body=%s reset=%s' % (got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        got = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'about'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ])"
                     "        print('ABOUT status=%s body=%s reset=%s' % (got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        got = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'about'),"
                     "            (b':path', b'/'),"
                     "            (b'host', authority),"
                     "        ])"
                     "        print('ABOUTHOST status=%s body=%s reset=%s' % (got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        got = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', authority),"
                     "            (b':path', b'/'),"
                     "        ])"
                     "        print('LATER status=%s body=%s reset=%s' % (got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu reset=None" out)
                     (search "ABOUT status=400 body=Bad Request reset=None" out)
                     (search "ABOUTHOST status=400 body=Bad Request reset=None" out)
                     (search "LATER status=200 body=pazuzu reset=None" out)
                     (not (search "ABOUT status=400 body=Bad Requestpazuzu" out))
                     (not (search "pazuzu" (subseq out (or (search "ABOUT " out) 0)
                                             (or (search "LATER " out) (length out))))))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-connect-path-test (port)
  "RFC 9114 §4.4. A CONNECT request omits :path. Including it, without
:protocol, is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 CONNECT request with :path is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-cpath")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "CPATH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-connect-scheme-test (port)
  "RFC 9114 §4.4. A CONNECT request omits :scheme. Including it, without
:protocol, is malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 CONNECT request with :scheme is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-cscheme")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "CSCHEME reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-connect-authority-test (port)
  "RFC 9114 §4.4. A CONNECT request includes :authority. Omitting it is
malformed, a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 CONNECT request without :authority is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-cauth")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "CAUTH reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-connect-port-test (port)
  "RFC 9110 §9.3.6. A CONNECT target with an empty or invalid port is 400.
A port in 0..65535 is 501, and the next GET / still returns pazuzu."
  (check "an HTTP/3 CONNECT request without a valid port is rejected"
    (let ((script "/tmp/pazuzu-h3-connect-port.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._events = {}"
                     "        self._waiters = {}"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, StreamReset):"
                     "            bucket = self._events.setdefault(event.stream_id, {'status': None, 'data': b'', 'reset': None})"
                     "            bucket['reset'] = event.error_code"
                     "            self._finish(event.stream_id)"
                     "            return"
                     "        for http_event in self._http.handle_event(event):"
                     "            stream_id = getattr(http_event, 'stream_id', None)"
                     "            if stream_id is None:"
                     "                continue"
                     "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b'', 'reset': None})"
                     "            if isinstance(http_event, HeadersReceived):"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        bucket['status'] = int(value)"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     "            elif isinstance(http_event, DataReceived):"
                     "                bucket['data'] += http_event.data"
                     "                if http_event.stream_ended:"
                     "                    self._finish(stream_id)"
                     ""
                     "    def _finish(self, stream_id):"
                     "        waiter = self._waiters.get(stream_id)"
                     "        if waiter is not None and not waiter.done():"
                     "            waiter.set_result(self._events[stream_id])"
                     ""
                     "    async def request(self, headers):"
                     "        stream_id = self._quic.get_next_available_stream_id()"
                     "        waiter = self._loop.create_future()"
                     "        self._waiters[stream_id] = waiter"
                     "        self._http.send_headers(stream_id, headers, end_stream=True)"
                     "        self.transmit()"
                     "        return await asyncio.wait_for(waiter, 4)"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "        for label, authority in ("
                     "            ('NONE', b'example.com'),"
                     "            ('EMPTY', b'example.com:'),"
                     "            ('BIG', b'example.com:65536'),"
                     "            ('ABC', b'example.com:abc'),"
                     "            ('V6', b'[::1]'),"
                     "            ('V6EMPTY', b'[::1]:'),"
                     "        ):"
                     "            got = await client.request(["
                     "                (b':method', b'CONNECT'),"
                     "                (b':authority', authority),"
                     "            ])"
                     "            print('%s status=%s body=%s reset=%s' % (label, got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        for label, authority in ("
                     "            ('OK', b'example.com:443'),"
                     "            ('ZERO', b'example.com:0'),"
                     "            ('V6OK', b'[::1]:443'),"
                     "        ):"
                     "            got = await client.request(["
                     "                (b':method', b'CONNECT'),"
                     "                (b':authority', authority),"
                     "            ])"
                     "            print('%s status=%s body=%s reset=%s' % (label, got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        got = await client.request(["
                     "            (b':method', b'GET'),"
                     "            (b':scheme', b'https'),"
                     "            (b':authority', f'127.0.0.1:{port}'.encode()),"
                     "            (b':path', b'/'),"
                     "        ])"
                     "        print('GET status=%s body=%s reset=%s' % (got['status'], got['data'].decode(errors='replace'), got['reset']))"
                     "        client.close()"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "NONE status=400 body=Bad Request reset=None" out)
                     (search "EMPTY status=400 body=Bad Request reset=None" out)
                     (search "BIG status=400 body=Bad Request reset=None" out)
                     (search "ABC status=400 body=Bad Request reset=None" out)
                     (search "V6 status=400 body=Bad Request reset=None" out)
                     (search "V6EMPTY status=400 body=Bad Request reset=None" out)
                     (search "OK status=501 body=Not Implemented reset=None" out)
                     (search "ZERO status=501 body=Not Implemented reset=None" out)
                     (search "V6OK status=501 body=Not Implemented reset=None" out)
                     (search "GET status=200 body=pazuzu reset=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-userinfo-authority-test (port)
  "RFC 9114 §4.3.1. :authority for an http or https URI excludes userinfo.
That value is invalid, so the request is malformed, a stream error
H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 :authority with userinfo is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-uinfo")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "UINFO reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-non-token-method-test (port)
  "RFC 9110 §9.1 method = token. RFC 9114 §4.3.1 says :method contains
that method, and §4.1.2 treats an invalid pseudo-header value as a
stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 :method that is not a token is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-mmethod")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "MMETHOD reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-invalid-scheme-test (port)
  "RFC 3986 §3.1 scheme is ALPHA then ALPHA, DIGIT, +, -, or .. RFC 9114
§4.3.1 says :scheme contains that scheme, and §4.1.2 treats an invalid
pseudo-header value as a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 :scheme that is not a URI scheme is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-ischeme")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "ISCHEME reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-fragment-path-test (port)
  "RFC 9114 §4.3.1. :path is path-absolute and an optional query. A
fragment delimiter is not part of either, so the value is invalid and
the request is a stream error H3_MESSAGE_ERROR (0x010e)."
  (check "an HTTP/3 :path with a fragment is malformed"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "qpack-frag")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "FRAG reset=270 status=None closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-grease-setting-test (port)
  "RFC 9114 §7.2.4.1. A reserved SETTINGS identifier (0x21) has no
meaning. The connection stays open and GET still returns the resource."
  (check "a reserved HTTP/3 setting identifier is ignored"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "grease-setting")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SETTING 33=9" out)
                     (search "STILL closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-h2-setting-test (port)
  "RFC 9114 §7.2.4.1. SETTINGS_ENABLE_PUSH (0x02) has no HTTP/3 setting.
Receipt is a connection error of type H3_SETTINGS_ERROR (0x0109)."
  (check "an HTTP/2 SETTINGS_ENABLE_PUSH identifier is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "h2-setting")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SETTING 2=0" out)
                     (search "SECOND closed=265" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-missing-settings-test (port)
  "RFC 9114 §6.2.1. The first frame on the control stream must be
SETTINGS. Any other type is H3_MISSING_SETTINGS (0x010a)."
  (check "a control stream that does not start with SETTINGS is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "missing-settings")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SECOND closed=266" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-priority-frame-test (port)
  "RFC 9114 §7.2.8. HTTP/2 PRIORITY (type 0x02) has no HTTP/3 frame.
Receipt is a connection error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "an HTTP/2 PRIORITY frame is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "h2-priority")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-reserved-frame-test (port)
  "RFC 9114 §7.2.8. HTTP/2 PING (0x06), WINDOW_UPDATE (0x08), and
CONTINUATION (0x09) have no HTTP/3 frame. Receipt is H3_FRAME_UNEXPECTED."
  (check "an HTTP/2 PING, WINDOW_UPDATE, or CONTINUATION frame is an HTTP/3 connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (dolist (mode '("h2-ping" "h2-window" "h2-continuation"))
        (multiple-value-bind (out err code)
            (uiop:run-program (list (aioquic-python) script (princ-to-string port) mode)
                              :output :string :error-output :string :ignore-error-status t)
          (unless (and code (zerop code)
                       (search "GET status=200 body=pazuzu" out)
                       (search "SECOND closed=261" out))
            (fail "~a exit ~s out ~s err ~s" mode code out err)))))))

(defun h3-client-push-promise-test (port)
  "RFC 9114 §7.2.5. A client MUST NOT send PUSH_PROMISE. A server treats
receipt as a connection error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a client PUSH_PROMISE is an HTTP/3 connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "push-promise")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-second-control-test (port)
  "RFC 9114 §6.2.1. A second control stream is a connection error of
type H3_STREAM_CREATION_ERROR (0x0103)."
  (check "a second HTTP/3 control stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "control2")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=259" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-cancel-unknown-push-test (port)
  "RFC 9114 §7.2.3. CANCEL_PUSH for a push ID that no PUSH_PROMISE has
mentioned is a connection error of type H3_ID_ERROR (0x0108)."
  (check "a CANCEL_PUSH for an unknown push ID is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "cancel-unknown")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=264" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-max-push-length-test (port)
  "RFC 9114 §7.1. A MAX_PUSH_ID payload with bytes after the push ID is a
connection error of type H3_FRAME_ERROR (0x0106)."
  (check "a MAX_PUSH_ID payload with extra bytes is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "max-push-long")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=262" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-max-push-on-request-test (port)
  "RFC 9114 §7.2.7. MAX_PUSH_ID on a stream other than the control stream
is a connection error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a MAX_PUSH_ID on a request stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "max-push-bidi")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-cancel-push-on-request-test (port)
  "RFC 9114 §7.2.3. CANCEL_PUSH on a stream other than the control stream
is a connection error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a CANCEL_PUSH on a request stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "cancel-bidi")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-settings-on-request-test (port)
  "RFC 9114 §7.2.4. A SETTINGS frame on a request stream is a connection
error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a SETTINGS frame on a request stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "settings-bidi")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-second-settings-test (port)
  "RFC 9114 §7.2.4. A second SETTINGS frame on the control stream is a
connection error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a second SETTINGS frame is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "settings-control")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-headers-on-control-test (port)
  "RFC 9114 §7.2.2. A HEADERS frame on the control stream is a connection
error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a HEADERS frame on the control stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "headers-control")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-data-on-control-test (port)
  "RFC 9114 §7.2.1. A DATA frame on the control stream is a connection
error of type H3_FRAME_UNEXPECTED (0x0105)."
  (check "a DATA frame on the control stream is a connection error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "data-control")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND closed=261" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-second-request-test (port)
  "RFC 9114 §4.1. A second request on the same stream is malformed.
Section 4.1.2 makes that a stream error of type H3_MESSAGE_ERROR (0x010e)."
  (check "a second request on one stream is a stream error"
    (let ((script "/tmp/pazuzu-h3-encoder.py"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "twice")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "GET status=200 body=pazuzu" out)
                     (search "SECOND reset=270 closed=None" out)
                     (search "LATER status=200 body=pazuzu closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun mint-retry-token (endpoint host port version retry-scid odcid timestamp)
  (cffi:with-foreign-objects ((remote :uint8 28)
                              (chosen :uint8 32)
                              (original :uint8 32)
                              (token :uint8 128))
    (let ((remote-len (pazuzu::fill-sockaddr remote host port))
          (secret (pazuzu::h3-endpoint-retry-secret endpoint)))
      (pazuzu::h3-put-cid chosen retry-scid)
      (pazuzu::h3-put-cid original odcid)
      (cffi:with-pointer-to-vector-data (secret-ptr secret)
        (let ((length (pazuzu::ngtcp2-generate-retry-token
                       token secret-ptr (length secret) version
                       remote remote-len chosen original timestamp)))
          (unless (plusp length)
            (fail "retry token length ~d" length))
          (pazuzu::foreign-to-octets token length))))))

(defun retry-secret-test ()
  "RFC 9000 §8.1.2. The Retry integrity secret is random per endpoint.
A token older than 10 seconds is rejected. A token sealed with another
endpoint's secret is rejected. A fresh token returns the original
destination connection ID."
  (multiple-value-bind (cert key) (make-cert #p"/tmp/pazuzu-retry-cert/" "retry")
    (call-with-server
     (lambda (left)
       (call-with-server
        (lambda (right)
          (check "a Retry token is bound to one endpoint and expires"
            (let* ((a (pazuzu::server-endpoint left))
                   (b (pazuzu::server-endpoint right))
                   (secret-a (pazuzu::h3-endpoint-retry-secret a))
                   (secret-b (pazuzu::h3-endpoint-retry-secret b))
                   (host (make-array 4 :element-type '(unsigned-byte 8)
                                     :initial-contents '(127 0 0 1)))
                   (scid (make-array 8 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 2 3 4 5 6 7 8)))
                   (odcid (make-array 8 :element-type '(unsigned-byte 8)
                                      :initial-contents '(9 10 11 12 13 14 15 16)))
                   (now (pazuzu::monotonic-ns)))
              (unless (and a b
                          (vectorp secret-a) (= (length secret-a) 32)
                          (vectorp secret-b) (= (length secret-b) 32)
                          (not (equalp secret-a secret-b))
                          (notevery #'zerop secret-a))
                (fail "secrets ~s ~s" secret-a secret-b))
              (let ((fresh (mint-retry-token a host 9 1 scid odcid now)))
                (unless (equalp (pazuzu::h3-verify-retry a host 9 1 fresh scid) odcid)
                  (fail "fresh ~s" (pazuzu::h3-verify-retry a host 9 1 fresh scid)))
                (when (pazuzu::h3-verify-retry b host 9 1 fresh scid)
                  (fail "other endpoint accepted the token")))
              (let ((recent (mint-retry-token a host 9 1 scid odcid (- now 9000000000))))
                (unless (equalp (pazuzu::h3-verify-retry a host 9 1 recent scid) odcid)
                  (fail "recent token rejected")))
              (let ((stale (mint-retry-token a host 9 1 scid odcid (- now 11000000000))))
                (when (pazuzu::h3-verify-retry a host 9 1 stale scid)
                  (fail "stale token accepted"))))))
        :certificate cert :private-key key))
     :certificate cert :private-key key)))

(defun redirect-date-test ()
  "RFC 9110 §6.6.1. A cleartext redirect is 301 or 308 and carries Date."
  (multiple-value-bind (cert key) (make-cert #p"/tmp/pazuzu-redirect-cert/" "redirect")
    (call-with-server
     (lambda (server)
       (let ((clear (pazuzu:server-clear-port server))
             (https (pazuzu:server-port server)))
         (check "a redirect has a Date"
           (let ((reply (exchange clear (request-text "GET /q?a=1 HTTP/1.1"
                                                      "Host: 127.0.0.1"))))
             (expect-status reply 301)
             (unless (header reply "date")
               (fail "301 without Date"))
             (unless (string= (header reply "location")
                              (format nil "https://127.0.0.1:~d/q?a=1" https))
               (fail "location ~s" (header reply "location"))))
           (let ((reply (exchange clear (request-text "POST /q HTTP/1.1"
                                                      "Host: 127.0.0.1"
                                                      "Content-Length: 0"))))
             (expect-status reply 308)
             (unless (header reply "date")
               (fail "308 without Date"))
             (unless (string= (header reply "location")
                              (format nil "https://127.0.0.1:~d/q" https))
               (fail "location ~s" (header reply "location")))))
         (check "a redirect does not generate an empty https host"
           ;; RFC 9110 §4.2.2. HTTP/1.0 without Host has no authority.
           ;; The redirect must not invent https://:port/.
           (let ((reply (exchange clear (request-text "GET /q HTTP/1.0"))))
             (expect-status reply 400)
             (when (header reply "location")
               (fail "location ~s" (header reply "location"))))
           (let ((reply (exchange clear (request-text "GET /q HTTP/1.0"
                                                      "Host: 127.0.0.1"))))
             (expect-status reply 301)
             (unless (string= (header reply "location")
                              (format nil "https://127.0.0.1:~d/q" https))
               (fail "location ~s" (header reply "location")))))
         (check "a generated https URI has no userinfo"
           ;; RFC 9110 §4.2.4. The redirect target is an https URI.
           ;; An @ in the path and the query is not a userinfo subcomponent.
           (let ((reply (exchange clear (request-text "GET /a@b?x=@ HTTP/1.1"
                                                     "Host: 127.0.0.1"))))
             (expect-status reply 301)
             (let* ((location (or (header reply "location") ""))
                    (slash (search "/" location :start2 8)))
               (unless (string= location
                                (format nil "https://127.0.0.1:~d/a@b?x=@" https))
                 (fail "location ~s" location))
               (unless slash
                 (fail "location ~s" location))
               (when (find #\@ (subseq location 8 slash))
                 (fail "userinfo ~a" (subseq location 8 slash))))))))
     :certificate cert :private-key key :redirect-port 0)))

