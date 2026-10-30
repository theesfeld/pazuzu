(in-package #:pazuzu/tests)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (load (asdf:system-relative-pathname :pazuzu "examples/site.lisp")))

(defun example-site-test ()
  (call-with-server
   (lambda (server)
     (pazuzu/example:install server)
     (let ((port (pazuzu::server-port server)))
       (check "the example site is a Lisp program"
         (let ((home (exchange port (request-text "GET / HTTP/1.1" "Host: 127.0.0.1"))))
           (expect-status home 200)
           (unless (string= (body-text home) "hello from pazuzu")
             (fail "home ~s" (body-text home)))
           (unless (string= (header home "x-example") "site")
             (fail "mark ~s" (header home "x-example"))))
         (let ((greet (exchange port (request-text "GET /greet HTTP/1.1"
                                                   "Host: 127.0.0.1"
                                                   "X-Name: lisp"))))
           (expect-status greet 200)
           (unless (string= (body-text greet) "hello lisp")
             (fail "greet ~s" (body-text greet)))))))))

(defun h3load-test ()
  "script/h3load.sh issues many HTTP/3 requests on one curl connection."
  (multiple-value-bind (cert key) (make-cert #p"/tmp/pazuzu-h3load/" "127.0.0.1")
    (call-with-server
     (lambda (server)
       (pazuzu:add-route server :get "/h3load"
                         (lambda (request)
                           (declare (ignore request))
                           (pazuzu:text-response "h3")))
       (let* ((url (format nil "https://127.0.0.1:~d/h3load"
                           (pazuzu::server-port server)))
              (script (namestring
                       (asdf:system-relative-pathname :pazuzu "script/h3load.sh"))))
         (check "http/3 load reuses one connection"
           (multiple-value-bind (text code)
               (command-text script url "8")
             (unless (and code (zerop code))
               (fail "h3load exit ~s output ~s" code text))
             (unless (search "ok=8" text)
               (fail "h3load ~s" text))
             (when (search "connects=8" text)
               (fail "one connection per request: ~s" text))))))
     :certificate cert :private-key key)))
