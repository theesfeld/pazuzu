(in-package #:pazuzu/tests)

(defvar *live-body* "one")

(defun live-handler (request)
  (declare (ignore request))
  (pazuzu:text-response *live-body*))

(defun app-tests (server)
  (let ((port (pazuzu::server-port server)))
    (check "a symbol handler follows a redefinition"
      (setf *live-body* "one")
      (pazuzu:add-route server :get "/live" 'live-handler)
      (let ((first (exchange port (request-text "GET /live HTTP/1.1" "Host: 127.0.0.1"))))
        (expect-status first 200)
        (unless (string= (body-text first) "one")
          (fail "first body ~s" (body-text first))))
      (setf *live-body* "two")
      (let ((second (exchange port (request-text "GET /live HTTP/1.1" "Host: 127.0.0.1"))))
        (expect-status second 200)
        (unless (string= (body-text second) "two")
          (fail "second body ~s" (body-text second)))))
    (check "defroute stores a symbol"
      (setf *live-body* "macro")
      (pazuzu:defroute server :get "/macro" live-handler)
      (let ((reply (exchange port (request-text "GET /macro HTTP/1.1" "Host: 127.0.0.1"))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "macro")
          (fail "macro body ~s" (body-text reply)))))
    (check "middleware runs outer first"
      (pazuzu:add-middleware server
                             (lambda (request next)
                               (let ((response (funcall next request)))
                                 (when (string= (pazuzu:request-path request) "/mw")
                                   (setf (pazuzu:response-headers response)
                                         (acons "x-outer" "1" (pazuzu:response-headers response))))
                                 response)))
      (pazuzu:add-route server :get "/mw"
                        (lambda (request)
                          (declare (ignore request))
                          (pazuzu:text-response "mw"))
                        :middleware (list (lambda (request next)
                                            (let ((response (funcall next request)))
                                              (setf (pazuzu:response-headers response)
                                                    (acons "x-inner" "1"
                                                           (pazuzu:response-headers response)))
                                              response))))
      (let ((reply (exchange port (request-text "GET /mw HTTP/1.1" "Host: 127.0.0.1"))))
        (expect-status reply 200)
        (unless (string= (header reply "x-outer") "1")
          (fail "outer ~s" (header reply "x-outer")))
        (unless (string= (header reply "x-inner") "1")
          (fail "inner ~s" (header reply "x-inner")))))
    (check "abort-request answers 500"
      (pazuzu:add-route server :get "/abort"
                        (lambda (request)
                          (declare (ignore request))
                          (if (find-restart 'pazuzu:abort-request)
                              (invoke-restart 'pazuzu:abort-request)
                              (pazuzu:text-response "no-restart"))))
      (expect-status (exchange port (request-text "GET /abort HTTP/1.1" "Host: 127.0.0.1"))
                     500))
    (check "retry-handler runs the handler again"
      (let ((tries 0))
        (pazuzu:add-route server :get "/retry"
                          (lambda (request)
                            (declare (ignore request))
                            (incf tries)
                            (if (= tries 1)
                                (invoke-restart 'pazuzu:retry-handler)
                                (pazuzu:text-response "retried")))))
      (let ((reply (exchange port (request-text "GET /retry HTTP/1.1" "Host: 127.0.0.1"))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "retried")
          (fail "retry body ~s" (body-text reply)))))
    (check "the lisp listener refuses a public address"
      (handler-case
          (progn
            (pazuzu:start-listener :interface :swank :port 4005 :address "0.0.0.0")
            (fail "public listener was accepted"))
        (error (condition)
          (unless (search "localhost" (princ-to-string condition))
            (fail "error ~a" condition)))))
    (check "a lack app sees the method and path"
      (pazuzu:mount-lack server
                         (lambda (env)
                           (list 200
                                 '(:content-type "text/plain; charset=utf-8")
                                 (list (format nil "~a ~a"
                                               (getf env :request-method)
                                               (getf env :path-info)))))
                         :path "/lack")
      (let ((reply (exchange port (request-text "GET /lack/hi?x=1 HTTP/1.1"
                                                "Host: app.example"))))
        (expect-status reply 200)
        (unless (string= (body-text reply) "GET /lack/hi")
          (fail "lack body ~s" (body-text reply)))))))
