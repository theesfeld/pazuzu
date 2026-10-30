(in-package #:pazuzu/tests)

(defun reliability-tests (server)
  (let ((port (pazuzu::server-port server)))
    (check "a handler sees a request id"
      (let ((seen nil))
        (pazuzu:add-route server :get "/rid"
                          (lambda (request)
                            (declare (ignore request))
                            (setf seen pazuzu::*request-id*)
                            (pazuzu:text-response "rid")))
        (expect-status (exchange port (request-text "GET /rid HTTP/1.1"
                                                    "Host: 127.0.0.1"))
                       200)
        (unless (and seen (= (length seen) 16)
                     (every (lambda (char) (find char "0123456789abcdef")) seen))
          (fail "id ~s" seen))))
    (check "a full connection cap refuses before the slot is taken"
      (let ((saved (pazuzu::server-max-connections server)))
        (unwind-protect
             (progn
               (setf (pazuzu::server-max-connections server) 1)
               (pazuzu:add-route server :get "/hold"
                                 (lambda (request)
                                   (declare (ignore request))
                                   (sleep 1)
                                   (pazuzu:text-response "held")))
               (let ((holder (bt:make-thread
                              (lambda ()
                                (exchange port (request-text "GET /hold HTTP/1.1"
                                                             "Host: 127.0.0.1"))))))
                 (sleep 0.3)
                 (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                             "Host: 127.0.0.1"))
                                503)
                 (let ((count (bt:with-lock-held ((pazuzu::server-lock server))
                                 (pazuzu::connection-count server))))
                   (unless (= count 1)
                     (fail "admitted ~d" count)))
                 (bt:join-thread holder)))
          (setf (pazuzu::server-max-connections server) saved))))
    (check "a heap watermark refuses new connections"
      (let ((saved (pazuzu::server-heap-limit server)))
        (unwind-protect
             (progn
               (setf (pazuzu::server-heap-limit server) 1)
               (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                           "Host: 127.0.0.1"))
                              503)
               (setf (pazuzu::server-heap-limit server) nil)
               (expect-status (exchange port (request-text "GET / HTTP/1.1"
                                                           "Host: 127.0.0.1"))
                              200))
          (setf (pazuzu::server-heap-limit server) saved))))
    (check "an http3 connection error does not stop the next one"
      (let ((second nil))
        (pazuzu::h3-guard-conn nil nil (lambda () (error "one connection")))
        (pazuzu::h3-guard-conn nil nil (lambda () (setf second t)))
        (unless second
          (fail "the endpoint stopped"))))
    (check "random octets stay inside the request parser"
      (dotimes (i 80)
        (let* ((count (+ 1 (random 180)))
               (data (make-array count :element-type '(unsigned-byte 8)))
               (source (make-instance 'byte-source :data data)))
          (loop for index below count
                do (setf (aref data index) (random 256)))
          (let ((pazuzu::*read-ahead* (if (evenp i) (pazuzu::make-read-ahead) nil)))
            (handler-case (pazuzu::read-request source)
              (pazuzu:protocol-error ())
              (pazuzu::end-of-request ())
              (pazuzu::final-before-content ())
              (error (condition)
                (fail "fuzz ~d signaled ~a" i condition)))))))))

(defun handoff-test ()
  "A new process inherits the listening socket and answers on the same port."
  (format t "handoff...~%")
  (finish-output)
  (with-open-file (out "/tmp/pazuzu-handoff-child.lisp"
                       :direction :output :if-exists :supersede)
    (write-string "(asdf:load-asd (truename \"/workspace/pazuzu.asd\"))
(ql:quickload :pazuzu)
(let ((server (pazuzu:start :address \"127.0.0.1\" :port 9)))
  (pazuzu:add-route server :get \"/handed\"
                    (lambda (request)
                      (declare (ignore request))
                      (pazuzu:text-response \"handed\")))
  (format t \"CHILD ~a~%\" (pazuzu:server-port server))
  (finish-output)
  (loop (sleep 30)))
" out))
  (call-with-server
   (lambda (server)
     (let* ((port (pazuzu::server-port server))
            (sbcl (namestring sb-ext:*runtime-pathname*))
            (process (sb-sys:with-deadline (:seconds 45)
                       (pazuzu::reexec server
                                       :program sbcl
                                       :output #p"/tmp/handoff-spawn.log"
                                       :arguments
                                       (list "--dynamic-space-size" "2048"
                                             "--noinform" "--disable-debugger"
                                             "--load" "/tmp/ql/quicklisp/setup.lisp"
                                             "--load" "/tmp/pazuzu-handoff-child.lisp")))))
       (unwind-protect
            (let ((reply nil))
              (loop repeat 40
                    do (setf reply (ignore-errors
                                    (exchange port
                                              (request-text "GET /handed HTTP/1.1"
                                                            "Host: 127.0.0.1"))))
                    when (and reply (= (reply-status reply) 200)
                              (string= (body-text reply) "handed"))
                      return nil
                    do (sleep 0.5)
                    finally (fail "child did not answer on ~d" port)))
         (ignore-errors (sb-ext:process-kill process 15))
         (ignore-errors (sb-ext:process-wait process))))))
  (format t "ok   listening socket handed to a new process~%")
  (finish-output))
