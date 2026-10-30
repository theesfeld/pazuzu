;;; Cleartext origin for h2spec. HTTP/2 prior knowledge is accepted on the
;;; same socket as HTTP/1.1. Set H2SPEC_PORT to choose the port (default 18080).
(defvar *h2spec-port*
  (let ((text (sb-ext:posix-getenv "H2SPEC_PORT")))
    (if (and text (plusp (length text)))
        (parse-integer text)
        18080)))

(defvar *h2spec-server*
  (pazuzu:start :address "127.0.0.1" :port *h2spec-port*))

(pazuzu:add-route *h2spec-server* :get "/"
                  (lambda (request)
                    (declare (ignore request))
                    (pazuzu:text-response "pazuzu")))

(format t "h2spec-ready ~d~%" (pazuzu:server-port *h2spec-server*))
(finish-output)
(loop (sleep 3600))
