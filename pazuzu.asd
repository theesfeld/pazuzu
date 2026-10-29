(defsystem "pazuzu"
  :description "Origin server for HTTP/1.1, HTTP/2, and HTTP/3."
  :author "pazuzu"
  :license "MIT"
  :depends-on ("alexandria"
               "babel"
               "bordeaux-threads"
               "cffi"
               "chipz"
               "cl-base64"
               "cl+ssl"
               "ironclad"
               "salza2"
               "usocket")
  :serial t
  :components ((:module "src"
                :components ((:file "package")
                             (:file "conditions")
                             (:file "bytes")
                             (:file "dates")
                             (:file "headers")
                             (:file "http1")
                             (:file "semantics")
                             (:file "coding")
                             (:file "cookies")
                             (:file "auth")
                             (:file "websocket")
                             (:file "pins")
                             (:file "observe")
                             (:file "http2")
                             (:file "http3")
                             (:file "server")
                             (:file "config"))))
  :in-order-to ((test-op (test-op "pazuzu/tests"))))

(defsystem "pazuzu/tests"
  :depends-on ("pazuzu")
  :serial t
  :components ((:module "t"
                :components ((:file "run"))))
  :perform (test-op (op system)
             (uiop:symbol-call :pazuzu/tests :run)))
