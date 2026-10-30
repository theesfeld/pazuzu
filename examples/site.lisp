;;;; A small site written as a Lisp program.
;;;;
;;;; Load pazuzu, then:
;;;;
;;;;   (load "examples/site.lisp")
;;;;   (defvar *site* (pazuzu/example:start :port 8080))
;;;;
;;;; GET / answers "hello from pazuzu". GET /greet reads the X-Name header.
;;;; A middleware sets X-Example on every response. The handlers are symbols,
;;;; so redefining pazuzu/example:home or greet updates the live server.

(defpackage #:pazuzu/example
  (:use #:common-lisp #:pazuzu)
  ;; START is this site's entry point. Without the shadow, DEFUN would
  ;; redefine pazuzu:start.
  (:shadow #:start)
  (:export #:home #:greet #:install #:start))

(in-package #:pazuzu/example)

(defun home (request)
  (declare (ignore request))
  (text-response "hello from pazuzu"))

(defun greet (request)
  (text-response (format nil "hello ~a"
                         (or (request-header request "x-name") "lisp"))))

(defun stamp (request next)
  "Mark the response as coming from this example."
  (let ((response (funcall next request)))
    (setf (response-headers response)
          (acons "x-example" "site" (response-headers response)))
    response))

(defun install (server)
  "Mount the example routes on SERVER. Safe to call on a server that is already up."
  (add-middleware server #'stamp)
  (defroute server :get "/" home)
  (defroute server :get "/greet" greet)
  server)

(defun start (&key (port 8080) (address "127.0.0.1"))
  "Start an origin and mount this site. Returns the server."
  (let ((server (pazuzu:start :address address :port port)))
    (install server)
    (format t "example site on http://~a:~d/~%" address (pazuzu:server-port server))
    (finish-output)
    server))
