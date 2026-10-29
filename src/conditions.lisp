(in-package #:pazuzu)

(define-condition protocol-error (error)
  ((status :initarg :status :reader protocol-error-status)
   (close-connection :initarg :close-connection :initform t
                     :reader protocol-error-close-connection)
   (detail :initarg :detail :initform nil :reader protocol-error-detail))
  (:report (lambda (condition stream)
             (format stream "HTTP ~d~@[ (~a)~]"
                     (protocol-error-status condition)
                     (protocol-error-detail condition)))))

(defun protocol-error (status &key (close-connection t) detail)
  (error 'protocol-error
         :status status
         :close-connection close-connection
         :detail detail))

(define-condition end-of-request (error) ()
  (:documentation "The peer closed the connection between requests."))

(define-condition final-before-content (error)
  ((request :initarg :request :reader final-before-content-request)
   (response :initarg :response :reader final-before-content-response))
  (:documentation "RFC 9110 §10.1.1. The final status is known from the
method, target, and header fields. The request content is not read.")
  (:report (lambda (condition stream)
             (declare (ignore condition))
             (format stream "final status before request content"))))
