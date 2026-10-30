(in-package #:pazuzu)

(defparameter *duration-bounds*
  #(0.005d0 0.01d0 0.025d0 0.05d0 0.1d0 0.25d0 0.5d0 1d0 2.5d0 5d0 10d0)
  "Classic Prometheus histogram bounds for request duration, in seconds.")

(defparameter *access-months*
  #("Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"))

(defstruct metrics
  (lock (bt:make-lock "pazuzu-metrics"))
  (accepted 0)
  (rejected 0)
  (requests (make-hash-table :test #'equal))
  (duration-buckets (make-array 11 :element-type 'fixnum :initial-element 0))
  (duration-sum 0d0)
  (duration-count 0)
  (response-bytes 0))

(defstruct logger
  (lock (bt:make-lock "pazuzu-log"))
  access-path
  error-path
  access-stream
  error-stream)

(defun open-log-stream (path)
  (when path
    (ensure-directories-exist path)
    (open path :direction :output
          :if-exists :append
          :if-does-not-exist :create
          :element-type 'character)))

(defun open-logger (&key access-log error-log)
  (make-logger :access-path access-log
               :error-path error-log
               :access-stream (open-log-stream access-log)
               :error-stream (open-log-stream error-log)))

(defun close-logger (logger)
  (when logger
    (bt:with-lock-held ((logger-lock logger))
      (when (logger-access-stream logger)
        (close (logger-access-stream logger))
        (setf (logger-access-stream logger) nil))
      (when (logger-error-stream logger)
        (close (logger-error-stream logger))
        (setf (logger-error-stream logger) nil)))))

(defun reopen-logger (logger)
  "Close and reopen the log files so a rotated file is picked up.
A path that is now NIL closes that log."
  (when logger
    (bt:with-lock-held ((logger-lock logger))
      (when (logger-access-stream logger)
        (close (logger-access-stream logger)))
      (setf (logger-access-stream logger)
            (open-log-stream (logger-access-path logger)))
      (when (logger-error-stream logger)
        (close (logger-error-stream logger)))
      (setf (logger-error-stream logger)
            (open-log-stream (logger-error-path logger))))))

(defun write-log-line (stream text)
  (when stream
    (write-line text stream)
    (finish-output stream)))

(defun one-log-line (text)
  "CR, LF, and NUL would split a log record. Replace them with a space."
  (map 'string
       (lambda (character)
         (if (member character '(#\Return #\Newline #\Nul))
             #\Space
             character))
       text))

(defvar *log-level* :notice
  "notice writes notice and error. error writes only error.")

(defvar *access-on-stdout* nil
  "When true, access lines are also written to standard output for journald.")

(defun set-log-level (name)
  "NAME is notice or error."
  (cond ((member name '("notice" "info") :test #'string-equal)
         (setf *log-level* :notice))
        ((string-equal name "error")
         (setf *log-level* :error))
        (t (error "unknown log level ~a (expected notice or error)" name))))

(defun log-level-enabled-p (level)
  (or (string-equal level "error")
      (eq *log-level* :notice)))

(defun error-log (logger level control &rest args)
  "Write one error-log line. LEVEL is a short word such as \"error\".
The line goes to the error stream so journald records it. A notice line
is skipped when the log level is error."
  (unless (log-level-enabled-p level)
    (return-from error-log nil))
  (let ((text (one-log-line (format nil "~a [~a] ~a"
                                    (iso-timestamp)
                                    level
                                    (apply #'format nil control args)))))
    (write-log-line *error-output* text)
    (when logger
      (bt:with-lock-held ((logger-lock logger))
        (ignore-errors (write-log-line (logger-error-stream logger) text))))))

(defun iso-timestamp ()
  (multiple-value-bind (sec min hour day month year) (decode-universal-time (get-universal-time) 0)
    (format nil "~4,'0d-~2,'0d-~2,'0dT~2,'0d:~2,'0d:~2,'0dZ"
            year month day hour min sec)))

(defun access-time (universal)
  (multiple-value-bind (sec min hour day month year) (decode-universal-time universal 0)
    (format nil "[~2,'0d/~a/~d:~2,'0d:~2,'0d:~2,'0d +0000]"
            day
            (aref *access-months* (1- month))
            year hour min sec)))

(defun log-quote (text)
  (if (null text)
      "-"
      (with-output-to-string (out)
        (loop for char across text
              do (case char
                   ((#\" #\\) (write-char #\\ out) (write-char char out))
                   ((#\Return #\Newline) (write-char #\Space out))
                   (t (write-char char out)))))))

(defun protocol-token (http-version)
  (case http-version
    (10 "HTTP/1.0")
    (20 "HTTP/2")
    (30 "HTTP/3")
    (t "HTTP/1.1")))

(defun protocol-label (http-version)
  (case http-version
    (10 "1.0")
    (20 "2")
    (30 "3")
    (t "1.1")))

(defun access-log (logger &key peer request status bytes referer user-agent time
                            (id *request-id*))
  "Write one line in the Combined Log Format, with id= when a request id is bound."
  (let ((line (format nil "~a - - ~a \"~a\" ~d ~a \"~a\" \"~a\"~@[ id=~a~]"
                      (or peer "-")
                      (access-time (or time (get-universal-time)))
                      (log-quote request)
                      status
                      (if bytes (princ-to-string bytes) "-")
                      (log-quote (or referer "-"))
                      (log-quote (or user-agent "-"))
                      id)))
    (when *access-on-stdout*
      (write-log-line *standard-output* line))
    (when (and logger (logger-access-stream logger))
      (bt:with-lock-held ((logger-lock logger))
        (ignore-errors (write-log-line (logger-access-stream logger) line))))))

(defun count-response (metrics protocol status bytes seconds)
  (bt:with-lock-held ((metrics-lock metrics))
    (let ((key (cons protocol status)))
      (setf (gethash key (metrics-requests metrics))
            (1+ (gethash key (metrics-requests metrics) 0))))
    (incf (metrics-response-bytes metrics) (max 0 (or bytes 0)))
    (when seconds
      (incf (metrics-duration-count metrics))
      (incf (metrics-duration-sum metrics) (coerce seconds 'double-float))
      (loop for index below (length *duration-bounds*)
            when (<= seconds (aref *duration-bounds* index))
              do (incf (aref (metrics-duration-buckets metrics) index))))))

(defun count-accept (metrics)
  (bt:with-lock-held ((metrics-lock metrics))
    (incf (metrics-accepted metrics))))

(defun count-reject (metrics)
  (bt:with-lock-held ((metrics-lock metrics))
    (incf (metrics-rejected metrics))))

(defun prom-escape (text)
  (with-output-to-string (out)
    (loop for char across (princ-to-string text)
          do (case char
               (#\\ (write-string "\\\\" out))
               (#\" (write-string "\\\"" out))
               (#\Newline (write-string "\\n" out))
               (t (write-char char out))))))

(defun metrics-text (metrics &key active workers)
  "Prometheus text exposition 0.0.4."
  (bt:with-lock-held ((metrics-lock metrics))
    (with-output-to-string (out)
      (format out "# HELP pazuzu_connections_accepted_total TCP connections admitted.~%")
      (format out "# TYPE pazuzu_connections_accepted_total counter~%")
      (format out "pazuzu_connections_accepted_total ~d~%" (metrics-accepted metrics))
      (format out "# HELP pazuzu_connections_rejected_total Connections refused by a limit.~%")
      (format out "# TYPE pazuzu_connections_rejected_total counter~%")
      (format out "pazuzu_connections_rejected_total ~d~%" (metrics-rejected metrics))
      (format out "# HELP pazuzu_connections_active Connections currently admitted.~%")
      (format out "# TYPE pazuzu_connections_active gauge~%")
      (format out "pazuzu_connections_active ~d~%" (or active 0))
      (format out "# HELP pazuzu_workers Configured accept workers.~%")
      (format out "# TYPE pazuzu_workers gauge~%")
      (format out "pazuzu_workers ~d~%" (or workers 0))
      (format out "# HELP pazuzu_requests_total HTTP responses by protocol and status.~%")
      (format out "# TYPE pazuzu_requests_total counter~%")
      (maphash (lambda (key count)
                 (format out "pazuzu_requests_total{protocol=\"~a\",status=\"~a\"} ~d~%"
                         (prom-escape (car key))
                         (prom-escape (cdr key))
                         count))
               (metrics-requests metrics))
      (format out "# HELP pazuzu_response_bytes_total Response body bytes observed.~%")
      (format out "# TYPE pazuzu_response_bytes_total counter~%")
      (format out "pazuzu_response_bytes_total ~d~%" (metrics-response-bytes metrics))
      (format out "# HELP pazuzu_request_duration_seconds Request duration.~%")
      (format out "# TYPE pazuzu_request_duration_seconds histogram~%")
      (loop for index below (length *duration-bounds*)
            do (format out "pazuzu_request_duration_seconds_bucket{le=\"~a\"} ~d~%"
                       (prom-escape (format nil "~f" (aref *duration-bounds* index)))
                       (aref (metrics-duration-buckets metrics) index)))
      (format out "pazuzu_request_duration_seconds_bucket{le=\"+Inf\"} ~d~%"
              (metrics-duration-count metrics))
      (format out "pazuzu_request_duration_seconds_sum ~f~%" (metrics-duration-sum metrics))
      (format out "pazuzu_request_duration_seconds_count ~d~%" (metrics-duration-count metrics)))))
