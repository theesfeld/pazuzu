;;; Build build/pazuzu. Loaded after Quicklisp's setup.lisp.
(asdf:load-asd (truename "pazuzu.asd"))
(ql:quickload :pazuzu)

(defun pazuzu-toplevel ()
  (let ((code 0))
    (handler-case (pazuzu:main (rest sb-ext:*posix-argv*))
      (sb-sys:interactive-interrupt ()
        (setf code 0))
      (error (condition)
        (format *error-output* "pazuzu: ~a~%" condition)
        (finish-output *error-output*)
        (setf code 1)))
    (sb-ext:exit :code code :abort t)))

(ensure-directories-exist "build/")
(let ((path "build/pazuzu")
      (common (list :executable t
                    :toplevel #'pazuzu-toplevel
                    :save-runtime-options t)))
  (handler-case
      (apply #'sb-ext:save-lisp-and-die path :compression 9 common)
    (error (condition)
      (format *error-output* "pazuzu: saving without compression (~a)~%" condition)
      (finish-output *error-output*)
      (apply #'sb-ext:save-lisp-and-die path common))))
