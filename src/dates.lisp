(in-package #:pazuzu)

(defparameter *weekday-names*
  #("Mon" "Tue" "Wed" "Thu" "Fri" "Sat" "Sun"))

(defparameter *weekday-long-names*
  #("Monday" "Tuesday" "Wednesday" "Thursday" "Friday" "Saturday" "Sunday"))

(defparameter *month-names*
  #("Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"))

(defun format-imf-fixdate (&optional (universal (get-universal-time)))
  "IMF-fixdate, the only HTTP-date an origin may generate (RFC 9110)."
  (multiple-value-bind (second minute hour day month year weekday)
      (decode-universal-time universal 0)
    (format nil "~a, ~2,'0d ~a ~4,'0d ~2,'0d:~2,'0d:~2,'0d GMT"
            (aref *weekday-names* weekday)
            day
            (aref *month-names* (1- month))
            year hour minute second)))

(defun month-number (name)
  "Month number 1–12. HTTP-date names are case-sensitive (RFC 9110 §5.6.7)."
  (let ((pos (position name *month-names* :test #'string=)))
    (and pos (1+ pos))))

(defun weekday-short-p (name)
  "True for a case-sensitive day-name: Mon, Tue, Wed, Thu, Fri, Sat, Sun."
  (find name *weekday-names* :test #'string=))

(defun weekday-long-p (name)
  "True for a case-sensitive day-name-l, the long name used by rfc850-date."
  (find name *weekday-long-names* :test #'string=))

(defun two-digits (string start)
  (let ((a (char string start))
        (b (char string (1+ start))))
    (and (digit-char-p a) (digit-char-p b)
         (+ (* 10 (digit-char-p a)) (digit-char-p b)))))

(defun encode-http-time (second minute hour day month year)
  ;; RFC 9110 §5.6.7 time-of-day includes a leap second. SBCL's
  ;; encode-universal-time rejects second 60, so that second is the
  ;; universal time one second after second 59 of the same minute.
  (and second minute hour day month year
       (<= 1 month 12)
       (<= 1 day 31)
       (<= 0 hour 23)
       (<= 0 minute 59)
       (<= 0 second 60)
       (if (= second 60)
           (let ((stamp (ignore-errors
                          (encode-universal-time 59 minute hour day month year 0))))
             (and stamp (1+ stamp)))
           (ignore-errors
             (encode-universal-time second minute hour day month year 0)))))

(defun parse-imf-fixdate (value)
  ;; Sun, 06 Nov 1994 08:49:37 GMT
  (when (and (= (length value) 29)
             (char= (char value 3) #\,)
             (char= (char value 4) #\Space)
             (weekday-short-p (subseq value 0 3)))
    (let ((day (two-digits value 5))
          (month (and (char= (char value 7) #\Space)
                      (month-number (subseq value 8 11))))
          (year (ignore-errors (parse-integer value :start 12 :end 16)))
          (hour (and (char= (char value 16) #\Space) (two-digits value 17)))
          (minute (and (char= (char value 19) #\:) (two-digits value 20)))
          (second (and (char= (char value 22) #\:) (two-digits value 23))))
      (when (string= value " GMT" :start1 25)
        (encode-http-time second minute hour day month year)))))

(defun universal-plus-years (universal years)
  "UNIVERSAL plus YEARS, clamping a day that does not exist in the target year."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time universal 0)
    (loop for candidate-day from day downto (max 28 (- day 3))
          for stamp = (ignore-errors
                        (encode-universal-time second minute hour
                                               candidate-day month
                                               (+ year years) 0))
          when stamp
            do (return stamp))))

(defun rfc850-stamp (second minute hour day month year2 now)
  "RFC 9110 §5.6.7. Use the occurrence of YEAR2 nearest to NOW. A stamp
more than 50 years ahead is the most recent past year with those digits."
  (let* ((now-year (nth-value 5 (decode-universal-time now 0)))
         (base (* 100 (floor now-year 100)))
         (best nil)
         (best-distance nil))
    (dolist (year (list (- (+ base year2) 100) (+ base year2) (+ base year2 100)))
      (let ((stamp (encode-http-time second minute hour day month year)))
        (when stamp
          (let ((distance (abs (- stamp now))))
            (when (or (null best-distance)
                      (< distance best-distance)
                      (and (= distance best-distance) (> year (car best))))
              (setf best (cons year stamp)
                    best-distance distance))))))
    (when best
      (let ((limit (universal-plus-years now 50)))
        (if (and limit (> (cdr best) limit))
            (encode-http-time second minute hour day month (- (car best) 100))
            (cdr best))))))

(defun parse-rfc850-date (value &key (now (get-universal-time)))
  ;; Sunday, 06-Nov-94 08:49:37 GMT
  (let ((comma (position #\, value)))
    (when (and comma (weekday-long-p (subseq value 0 comma)))
      (let ((rest (subseq value (1+ comma))))
        (when (and (>= (length rest) 23)
                   (char= (char rest 0) #\Space))
          (let ((day (two-digits rest 1))
                (month (and (char= (char rest 3) #\-)
                            (month-number (subseq rest 4 7))))
                (year2 (and (char= (char rest 7) #\-)
                            (two-digits rest 8)))
                (hour (and (char= (char rest 10) #\Space) (two-digits rest 11)))
                (minute (and (char= (char rest 13) #\:) (two-digits rest 14)))
                (second (and (char= (char rest 16) #\:) (two-digits rest 17))))
            (when (and year2 (string= rest " GMT" :start1 19))
              (rfc850-stamp second minute hour day month year2 now))))))))

(defun parse-asctime-date (value)
  ;; Sun Nov  6 08:49:37 1994
  (when (and (= (length value) 24)
             (weekday-short-p (subseq value 0 3))
             (char= (char value 3) #\Space))
    (let ((month (month-number (subseq value 4 7)))
          (day (cond ((and (char= (char value 8) #\Space) (digit-char-p (char value 9)))
                      (digit-char-p (char value 9)))
                     (t (two-digits value 8))))
          (hour (and (char= (char value 10) #\Space) (two-digits value 11)))
          (minute (and (char= (char value 13) #\:) (two-digits value 14)))
          (second (and (char= (char value 16) #\:) (two-digits value 17)))
          (year (and (char= (char value 19) #\Space)
                     (ignore-errors (parse-integer value :start 20 :end 24)))))
      (encode-http-time second minute hour day month year))))

(defun parse-http-date (value &key (now (get-universal-time)))
  "Accept IMF-fixdate, obsolete RFC 850, and obsolete asctime (RFC 9110 §5.6.7)."
  (when (stringp value)
    (or (parse-imf-fixdate value)
        (parse-rfc850-date value :now now)
        (parse-asctime-date value))))
