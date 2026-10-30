;; WARNING: metrics below listen on port 9090 with no :metrics-token.
;; Anyone who can open that socket can read the Prometheus exposition.
;; :metrics-address is 127.0.0.1, so that is this machine only. Do not
;; point it at a public or wildcard address unless :metrics-token is set.
;; A missing token is not authentication.
;;
;; pazuzu configuration. This file is data, not a program.
;; The server reads it with *read-eval* bound to nil.
;;
;; Start in the foreground from the clone directory:
;;   sbcl --noinform --disable-debugger \
;;     --load ~/quicklisp/setup.lisp \
;;     --eval '(asdf:load-asd (truename "pazuzu.asd"))' \
;;     --eval '(ql:quickload :pazuzu)' \
;;     --eval '(pazuzu:main)' -- examples/config.lisp
;;
;; SIGINT and SIGTERM stop the process. SIGHUP reloads this file:
;; workers, connection caps, the request rate, timeouts, HSTS, CORS, log
;; paths, the metrics token, the certificate chain, the base directory,
;; and, when the key is present, the directory and host mappings.
;; address, port, redirect-port, backlog, metrics-address, metrics-port,
;; user, and group stay as they were at start; restart to change them.
;; Omitting :directories or :hosts on reload leaves that mapping mounted.
;; Omitting :root leaves the base directory. A present :root resolves
;; relative directory and host paths again. An empty list clears a mapping.
;; With neither directories nor hosts, this file serves no files.
;;
;; Socket activation: when LISTEN_PID is this process and LISTEN_FDS is
;; set, those descriptors are the listeners (sd_listen_fds, fd 3 and up).
;; Names http, https, and web are the main listener. metrics and redirect
;; select the other two. With no names, the first descriptor is the main
;; listener. Adopted roles are not bound again, and :port is not used for
;; an adopted main listener.
;;
;; Omit a key to keep that setting's default. :read-timeout nil waits with
;; no deadline. Paths may be strings or pathnames.

(:address "127.0.0.1"
 :port 8080
 ;; Accept threads on the main listener. HTTP/3 stays on its one UDP thread.
 :workers 2
 :backlog 128
 ;; Global cap, then a tighter cap for a single client address.
 ;; The count includes TCP connections and HTTP/3 connections after Retry.
 ;; 0 rejects a new TCP connection with 503 and a new HTTP/3 connection
 ;; with CONNECTION_REFUSED.
 :max-connections 128
 :max-connections-per-peer 32
 ;; Seconds. A stall after the first byte is 408. nil waits forever.
 :read-timeout 30
 :max-body 1048576
 ;; Requests one client address may send in one second. Past that, 429.
 ;; Omit the key for no request rate limit.
 ;; :request-rate 100
 ;; Applied after the sockets are bound. Omit both to keep the startup account.
 ;; :user "www-data"
 ;; :group "www-data"
 ;; PEM chain (subject first) and its private key. Omit both for cleartext HTTP.
 ;; :certificate "/etc/pazuzu/cert.pem"
 ;; :private-key "/etc/pazuzu/key.pem"
 ;; :hsts-max-age 31536000
 ;; :hsts-include-subdomains t
 ;; Cleartext listener that redirects to the HTTPS port. Requires a certificate.
 ;; :redirect-port 8080
 ;; Relative paths are created from the process's working directory.
 :access-log "log/access.log"
 :error-log "log/error.log"
 ;; Prometheus text at /metrics. Omit :metrics-port to leave it off.
 ;; WARNING: this port is open with no token. Keep :metrics-address on
 ;; 127.0.0.1, or set :metrics-token before binding any other address.
 ;; :metrics-token, when set, requires Authorization: Bearer <token>.
 :metrics-address "127.0.0.1"
 :metrics-port 9090
 ;; :metrics-token "replace-me"
 :cors (:origins ("https://example.test")
        :methods (:get :post)
        :headers ("content-type")
        :credentials t
        :max-age 60)
 ;; Base directory for a relative entry root. The default is /var/www.
 ;; Change this to any absolute path you can write, then uncomment a mapping.
 :root "/var/www"
 ;; Files. Commented out so this file serves nothing.
 ;; A prefix, and a directory under it, returns that directory's index.html.
 ;; A relative entry root is under :root. An absolute path is used as written.
 ;; :directories ((:prefix "/" :root "html")
 ;;               (:prefix "/docs" :root "docs"))
 ;; One directory per host name, including a subdomain. The request Host
 ;; selects it. A name this file does not list does not receive these files.
 ;; :hosts ((:host "www.example.com" :root "www")
 ;;         (:host "blog.example.com" :root "blog"))
 )
