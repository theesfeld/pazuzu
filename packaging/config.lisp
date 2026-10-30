;; Installed default. This file is data. The reader binds *read-eval* to nil.
;;
;; Socket activation (packaging/pazuzu.socket) passes listeners named
;; http, https, and quic. Those roles are not bound again. Without them,
;; :port is a cleartext listener. :address and :port are ignored for an
;; adopted main listener and do not change on SIGHUP.
;;
;; Metrics are off. A :metrics-port without :metrics-token exposes the
;; scrape to every client that can open the socket. Keep the address on
;; 127.0.0.1 if you turn it on, or set a token first.
;;
;; SIGHUP reloads workers, limits, timeouts, HSTS, CORS, log paths, the
;; metrics token, certificates, and file mappings. Restart to change a
;; listener or the account. SIGINT and SIGTERM drain connections and exit.

(:address "0.0.0.0"
 :port 8080
 :workers 2
 :backlog 128
 :max-connections 1024
 :max-connections-per-peer 32
 :read-timeout 30
 :max-body 1048576
 :root "/var/lib/pazuzu/www"
 ;; :certificate "/etc/pazuzu/cert.pem"
 ;; :private-key "/etc/pazuzu/key.pem"
 ;; :redirect-port 8080
 ;; :access-log "/var/log/pazuzu/access.log"
 ;; :error-log "/var/log/pazuzu/error.log"
 ;; :metrics-address "127.0.0.1"
 ;; :metrics-port 9090
 ;; :metrics-token "replace-me"
 ;; :directories ((:prefix "/" :root "html"))
 )
