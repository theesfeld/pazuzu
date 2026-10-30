# pazuzu

Origin server for HTTP/1.1, HTTP/2, and HTTP/3. One application handler serves all three. The listener scheme, the `Host` header, and the path are the request that handler sees.

Run it from Lisp, or start it in the foreground from a configuration file. The file sets the listen address, workers, connection limits, rate limit, account, timeouts, TLS certificate, logs, Prometheus listener, HSTS, CORS, the base directory, the directories to serve, and which host name serves which directory. `SIGHUP` reloads the file. `SIGINT` and `SIGTERM` stop the process.

## Requirements

- Linux x86_64
- [SBCL](https://www.sbcl.org/)
- [Quicklisp](https://www.quicklisp.org/)
- OpenSSL 3.5 or newer (`libssl`), used for TLS through `cl+ssl` and for `libngtcp2_crypto_ossl`
- `libnghttp2` 1.70.0 (`#x014600`)
- `libngtcp2` and `libngtcp2_crypto_ossl` 1.25.0 (`#x011900`)
- `libnghttp3` 1.18.0 (`#x011200`)
- `libbrotlienc`, `libbrotlidec`, and `libzstd` for `br` and `zstd`

A different `version_num` from nghttp2, ngtcp2, or nghttp3 is refused at load. HTTP/3 uses the OpenSSL crypto backend (`libngtcp2_crypto_ossl`), not the GnuTLS one. Distro packages are often older, or built against GnuTLS, and then `ql:quickload` fails the version check.

Quicklisp systems: alexandria, babel, bordeaux-threads, cffi, cffi-libffi, chipz, cl-base64, cl+ssl, ironclad, salza2, usocket. `cffi-libffi` calls `nghttp3_rcbuf_get_buf`, which returns a 16-byte struct by value. The first load compiles a small probe, so a C compiler has to be installed.

## Platform

pazuzu is written for Linux on x86_64 and for SBCL.

- `struct msghdr`, `struct cmsghdr`, and `struct iovec` follow the Linux x86_64 System V layout, including the padding after `msg_namelen`. Load fails when CFFI lays those structs out differently.
- `eventfd`, `poll`, and `__errno_location` are the Linux C library. `EAGAIN` is 11 and `EINTR` is 4.
- Socket activation reads systemd's `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES`.

## Native libraries

`script/build-deps.sh` builds and installs the pinned versions. The default prefix is `/usr/local`. A matching stamp under that prefix skips a second build.

| Library | Version |
| --- | --- |
| OpenSSL | 3.5.9 |
| nghttp2 | 1.70.0 |
| ngtcp2 | 1.25.0, including `libngtcp2_crypto_ossl` |
| nghttp3 | 1.18.0 |
| brotli | 1.1.1 |
| zstd | 1.5.7 |
| curl | 8.23.0, with HTTP/3, brotli, and zstd, for the test suite |

```sh
sudo PREFIX=/usr/local ./script/build-deps.sh
```

When the script is not run as root it prints the `PATH` and `LD_LIBRARY_PATH` to export. `PREFIX=/opt/pazuzu ./script/build-deps.sh` installs into a directory you can write.

## Installation

The installed program is one executable, `pazuzu-bin`, plus a `pazuzu` wrapper. Quicklisp is used to build the image and is not needed to run it. Native libraries are installed under `PREFIX/lib/pazuzu`. The libraries record `$ORIGIN` so they find each other. The wrapper and the systemd unit set `LD_LIBRARY_PATH` to that directory. patchelf is not applied to the executable: changing its headers makes SBCL lose the embedded core.

### From a release tarball

A tag `v*` builds `pazuzu-<tag>-linux-x86_64.tar.gz` and attaches it to the GitHub release. The archive is a DESTDIR tree (`usr/local`, `etc/pazuzu`, `etc/systemd/system`).

```sh
curl -fsSL -o pazuzu.tar.gz https://github.com/theesfeld/pazuzu/releases/download/v0.1.0/pazuzu-v0.1.0-linux-x86_64.tar.gz
sudo tar -C / -xzf pazuzu.tar.gz
sudo useradd --system --user-group --home-dir /var/lib/pazuzu --shell /usr/sbin/nologin pazuzu || true
sudo install -d -o pazuzu -g pazuzu /var/lib/pazuzu/www /var/log/pazuzu
```

### From source

`install.sh` builds the pinned libraries, saves the executable, installs them, and creates the `pazuzu` user. It is safe to run again: an existing `/etc/pazuzu/config.lisp` is left in place.

```sh
git clone https://github.com/theesfeld/pazuzu.git
cd pazuzu
sudo ./install.sh
```

`make` and `make install` are the same steps without creating the user. `PREFIX` defaults to `/usr/local`. `DESTDIR` prefixes every installed path, which is how a package is staged. `make uninstall` removes the binary, the private library directory, and the units, and leaves `/etc/pazuzu` and `/var/lib/pazuzu` in place.

### Docker

The image runs the same binary as `/usr/local/bin/pazuzu` and listens on 8080 until the config is replaced.

```sh
docker build -t pazuzu .
docker run --rm -p 8080:8080 -v "$PWD/html:/var/lib/pazuzu/www" pazuzu
```

## Running as a service

`packaging/pazuzu.socket` lets systemd bind port 80, port 443 TCP, and port 443 UDP. The names are `http`, `https`, and `quic`. pazuzu adopts those descriptors and does not bind them again, so the process does not need to be root. `packaging/pazuzu.service` runs as the `pazuzu` user with `Type=notify` (readiness is `sd_notify` / `READY=1`), `Restart=on-failure`, and a sandbox: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, an empty `CapabilityBoundingSet`, and related restrictions. `MemoryDenyWriteExecute` stays off because SBCL writes executable code pages.

```sh
sudo systemctl enable --now pazuzu.socket
sudo systemctl status pazuzu.service
```

Logs go to stderr (notices and errors) and, for the foreground binary, access lines go to stdout, which journald records. A configured `:access-log` or `:error-log` is an additional file. `--log-level error` drops notice lines.

```sh
pazuzu --config /etc/pazuzu/config.lisp
pazuzu --check-config /etc/pazuzu/config.lisp
pazuzu --version
pazuzu --log-level error --config /etc/pazuzu/config.lisp
```

`SIGINT` and `SIGTERM` stop accepting, tell HTTP/2 and HTTP/3 to close, wait for in-flight connections, then exit. `SIGHUP` reloads workers, limits, timeouts, HSTS, CORS, log paths, the metrics token, the heap limit, the certificate chain, and the file mappings. The listen address, ports, backlog, and account do not change on reload; restart the service to change those. `SIGUSR2` hands the listening sockets to a new copy of this program (`script/handoff.py`) and then drains.

## Load from Lisp

pazuzu is an ASDF system. Quicklisp and ocicl do not publish it yet. A
release on those indexes is a separate request to quicklisp-projects or the
ocicl index. Until then, load this repository. The native libraries still
have to be the pinned build from `script/build-deps.sh`. `ql:quickload` and
`asdf:load-system` both refuse a different nghttp2, ngtcp2, or nghttp3
`version_num`.

```sh
PREFIX=/opt/pazuzu ./script/build-deps.sh
export PATH="/opt/pazuzu/bin:$PATH"
export LD_LIBRARY_PATH="/opt/pazuzu/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Quicklisp finds a clone in `~/quicklisp/local-projects/pazuzu`:

```sh
git clone https://github.com/theesfeld/pazuzu.git ~/quicklisp/local-projects/pazuzu
sbcl --load ~/quicklisp/setup.lisp --eval '(ql:quickload :pazuzu)' --quit
```

ocicl uses the same ASDF system. Put the clone where ASDF searches, for
example `~/common-lisp/pazuzu`, with the native libraries on
`LD_LIBRARY_PATH`, then `(asdf:load-system :pazuzu)`. The first load of
`cffi-libffi` compiles a probe, so a C compiler has to be installed. The
saved `pazuzu` binary does not need Quicklisp or ocicl at runtime.

Clone the repository and load it from that directory:

```sh
git clone https://github.com/theesfeld/pazuzu.git
cd pazuzu
sbcl --noinform --disable-debugger \
  --load ~/quicklisp/setup.lisp \
  --eval '(asdf:load-asd (truename "pazuzu.asd"))' \
  --eval '(ql:quickload :pazuzu)'
```

## Serve a directory

Put `index.html` in a directory, name that directory in the configuration file, and start `main`.

The default is `/var/www`. `:root` is that base, and it can be any absolute path. A relative entry such as `html` is a directory under the base. This layout serves `index.html` at `/`:

```text
/var/www/html/index.html
```

```lisp
:root "/var/www"
:directories ((:prefix "/" :root "html"))
```

These URLs return that file:

- `http://127.0.0.1:8080/`
- `http://127.0.0.1:8080/index.html`

A subdirectory is the same. `/var/www/html/about/index.html` is served at `/about` and `/about/`. The content type comes from the file extension. `html` is `text/html; charset=utf-8`.

`:root` alone does not publish the base. Uncomment `:directories`, or add a `:hosts` entry, before any file is served. A path that escapes the named directory is `404`.

To keep the files somewhere you can write, set `:root` to that absolute directory and leave the entry root relative:

```lisp
:root "/home/you/www"
:directories ((:prefix "/" :root "html"))
```

The file is then `/home/you/www/html/index.html`. An entry root that is already absolute is used as written and is not joined onto `:root`. `.` means the base itself.

`examples/config.lisp` is a complete file. The file mappings are commented out, so a copied file serves nothing until you uncomment one.

## Run in the foreground

From the clone directory:

```sh
sbcl --noinform --disable-debugger \
  --load ~/quicklisp/setup.lisp \
  --eval '(asdf:load-asd (truename "pazuzu.asd"))' \
  --eval '(ql:quickload :pazuzu)' \
  --eval '(pazuzu:main)' \
  -- examples/config.lisp
```

`main` reads `--config PATH`, or the first argument that is an existing file and does not start with `-`. The process stays up until `SIGINT` or `SIGTERM`.

Reload the file after you edit it:

```sh
kill -HUP PID
```

`PID` is the SBCL process running `pazuzu:main`. `SIGHUP` re-reads that same file. It applies workers, connection caps, the request rate, timeouts, HSTS, CORS, log paths, the metrics token, the certificate chain, and the base directory. When `:directories` or `:hosts` is present, that list replaces the whole mapping. An empty list clears it. Omitting either key leaves that mapping mounted. A present `:root` resolves relative directory and host paths again. Omitting `:root` leaves the base.

`:address`, `:port`, `:redirect-port`, `:backlog`, `:metrics-address`, `:metrics-port`, `:user`, and `:group` stay as they were at start. Restart the process to change a listener or the account.

`SIGHUP` is installed by `main` and by `enable-reload`. A server started with `start` or `start-from-config` alone ignores it. From Lisp, `reload` applies the file once on the calling thread:

```lisp
(defvar *server* (pazuzu:start-from-config "examples/config.lisp"))
(pazuzu:enable-reload *server*)
(pazuzu:reload *server*)
```

## Configuration

The file is one property list. It is data. The reader binds `*read-eval*` to `nil`, so `#.` does not run. Symbols are read as keywords. A key the server does not know is an error. Omit a key to keep that setting's default.

| Key | Default | Applied by reload |
| --- | --- | --- |
| `:address` | `"127.0.0.1"` | no |
| `:port` | `8080` | no |
| `:workers` | `2` | yes |
| `:backlog` | `128` | no |
| `:max-connections` | `128` | yes |
| `:max-connections-per-peer` | `32` | yes |
| `:read-timeout` | `30` | yes |
| `:max-body` | `1048576` | yes |
| `:certificate` | none | yes |
| `:private-key` | none | yes |
| `:hsts-max-age` | none | yes |
| `:hsts-include-subdomains` | `nil` | yes |
| `:redirect-port` | none | no |
| `:access-log` | none | yes |
| `:error-log` | none | yes |
| `:metrics-address` | `"127.0.0.1"` | no |
| `:metrics-port` | none | no |
| `:metrics-token` | none | yes |
| `:request-rate` | none | yes |
| `:user` | none | no |
| `:group` | none | no |
| `:cors` | none | yes |
| `:root` | `/var/www` | yes |
| `:directories` | none | yes, when the key is present |
| `:hosts` | none | yes, when the key is present |

`:read-timeout nil` waits with no deadline. The key has to be present, because omitting it means 30 seconds.

`:address` is an IPv4 or IPv6 literal. `:port 0` and `:metrics-port 0` bind an ephemeral port. `:workers` is a positive integer. `:max-connections` and `:max-connections-per-peer` are non-negative integers. `0` rejects every new TCP connection with `503` and every new HTTP/3 connection with `CONNECTION_REFUSED`.

### Directories and hosts

`:directories` is a list of `(:prefix "/docs" :root "docs")` entries. `:hosts` is a list of `(:host "blog.example.com" :root "blog")` entries. One entry may be written as the property list itself.

A prefix has to be an absolute URL path. The request for that prefix, and a request for a directory under it, returns that directory's `index.html`. A directory prefix applies to every host and outranks that host's document root for paths under the prefix.

Each `:host` name is that host's document root, including a subdomain. The request `Host` selects it. The port is ignored, and one trailing dot is ignored, so `WWW.Example.Test:9` matches `www.example.test`. One host's files are not returned to another host. A host the file does not name does not receive a named host's files. On HTTPS, a host the certificate does not cover is `421` before any file is chosen.

```lisp
:root "/var/www"
:directories ((:prefix "/" :root "html")
              (:prefix "/docs" :root "docs"))
:hosts ((:host "www.example.com" :root "www")
        (:host "blog.example.com" :root "blog"))
```

| File | URL |
| --- | --- |
| `/var/www/html/index.html` | `/` |
| `/var/www/docs/index.html` | `/docs` and `/docs/` |
| `/var/www/www/index.html` | `/` when `Host` is `www.example.com` |
| `/var/www/blog/page.txt` | `/page.txt` when `Host` is `blog.example.com` |

`/docs/guide.txt` is the `/docs` prefix even when the request names `blog.example.com`. `/page.txt` is the blog host only when `Host` matches.

### HTTPS

`:certificate` and `:private-key` are a PEM chain and its key. The chain is the subject certificate first, then intermediates. Both are required for HTTPS. The TCP listener then speaks TLS 1.2 or newer, and HTTP/3 listens on UDP at the same port. ALPN offers `h2` and `http/1.1` and prefers `h2`. HTTP/3 uses ALPN `h3`.

`:redirect-port` is a cleartext listener that redirects to the HTTPS port. It requires a certificate and speaks HTTP/1.1 only.

`:hsts-max-age` sends `Strict-Transport-Security` on HTTPS responses with status 200 and above. `:hsts-include-subdomains` adds `includeSubDomains`. HTTPS responses advertise the UDP port in `Alt-Svc` when the QUIC socket is bound. Cleartext responses do not send `Alt-Svc`.

Replace the PEM files, or point the two keys at new paths, then send `SIGHUP`. A new handshake presents the new chain. A connection that already holds the old chain keeps it until that connection closes.

```lisp
:certificate "/etc/pazuzu/cert.pem"
:private-key "/etc/pazuzu/key.pem"
:hsts-max-age 31536000
:hsts-include-subdomains t
:redirect-port 8080
```

There is one certificate chain. A request whose target origin that certificate does not cover is `421`.

### Accounts, limits, and rate

`:user` and `:group` are account names applied after the sockets are bound and before accept threads start. An unknown name is an error and `start` does not keep running. Supplementary groups are set with `initgroups` only when the process is still root. Restart to change the account.

`:workers` is how many threads accept on the main TCP listener. The default is 2. Each connection then gets its own client thread, so a WebSocket or a server-sent event does not occupy an accept thread. HTTP/3 stays on one UDP thread. `set-workers` changes the accept-thread count without a file.

`:max-connections` counts admitted TCP connections plus HTTP/3 connections that presented a verified Retry token. `:max-connections-per-peer` is that count for one client address. A TCP connection past either cap is `503`. An HTTP/3 Initial past either cap, after its token verifies, is `CONNECTION_REFUSED`.

`:read-timeout` is the per-request read deadline in seconds. A stall after the first byte is `408`. `:max-body` is the largest request body, in octets. A larger body is `413`.

`:request-rate` is how many requests one client address may send in one second. Past that, the response is `429` with `Retry-After: 1`. Omit the key for no limit. The same limit applies to HTTP/1.1, HTTP/2, and HTTP/3.

### CORS

`:cors` is a property list passed to `make-cors-policy`. A reflected `Origin` is echoed only when it is in the list. Credentials are rejected when the origin list is `:any`.

```lisp
:cors (:origins ("https://example.test")
       :methods (:get :post)
       :headers ("content-type")
       :credentials t
       :max-age 60)
```

### Logs

`:access-log` and `:error-log` are files. A relative path is created from the process working directory. On reload the files are closed and opened again.

The access log is the Combined Log Format. Ident and user are `-`. The time is GMT. The request field is the method, the target, and `HTTP/1.0`, `HTTP/1.1`, `HTTP/2`, or `HTTP/3`. With no `:access-log` path, no access line is written.

The error log is one line per event: an ISO-8601 UTC timestamp, a level (`notice` or `error`), and the message. The same line is written to the error stream of the process.

### Metrics

Set `:metrics-port` to serve Prometheus text exposition 0.0.4 at `GET /metrics` on `:metrics-address`. Omit `:metrics-port` and no metrics socket is opened. The metrics listener does not speak TLS.

When `:metrics-token` is set, the scrape must send `Authorization: Bearer` and that exact token. A missing or different token is `401`.

| Series | Kind |
| --- | --- |
| `pazuzu_connections_accepted_total` | counter |
| `pazuzu_connections_rejected_total` | counter |
| `pazuzu_connections_active` | gauge |
| `pazuzu_workers` | gauge |
| `pazuzu_requests_total{protocol,status}` | counter |
| `pazuzu_response_bytes_total` | counter |
| `pazuzu_request_duration_seconds` | histogram |

`protocol` is `1.0`, `1.1`, `2`, or `3`. Histogram bounds, in seconds, are 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, and `+Inf`.

### Socket activation

If `LISTEN_PID` is this process and `LISTEN_FDS` is a positive integer, pazuzu adopts those listening sockets and does not bind the same roles again. This is the systemd `sd_listen_fds` protocol. Descriptors start at 3.

`LISTEN_FDNAMES`, when set, is a colon-separated list. `https` is the TLS listener. `http` is the main listener when no `https` socket was passed, and the cleartext redirect when `https` was. `redirect` is the cleartext listener. `web`, an empty name, or a missing name is the main listener. `metrics` is the Prometheus listener. A datagram socket, including one named `quic` or `http3`, is the HTTP/3 socket and is not bound again. With no names, the first stream socket is the main listener. `:port` is not used for an adopted main listener.

The unit installed by `make install` is `packaging/pazuzu.socket`. It listens on 80, 443/TCP, and 443/UDP.

## Use it from Lisp

`examples/site.lisp` is a site written as a program: symbol handlers, `defroute`, and a middleware. Load pazuzu, then `(load "examples/site.lisp")` and `(pazuzu/example:start :port 8080)`. Redefining `pazuzu/example:home` changes the next request. The listeners stay up.

`defroute` quotes a function name. `add-middleware` appends a function of `(request next)`. `mount-lack` sends a path to a function of a Lack environment; the function returns `(status headers body)`. Clack is not loaded. `start-listener` opens Swank or Slynk on `127.0.0.1` only, and only when called. `:swank-port` and `:slynk-port` in the config do the same. `:heap-limit` is a dynamic-space watermark in bytes. Above it, new connections are refused.

`script/h3load.sh URL [COUNT]` sends COUNT HTTP/3 requests with one curl process. curl keeps the QUIC connection. The curl from `script/build-deps.sh` is the one with HTTP/3.

`start` accepts the same keys as the configuration file. Paths are pathnames or namestrings. Port `0` binds an ephemeral port.

```lisp
(defvar *server*
  (pazuzu:start :address "127.0.0.1" :port 8080))

(pazuzu:add-route *server* :get "/"
  (lambda (request)
    (declare (ignore request))
    (pazuzu:text-response "pazuzu")))
```

After `start` returns, `server-port` is the main listener, `server-address` is the address you passed, `server-clear-port` is the redirect listener or `nil`, and `server-metrics-port` is the Prometheus listener or `nil`.

```lisp
(pazuzu:stop *server*)
```

`stop` sends an HTTP/2 `GOAWAY` with `NO_ERROR` and an HTTP/3 connection close with `H3_NO_ERROR`, then closes the listeners and joins the threads.

`add-route` takes a keyword or a list of keywords. `GET` also registers `HEAD`. Every registered resource answers `OPTIONS`. `:prefix t` matches the path and everything under it.

```lisp
(pazuzu:add-route *server* :get "/item"
  (lambda (request)
    (pazuzu:text-response "item" :etag "\"v1\""))
  :etag (lambda (request)
          (declare (ignore request))
          "\"v1\""))

(pazuzu:serve-directory *server* "/files" #p"/var/www/html/")
```

`serve-directory` uses the filesystem path you give it. The configuration `:root` does not apply to that path. A later `add-route` or `serve-directory` at the same any-host path replaces that file route. A host route stays beside an any-host route.

Response helpers are `text-response`, `octet-response`, `empty-response`, `redirect-response`, `sse-response`, `make-response`, and `copy-response`. A body may be a string, an octet vector, `nil`, or a function. A function is called with a sender and may write over time.

`make-response` accepts `:representations`, a list of `representation` objects (`content-type`, `language`, `body`, `etag`, `last-modified`). The server picks one from `Accept` and `Accept-Language` and sends `Vary`.

`query-parameters` decodes the query string. `+` is a space. `request-header` reads one field. The request readers are `request-method`, `request-target`, `request-path`, `request-query`, `request-http-version`, `request-headers`, `request-body`, `request-host`, `request-scheme`, `request-peer`, and `request-trailers`.

```lisp
(pazuzu:set-workers *server* 4)
(pazuzu:worker-count *server*)
```

## WebSocket

`add-websocket-route` speaks the WebSocket protocol on HTTP/1.1 (`GET` with `Upgrade: websocket`, version 13). The handler receives a socket and uses `websocket-receive`, `websocket-send`, and `websocket-close`.

On HTTP/2 and HTTP/3 the same route is reached with extended `CONNECT` and `:protocol` set to `websocket`. The server sends `SETTINGS_ENABLE_CONNECT_PROTOCOL`. A `CONNECT` with another protocol is `501`. A `GET` of a WebSocket route on HTTP/2 or HTTP/3 is `400` and does not send `Upgrade`.

## Cookies and authentication

`set-cookie` returns a header pair. It accepts `:domain`, `:path`, `:expires`, `:max-age`, `:secure`, `:http-only`, and `:same-site`. `cookies` reads the request.

`require-basic`, `require-bearer`, and `require-digest` wrap a handler. Digest is SHA-256 with `qop=auth`. MD5 is not accepted. The digest realm defaults to `pazuzu`.

## What this server does not do

pazuzu is an origin. It does not reverse-proxy, cache, run CGI, list directories, accept uploads, or rewrite URLs. There is one certificate chain, not a certificate chosen from the hostname.

The behavior locked by the test suite is recorded in [CONFORMANCE.md](CONFORMANCE.md). That file is the standards tracker. This page is how to run the server.

## Tests

From the clone directory, with the `curl` from `script/build-deps.sh` on `PATH`, plus `node`, `openssl`, and `timeout`. HTTP/3 checks also need an aioquic interpreter at `/tmp/pazuzu-h3venv/bin/python` (`python3 -m venv /tmp/pazuzu-h3venv && /tmp/pazuzu-h3venv/bin/pip install 'aioquic==1.2.0'`).

h2spec 2.6.0, against a cleartext listener, is the HTTP/2 check named in [CONFORMANCE.md](CONFORMANCE.md). `script/h2spec-server.lisp` starts that listener on `127.0.0.1:18080` after pazuzu is loaded:

```sh
h2spec -h 127.0.0.1 -p 18080
```

```sh
sbcl --dynamic-space-size 4096 --noinform --disable-debugger \
  --load ~/quicklisp/setup.lisp \
  --eval '(asdf:load-asd (truename "pazuzu.asd"))' \
  --eval '(ql:quickload :pazuzu)' \
  --eval '(asdf:test-system :pazuzu)' \
  --quit
```

`asdf:test-system` runs `pazuzu/tests:run`. `--dynamic-space-size 4096` gives the compiler room for the large test functions. The server itself does not need that heap.

## License

MIT. See [LICENSE](LICENSE).
