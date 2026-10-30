# Conformance tracker

Issue list for this origin against RFC 9110, RFC 9112, RFC 9113, RFC 9114, RFC 9000, RFC 9204, and RFC 6455.
A sentence is met when a check in the files under `t/`, or a case in h2spec, fails if that behavior breaks. `t/run.lisp` is the entry point `asdf:test-system` calls.
A sentence in this file or in `README.md` is not that check.

Date of this pass: 2026-10-29.

## Measured this pass

| Run | Result |
| --- | --- |
| h2spec 2.6.0, `127.0.0.1:18080`, image that contains the PRIORITY edits | 146 passed, 0 failed, 0.3520 seconds. Log `/tmp/pazuzu-h2spec/h2spec4.log` |
| h2spec 2.6.0 re-run on 2026-10-29 against that same listener | 146 passed, 0 failed, 0.4468 seconds. Log `/tmp/pazuzu-h2spec/h2spec5.log` |
| Gap checks (Allow, Via, qvalue, User-Agent, product identifier, initial window, QPACK eviction, Retry token) | 8 ok, `GAP-OK`, EXIT 0. Log `/tmp/pazuzu-gap.log` |
| Full `asdf:test-system :pazuzu` before the Allow, qvalue, Via, and QPACK route edits | 726 ok, 0 lines starting with `FAIL`, EXIT 0. Log `/tmp/pazuzu-suite2.log` |
| Full `asdf:test-system :pazuzu` after those edits, before the path checks below | 734 ok, 0 lines starting with `FAIL`, EXIT 0. Log `/tmp/pazuzu-suite4.log` |
| Full `asdf:test-system :pazuzu` with the path checks, before the dropped-gap check | 736 ok, 0 lines starting with `FAIL`, EXIT 0. Log `/tmp/pazuzu-suite5.log` |
| Full `asdf:test-system :pazuzu` with the dropped-gap check | 737 ok, 0 lines starting with `FAIL`, EXIT 0. Log `/tmp/pazuzu-suite6.log` |
| Full `asdf:test-system :pazuzu` with the 1-octet packet number check and the ACK Delay check | 739 ok, 0 lines starting with `FAIL`, EXIT 0. Log `/tmp/pazuzu-suite7.log` |
| Full `asdf:test-system :pazuzu` with the confirmed path-reset check and the stale `ACK_ECN` check | 742 ok, 0 lines starting with `FAIL`, EXIT 0. |
| h2spec 2.6.0, `127.0.0.1:18081`, after those checks | 146 passed, 0 failed, 0.4713 seconds. |

The old "882 of 882" figure counted a paragraph as met when the code, the README, or an unreachable branch was judged to cover it. That figure is not an execution count. It is withdrawn. These seven RFCs still contain sentences this suite does not execute. Client, proxy, intermediary, cache, user-agent, and IANA sentences are out of role. The open list names the in-role origin issues an executing check locks. It is empty.

## Sentence execution

Counted from the RFC text on 2026-10-28, then checked against the files under `t/` and the h2spec log on 2026-10-29. A section number missing from those files is not proof the sentence is untested. h2spec is a separate program and does not appear in that file.

| RFC | Sentences | Normative (MUST / MUST NOT / REQUIRED / SHALL) | Normative whose section number is absent from the files under `t/` |
| --- | --- | --- | --- |
| 9110 | 2187 | 198 | 57 |
| 9112 | 480 | 83 | 8 |
| 9113 | 1122 | 207 | 4 |
| 9114 | 903 | 139 | 16 |
| 9000 | 2420 | 297 | 78 |
| 9204 | 410 | 38 | 9 |
| 6455 | 747 | 124 | 10 |
| Total | 8269 | 1086 | 182 |

The 182 are listed with a disposition below. None of them is a new open issue. O-1 and O-3 are closed by "a confirmed path migration resets congestion control and the RTT estimator" and "a stale ACK_ECN does not fail ECN validation". The rest are already executed under a check name, are the wrong role, or name a condition this origin does not create.

### Already executed, under another check name

The section string is absent from the files under `t/`. The check still fails if the behavior breaks.

| Sentence | Check |
| --- | --- |
| RFC 9110 §7.6.3, do not combine Via members with different received-protocol values | "Via members with different protocols stay distinct" |
| RFC 9110 §8.3.3, multipart line breaks are CRLF | "an HTTP/2 multipart range uses CRLF between parts" |
| RFC 9110 §10.1.5, product identifier | "the server product identifier is only the product name" |
| RFC 9110 §10.2.1 and §15.5.6, Allow on 405 | "a handler 405 carries the resource Allow list" |
| RFC 9110 §12.4.2, qvalue has at most three fraction digits | "a generated qvalue has at most three fraction digits" |
| RFC 9110 §15.2.2, 101 names the protocol in Upgrade | "a 101 names the upgraded protocol" |
| RFC 9110 §15.5.2, 401 sends WWW-Authenticate | "a 401 carries a challenge" |
| RFC 9110 §15.5.22, 426 sends Upgrade | "a 426 lists upgrade" |
| RFC 9112 §7.1.2, do not merge a trailer unless its definition allows it | "forbidden trailer fields are ignored", "an HTTP/2 trailer is not merged into the header section" |
| RFC 9113 §5.2.1, a sender respects the peer flow-control window | "a response stays within the default flow-control window", "a negative flow-control window sends no data" |
| RFC 9113 §6.9.3, in-flight DATA after a reduced initial window | Not the acceptance path. The executing lock is "the server does not reduce the initial flow-control window". nghttp2 1.70 would report that DATA as `FLOW_CONTROL_ERROR`. |
| RFC 9114 §4.3.2, every response includes `:status` | "an HTTP/3 response carries only :status" |
| RFC 9000 §8.1.2 and §8.1.4, Retry token integrity, binding, and expiry | "a Retry token is bound to one endpoint and expires", "a modified Retry token is not accepted", "a retagged Retry token is not accepted" |
| RFC 9000 §9.4, path-validation timer is not more aggressive than one PTO | "a lost PATH_CHALLENGE is not retransmitted sooner than one PTO" |
| RFC 9000 §9.5, do not reuse a connection ID toward two destinations | "datagrams to the old and new peer addresses carry different connection IDs" |
| RFC 9000 §13.2.3, drop a packet number from a discarded range, and keep the largest processed number | "a packet number from a dropped gap is discarded", "a 1-octet packet number is recovered from the largest processed number" |
| RFC 9000 §13.2.5, ACK Delay excludes delay the endpoint does not control | "ACK Delay does not include time spent queued in the kernel" |
| RFC 9000 §18.2, `active_connection_id_limit` is at least 2 | "the server active_connection_id_limit is at least 2" |
| RFC 9000 §19.17, PATH_CHALLENGE is answered with the same data | "one PATH_CHALLENGE produces one PATH_RESPONSE" |
| RFC 9204 §2.1.1, do not evict an unacknowledged dynamic-table entry | "an unacknowledged QPACK entry is not evicted" |
| RFC 9204 §2.2.1, a Required Insert Count smaller than expected is `QPACK_DECOMPRESSION_FAILED` | "a QPACK dynamic reference at the required insert count is a connection error" |
| RFC 6455 §7.1.2 and §10.7, Close frame and invalid WebSocket data | "a server close frame is one frame of at most 125 bytes", "websocket echoes a close code", "a WebSocket text message must be UTF-8", "an unmasked client frame closes the connection" |
| RFC 6455 §11.3.5, as applied to a request this server receives | "a repeated WebSocket version is rejected" |
| RFC 9000 §13.4.1, report ECN counts when the fields are accessible | "a stale ACK_ECN does not fail ECN validation". The socket sets `IP_RECVTOS` or `IPV6_RECVTCLASS` and passes the codepoint into `ngtcp2_conn_read_pkt`. ngtcp2 writes the totals into `ACK_ECN`. |

h2spec 2.6.0 executes its own 146 HTTP/2 cases, including PRIORITY on stream 0, a self-dependent PRIORITY, DATA after RST_STREAM, and PING after GOAWAY. Log `/tmp/pazuzu-h2spec/h2spec5.log`. `/tmp/pazuzu-h2spec/h2spec.log` is the pre-fix run (142 passed, 4 failed) and is not the current result.

### Wrong role

Do not file these. This program is an origin. It is not a client, proxy, intermediary, cache, user agent, or IANA registry.

| Section | Count | Role |
| --- | --- | --- |
| RFC 9110 §4.3.4 | 7 | Client certificate verification. Explicit non-goal. |
| RFC 9110 §7.6.2 | 3 | Intermediary Max-Forwards. |
| RFC 9110 §7.6.3, the two proxy and gateway sentences | 2 | Proxy and gateway Via. The third sentence is in the executed table. |
| RFC 9110 §7.7 | 3 | Proxy message transformation. |
| RFC 9110 §9.3.7 | 2 | Proxy Max-Forwards, client OPTIONS content. |
| RFC 9110 §9.3.8 | 2 | Client TRACE. |
| RFC 9110 §10.1.3 | 3 | User agent Referer. |
| RFC 9110 §10.2.1, the proxy sentence | 1 | Proxy Allow. |
| RFC 9110 §11.6.2 | 1 | Proxy Authorization. |
| RFC 9110 §11.7.1 and §15.5.8 | 2 | Proxy 407. |
| RFC 9110 §12.5.4 | 1 | User agent Accept-Language. |
| RFC 9110 §12.5.5 | 2 | Proxy Vary, cache recipient. |
| RFC 9110 §14.3 | 1 | Client Accept-Ranges. |
| RFC 9110 §15.3.7.3 | 3 | Client combining stored 206 parts. |
| RFC 9110 §15.4.8 | 1 | User agent 307 method. |
| RFC 9110 §15.5.20 | 1 | Proxy 421. This origin does send 421. PZ-1. |
| RFC 9110 §16.1.1 through §16.7 | 11 | IANA registration rules. |
| RFC 9112 §3.2.1 and §3.2.4 | 4 | Client request-target, and the last proxy on an OPTIONS chain. |
| RFC 9113 §8.4.2 and §9.1.1 | 2 | Client push validation and client certificate checks. |
| RFC 9114 §3.1.2 and §7.2.6 | 3 | Client scheme check, client GOAWAY stream-id rules. |
| RFC 9114 §11.2.1 through §11.2.4 | 10 | IANA registration rules. |
| RFC 9000 §5.2.1 | 1 | Client version handling. |
| RFC 9000 §5.2.3 and §21.11 | 3 | Load-balancer arrangement of a shared stateless-reset key. This process does not share one. "a stateless reset token is not shared". |
| RFC 9000 §8.1.2, the client repeat-the-token sentence | 1 | Client. |
| RFC 9000 §9.6.1, §9.6.2, §9.6.3, §21.5.3 | 8 | Client preferred-address migration. This server does not send `preferred_address`. |
| RFC 9000 §17.2.3, §17.2.5.2, §17.2.5.3 | 10 | Client 0-RTT and client Retry handling. "an incoming Retry packet is dropped". "0-RTT data is not accepted". |
| RFC 9000 §18.2, the client-only sentences | 4 | Client transport parameters. A client parameter this server must reject is already a connection error in the suite (`original_destination_connection_id` and the limit checks). |
| RFC 9000 §21.5 and §21.12 | 2 | Future extensions and future versions. |
| RFC 9000 §22.1.2 through §22.5 | 9 | IANA. |
| RFC 9204 §4.5.4 and §7.1.3 | 5 | Intermediary re-encoding of a never-indexed literal. |
| RFC 6455 §11.1.1 and §11.1.2 | 4 | URI scheme registration encoding. |
| RFC 6455 §11.3.5, the request-sender sentence | 1 | Client. The server side is "a repeated WebSocket version is rejected". |

### Condition this origin does not create

| Section | Why it is not a task |
| --- | --- |
| RFC 9110 §10.1.4, a sender of TE | This origin does not send `TE`. |
| RFC 9112 §1.1, RFC 9000 §1.2, RFC 9204 §1.1 | BCP 14 boilerplate. |
| RFC 9112 §9.7, HTTP bytes are TLS application data | The https listener writes through OpenSSL. Cleartext HTTP is a different listener. |
| RFC 9114 §10.9, 0-RTT anti-replay | 0-RTT application data is not accepted. |
| RFC 9000 §8.1.4, NEW_TOKEN carries the client address | This server does not send `NEW_TOKEN`. |
| RFC 9000 §9.5, do not reuse a connection ID from two local addresses | This server does not migrate its local address. |
| RFC 9000 §9.7, IPv6 flow label | No product code sets a flow label. The kernel chooses it. Not measured, and not filed. |
| RFC 9000 §10.2.1, amplification limit while closing | ngtcp2 enforces the limit. No separate size assertion is red. |
| RFC 9000 §10.3.3, a Stateless Reset is smaller than its trigger | ngtcp2 builds the reset. No size assertion is red. |
| RFC 9000 §13.4.2.2, disable ECN after validation fails | ngtcp2 moves the path to `NGTCP2_ECN_STATE_FAILED` and later datagrams stay `NOT_ECT`. The suite does not manufacture a failing validation. Sent datagrams are ECT while validation holds, which "a stale ACK_ECN does not fail ECN validation" locks. |
| RFC 9000 §14.2.1, ICMP PMTU | No ICMP reader raises or lowers the PMTU. |
| RFC 9000 §17.4, spin bit | Installed `ngtcp2.h` has no spin-bit symbol. The feature is absent. |
| RFC 9000 §19.21, extension frames | This origin sends no extension frame type. |
| RFC 9204 §2.2.2.1, emit a Section Acknowledgement after a dynamic reference | Decoder capacity stays 0, so that reference does not occur. A spurious acknowledgement is "a QPACK section acknowledgment with nothing to acknowledge is a connection error". |
| RFC 6455 §5.8, §11.3.2, §11.3.4 | The response does not send `Sec-WebSocket-Extensions` or a second `Sec-WebSocket-Protocol`. "an unselected WebSocket subprotocol is omitted". |

### General recipient rule

RFC 9110 §2.4 says a recipient interprets a protocol element by the semantics in this specification. That sentence is the rule the other checks apply. It has no separate switch to flip. It is not an open issue.

## Open issues

No open in-role origin issue remains against RFC 9110, RFC 9112, RFC 9113, RFC 9114, RFC 9000, RFC 9204, and RFC 6455.

O-1 is locked by "a confirmed path migration resets congestion control and the RTT estimator". O-3 is locked by "a stale ACK_ECN does not fail ECN validation". Client, proxy, intermediary, cache, user-agent, and IANA sentences stay out of role.

## Fixed this pass

### O-1. Confirmed path migration resets congestion control and the RTT estimator

- Document: RFC 9000 §9.4
- On `PATH_RESPONSE` for an address whose IP or port differs from the first peer, the process writes the initial congestion window and the initial RTT, zeros the retransmission bytes-in-flight and the delivery-rate sample, then restores that RTT triple when a later ACK names a packet sent before the reset. ngtcp2 1.25.0 still skips its own reset once the path already matches, and it has no public reset call. The correction is in `src/http3.lisp`. System libngtcp2 is unchanged.
- Check: "a confirmed path migration resets congestion control and the RTT estimator".
- Status: fixed.

### O-3. A stale ACK_ECN does not fail ECN validation

- Document: RFC 9000 §13.4.2.1 and §13.4.2.2
- Datagrams ngtcp2 marks ECT(0) leave with that codepoint (`IP_TOS` / `IPV6_TCLASS`). Received marks are passed back into `ngtcp2_conn_read_pkt`. A stale `ACK_ECN` does not move the path to `NGTCP2_ECN_STATE_FAILED`, so a later datagram is still ECT.
- Check: "a stale ACK_ECN does not fail ECN validation".
- Status: fixed.

### F-1. h2spec PRIORITY and DATA-after-RST

- Documents: RFC 9113 §5.1 and §6.3. h2spec 5.1/8, 5.1/9, 5.3.1/2, 6.3/1, and generic 3.8.
- A `PRIORITY` on stream 0 is `PROTOCOL_ERROR`. A self-dependent `PRIORITY` is `PROTOCOL_ERROR`. `DATA` or `HEADERS` after a received `RST_STREAM` is `STREAM_CLOSED`. A `PING` written immediately after a peer `GOAWAY` is acknowledged. Weights stay unused.
- Checks: "a PRIORITY frame on stream 0 is a connection error", "a self-dependent PRIORITY frame is PROTOCOL_ERROR", "DATA after a received RST_STREAM is STREAM_CLOSED", "HEADERS after a received RST_STREAM is STREAM_CLOSED". h2spec: 146 passed, 0 failed.
- Status: fixed.

### F-2. A handler 405 sends the resource Allow list

- Documents: RFC 9110 §10.2.1 and §15.5.6
- Sentence: the origin must generate `Allow` on 405, listing the target resource's currently supported methods.
- The router already sent `Allow`. A handler that returned 405, including one that named a shorter list, did not. `ensure-allow` replaces that field with the route's methods (`GET` implies `HEAD`, and `OPTIONS` is included).
- Check: "a handler 405 carries the resource Allow list". `GET /method-no` and `POST /method-no` and `POST /method-own` are 405 with `Allow: GET, HEAD, POST, OPTIONS`.
- Status: fixed.

### F-3. A generated qvalue has at most three fraction digits

- Document: RFC 9110 §12.4.2
- `limit-qvalue-digits` drops fraction digits past the third on a `;q=` weight. A quoted qvalue is unchanged. A value that is not a weight parameter is unchanged.
- Check: "a generated qvalue has at most three fraction digits". `GET /long-q` sends `gzip;q=0.000` and `br;q=1.000`, keeps `x-note: q=0.0001`, and keeps the quoted form.
- Status: fixed.

### F-4. Via members with different protocols stay distinct

- Document: RFC 9110 §7.6.3
- Sentence: a sender must not combine Via members that have different received-protocol values.
- Two handler lines are sent as `1.0 fred, 1.1 p.example.net`. That is two members. Check: "Via members with different protocols stay distinct".
- Status: fixed. The behavior was already the comma-SP join. The check is what executes the sentence.

### F-5. User-Agent does not change another field's meaning

- Document: RFC 9110 §2.4
- Check: "User-Agent does not change content-coding semantics". `GET /range` with `User-Agent: broken-browser` and `Accept-Encoding: identity;q=0` is 406, has no `Content-Encoding`, and the body is not `abcdefghij`.
- Status: fixed. The behavior was already independent of `User-Agent`. The check is what executes the sentence.

### F-6. The product identifier is only the product name

- Document: RFC 9110 §10.1.5
- Check: "the server product identifier is only the product name". `GET /` sends `Server: pazuzu` and does not send `User-Agent`.
- Status: fixed. The check is what executes the sentence.

### F-7. The server does not reduce the HTTP/2 initial window

- Document: RFC 9113 §6.9.3
- Sentence: a receiver that reduces the initial flow-control window must accept DATA that still fit the previous window.
- This origin does not send `SETTINGS_INITIAL_WINDOW_SIZE` (identifier 4). nghttp2 1.70 would report DATA past a reduced window as `FLOW_CONTROL_ERROR`, which is the opposite of that sentence. The preface settings stay `#x03` 100, `#x06` 65536, `#x08` 1, `#x09` 1.
- Check: "the server does not reduce the initial flow-control window".
- Status: fixed by not reducing. The acceptance path is not executed, and it must not be added by sending identifier 4 through nghttp2 1.70.

### F-8. An unacknowledged QPACK entry is not evicted

- Document: RFC 9204 §2.1.1
- The peer allows a 48-byte dynamic table, which holds one of the two `content-type` entries (`a` is 45 bytes, `bb` is 46) and not both. The client writes no decoder-stream instruction, so nothing is acknowledged. The encoder insert count is 0 or 1. Both responses arrive and the connection stays open.
- Check: "an unacknowledged QPACK entry is not evicted". `GET /qpack-a` and `GET /qpack-b`.
- Status: fixed. nghttp3's encoder already refused the second insert. The check is what executes the sentence. Decoder capacity stays 0.

### F-9. A Retry token is bound to one endpoint and expires

- Document: RFC 9000 §8.1.2 and §8.1.3
- Each endpoint's retry secret is 32 random bytes and differs from the other endpoint's secret. A token sealed now, and one sealed 9 seconds ago, verifies and returns the original destination connection ID. A token sealed 11 seconds ago is rejected (`+retry-token-timeout+` is 10 seconds). The other endpoint rejects the fresh token.
- Check: "a Retry token is bound to one endpoint and expires".
- Status: fixed.

### F-10. Migrated paths use different connection IDs

- Document: RFC 9000 §9.5
- Sentence: an endpoint must not reuse a connection ID when sending to more than one destination address.
- The client sends a non-probing packet from a new port, using a server connection ID it had not used yet. After it answers the new path's `PATH_CHALLENGE`, the server challenges the previous path. The Destination Connection ID on the new path differs from the one on the previous path.
- Check: "datagrams to the old and new peer addresses carry different connection IDs".
- Status: fixed. ngtcp2 already chose a different connection ID. The check is what executes the sentence.

### F-11. A lost PATH_CHALLENGE waits one PTO

- Document: RFC 9000 §9.4
- Sentence: the path-validation timer must not be more aggressive than the PTO in RFC 9002 §6.2.1.
- ngtcp2 1.25.0 sends two `PATH_CHALLENGE` packets in the first flight (`NGTCP2_PV_NUM_PROBE_PKT` is 2) and arms the next flight at `max(PTO, initial PTO)`. The initial RTT is 333 ms, so that gap is about one second. The measured gap from the first challenge to the first challenge that is not in that opening flight is between 700 ms and 4 s.
- Check: "a lost PATH_CHALLENGE is not retransmitted sooner than one PTO".
- Status: fixed. The library already waited. The check is what executes the sentence.

### F-12. A packet number from a dropped gap is discarded

- Document: RFC 9000 §13.2.3
- Sentence: a receiver must not accept a packet number from a range it has dropped, and it must still accept a later number.
- The client sends 300 1-RTT packets on every other packet number, which opens more than 256 one-number gaps. ngtcp2 1.25.0 drops the oldest gap once `pngap` holds more than 256 entries. `CONNECTION_CLOSE` in the oldest hole does not close the connection. A later ping completes.
- Check: "a packet number from a dropped gap is discarded".
- Status: fixed. The library already discarded that number. The check is what executes the sentence. Recovery of a truncated packet number is F-13.

### F-13. A 1-octet packet number is recovered from the largest processed number

- Documents: RFC 9000 §13.2.3 and §17.1
- Sentence: after a gap is dropped, the largest processed packet number stays, and the next short-header packet number is recovered from it.
- The client opens more than 256 one-number gaps with 4-octet packet numbers, then sends `CONNECTION_CLOSE` as the next number in one octet. The server enters draining. A following 4-octet PING draws no datagram. A receiver of `CONNECTION_CLOSE` sends nothing, so silence after a live connection is the acceptance signal.
- Check: "a 1-octet packet number is recovered from the largest processed number".
- Status: fixed. ngtcp2 1.25.0 already reconstructed from `acktr.max_pkt_num`. The check is what executes the sentence.

### F-14. ACK Delay does not include kernel queue time

- Document: RFC 9000 §13.2.5
- Sentence: an endpoint must not include delays it does not control when it fills ACK Delay. Time a datagram spends queued in the kernel is such a delay.
- `h3-read-conn` passes `(monotonic-ns)` into `ngtcp2_conn_read_pkt` after `recv` returns. The test stops the QUIC thread, then sends one 1-RTT PING so the datagram waits in the kernel for about 0.45 s. The ACK Delay on the acknowledgement of that packet stays far below that wait.
- Check: "ACK Delay does not include time spent queued in the kernel".
- Status: fixed. The clock was already the post-recv clock. The check is what executes the sentence.

## Met

### PZ-1. An https request for an origin the certificate does not cover is rejected

- Document: RFC 9110 §7.4
- An https request whose target origin the connection certificate does not cover is `421` and is not that representation. A covered origin is served. Cleartext http is unchanged. The handshake is not refused because SNI is absent or unrecognized.
- Status: met.

### PZ-2. A PUT that creates a resource is answered 201

- Document: RFC 9110 §9.3.4
- A successful PUT that had no current representation is `201`. The validators are read before the handler stores that representation. A successful modification of an existing representation stays `200` or `204`. A PUT toward a different resource is not turned into a `3xx`.
- Status: met.

### PZ-3. A 401 carries WWW-Authenticate

- Documents: RFC 9110 §11.6.1 and §15.5.2
- A `401` with no challenge is given `WWW-Authenticate: Basic realm="pazuzu"`. A challenge the handler already chose is left as it is.
- Status: met.

### PZ-4. The metrics 401 Bearer challenge has an auth-param

- Document: RFC 6750 §3
- The metrics listener sends `WWW-Authenticate: Bearer realm="metrics"`.
- Status: met.

### PZ-5. Mixed confidential and attacker-controlled content is not content-coded on a secure connection

- Documents: RFC 9113 §10.6 and RFC 9114 §10.6
- A secure response marked as mixing those sources is sent with no content coding. A single-source body may still be coded. TLS-level compression stays disabled.
- Status: met.

### PZ-6. RESET_STREAM on a send-only stream is STREAM_STATE_ERROR

- Document: RFC 9000 §19.4
- A `RESET_STREAM` frame for a send-only stream closes the connection with `STREAM_STATE_ERROR` (`0x05`). A `STREAM` frame on a send-only stream stays `STREAM_STATE_ERROR`. Other `PROTOCOL_VIOLATION` results stay `0x0a`.
- Status: met.

## Checked and not open

These were in the survey and are not issues.

- RFC 9220 adds no MUST of its own. Extended `CONNECT` for WebSocket on HTTP/3 follows RFC 8441. The server does not open a TCP tunnel to `:authority` when `:protocol` is present.
- RFC 9218. `SETTINGS_NO_RFC7540_PRIORITIES` is 1 in the first SETTINGS, and priority weights are not used for scheduling. The server does not send `PRIORITY_UPDATE`. A malformed `PRIORITY` is still an error: stream 0 and a self-dependency are `PROTOCOL_ERROR` (RFC 9113 §6.3). h2spec 2.6.0 reports 146 passed and 0 failed.
- RFC 9110 §9.3.4 validators on PUT, §10.2.1 `Allow` on 405, and §15.5.2 `Upgrade` on 426 are implemented. The 401 sentence in that same status-code section is met.
- RFC 7616. The digest `uri` parameter is checked against the request target (`src/auth.lisp`). The only challenge is SHA-256, so the "each challenge uses a different algorithm" rule does not arise. MD5 is not offered. Proxy 407 rules do not apply.
- RFC 7617. Credentials are decoded as UTF-8. A user-id cannot contain a colon, which matches the encoding rule. The server does not advertise `charset`.
- RFC 6750. `require-bearer` accepts the `Authorization: Bearer` method and sends a realm. The metrics listener sends `Bearer realm="metrics"`.
- RFC 6797. HSTS is sent only on https responses, only when `:hsts-max-age` is set, and only as one field. `max-age` is always present in that field. Sending the field at all is a SHOULD.
- RFC 7838. `Alt-Svc` includes a freshness lifetime (`ma=86400`). The "ignore Alt-Svc on 421" rule is a client rule.
- RFC 7301 and the ALPN parts of RFC 9325. The server offers `h2` and `http/1.1`, prefers `h2`, and does not select `h2c`.
- RFC 9325 versions and ciphers that this process configures. TLS 1.0 and 1.1 are disabled, TLS 1.2 is the minimum on TCP, the TLS 1.2 cipher list is AEAD only, compression and renegotiation are off, and HTTP/3 is TLS 1.3. 0-RTT application data is not accepted. DTLS is not this stack.
- RFC 6066 `unrecognized_name` is a SHOULD. It is not sent. SNI support itself is the TLS library; this server's policy is one certificate. An https request for an origin that certificate does not cover is `421`.
- RFC 6265 server profile. Cookie names are tokens and values are cookie-octets. The uppercase MUSTs in that RFC that this pass extracted are user-agent rules.
- Fetch CORS response headers, when a policy is configured. A wildcard origin is not combined with credentials. A specific origin is echoed and `Vary` includes `Origin`. Preflight sends the allowed methods. Browser algorithms in Fetch are not this server's job.
- HTML server-sent events. `text/event-stream` is written as UTF-8, one field per line, with a blank line ending the event, and a data line split on newlines.
- RFC 2046 `multipart/byteranges` line endings are CR LF. The `message/external-body` rules are not used.
- RFC 9000 preferred-address rules. The server does not send `preferred_address`, and a client transport parameter of that name is a connection error. The server-side duties in that section do not arise.
- QPACK. The decoder capacity stays 0, so a dynamic reference at a required insert count is a connection error and a Section Acknowledgement does not arise. When the peer allows a dynamic table, the encoder may set a capacity inside that maximum. An insert that would evict an unacknowledged entry is not performed (check "an unacknowledged QPACK entry is not evicted").
- HTTP/3 0-RTT settings compatibility. 0-RTT is not enabled, so those MUSTs do not apply.
- CONNECT and TRACE. Both answer `501`. Tunnel duties in RFC 9113, RFC 9114, and RFC 9931 apply to a proxy that has switched to a tunnel. This origin does not.

## Documents in the survey

| Document | In the score? |
| --- | --- |
| RFC 9110, 9112, 9113, 9114, 9000, 9204, 6455 | Yes, origin paragraphs |
| RFC 6265, 7616, 7617, 6750 | Yes, the server parts |
| RFC 8441, 9220, 9218, 9931 | Yes. 9220 has no extra MUST |
| RFC 7838, 6797, 7301, 6066, 9325 | Yes, the parts this process configures |
| RFC 3986 | No uppercase RFC 2119 keywords. Host parsing follows it and is covered by the HTTP checks |
| RFC 2046 | Only the multipart framing this origin generates |
| RFC 8446 | No. OpenSSL |
| RFC 9111 | No. Cache role |
| HTML, CSS, DOM, JavaScript, WebRTC | No. Not this program |
| Any whitepaper not named by this repository | No such document |
