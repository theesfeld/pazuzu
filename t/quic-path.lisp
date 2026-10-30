;;; QUIC path validation, migration, and ECN checks.

(in-package #:pazuzu/tests)

(defun quic-path-challenge-test (port)
  "RFC 9000 §8.2.2. A PATH_CHALLENGE is answered with one PATH_RESPONSE
that repeats its data, and that datagram is at least 1200 bytes.
One challenge produces one PATH_RESPONSE frame."
  (let ((script (quic-path-challenge-script)))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (check "a PATH_CHALLENGE is answered with the same data"
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "ANSWERED True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "one PATH_CHALLENGE produces one PATH_RESPONSE"
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "RESPONSES 1" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "a PATH_RESPONSE datagram is at least 1200 bytes"
        (unless (and code (zerop code)
                     (search "PADDED True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "a PATH_CHALLENGE smaller than 1200 bytes is answered"
        ;; RFC 9000 §8.2.1. A datagram that looks too small is not
        ;; discarded when it contains a PATH_CHALLENGE.
        (let ((start (search "SMALL " out)))
          (unless (and code (zerop code)
                       start
                       (search "ANSWERED True" out)
                       (search "CLOSED None" out)
                       (let ((n (parse-integer out :start (+ start 6) :junk-allowed t)))
                         (and n (< n 1200))))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun quic-migration-script ()
  "Client that sends one PING from a new local port after the handshake."
  (let ((script "/tmp/pazuzu-h3-migration.py"))
    (write-lines script
                 '("import asyncio, socket, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def decrypt_datagram(quic, data):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or not data or (data[0] & 0x80):"
                   "        return None"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    for cid_len in range(0, 21):"
                   "        if 1 + cid_len + 20 > len(data):"
                   "            continue"
                   "        try:"
                   "            buf = Buffer(data=data)"
                   "            pull_quic_header(buf, host_cid_length=cid_len)"
                   "            _header, payload, _number = crypto.decrypt_packet("
                   "                data, buf.tell(), space.expected_packet_number)"
                   "            return payload"
                   "        except Exception:"
                   "            continue"
                   "    return None"
                   ""
                   "def challenge_data(payload):"
                   "    buf = Buffer(data=payload)"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type == 0x1a:"
                   "            return buf.pull_bytes(8)"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        return None"
                   "    return None"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.closed = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   ""
                   "def send_ping(quic, sock, dest):"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    pad = max(0, 1200 - len(header) - 16 - 1)"
                   "    payload = bytes([0x01]) + bytes(pad)"
                   "    packet = crypto.encrypt_packet(header, payload, pn)"
                   "    sock.sendto(packet, dest)"
                   "    return len(packet) >= 1200"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
                   "            sock.bind(('127.0.0.1', 0))"
                   "            sock.setblocking(False)"
                   "            await asyncio.sleep(0.05)"
                   "            loop = asyncio.get_running_loop()"
                   "            token = None"
                   "            padded = False"
                   "            sent = False"
                   "            # A duplicate packet number is discarded. Send a later"
                   "            # number from this socket until one datagram is accepted."
                   "            for _attempt in range(4):"
                   "                sent = send_ping(quic, sock, ('127.0.0.1', port)) or sent"
                   "                for _ in range(8):"
                   "                    try:"
                   "                        data = await asyncio.wait_for(loop.sock_recv(sock, 65535), 0.2)"
                   "                    except TimeoutError:"
                   "                        continue"
                   "                    payload = decrypt_datagram(quic, data)"
                   "                    if payload is None:"
                   "                        continue"
                   "                    token = challenge_data(payload)"
                   "                    if token is not None:"
                   "                        padded = len(data) >= 1200"
                   "                        break"
                   "                if token is not None:"
                   "                    break"
                   "            print('SENT %s' % sent)"
                   "            print('CHALLENGE %s' % (token is not None))"
                   "            print('PADDED %s' % padded)"
                   "            print('TOKEN %s' % (token is not None and token != bytes(8)))"
                   "            print('CLOSED %s' % client.closed)"
                   "            sock.close()"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-migration-test (port)
  "RFC 9000 §9 and §9.3. A non-probing packet from a new peer address
starts path validation. The server sends a PATH_CHALLENGE to that
address. Section 8.2.1 requires the datagram to be at least 1200 bytes,
and the challenge data must not be predictable."
  (let ((script (quic-migration-script)))
    (check "a changed peer address is path validated"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "CHALLENGE True" out)
                     (search "PADDED True" out)
                     (search "TOKEN True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-path-cc-script ()
  "Migrate, answer PATH_CHALLENGE, then ACK that challenge packet again."
  (let ((script "/tmp/pazuzu-h3-path-cc.py"))
    (write-lines script
                 '("import asyncio, socket, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def decrypt_datagram(quic, data):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or not data or (data[0] & 0x80):"
                   "        return None, None"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    for cid_len in range(0, 21):"
                   "        if 1 + cid_len + 20 > len(data):"
                   "            continue"
                   "        try:"
                   "            buf = Buffer(data=data)"
                   "            pull_quic_header(buf, host_cid_length=cid_len)"
                   "            _header, payload, number = crypto.decrypt_packet("
                   "                data, buf.tell(), space.expected_packet_number)"
                   "            return payload, number"
                   "        except Exception:"
                   "            continue"
                   "    return None, None"
                   ""
                   "def challenge_data(payload):"
                   "    if payload is None:"
                   "        return None"
                   "    buf = Buffer(data=payload)"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type == 0x1a:"
                   "            return buf.pull_bytes(8)"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var(); buf.pull_uint_var(); buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        return None"
                   "    return None"
                   ""
                   "def send_payload(quic, sock, dest, payload):"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    cid = quic._peer_cid.cid"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + cid + pn.to_bytes(4, 'big')"
                   "    sock.sendto(crypto.encrypt_packet(header, payload, pn), dest)"
                   ""
                   "def ack_bytes(largest):"
                   "    buf = Buffer(capacity=32)"
                   "    buf.push_uint_var(0x02)"
                   "    buf.push_uint_var(largest)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    return buf.data"
                   ""
                   "def confirm_bytes(largest, token, quic):"
                   "    cid = quic._peer_cid.cid"
                   "    buf = Buffer(capacity=1400)"
                   "    buf.push_uint_var(0x1b)"
                   "    buf.push_bytes(token)"
                   "    buf.push_uint_var(0x02)"
                   "    buf.push_uint_var(largest)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    raw = buf.data"
                   "    need = 1200 - (1 + len(cid) + 4) - 16"
                   "    if len(raw) < need:"
                   "        raw = raw + bytes(need - len(raw))"
                   "    return raw"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.closed = None"
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True, alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1])"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            await asyncio.sleep(0.15)"
                   "            quic.send_ping(1)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.15)"
                   "            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
                   "            sock.bind(('127.0.0.1', 0))"
                   "            sock.setblocking(False)"
                   "            loop = asyncio.get_running_loop()"
                   "            dest = ('127.0.0.1', port)"
                   "            token = None"
                   "            number = None"
                   "            for _attempt in range(4):"
                   "                send_payload(quic, sock, dest, bytes([0x01]) + bytes(1100))"
                   "                for _ in range(10):"
                   "                    try:"
                   "                        data = await asyncio.wait_for(loop.sock_recv(sock, 65535), 0.15)"
                   "                    except TimeoutError:"
                   "                        continue"
                   "                    payload, pn = decrypt_datagram(quic, data)"
                   "                    token = challenge_data(payload)"
                   "                    if token is not None:"
                   "                        number = pn"
                   "                        break"
                   "                if token is not None:"
                   "                    break"
                   "            acked = False"
                   "            if token is not None and number is not None:"
                   "                send_payload(quic, sock, dest, confirm_bytes(number, token, quic))"
                   "                await asyncio.sleep(0.05)"
                   "                send_payload(quic, sock, dest, ack_bytes(number))"
                   "                acked = True"
                   "                await asyncio.sleep(0.25)"
                   "            print('CHALLENGE %s' % (token is not None))"
                   "            print('NUMBER %s' % number)"
                   "            print('ACKED %s' % acked)"
                   "            print('CLOSED %s' % client.closed)"
                   "            sock.close()"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-path-cc-test (port)
  "RFC 9000 §9.4. After the new address is confirmed, the congestion
window and the RTT estimator are initial again, the in-flight byte
count that feeds loss detection is zero, and the delivery sample is
zero. An ACK of the packet that carried PATH_CHALLENGE was sent before
that reset, so it does not move latest_rtt, min_rtt, or smoothed_rtt."
  (pazuzu::h3-clear-path-log)
  (let ((script (quic-path-cc-script)))
    (check "a confirmed path migration resets congestion control and the RTT estimator"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "ACKED True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))
        (let* ((log (pazuzu::h3-path-log))
               (initial (find :initial log :key #'first))
               (before (find :before log :key #'first))
               (confirmed (find :confirmed log :key #'first))
               (stales (remove-if-not (lambda (entry) (eq (first entry) :stale)) log)))
          (unless (and initial before confirmed stales
                       (= (sixth before) 1)
                       (plusp (seventh before))
                       (plusp (eighth before))
                       (= (second confirmed) 0)
                       (= (third confirmed) pazuzu::+uint64-max+)
                       (= (fourth confirmed) pazuzu::+h3-initial-rtt+)
                       (= (fifth confirmed) (second initial))
                       (zerop (sixth confirmed))
                       (zerop (seventh confirmed))
                       (every (lambda (entry)
                                (and (= (second entry) 0)
                                     (= (third entry) pazuzu::+uint64-max+)
                                     (= (fourth entry) pazuzu::+h3-initial-rtt+)))
                              stales))
            (fail "log ~s out ~s err ~s" log out err)))))))

(defun quic-ecn-script ()
  "Handshake with ACK_ECN, then an ACK whose largest number does not grow."
  (let ((script "/tmp/pazuzu-h3-ecn.py"))
    (write-lines script
                 '("import asyncio, socket, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType"
                   "from aioquic.quic.packet import push_ack_frame, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   "from asyncio.selector_events import _SelectorDatagramTransport"
                   ""
                   "def install_recv_ecn():"
                   "    def read_ready(self):"
                   "        if self._conn_lost:"
                   "            return"
                   "        try:"
                   "            data, anc, _flags, addr = self._sock.recvmsg(self.max_size, 256)"
                   "        except (BlockingIOError, InterruptedError):"
                   "            return"
                   "        except OSError as exc:"
                   "            self._protocol.error_received(exc)"
                   "            return"
                   "        except (SystemExit, KeyboardInterrupt):"
                   "            raise"
                   "        except BaseException as exc:"
                   "            self._fatal_error(exc, 'Fatal read error on datagram transport')"
                   "            return"
                   "        ecn = 0"
                   "        for level, kind, payload in anc:"
                   "            if not payload:"
                   "                continue"
                   "            if ((level == socket.IPPROTO_IP and kind == socket.IP_TOS) or"
                   "                (level == socket.IPPROTO_IPV6 and kind == socket.IPV6_TCLASS)):"
                   "                ecn = payload[0] & 3"
                   "        proto = self._protocol"
                   "        if hasattr(proto, '_tos'):"
                   "            proto._last_ecn = ecn"
                   "            proto._tos.append(ecn)"
                   "            if len(proto._anc) < 6:"
                   "                proto._anc.append([(level, kind, list(payload[:4])) for level, kind, payload in anc])"
                   "        proto.datagram_received(data, addr)"
                   "    _SelectorDatagramTransport._read_ready = read_ready"
                   ""
                   "install_recv_ecn()"
                   ""
                   "def install_ack_ecn():"
                   "    original = QuicConnection.receive_datagram"
                   "    def receive_datagram(self, data, addr, now):"
                   "        ecn = getattr(self, '_pending_ecn', 0)"
                   "        if not hasattr(self, '_pazuzu_ecn'):"
                   "            self._pazuzu_ecn = {}"
                   "        saved = []"
                   "        for epoch, space in list(self._spaces.items()):"
                   "            add = space.ack_queue.add"
                   "            def make(epoch, add):"
                   "                def wrapped(start, stop=None):"
                   "                    add(start, stop)"
                   "                    end = start + 1 if stop is None else stop"
                   "                    bucket = self._pazuzu_ecn.setdefault(epoch, {})"
                   "                    for pn in range(start, end):"
                   "                        bucket[pn] = ecn"
                   "                return wrapped"
                   "            space.ack_queue.add = make(epoch, add)"
                   "            saved.append((space, add))"
                   "        try:"
                   "            original(self, data, addr, now)"
                   "        finally:"
                   "            for space, add in saved:"
                   "                space.ack_queue.add = add"
                   "    QuicConnection.receive_datagram = receive_datagram"
                   "    def write_ack(self, builder, space, now):"
                   "        ack_delay = now - space.largest_received_time"
                   "        encoded = int(ack_delay * 1000000) >> self._local_ack_delay_exponent"
                   "        epoch = next(item for item, found in self._spaces.items() if found is space)"
                   "        marks = getattr(self, '_pazuzu_ecn', {}).get(epoch, {})"
                   "        ect0 = sum(1 for value in marks.values() if value == 2)"
                   "        ect1 = sum(1 for value in marks.values() if value == 1)"
                   "        ce = sum(1 for value in marks.values() if value == 3)"
                   "        buf = builder.start_frame(QuicFrameType.ACK_ECN, capacity=512,"
                   "            handler=self._on_ack_delivery,"
                   "            handler_args=(space, space.largest_received_packet))"
                   "        push_ack_frame(buf, space.ack_queue, encoded)"
                   "        buf.push_uint_var(ect0)"
                   "        buf.push_uint_var(ect1)"
                   "        buf.push_uint_var(ce)"
                   "        space.ack_at = None"
                   "    QuicConnection._write_ack_frame = write_ack"
                   ""
                   "install_ack_ecn()"
                   ""
                   "def send_stale(quic, largest):"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    cid = quic._peer_cid.cid"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + cid + pn.to_bytes(4, 'big')"
                   "    buf = Buffer(capacity=32)"
                   "    buf.push_uint_var(0x03)"
                   "    buf.push_uint_var(largest)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    return crypto.encrypt_packet(header, buf.data, pn)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._tos = []"
                   "        self._last_ecn = 0"
                   "        self._status = None"
                   "        self._data = b''"
                   "        self._waiter = None"
                   "        self.closed = None"
                   "        self._anc = []"
                   "    def connection_made(self, transport):"
                   "        super().connection_made(transport)"
                   "        sock = transport._sock"
                   "        sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)"
                   "        if sock.family == socket.AF_INET6:"
                   "            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)"
                   "    def datagram_received(self, data, addr):"
                   "        self._quic._pending_ecn = self._last_ecn"
                   "        super().datagram_received(data, addr)"
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "                if http_event.stream_ended and self._waiter and not self._waiter.done():"
                   "                    self._waiter.set_result(True)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                self._data += http_event.data"
                   "                if http_event.stream_ended and self._waiter and not self._waiter.done():"
                   "                    self._waiter.set_result(True)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True, alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1])"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            client._waiter = client._loop.create_future()"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'), (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'), (b':path', b'/')], end_stream=True)"
                   "            client.transmit()"
                   "            try:"
                   "                await asyncio.wait_for(client._waiter, 3)"
                   "            except TimeoutError:"
                   "                pass"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.2)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.05)"
                   "            space = client._quic._spaces[Epoch.ONE_RTT]"
                   "            largest = space.largest_received_packet"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.1)"
                   "            mark = len(client._tos)"
                   "            packet = send_stale(client._quic, largest)"
                   "            client._transport.sendto(packet, client._quic._network_paths[0].addr)"
                   "            client._quic.send_ping(7)"
                   "            client.transmit()"
                   "            for _ in range(30):"
                   "                if 2 in client._tos[mark:]:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            tail = client._tos[:mark][-8:]"
                   "            print('STATUS %s' % client._status)"
                   "            print('LARGEST %s' % largest)"
                   "            print('ECT_BEFORE %s' % (2 in tail))"
                   "            print('ECT_AFTER %s' % (2 in client._tos[mark:]))"
                   "            print('TOS %s' % client._tos)"
                   "            print('ANC %s' % client._anc)"
                   "            print('ACKED True')"
                   "            print('CLOSED %s' % client.closed)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ecn-test (port)
  "RFC 9000 §13.4.2.1 and §13.4.2.2. Sent datagrams are ECT. An ACK_ECN
that does not increase the largest acknowledged packet number does not
fail validation, so a later datagram is still ECT."
  (let ((script (quic-ecn-script)))
    (check "a stale ACK_ECN does not fail ECN validation"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "ECT_BEFORE True" out)
                     (search "ECT_AFTER True" out)
                     (search "ACKED True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-previous-path-script ()
  "Client that migrates, answers the new-path challenge, and watches the
original socket for a PATH_CHALLENGE."
  (let ((script "/tmp/pazuzu-h3-prev-path.py"))
    (write-lines script
                 '("import asyncio, socket, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def decrypt_datagram(quic, data):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or not data or (data[0] & 0x80):"
                   "        return None, None"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    for cid_len in range(0, 21):"
                   "        if 1 + cid_len + 20 > len(data):"
                   "            continue"
                   "        try:"
                   "            buf = Buffer(data=data)"
                   "            header = pull_quic_header(buf, host_cid_length=cid_len)"
                   "            _plain, payload, _number = crypto.decrypt_packet("
                   "                data, buf.tell(), space.expected_packet_number)"
                   "            return payload, header.destination_cid"
                   "        except Exception:"
                   "            continue"
                   "    return None, None"
                   ""
                   "def challenge_data(payload):"
                   "    if payload is None:"
                   "        return None"
                   "    buf = Buffer(data=payload)"
                   "    try:"
                   "        while not buf.eof():"
                   "            frame_type = buf.pull_uint_var()"
                   "            if frame_type in (0x00, 0x01, 0x1e):"
                   "                continue"
                   "            if frame_type == 0x1a:"
                   "                return buf.pull_bytes(8)"
                   "            if frame_type in (0x02, 0x03):"
                   "                pull_ack_frame(buf)"
                   "                if frame_type == 0x03:"
                   "                    buf.pull_uint_var()"
                   "                    buf.pull_uint_var()"
                   "                    buf.pull_uint_var()"
                   "                continue"
                   "            if frame_type == 0x06:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_bytes(buf.pull_uint_var())"
                   "                continue"
                   "            return None"
                   "    except Exception:"
                   "        return None"
                   "    return None"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.closed = None"
                   "        self.arm = False"
                   "        self.old_token = None"
                   "        self.old_len = None"
                   "        self.old_dcid = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        if self.arm and self.old_token is None:"
                   "            payload, dcid = decrypt_datagram(self._quic, data)"
                   "            token = challenge_data(payload)"
                   "            if token is not None:"
                   "                self.old_token = token"
                   "                self.old_len = len(data)"
                   "                self.old_dcid = dcid"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   ""
                   "def send_frame(quic, sock, dest, body, cid):"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + cid + pn.to_bytes(4, 'big')"
                   "    pad = max(0, 1200 - len(header) - 16 - len(body))"
                   "    payload = body + bytes(pad)"
                   "    packet = crypto.encrypt_packet(header, payload, pn)"
                   "    sock.sendto(packet, dest)"
                   "    return len(packet) >= 1200"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
                   "            sock.bind(('127.0.0.1', 0))"
                   "            sock.setblocking(False)"
                   "            await asyncio.sleep(0.05)"
                   "            loop = asyncio.get_running_loop()"
                   "            spare = quic._peer_cid_available[0].cid if quic._peer_cid_available else None"
                   "            cid = spare if spare is not None else quic._peer_cid.cid"
                   "            new_token = None"
                   "            new_dcid = None"
                   "            for _attempt in range(4):"
                   "                send_frame(quic, sock, ('127.0.0.1', port), bytes([0x01]), cid)"
                   "                for _ in range(8):"
                   "                    try:"
                   "                        data = await asyncio.wait_for(loop.sock_recv(sock, 65535), 0.2)"
                   "                    except TimeoutError:"
                   "                        continue"
                   "                    payload, dcid = decrypt_datagram(quic, data)"
                   "                    token = challenge_data(payload)"
                   "                    if token is not None:"
                   "                        new_token = token"
                   "                        new_dcid = dcid"
                   "                        break"
                   "                if new_token is not None:"
                   "                    break"
                   "            replied = False"
                   "            if new_token is not None:"
                   "                client.arm = True"
                   "                replied = send_frame(quic, sock, ('127.0.0.1', port), bytes([0x1b]) + new_token, cid)"
                   "                for _ in range(30):"
                   "                    if client.old_token is not None or client.closed is not None:"
                   "                        break"
                   "                    await asyncio.sleep(0.1)"
                   "            print('SPARE %s' % (spare is not None))"
                   "            print('NEW %s' % (new_token is not None))"
                   "            print('REPLIED %s' % replied)"
                   "            print('OLD %s' % (client.old_token is not None))"
                   "            print('OLDPAD %s' % (client.old_len is not None and client.old_len >= 1200))"
                   "            print('DISTINCT %s' % (client.old_token is not None and new_token is not None and client.old_token != new_token))"
                   "            print('UNPREDICTABLE %s' % (client.old_token is not None and client.old_token != bytes(8)))"
                   "            print('DCIDDIFF %s' % (spare is not None and new_dcid is not None and client.old_dcid is not None and new_dcid != client.old_dcid and len(new_dcid) > 0))"
                   "            print('NEWDCID %s' % (new_dcid.hex() if new_dcid else '-'))"
                   "            print('OLDDCID %s' % (client.old_dcid.hex() if client.old_dcid else '-'))"
                   "            print('CLOSED %s' % client.closed)"
                   "            sock.close()"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-previous-path-test (port)
  "RFC 9000 §9.3.3 and §9.5. After a new peer address answers its
PATH_CHALLENGE, the server sends a different PATH_CHALLENGE on the
previously active path. The client used a Destination Connection ID it
had not used before. Datagrams to the two peer addresses carry different
Destination Connection IDs."
  (let ((script (quic-previous-path-script)))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (check "an apparent migration challenges the previously active path"
        (unless (and code (zerop code)
                     (search "NEW True" out)
                     (search "REPLIED True" out)
                     (search "OLD True" out)
                     (search "OLDPAD True" out)
                     (search "DISTINCT True" out)
                     (search "UNPREDICTABLE True" out)
                     (search "CLOSED None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "datagrams to the old and new peer addresses carry different connection IDs"
        (unless (and code (zerop code)
                     (search "SPARE True" out)
                     (search "DCIDDIFF True" out)
                     (search "CLOSED None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-path-retransmit-script ()
  "Client that migrates and does not answer PATH_CHALLENGE."
  (let ((script "/tmp/pazuzu-h3-path-retransmit.py"))
    (write-lines script
                 '("import asyncio, socket, ssl, sys, time"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def decrypt_datagram(quic, data):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or not data or (data[0] & 0x80):"
                   "        return None"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    for cid_len in range(0, 21):"
                   "        if 1 + cid_len + 20 > len(data):"
                   "            continue"
                   "        try:"
                   "            buf = Buffer(data=data)"
                   "            pull_quic_header(buf, host_cid_length=cid_len)"
                   "            _header, payload, _number = crypto.decrypt_packet("
                   "                data, buf.tell(), space.expected_packet_number)"
                   "            return payload"
                   "        except Exception:"
                   "            continue"
                   "    return None"
                   ""
                   "def challenge_data(payload):"
                   "    if payload is None:"
                   "        return None"
                   "    buf = Buffer(data=payload)"
                   "    try:"
                   "        while not buf.eof():"
                   "            frame_type = buf.pull_uint_var()"
                   "            if frame_type in (0x00, 0x01, 0x1e):"
                   "                continue"
                   "            if frame_type == 0x1a:"
                   "                return buf.pull_bytes(8)"
                   "            if frame_type in (0x02, 0x03):"
                   "                pull_ack_frame(buf)"
                   "                if frame_type == 0x03:"
                   "                    buf.pull_uint_var()"
                   "                    buf.pull_uint_var()"
                   "                    buf.pull_uint_var()"
                   "                continue"
                   "            if frame_type == 0x06:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_bytes(buf.pull_uint_var())"
                   "                continue"
                   "            return None"
                   "    except Exception:"
                   "        return None"
                   "    return None"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.closed = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   ""
                   "def send_bytes(quic, sock, dest, payload):"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    pad = max(0, 1200 - len(header) - 16 - len(payload))"
                   "    packet = crypto.encrypt_packet(header, payload + bytes(pad), pn)"
                   "    sock.sendto(packet, dest)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
                   "            sock.bind(('127.0.0.1', 0))"
                   "            sock.setblocking(False)"
                   "            await asyncio.sleep(0.05)"
                   "            loop = asyncio.get_running_loop()"
                   "            first = None"
                   "            for _attempt in range(4):"
                   "                send_bytes(quic, sock, ('127.0.0.1', port), bytes([0x01]))"
                   "                for _ in range(8):"
                   "                    try:"
                   "                        data = await asyncio.wait_for(loop.sock_recv(sock, 65535), 0.2)"
                   "                    except TimeoutError:"
                   "                        continue"
                   "                    if challenge_data(decrypt_datagram(quic, data)) is not None:"
                   "                        first = time.monotonic()"
                   "                        break"
                   "                if first is not None:"
                   "                    break"
                   "            offsets = []"
                   "            if first is not None:"
                   "                for _ in range(4):"
                   "                    send_bytes(quic, sock, ('127.0.0.1', port), b'')"
                   "                deadline = time.monotonic() + 3.2"
                   "                while time.monotonic() < deadline:"
                   "                    left = deadline - time.monotonic()"
                   "                    try:"
                   "                        data = await asyncio.wait_for(loop.sock_recv(sock, 65535), min(0.2, max(0.01, left)))"
                   "                    except TimeoutError:"
                   "                        continue"
                   "                    if challenge_data(decrypt_datagram(quic, data)) is not None:"
                   "                        offsets.append(int((time.monotonic() - first) * 1000))"
                   "            later = [n for n in offsets if n >= 50]"
                   "            nxt = later[0] if later else -1"
                   "            print('FIRST %s' % (first is not None))"
                   "            print('COUNT %s' % ((1 if first is not None else 0) + len(offsets)))"
                   "            print('OFFSETS %s' % (','.join(str(n) for n in offsets) or '-'))"
                   "            print('NEXT %s' % nxt)"
                   "            print('CLOSED %s' % client.closed)"
                   "            sock.close()"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-path-retransmit-test (port)
  "RFC 9000 §9.4. A lost PATH_CHALLENGE is not retransmitted sooner than
one PTO. ngtcp2 1.25.0 arms that probe at max(PTO, initial PTO). The
initial RTT is 333 ms, so the first repeat is at least about one second."
  (let ((script (quic-path-retransmit-script)))
    (check "a lost PATH_CHALLENGE is not retransmitted sooner than one PTO"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (let* ((start (search "NEXT " out))
               (gap (and start (parse-integer out :start (+ start 5) :junk-allowed t))))
          (unless (and code (zerop code)
                       (search "FIRST True" out)
                       gap
                       (<= 700 gap 4000)
                       (search "CLOSED None" out)
                       (not (search "ERR " out)))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun quic-gap-drop-script ()
  "Client that opens more than 256 one-number gaps, then sends
CONNECTION_CLOSE in the oldest hole."
  (let ((script "/tmp/pazuzu-h3-gap-drop.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def send_pn(client, pn, payload):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    packet = crypto.encrypt_packet(header, payload, pn)"
                   "    client._transport.sendto(packet, client._quic._network_paths[0].addr)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            start = quic._packet_number"
                   "            for i in range(300):"
                   "                send_pn(client, start + (2 * i), bytes([0x01]))"
                   "            quic._packet_number = start + 700"
                   "            await asyncio.sleep(0.2)"
                   "            send_pn(client, start + 1, bytes([0x1c, 0x00, 0x00, 0x00]))"
                   "            await asyncio.sleep(0.3)"
                   "            ping = True"
                   "            try:"
                   "                await asyncio.wait_for(client.ping(), 2)"
                   "            except Exception:"
                   "                ping = False"
                   "            print('HOLE %s' % (start + 1))"
                   "            print('PING %s' % ping)"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-gap-drop-test (port)
  "RFC 9000 §13.2.3. After more than 256 received-number gaps, a packet
number from a dropped gap is not accepted. CONNECTION_CLOSE in that
hole does not close the connection, and a later ping still completes."
  (let ((script (quic-gap-drop-script)))
    (check "a packet number from a dropped gap is discarded"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "PING True" out)
                     (search "CLOSED None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-truncated-pn-script ()
  "After more than 256 gaps, send CONNECTION_CLOSE with a 1-octet packet
number of the next number."
  (let ((script "/tmp/pazuzu-h3-truncated-pn.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._seen = 0"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._seen += 1"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def send_pn(client, pn, payload, pn_len):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | (pn_len - 1)"
                   "    low = pn & ((1 << (8 * pn_len)) - 1)"
                   "    header = bytes([first]) + quic._peer_cid.cid + low.to_bytes(pn_len, 'big')"
                   "    packet = crypto.encrypt_packet(header, payload, pn)"
                   "    client._transport.sendto(packet, client._quic._network_paths[0].addr)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    printed = False"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            start = quic._packet_number"
                   "            for i in range(300):"
                   "                send_pn(client, start + (2 * i), bytes([0x01]), 4)"
                   "            quic._packet_number = start + 700"
                   "            await asyncio.sleep(0.2)"
                   "            ping = True"
                   "            try:"
                   "                await asyncio.wait_for(client.ping(), 2)"
                   "            except Exception:"
                   "                ping = False"
                   "            pn = quic._packet_number"
                   "            quic._packet_number = pn + 20"
                   "            send_pn(client, pn, bytes([0x1c, 0x00, 0x00, 0x00]) + bytes(32), 1)"
                   "            await asyncio.sleep(0.15)"
                   "            before = client._seen"
                   "            send_pn(client, pn + 1, bytes([0x01]), 4)"
                   "            await asyncio.sleep(0.4)"
                   "            print('PING %s' % ping)"
                   "            print('PN %s' % pn)"
                   "            print('AFTER %s' % (client._seen - before))"
                   "            printed = True"
                   "    except Exception as exc:"
                   "        if not printed:"
                   "            print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-truncated-pn-test (port)
  "RFC 9000 §13.2.3 and §17.1. After the oldest gap is dropped, the largest
processed packet number still recovers the next 1-octet number. A
CONNECTION_CLOSE in that number puts the server in draining, so a later
PING draws no datagram. A receiver of CONNECTION_CLOSE sends nothing."
  (let ((script (quic-truncated-pn-script)))
    (check "a 1-octet packet number is recovered from the largest processed number"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) "-u" script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "PING True" out)
                     (search "AFTER 0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun wait-probe (path seconds)
  (loop for i below (ceiling (* seconds 20))
        when (probe-file path) return t
        do (sleep 0.05)))

(defun quic-ack-delay-pause (server ready go)
  "Pause the QUIC thread after READY so one datagram sits in the kernel."
  (unless (wait-probe ready 3)
    (return-from quic-ack-delay-pause nil))
  (let ((thread (find "pazuzu-quic" (pazuzu::server-threads server)
                      :key #'bt:thread-name :test #'string=))
        (asleep "/tmp/pazuzu-ackdelay-asleep"))
    (when (probe-file asleep)
      (delete-file asleep))
    (unless thread
      (return-from quic-ack-delay-pause nil))
    (bt:interrupt-thread
     thread
     (lambda ()
       (with-open-file (out asleep :direction :output :if-exists :supersede
                                      :if-does-not-exist :create)
         (write-string "1" out)
         (finish-output out))
       (sleep 0.45)))
    (pazuzu::eventfd-write (pazuzu::h3-endpoint-wake (pazuzu::server-endpoint server)))
    (unless (wait-probe asleep 2)
      (return-from quic-ack-delay-pause nil))
    (with-open-file (out go :direction :output :if-exists :supersede
                                 :if-does-not-exist :create)
      (write-string "1" out)
      (finish-output out))
    t))

(defun quic-ack-delay-script ()
  "Establish GET /, then send one PING while the server read loop is paused."
  (let ((script "/tmp/pazuzu-h3-ack-delay.py"))
    (write-lines script
                 '("import asyncio, os, ssl, sys, time"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.logger import QuicLogger"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def send_pn(client, pn, payload, pn_len):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | (pn_len - 1)"
                   "    low = pn & ((1 << (8 * pn_len)) - 1)"
                   "    header = bytes([first]) + quic._peer_cid.cid + low.to_bytes(pn_len, 'big')"
                   "    packet = crypto.encrypt_packet(header, payload, pn)"
                   "    client._transport.sendto(packet, client._quic._network_paths[0].addr)"
                   ""
                   "def ack_ms(quic, pn):"
                   "    trace = quic._quic_logger"
                   "    events = trace._events if trace is not None else []"
                   "    found = None"
                   "    largest_seen = None"
                   "    for event in events:"
                   "        if event.get('name') != 'transport:packet_received':"
                   "            continue"
                   "        for frame in (event.get('data') or {}).get('frames') or []:"
                   "            if frame.get('frame_type') != 'ack':"
                   "                continue"
                   "            largest = None"
                   "            for pair in frame.get('acked_ranges') or []:"
                   "                stop = pair[1]"
                   "                if largest is None or stop > largest:"
                   "                    largest = stop"
                   "            if largest_seen is None or (largest is not None and largest > largest_seen):"
                   "                largest_seen = largest"
                   "            if largest == pn:"
                   "                found = frame.get('ack_delay')"
                   "    return found, largest_seen"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    go = sys.argv[2]"
                   "    ready = '/tmp/pazuzu-ackdelay-ready'"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        quic_logger=QuicLogger(),"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            if client._timer is not None:"
                   "                client._timer.cancel()"
                   "                client._timer = None"
                   "            saved_transmit = client.transmit"
                   "            client.transmit = lambda: None"
                   "            with open(ready, 'w') as handle:"
                   "                handle.write('1')"
                   "            found = False"
                   "            for _ in range(80):"
                   "                if os.path.exists(go):"
                   "                    found = True"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            if not found:"
                   "                print('ERR no-go')"
                   "                return"
                   "            quic = client._quic"
                   "            pn = quic._packet_number + 20"
                   "            quic._packet_number = pn + 30"
                   "            t0 = time.monotonic()"
                   "            send_pn(client, pn, bytes([0x01]), 4)"
                   "            delay = None"
                   "            largest = None"
                   "            while time.monotonic() - t0 < 2:"
                   "                delay, largest = ack_ms(quic, pn)"
                   "                if delay is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.02)"
                   "            wait_ms = (time.monotonic() - t0) * 1000"
                   "            print('BODY %s' % (client._body == b'pazuzu'))"
                   "            print('PN %s' % pn)"
                   "            print('LARGEST %s' % largest)"
                   "            print('WAITMS %.1f' % wait_ms)"
                   "            print('ACKMS %s' % delay)"
                   "            print('CLOSED %s' % client._terminated)"
                   "            client.transmit = saved_transmit"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun prefixed-float (prefix text)
  (let ((pos (search prefix text)))
    (when pos
      (ignore-errors
        (let ((value (read-from-string text nil nil :start (+ pos (length prefix)))))
          (when (numberp value)
            (float value)))))))

(defun quic-ack-delay-test (server)
  "RFC 9000 §13.2.5. ACK Delay is the time this process holds the packet
after recv, not the time the datagram waited in the kernel. The QUIC
thread sleeps while one PING sits unread. The acknowledgement delay stays
far below that wait."
  (let ((script (quic-ack-delay-script))
        (ready "/tmp/pazuzu-ackdelay-ready")
        (go "/tmp/pazuzu-ackdelay-go")
        (asleep "/tmp/pazuzu-ackdelay-asleep"))
    (dolist (path (list ready go asleep))
      (when (probe-file path)
        (delete-file path)))
    (check "ACK Delay does not include time spent queued in the kernel"
      (let ((helper (bt:make-thread
                     (lambda () (quic-ack-delay-pause server ready go))
                     :name "pazuzu-ack-delay-pause")))
        (unwind-protect
             (multiple-value-bind (out err code)
                 (uiop:run-program
                  (list (aioquic-python) "-u" script
                        (princ-to-string (pazuzu::server-port server)) go)
                  :output :string :error-output :string :ignore-error-status t)
               (let ((paused (bt:join-thread helper))
                     (wait (prefixed-float "WAITMS " out))
                     (ack (prefixed-float "ACKMS " out)))
                 (unless (and paused code (zerop code)
                              (search "BODY True" out)
                              (search "CLOSED None" out)
                              wait ack
                              (>= wait 200)
                              (< ack 150)
                              (< (* ack 3) wait)
                              (not (search "ERR " out)))
                   (fail "paused ~s exit ~s wait ~s ack ~s out ~s err ~s"
                         paused code wait ack out err))))
          (when (bt:thread-alive-p helper)
            (ignore-errors (bt:destroy-thread helper)))
          (dolist (path (list ready go asleep))
            (when (probe-file path)
              (delete-file path))))))))

(defun quic-server-initial-script ()
  "Client that records the server Initial packets of one handshake."
  (let ((script "/tmp/pazuzu-h3-server-initial.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import pull_quic_header, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def ack_eliciting(payload):"
                   "    buf = Buffer(data=payload)"
                   "    found = False"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type == 0x00:"
                   "            continue"
                   "        if frame_type == 0x01:"
                   "            found = True"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            range_count = buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            for _ in range(range_count):"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            found = True"
                   "            continue"
                   "        return None"
                   "    return found"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._tokens = []"
                   "        self._elicited = []"
                   "        self._decode = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._note(data)"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def _note(self, data):"
                   "        quic = self._quic"
                   "        crypto = quic._cryptos_initial.get(QuicProtocolVersion.VERSION_1)"
                   "        space = quic._spaces[Epoch.INITIAL]"
                   "        buf = Buffer(data=data)"
                   "        while not buf.eof():"
                   "            start = buf.tell()"
                   "            if data[start] & 0x80 == 0:"
                   "                return"
                   "            try:"
                   "                header = pull_quic_header(buf)"
                   "            except Exception as exc:"
                   "                self._decode = repr(exc)"
                   "                return"
                   "            end = start + header.packet_length"
                   "            if header.packet_type == QuicPacketType.INITIAL:"
                   "                encrypted_off = buf.tell() - start"
                   "                self._tokens.append(header.token)"
                   "                try:"
                   "                    _header, payload, _number = crypto.decrypt_packet("
                   "                        data[start:end], encrypted_off, space.expected_packet_number)"
                   "                    elicited = ack_eliciting(payload)"
                   "                except Exception as exc:"
                   "                    elicited = None"
                   "                    self._decode = repr(exc)"
                   "                if elicited:"
                   "                    self._elicited.append(len(data))"
                   "                elif elicited is None and self._decode is None:"
                   "                    self._decode = 'frame'"
                   "            if end <= start or end > len(data):"
                   "                return"
                   "            buf.seek(end)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            sizes = client._elicited"
                   "            print('INITIALS %d' % len(client._tokens))"
                   "            print('TOKEN0 %s' % (len(client._tokens) > 0 and all(token == b'' for token in client._tokens)))"
                   "            print('ELICITING %d' % len(sizes))"
                   "            print('MIN %s' % (min(sizes) if sizes else None))"
                   "            print('ELICITED %s' % (len(sizes) > 0 and min(sizes) >= 1200))"
                   "            print('DECODE %s' % client._decode)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-server-initial-test (port)
  "RFC 9000 §§17.2.2 and 14.1. A server Initial has an empty token, and a
datagram that carries an ack-eliciting Initial is at least 1200 bytes."
  (let ((script (quic-server-initial-script)))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (check "a server Initial packet has an empty token"
        (unless (and code (zerop code)
                     (search "TOKEN0 True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "an ack-eliciting server Initial datagram is at least 1200 bytes"
        (unless (and code (zerop code)
                     (search "ELICITED True" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun socket-int-option (fd level name)
  (cffi:with-foreign-objects ((value :int) (length :unsigned-int))
    (setf (cffi:mem-ref length :unsigned-int) (cffi:foreign-type-size :int))
    (unless (zerop (pazuzu::%getsockopt fd level name value length))
      (fail "getsockopt ~s ~s" level name))
    (cffi:mem-ref value :int)))

(defun quic-dont-fragment-test (server)
  "RFC 9000 §14. The live QUIC socket does not allow IP fragmentation."
  (let* ((fd (sb-bsd-sockets:socket-file-descriptor
              (pazuzu::server-quic-socket server)))
         (ipv6 (= (pazuzu::fd-domain fd) 10)))
    (if ipv6
        (check "QUIC IPv6 datagrams are not fragmented"
          (unless (and (= (socket-int-option fd 41 62) 1)
                       (= (socket-int-option fd 41 23) 2))
            (fail "dontfrag ~s discover ~s"
                  (socket-int-option fd 41 62)
                  (socket-int-option fd 41 23))))
        (check "QUIC IPv4 datagrams set the DF bit"
          (unless (= (socket-int-option fd 0 10) 2)
            (fail "IP_MTU_DISCOVER ~s" (socket-int-option fd 0 10)))))))

(defun quic-server-ids-script ()
  "Client that records the server transport parameters that authenticate
connection IDs."
  (let ((script "/tmp/pazuzu-h3-server-ids.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import pull_quic_transport_parameters, QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._params = None"
                   "        quic = self._quic"
                   "        original = quic._parse_transport_parameters"
                   "        def wrapped(data, from_session_ticket=False):"
                   "            if not from_session_ticket:"
                   "                self._params = pull_quic_transport_parameters(Buffer(data=data))"
                   "            return original(data, from_session_ticket)"
                   "        quic._parse_transport_parameters = wrapped"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            quic = client._quic"
                   "            params = client._params"
                   "            print('ODCID %s' % (params is not None and params.original_destination_connection_id is not None and params.original_destination_connection_id == quic.original_destination_connection_id))"
                   "            print('RETRYID %s' % (params is not None and quic._retry_count == 1 and params.retry_source_connection_id not in (None, b'') and params.retry_source_connection_id == quic._retry_source_connection_id))"
                   "            print('ISCID %s' % (params is not None and params.initial_source_connection_id is not None and params.initial_source_connection_id == quic._remote_initial_source_connection_id))"
                   "            print('LIMIT %s' % (params is not None and (params.active_connection_id_limit is None or params.active_connection_id_limit >= 2)))"
                   "            print('PAYLOAD %s' % (params is not None and (params.max_udp_payload_size is None or params.max_udp_payload_size >= 1200)))"
                   "            uni = None if params is None else params.initial_max_streams_uni"
                   "            print('UNI %s %s tail=1' % (uni is not None and uni >= 3, uni))"
                   "            print('EXP %s' % (params is not None and (params.ack_delay_exponent is None or params.ack_delay_exponent <= 20)))"
                   "            print('DELAY %s' % (params is not None and (params.max_ack_delay is None or params.max_ack_delay < 16384)))"
                   "            print('RESET %s' % (params is not None and (params.stateless_reset_token is None or len(params.stateless_reset_token) == 16)))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-server-ids-test (port)
  "RFC 9000 §§7.3 and 18.2. The server authenticates its handshake
connection IDs, and integer transport parameters stay inside their limits."
  (let ((script (quic-server-ids-script)))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (check "the server authenticates original_destination_connection_id"
        (unless (and code (zerop code) (search "ODCID True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server authenticates retry_source_connection_id"
        (unless (and code (zerop code) (search "RETRYID True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server authenticates initial_source_connection_id"
        (unless (and code (zerop code) (search "ISCID True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server active_connection_id_limit is at least 2"
        (unless (and code (zerop code) (search "LIMIT True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server max_udp_payload_size is at least 1200"
        (unless (and code (zerop code) (search "PAYLOAD True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server allows at least three unidirectional streams"
        (unless (and code (zerop code)
                     (search "UNI True " out)
                     (not (search "UNI False" out))
                     (not (search "UNI None" out)))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server ack_delay_exponent is at most 20"
        (unless (and code (zerop code) (search "EXP True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "the server max_ack_delay is below 2^14"
        (unless (and code (zerop code) (search "DELAY True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "a server stateless_reset_token is omitted or 16 bytes"
        (unless (and code (zerop code) (search "RESET True" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-transport-parameters-once-test (port)
  "RFC 9000 §18. Each transport parameter identifier appears once in the
server's quic_transport_parameters extension."
  (check "server transport parameters are sent once"
    (let ((script "/tmp/pazuzu-h3-tp-once.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.buffer import Buffer"
                     "from aioquic.h3.connection import H3_ALPN"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "def parameter_ids(data):"
                     "    buf = Buffer(data=data)"
                     "    found = []"
                     "    while not buf.eof():"
                     "        found.append(buf.pull_uint_var())"
                     "        buf.pull_bytes(buf.pull_uint_var())"
                     "    return found"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._ids = None"
                     "        quic = self._quic"
                     "        original = quic._parse_transport_parameters"
                     "        def wrapped(data, from_session_ticket=False):"
                     "            if not from_session_ticket:"
                     "                self._ids = parameter_ids(data)"
                     "            return original(data, from_session_ticket)"
                     "        quic._parse_transport_parameters = wrapped"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    try:"
                     "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "            ids = client._ids or []"
                     "            print('COUNT %d' % len(ids))"
                     "            print('UNIQUE %s' % (len(ids) > 0 and len(ids) == len(set(ids))))"
                     "            print('IDS %s' % ','.join(str(item) for item in ids))"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "UNIQUE True" out)
                     (not (search "UNIQUE False" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-connection-id-once-test (port)
  "RFC 9000 §5.1. The server does not issue the same connection ID more
than once. The Retry Source Connection ID, the Initial Source Connection
ID, and each NEW_CONNECTION_ID are distinct, and GET / returns pazuzu."
  (check "a connection ID is not issued twice"
    (let ((script "/tmp/pazuzu-h3-cid-once.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated"
                     "from aioquic.quic.logger import QuicLogger"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._terminated = None"
                     "        self._status = None"
                     "        self._body = b''"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "        for http_event in self._http.handle_event(event):"
                     "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        self._status = int(value)"
                     "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                     "                self._body += http_event.data"
                     ""
                     "def issued(trace, quic):"
                     "    by_seq = {}"
                     "    conflict = False"
                     "    for event in trace._events:"
                     "        if event['name'] != 'transport:packet_received':"
                     "            continue"
                     "        for frame in event['data'].get('frames') or []:"
                     "            if frame.get('frame_type') != 'new_connection_id':"
                     "                continue"
                     "            seq = frame['sequence_number']"
                     "            cid = frame['connection_id']"
                     "            previous = by_seq.get(seq)"
                     "            if previous is None:"
                     "                by_seq[seq] = cid"
                     "            elif previous != cid:"
                     "                conflict = True"
                     "    values = []"
                     "    initial = quic._remote_initial_source_connection_id"
                     "    if initial:"
                     "        values.append(initial.hex())"
                     "    retry = quic._retry_source_connection_id"
                     "    if retry:"
                     "        values.append(retry.hex())"
                     "    for seq in sorted(by_seq):"
                     "        values.append(by_seq[seq])"
                     "    return conflict, by_seq, values"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        quic_logger=QuicLogger(),"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    try:"
                     "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "            stream_id = client._quic.get_next_available_stream_id()"
                     "            client._http.send_headers(stream_id, ["
                     "                (b':method', b'GET'),"
                     "                (b':scheme', b'https'),"
                     "                (b':authority', b'127.0.0.1'),"
                     "                (b':path', b'/'),"
                     "            ], end_stream=True)"
                     "            client.transmit()"
                     "            for _ in range(40):"
                     "                if client._body == b'pazuzu':"
                     "                    break"
                     "                await asyncio.sleep(0.05)"
                     "            conflict, by_seq, values = issued(client._quic._quic_logger, client._quic)"
                     "            unique = (not conflict and len(by_seq) >= 1 and len(values) >= 2"
                     "                      and len(values) == len(set(values)))"
                     "            print('UNIQUE %s' % unique)"
                     "            print('CONFLICT %s' % conflict)"
                     "            print('FRAMES %d' % len(by_seq))"
                     "            print('COUNT %d' % len(values))"
                     "            print('IDS %s' % ','.join(values))"
                     "            body = client._body.decode('ascii', 'replace') or '-'"
                     "            print('GET %s %s' % (client._status, body))"
                     "            print('CLOSED %s' % client._terminated)"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "UNIQUE True" out)
                     (not (search "UNIQUE False" out))
                     (not (search "CONFLICT True" out))
                     (not (search "FRAMES 0" out))
                     (search "GET 200 pazuzu" out)
                     (search "CLOSED None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-cid-prefix-test (port)
  "RFC 9000 §5.1. Connection IDs issued for one connection must not carry
information an observer can use to correlate them. The Initial Source
Connection ID, a Retry Source Connection ID, and each NEW_CONNECTION_ID
do not share an eight-octet prefix. GET / returns pazuzu."
  (check "issued connection IDs do not share an eight-octet prefix"
    (let ((script "/tmp/pazuzu-h3-cid-prefix.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated"
                     "from aioquic.quic.logger import QuicLogger"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._terminated = None"
                     "        self._status = None"
                     "        self._body = b''"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "        for http_event in self._http.handle_event(event):"
                     "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        self._status = int(value)"
                     "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                     "                self._body += http_event.data"
                     ""
                     "def as_bytes(value):"
                     "    if isinstance(value, str):"
                     "        return bytes.fromhex(value)"
                     "    return bytes(value)"
                     ""
                     "def issued(trace, quic):"
                     "    values = []"
                     "    def add(value):"
                     "        if not value:"
                     "            return"
                     "        cid = as_bytes(value)"
                     "        if cid not in values:"
                     "            values.append(cid)"
                     "    add(quic._remote_initial_source_connection_id)"
                     "    add(quic._retry_source_connection_id)"
                     "    for event in trace._events:"
                     "        if event['name'] != 'transport:packet_received':"
                     "            continue"
                     "        for frame in event['data'].get('frames') or []:"
                     "            if frame.get('frame_type') == 'new_connection_id':"
                     "                add(frame['connection_id'])"
                     "    return values"
                     ""
                     "def shares_prefix(values):"
                     "    for index, left in enumerate(values):"
                     "        for right in values[index + 1:]:"
                     "            if len(left) >= 8 and len(right) >= 8 and left[:8] == right[:8]:"
                     "                return True"
                     "            if left.startswith(right) or right.startswith(left):"
                     "                return True"
                     "    return False"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        quic_logger=QuicLogger(),"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    try:"
                     "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "            stream_id = client._quic.get_next_available_stream_id()"
                     "            client._http.send_headers(stream_id, ["
                     "                (b':method', b'GET'),"
                     "                (b':scheme', b'https'),"
                     "                (b':authority', b'127.0.0.1'),"
                     "                (b':path', b'/'),"
                     "            ], end_stream=True)"
                     "            client.transmit()"
                     "            for _ in range(40):"
                     "                if client._body == b'pazuzu':"
                     "                    break"
                     "                await asyncio.sleep(0.05)"
                     "            values = issued(client._quic._quic_logger, client._quic)"
                     "            print('CORRELATED %s' % shares_prefix(values))"
                     "            print('MANY %s' % (len(values) >= 2))"
                     "            print('COUNT %d' % len(values))"
                     "            body = client._body.decode('ascii', 'replace') or '-'"
                     "            print('GET %s %s' % (client._status, body))"
                     "            print('CLOSED %s' % client._terminated)"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "CORRELATED False" out)
                     (not (search "CORRELATED True" out))
                     (search "MANY True" out)
                     (not (search "MANY False" out))
                     (search "GET 200 pazuzu" out)
                     (search "CLOSED None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reset-token-once-test (port)
  "RFC 9000 §10.3.2. The same stateless reset token is not used for more
than one connection ID. Each NEW_CONNECTION_ID keeps one token, and a
token carried for the Initial connection ID is not reused."
  (check "a stateless reset token is not shared"
    (let ((script "/tmp/pazuzu-h3-reset-token.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated"
                     "from aioquic.quic.logger import QuicLogger"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._terminated = None"
                     "        self._status = None"
                     "        self._body = b''"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "        for http_event in self._http.handle_event(event):"
                     "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                     "                for name, value in http_event.headers:"
                     "                    if name == b':status':"
                     "                        self._status = int(value)"
                     "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                     "                self._body += http_event.data"
                     ""
                     "def reset_tokens(trace, quic):"
                     "    by_cid = {}"
                     "    conflict = False"
                     "    for event in trace._events:"
                     "        if event['name'] != 'transport:packet_received':"
                     "            continue"
                     "        for frame in event['data'].get('frames') or []:"
                     "            if frame.get('frame_type') != 'new_connection_id':"
                     "                continue"
                     "            cid = frame['connection_id']"
                     "            token = frame['reset_token']"
                     "            previous = by_cid.get(cid)"
                     "            if previous is None:"
                     "                by_cid[cid] = token"
                     "            elif previous != token:"
                     "                conflict = True"
                     "    initial = quic._peer_cid"
                     "    if initial.sequence_number == 0 and initial.stateless_reset_token:"
                     "        cid = initial.cid.hex()"
                     "        token = initial.stateless_reset_token.hex()"
                     "        previous = by_cid.get(cid)"
                     "        if previous is None:"
                     "            by_cid[cid] = token"
                     "        elif previous != token:"
                     "            conflict = True"
                     "    values = list(by_cid.values())"
                     "    shared = len(values) != len(set(values))"
                     "    return conflict, shared, by_cid"
                     ""
                     "async def main():"
                     "    port = int(sys.argv[1])"
                     "    configuration = QuicConfiguration("
                     "        is_client=True,"
                     "        alpn_protocols=H3_ALPN,"
                     "        verify_mode=ssl.CERT_NONE,"
                     "        quic_logger=QuicLogger(),"
                     "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                     "    )"
                     "    try:"
                     "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                     "            stream_id = client._quic.get_next_available_stream_id()"
                     "            client._http.send_headers(stream_id, ["
                     "                (b':method', b'GET'),"
                     "                (b':scheme', b'https'),"
                     "                (b':authority', b'127.0.0.1'),"
                     "                (b':path', b'/'),"
                     "            ], end_stream=True)"
                     "            client.transmit()"
                     "            for _ in range(40):"
                     "                if client._body == b'pazuzu':"
                     "                    break"
                     "                await asyncio.sleep(0.05)"
                     "            conflict, shared, by_cid = reset_tokens(client._quic._quic_logger, client._quic)"
                     "            unique = (not conflict and not shared and len(by_cid) >= 2)"
                     "            print('UNIQUE %s' % unique)"
                     "            print('CONFLICT %s' % conflict)"
                     "            print('SHARED %s' % shared)"
                     "            print('MANY %s' % (len(by_cid) >= 2))"
                     "            print('COUNT %d' % len(by_cid))"
                     "            body = client._body.decode('ascii', 'replace') or '-'"
                     "            print('GET %s %s' % (client._status, body))"
                     "            print('CLOSED %s' % client._terminated)"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "UNIQUE True" out)
                     (search "MANY True" out)
                     (not (search "UNIQUE False" out))
                     (not (search "SHARED True" out))
                     (not (search "CONFLICT True" out))
                     (not (search "MANY False" out))
                     (search "GET 200 pazuzu" out)
                     (search "CLOSED None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-handshake-done-script ()
  "Client that drops the first HANDSHAKE_DONE and waits for another."
  (let ((script "/tmp/pazuzu-h3-handshake-done.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def payload_has_handshake_done(payload):"
                   "    buf = Buffer(data=payload)"
                   "    found = False"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01):"
                   "            continue"
                   "        if frame_type == 0x1e:"
                   "            found = True"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type in (0x10, 0x12, 0x13):"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x11:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x18:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint8())"
                   "            buf.pull_bytes(16)"
                   "            continue"
                   "        if 0x08 <= frame_type <= 0x0f:"
                   "            buf.pull_uint_var()"
                   "            if frame_type & 4:"
                   "                buf.pull_uint_var()"
                   "            if frame_type & 2:"
                   "                buf.pull_bytes(buf.pull_uint_var())"
                   "            else:"
                   "                buf.pull_bytes(buf.capacity - buf.tell())"
                   "            continue"
                   "        return False"
                   "    return found"
                   ""
                   "def datagram_has_handshake_done(quic, data):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None:"
                   "        return False"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    buf = Buffer(data=data)"
                   "    cid_len = quic._configuration.connection_id_length"
                   "    while not buf.eof():"
                   "        start = buf.tell()"
                   "        if data[start] & 0x80:"
                   "            header = pull_quic_header(buf)"
                   "            end = start + header.packet_length"
                   "            if end <= start or end > len(data):"
                   "                return False"
                   "            buf.seek(end)"
                   "            continue"
                   "        pull_quic_header(buf, host_cid_length=cid_len)"
                   "        encrypted_off = buf.tell() - start"
                   "        end = start + (len(data) - start)"
                   "        _header, payload, _number = crypto.decrypt_packet("
                   "            data[start:end], encrypted_off, space.expected_packet_number)"
                   "        return payload_has_handshake_done(payload)"
                   "    return False"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._hd = 0"
                   "        self._terminated = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        try:"
                   "            found = datagram_has_handshake_done(self._quic, data)"
                   "        except Exception:"
                   "            found = False"
                   "        if found and self._hd < 1:"
                   "            self._hd = 1"
                   "            return"
                   "        if found:"
                   "            self._hd += 1"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client, wait_connected=False) as client:"
                   "            client.transmit()"
                   "            for _ in range(60):"
                   "                if client._hd >= 2 or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            print('HDCOUNT %d' % client._hd)"
                   "            print('RETRANSMITTED %s' % (client._hd >= 2))"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-handshake-done-test (port)
  "RFC 9000 §13.3. A HANDSHAKE_DONE frame that is not acknowledged is sent again."
  (let ((script (quic-handshake-done-script)))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (check "a lost HANDSHAKE_DONE frame is retransmitted"
        (unless (and code (zerop code)
                     (search "RETRANSMITTED True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-initial-packet (total)
  "A QUIC v1 Initial whose header length matches TOTAL. DCID is 8 octets."
  (let* ((base (coerce #(#xC0 0 0 0 1
                         8 1 2 3 4 5 6 7 8
                         8 9 10 11 12 13 14 15 16
                         0)
                       '(vector (unsigned-byte 8))))
         (wide (>= total 1200))
         (payload (- total (length base) (if wide 2 1)))
         (packet (make-array total :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace packet base)
    (if wide
        (setf (aref packet (length base)) (logior #x40 (ash payload -8))
              (aref packet (1+ (length base))) (logand payload #xff))
        (setf (aref packet (length base)) payload))
    packet))

(defun quic-recv-packet (socket &key (seconds 0.4))
  "The next UDP datagram, or NIL when none arrives within SECONDS."
  (let ((buffer (make-array 1500 :element-type '(unsigned-byte 8)))
        (deadline (+ (get-internal-real-time)
                     (round (* seconds internal-time-units-per-second)))))
    (loop while (< (get-internal-real-time) deadline)
          do (multiple-value-bind (buf len)
                 (handler-case
                     (sb-bsd-sockets:socket-receive socket buffer nil
                                                    :dontwait t
                                                    :element-type '(unsigned-byte 8))
                   (sb-bsd-sockets:interrupted-error ()
                     (values nil 0)))
               (when (and buf len (plusp len))
                 (return (subseq buf 0 len))))
             (sleep 0.02))))

(defun quic-short-initial-test (port)
  "RFC 9000 §14.1. An Initial in a datagram under 1200 bytes is discarded.
The same header at 1200 bytes is answered."
  (check "a short QUIC Initial is discarded"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-initial-packet 200) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "short Initial was answered"))
             (sb-bsd-sockets:socket-send socket (quic-initial-packet 1200) nil
                                         :address (list #(127 0 0 1) port))
             (let ((reply (quic-recv-packet socket :seconds 2)))
               (unless (and reply
                            (logtest (aref reply 0) #x80)
                            (= (aref reply 1) 0) (= (aref reply 2) 0)
                            (= (aref reply 3) 0) (= (aref reply 4) 1))
                 (fail "full Initial reply ~s" reply))))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-long-cid-packet (which)
  "A 1200-byte QUIC v1 long header. WHICH is :dcid or :scid for a 21-octet
connection ID. The other connection ID is 8 octets."
  (let* ((dcid (if (eq which :dcid)
                   (coerce (loop for index below 21 collect index)
                           '(vector (unsigned-byte 8)))
                   (coerce #(1 2 3 4 5 6 7 8) '(vector (unsigned-byte 8)))))
         (scid (if (eq which :scid)
                   (coerce (loop for index from 30 below 51 collect index)
                           '(vector (unsigned-byte 8)))
                   (coerce #(9 10 11 12 13 14 15 16) '(vector (unsigned-byte 8)))))
         (head (concatenate '(vector (unsigned-byte 8))
                            #(#xc0 0 0 0 1)
                            (vector (length dcid)) dcid
                            (vector (length scid)) scid))
         (packet (make-array 1200 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace packet head)
    packet))

(defun quic-answered-initial-p (socket port)
  "True when a 1200-byte Initial with 8-octet connection IDs is answered
by a version 1 long header."
  (sb-bsd-sockets:socket-send socket (quic-initial-packet 1200) nil
                              :address (list #(127 0 0 1) port))
  (let ((reply (quic-recv-packet socket :seconds 2)))
    (and reply
         (logtest (aref reply 0) #x80)
         (= (aref reply 1) 0) (= (aref reply 2) 0)
         (= (aref reply 3) 0) (= (aref reply 4) 1))))

(defun quic-long-dcid-test (port)
  "RFC 9000 §17.2. A version 1 long header whose Destination Connection ID
Length is above 20 is dropped. An Initial with an 8-octet Destination
Connection ID is answered."
  (check "a version 1 Destination Connection ID longer than 20 is dropped"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-long-cid-packet :dcid) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "a 21-octet Destination Connection ID was answered"))
             (unless (quic-answered-initial-p socket port)
               (fail "an 8-octet Destination Connection ID was not answered")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-long-scid-test (port)
  "RFC 9000 §17.2. A version 1 long header whose Source Connection ID Length
is above 20 is dropped. An Initial with an 8-octet Source Connection ID
is answered."
  (check "a version 1 Source Connection ID longer than 20 is dropped"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-long-cid-packet :scid) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "a 21-octet Source Connection ID was answered"))
             (unless (quic-answered-initial-p socket port)
               (fail "an 8-octet Source Connection ID was not answered")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-fixed-bit-initial (total)
  "A QUIC v1 Initial of TOTAL bytes with the fixed bit clear."
  (let ((packet (quic-initial-packet total)))
    (setf (aref packet 0) (logand (aref packet 0) (lognot #x40)))
    packet))

(defun quic-fixed-bit-test (port)
  "RFC 9000 §17.2. A version 1 Initial with the fixed bit clear is
discarded. An Initial with that bit set is answered."
  (check "a version 1 Initial with the fixed bit clear is discarded"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-fixed-bit-initial 1200) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "an Initial with the fixed bit clear was answered"))
             (unless (quic-answered-initial-p socket port)
               (fail "an Initial with the fixed bit set was not answered")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-short-fixed-bit-script ()
  "Client that sends one valid 1-RTT PING and one with the fixed bit clear."
  (let ((script "/tmp/pazuzu-h3-short-fixed.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._replies = 0"
                   "        self._count = False"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        if self._count:"
                   "            self._replies += 1"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def send_ping(client, fixed):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = ((crypto.key_phase & 1) << 2) | 0x03"
                   "    if fixed:"
                   "        first = first | 0x40"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    packet = crypto.encrypt_packet(header, bytes([0x01]), pn)"
                   "    client._transport.sendto(packet, quic._network_paths[0].addr)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            await asyncio.sleep(0.4)"
                   "            client._count = True"
                   "            client._replies = 0"
                   "            send_ping(client, True)"
                   "            await asyncio.sleep(0.5)"
                   "            plain = client._replies"
                   "            client._replies = 0"
                   "            send_ping(client, False)"
                   "            await asyncio.sleep(0.5)"
                   "            clear = client._replies"
                   "            try:"
                   "                await asyncio.wait_for(client.ping(), 2)"
                   "                ping = 'ok'"
                   "            except Exception as exc:"
                   "                ping = 'err'"
                   "            print('PLAIN %s CLEAR %s PING %s CLOSED %s' % (plain, clear, ping, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-short-fixed-bit-test (port)
  "RFC 9000 §17.3.1. A 1-RTT packet with the fixed bit clear is discarded.
The same PING with the bit set draws a reply, and the connection stays
open."
  (let ((script (quic-short-fixed-bit-script)))
    (check "a 1-RTT packet with the fixed bit clear is discarded"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (not (search "PLAIN 0" out))
                     (search "CLEAR 0" out)
                     (search "PING ok" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-scid-script ()
  "Client that repeats an Initial during the handshake. One copy keeps the
client Source Connection ID and carries CONNECTION_CLOSE. The other copy
uses a different Source Connection ID and the same frame."
  (let ((script "/tmp/pazuzu-h3-scid.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, encode_long_header_first_byte"
                   "from aioquic.tls import Epoch"
                   ""
                   "def varint(value):"
                   "    if value < 64:"
                   "        return bytes([value])"
                   "    if value < 16384:"
                   "        return (value | 0x4000).to_bytes(2, 'big')"
                   "    raise ValueError(value)"
                   ""
                   "def build_initial(quic, scid):"
                   "    crypto = quic._cryptos[Epoch.INITIAL]"
                   "    dcid = quic._peer_cid.cid"
                   "    token = quic._peer_token or b''"
                   "    pn = 50"
                   "    close = bytes([0x1c, 0x2a, 0x00, 0x00])"
                   "    first = encode_long_header_first_byte(QuicProtocolVersion.VERSION_1, QuicPacketType.INITIAL, 1)"
                   "    prefix = bytes([first]) + (1).to_bytes(4, 'big') + bytes([len(dcid)]) + dcid"
                   "    prefix += bytes([len(scid)]) + scid + varint(len(token)) + token"
                   "    overhead = len(prefix) + 2 + 2 + 16"
                   "    pad = 1200 - overhead - len(close)"
                   "    if pad < 16:"
                   "        pad = 16"
                   "    payload = close + bytes(pad)"
                   "    length = 2 + len(payload) + 16"
                   "    header = prefix + (length | 0x4000).to_bytes(2, 'big') + pn.to_bytes(2, 'big')"
                   "    return crypto.encrypt_packet(header, payload, pn)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._sent = False"
                   "        self._bytes = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._build_error = None"
                   "        self._match = False"
                   "        self._dcid_len = 0"
                   "        self._token_len = 0"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._quic.receive_datagram(data, addr, now=self._loop.time())"
                   "        self._process_events()"
                   "        quic = self._quic"
                   "        ready = quic._cryptos[Epoch.HANDSHAKE].send.is_valid() and quic._peer_token"
                   "        if (not self._sent) and ready:"
                   "            scid = quic.host_cid if self._match else bytes([0xEE]) * len(quic.host_cid)"
                   "            self._dcid_len = len(quic._peer_cid.cid)"
                   "            self._token_len = len(quic._peer_token)"
                   "            try:"
                   "                packet = build_initial(quic, scid)"
                   "                self._transport.sendto(packet, addr)"
                   "                self._sent = True"
                   "                self._bytes = len(packet)"
                   "                if self._timer is not None:"
                   "                    self._timer.cancel()"
                   "                    self._timer = None"
                   "                return"
                   "            except Exception as exc:"
                   "                self._build_error = repr(exc)"
                   "        self.transmit()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def configuration():"
                   "    return QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   ""
                   "async def once(port, match):"
                   "    label = 'SAME' if match else 'DIFF'"
                   "    def create(connection, stream_handler=None):"
                   "        client = Client(connection, stream_handler=stream_handler)"
                   "        client._match = match"
                   "        return client"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=create, wait_connected=False) as client:"
                   "        client.transmit()"
                   "        for _ in range(40):"
                   "            if client._sent:"
                   "                break"
                   "            await asyncio.sleep(0.05)"
                   "        await asyncio.sleep(0.25)"
                   "        stream_id = client._quic.get_next_available_stream_id()"
                   "        client._http.send_headers(stream_id, ["
                   "            (b':method', b'GET'),"
                   "            (b':scheme', b'https'),"
                   "            (b':authority', b'127.0.0.1'),"
                   "            (b':path', b'/'),"
                   "        ], end_stream=True)"
                   "        client.transmit()"
                   "        await asyncio.sleep(0.8)"
                   "        body = client._body.decode('ascii', 'replace') or '-'"
                   "        print('RESULT %s status=%s body=%s sent=%s closed=%s bytes=%s err=%s' % (label, client._status, body, client._sent, client._terminated, client._bytes, client._build_error))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    try:"
                   "        await once(port, True)"
                   "        await once(port, False)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-scid-test (port)
  "RFC 9000 §7.2. After the first Initial is processed, a later Initial with
a different Source Connection ID is discarded. The same Initial, with the
client's Source Connection ID and a CONNECTION_CLOSE, is not discarded:
the handshake does not complete."
  (let ((script (quic-scid-script)))
    (check "a later Initial with a different Source Connection ID is discarded"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT SAME status=None body=- sent=True closed=None bytes=1200 err=None" out)
                     (search "RESULT DIFF status=200 body=pazuzu sent=True closed=None bytes=1200 err=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-no-early-data-script ()
  "Client that stores the session ticket and connects again with it."
  (let ((script "/tmp/pazuzu-h3-no-early.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._early = None"
                   "        self._resumed = None"
                   "        self._status = None"
                   "        self._body = b''"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, HandshakeCompleted):"
                   "            self._early = event.early_data_accepted"
                   "            self._resumed = event.session_resumed"
                   "        elif isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def configuration():"
                   "    return QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    tickets = []"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration(), session_ticket_handler=tickets.append) as client:"
                   "            for _ in range(20):"
                   "                if tickets:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "        if not tickets:"
                   "            print('NO TICKET')"
                   "            return"
                   "        ticket = tickets[0]"
                   "        print('TICKET early=%s' % ticket.max_early_data_size)"
                   "        resumed = configuration()"
                   "        resumed.session_ticket = ticket"
                   "        async with connect('127.0.0.1', port, configuration=resumed, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESUME early=%s status=%s body=%s closed=%s resumed=%s' % (client._early, client._status, body, client._terminated, client._resumed))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-no-early-data-test (port)
  "RFC 9114 §7.2.4. The server does not remember HTTP/3 settings, so it
cannot know that a client's remembered settings are compatible. It does
not accept 0-RTT: the session ticket omits early data, and a later
handshake that presents the ticket does not accept early data."
  (let ((script (quic-no-early-data-script)))
    (check "0-RTT data is not accepted"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "TICKET early=None" out)
                     (search "RESUME early=False status=200 body=pazuzu closed=None" out)
                     (not (search "ERR " out))
                     (not (search "NO TICKET" out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stop-sending-reset-script ()
  "Client that asks the server to stop a response it has started sending."
  (let ((script "/tmp/pazuzu-h3-stop-reset.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "LIMIT = 256"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._reset = None"
                   "        self._stopped = False"
                   "        self._status = None"
                   "        original = self._quic._write_stream_limits"
                   "        def frozen(builder, space, stream, _orig=original):"
                   "            if stream.stream_id == 0:"
                   "                return"
                   "            _orig(builder, space, stream)"
                   "        self._quic._write_stream_limits = frozen"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        elif isinstance(event, StreamReset) and event.stream_id == 0:"
                   "            self._reset = event.error_code"
                   "        elif isinstance(event, StreamDataReceived) and event.stream_id == 0 and not self._stopped and event.data:"
                   "            self._stopped = True"
                   "            self._quic.stop_stream(0, 42)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   ""
                   "def create(connection, stream_handler=None):"
                   "    connection._local_max_stream_data_bidi_local = LIMIT"
                   "    return Client(connection, stream_handler=stream_handler)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=create) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/flow-conn'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.8)"
                   "            print('RESULT stopped=%s reset=%s status=%s closed=%s' % (client._stopped, client._reset, client._status, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-stop-sending-reset-test (port)
  "RFC 9000 §3.5. STOP_SENDING on a stream the server has started sending
MUST be answered with RESET_STREAM. The client allows 256 bytes on the
response stream and does not raise that limit, so GET /flow-conn cannot
be finished before the stop."
  (let ((script (quic-stop-sending-reset-script)))
    (check "a STOP_SENDING frame on a sending stream is answered with RESET_STREAM"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT stopped=True reset=" out)
                     (not (search "RESULT stopped=True reset=None" out))
                     (search "status=200" out)
                     (search "closed=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reset-sent-no-stream-script ()
  "STOP_SENDING draws RESET_STREAM. Credit raised after that reset must
not bring more STREAM data."
  (let ((script "/tmp/pazuzu-h3-reset-sent.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "LIMIT = 256"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._reset = None"
                   "        self._stopped = False"
                   "        self._raised = False"
                   "        self._status = None"
                   "        self._before = 0"
                   "        self._after = 0"
                   "        self._credit = None"
                   "        original = self._quic._write_stream_limits"
                   "        self._original_limits = original"
                   "        def frozen(builder, space, stream, _orig=original):"
                   "            if stream.stream_id == 0:"
                   "                return"
                   "            _orig(builder, space, stream)"
                   "        self._quic._write_stream_limits = frozen"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        elif isinstance(event, StreamReset) and event.stream_id == 0:"
                   "            self._reset = event.error_code"
                   "            if not self._raised:"
                   "                self._raised = True"
                   "                quic = self._quic"
                   "                quic._write_stream_limits = self._original_limits"
                   "                stream = quic._streams[0]"
                   "                stream.max_stream_data_local = 200000"
                   "                self._credit = stream.max_stream_data_local"
                   "        elif isinstance(event, StreamDataReceived) and event.stream_id == 0:"
                   "            if self._reset is None:"
                   "                self._before += len(event.data)"
                   "                if event.data and not self._stopped:"
                   "                    self._stopped = True"
                   "                    self._quic.stop_stream(0, 42)"
                   "            else:"
                   "                self._after += len(event.data)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   ""
                   "def create(connection, stream_handler=None):"
                   "    connection._local_max_stream_data_bidi_local = LIMIT"
                   "    return Client(connection, stream_handler=stream_handler)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=create) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/flow-conn'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(1.0)"
                   "            print('RESULT stopped=%s reset=%s status=%s closed=%s before=%s after=%s credit=%s' % (client._stopped, client._reset, client._status, client._terminated, client._before, client._after, client._credit))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-reset-sent-no-stream-test (port)
  "RFC 9000 §3.3. After RESET_STREAM the sending part is Reset Sent, and
a STREAM frame MUST NOT be sent from that state. The client stops
GET /flow-conn, then raises the stream credit to 200000. Data that
arrives only because that credit was restored fails the check."
  (let ((script (quic-reset-sent-no-stream-script)))
    (check "a RESET_STREAM is not followed by another STREAM frame"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT stopped=True reset=" out)
                     (not (search "reset=None" out))
                     (search "status=200" out)
                     (search "closed=None" out)
                     (search "credit=200000" out)
                     (search "after=0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))
        (let* ((marker (search "before=" out))
               (tail (and marker (subseq out marker)))
               (space (and tail (position #\Space tail)))
               (text (and space (subseq tail 7 space))))
          (unless (and text (every #'digit-char-p text)
                       (plusp (parse-integer text))
                       (< (parse-integer text) 8192))
            (fail "before ~s out ~s" text out)))))))

(defun quic-dup-suppress-script ()
  "After the handshake, send one 1-RTT GET / whose last byte is flipped,
then the same datagram. Header protection still yields that packet number."
  (let ((script "/tmp/pazuzu-h3-dup-suppress.py"))
    (write-lines script
                 '("import asyncio, ssl, sys, time"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def arm(quic):"
                   "    original = quic._write_application"
                   "    state = {'padded': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['padded'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.PADDING, capacity=33)"
                   "            buf.push_bytes(bytes(32))"
                   "            state['padded'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   "    return state"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            state = arm(client._quic)"
                   "            info = {'corrupt': False, 'outside': False, 'length': 0, 'sample_end': 0, 'sends': 0}"
                   "            real_sendto = client._transport.sendto"
                   "            def sendto(data, addr):"
                   "                info['sends'] += 1"
                   "                raw = bytes(data)"
                   "                if info['corrupt'] or not state['padded'] or not raw or (raw[0] & 0x80):"
                   "                    return real_sendto(raw, addr)"
                   "                dcid_len = len(client._quic._peer_cid.cid)"
                   "                sample_end = 1 + dcid_len + 4 + 16"
                   "                info['length'] = len(raw)"
                   "                info['sample_end'] = sample_end"
                   "                info['outside'] = len(raw) > sample_end"
                   "                if not info['outside']:"
                   "                    return real_sendto(raw, addr)"
                   "                corrupt = bytearray(raw)"
                   "                corrupt[-1] ^= 0xFF"
                   "                info['corrupt'] = True"
                   "                real_sendto(bytes(corrupt), addr)"
                   "                time.sleep(0.1)"
                   "                return real_sendto(raw, addr)"
                   "            client._transport.sendto = sendto"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            once = info['sends'] == 1 and info['corrupt'] and info['outside']"
                   "            for _ in range(30):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s corrupt=%s outside=%s once=%s length=%s sample_end=%s padded=%s' % (client._status, body, client._terminated, info['corrupt'], info['outside'], once, info['length'], info['sample_end'], state['padded']))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-dup-suppress-test (port)
  "RFC 9000 §12.3. Duplicate suppression happens after packet protection
is removed. A 1-RTT datagram whose last byte is flipped fails
authentication and must not consume that packet number. The same
datagram, sent after the failure, is GET / and is answered."
  (let ((script (quic-dup-suppress-script)))
    (check "a failed decryption does not consume the packet number"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None corrupt=True outside=True once=True " out)
                     (search "padded=True" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-unauth-ack-script ()
  "Send one corrupted 1-RTT PING and not the original. Record whether
that packet number appears in an ACK, then request GET /."
  (let ((script "/tmp/pazuzu-h3-unauth-ack.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def arm(quic, info):"
                   "    original = quic._write_application"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if info['padded'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.PADDING, capacity=33)"
                   "            buf.push_bytes(bytes(32))"
                   "            info['padded'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   "    loss = quic._loss.on_ack_received"
                   "    def on_ack(*, ack_rangeset, ack_delay, now, space, _loss=loss):"
                   "        pn = info['pn']"
                   "        if pn is not None and space is quic._spaces[Epoch.ONE_RTT] and pn in ack_rangeset:"
                   "            info['acked'] = True"
                   "        return _loss(ack_rangeset=ack_rangeset, ack_delay=ack_delay, now=now, space=space)"
                   "    quic._loss.on_ack_received = on_ack"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            info = {'padded': False, 'corrupt': False, 'outside': False, 'pn': None, 'acked': False, 'sends': 0}"
                   "            arm(client._quic, info)"
                   "            real_sendto = client._transport.sendto"
                   "            def sendto(data, addr):"
                   "                raw = bytes(data)"
                   "                if info['corrupt'] or not info['padded'] or not raw or (raw[0] & 0x80):"
                   "                    return real_sendto(raw, addr)"
                   "                sample_end = 1 + len(client._quic._peer_cid.cid) + 4 + 16"
                   "                info['outside'] = len(raw) > sample_end"
                   "                if not info['outside']:"
                   "                    return real_sendto(raw, addr)"
                   "                corrupt = bytearray(raw)"
                   "                corrupt[-1] ^= 0xFF"
                   "                info['corrupt'] = True"
                   "                info['sends'] += 1"
                   "                return real_sendto(bytes(corrupt), addr)"
                   "            client._transport.sendto = sendto"
                   "            space = client._quic._spaces[Epoch.ONE_RTT]"
                   "            before = set(space.sent_packets)"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            new = sorted(set(space.sent_packets) - before)"
                   "            info['pn'] = new[0] if len(new) == 1 else None"
                   "            await asyncio.sleep(0.4)"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(30):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s corrupt=%s outside=%s acked=%s pn=%s sends=%s' % (client._status, body, client._terminated, info['corrupt'], info['outside'], info['acked'], info['pn'], info['sends']))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-unauth-ack-test (port)
  "RFC 9000 §13.1. A packet is not acknowledged until its protection has
been removed. The client sends a 1-RTT PING with the last byte flipped
and does not send the original. That packet number stays out of every
ACK, and a later GET / is answered."
  (let ((script (quic-unauth-ack-script)))
    (check "an unauthenticated packet is not acknowledged"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None corrupt=True outside=True acked=False " out)
                     (not (search "pn=None" out))
                     (search "sends=1" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-unterminated-flow-script ()
  "STOP_SENDING draws RESET_STREAM on one direction. A later STREAM frame
past the receive limit must still be FLOW_CONTROL_ERROR."
  (let ((script "/tmp/pazuzu-h3-unterminated-flow.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamReset"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._reset = None"
                   "        self._arm = False"
                   "        self._sent = False"
                   "        original = self._quic._write_application"
                   "        def wrapped(builder, network_path, now, _orig=original):"
                   "            real = builder.start_packet"
                   "            def start_packet(packet_type, crypto):"
                   "                real(packet_type, crypto)"
                   "                if self._sent or not self._arm or packet_type is not QuicPacketType.ONE_RTT:"
                   "                    return"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 6, capacity=8)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(256 * 1024)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "                self._sent = True"
                   "            builder.start_packet = start_packet"
                   "            _orig(builder, network_path, now)"
                   "        self._quic._write_application = wrapped"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        elif isinstance(event, StreamReset) and event.stream_id == 0 and self._reset is None:"
                   "            self._reset = event.error_code"
                   "            self._arm = True"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            client._quic._get_or_create_stream_for_send(0)"
                   "            client._quic.stop_stream(0, 42)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._terminated is not None and client._sent:"
                   "                    break"
                   "                if client._reset is not None and not client._sent:"
                   "                    client.transmit()"
                   "                await asyncio.sleep(0.1)"
                   "            print('RESULT reset=%s closed=%s sent=%s' % (client._reset, client._terminated, client._sent))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-unterminated-flow-test (port)
  "RFC 9000 §4.4. RESET_STREAM ends one direction of a bidirectional
stream. Flow-control state for the other direction stays until that
direction ends. The client stops stream 0, waits for RESET_STREAM, then
sends one byte at offset 256 KiB. That is FLOW_CONTROL_ERROR (0x03)."
  (let ((script (quic-unterminated-flow-script)))
    (check "flow control state remains on the unterminated direction"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT reset=" out)
                     (not (search "reset=None" out))
                     (search "closed=3" out)
                     (search "sent=True" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reset-retransmit-script ()
  "Drop the first RESET_STREAM so the server sends it again. The second
copy must carry the same stream, error, and final size."
  (let ((script "/tmp/pazuzu-h3-reset-retransmit.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def reset_streams(payload):"
                   "    buf = Buffer(data=payload)"
                   "    found = []"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type == 0x04:"
                   "            sid = buf.pull_uint_var()"
                   "            err = buf.pull_uint_var()"
                   "            fin = buf.pull_uint_var()"
                   "            if sid == 0:"
                   "                found.append((sid, err, fin))"
                   "            continue"
                   "        if frame_type == 0x05:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x07:"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x11, 0x15):"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x18:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint8())"
                   "            buf.pull_bytes(16)"
                   "            continue"
                   "        if frame_type in (0x1a, 0x1b):"
                   "            buf.pull_bytes(8)"
                   "            continue"
                   "        if frame_type == 0x1c:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x1d:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if 0x08 <= frame_type <= 0x0f:"
                   "            buf.pull_uint_var()"
                   "            if frame_type & 4:"
                   "                buf.pull_uint_var()"
                   "            if frame_type & 2:"
                   "                buf.pull_bytes(buf.pull_uint_var())"
                   "            else:"
                   "                buf.pull_bytes(buf.capacity - buf.tell())"
                   "            continue"
                   "        break"
                   "    return found"
                   ""
                   "def datagram_resets(quic, data):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or not data or (data[0] & 0x80):"
                   "        return []"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    buf = Buffer(data=data)"
                   "    cid_len = quic._configuration.connection_id_length"
                   "    start = buf.tell()"
                   "    pull_quic_header(buf, host_cid_length=cid_len)"
                   "    encrypted_off = buf.tell() - start"
                   "    _header, payload, _number = crypto.decrypt_packet("
                   "        data, encrypted_off, space.expected_packet_number)"
                   "    return reset_streams(payload)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._resets = []"
                   "        self._terminated = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        try:"
                   "            found = datagram_resets(self._quic, bytes(data))"
                   "        except Exception:"
                   "            found = []"
                   "        if found and not self._resets:"
                   "            self._resets.append(found[0])"
                   "            return"
                   "        if found:"
                   "            self._resets.append(found[0])"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            client._quic._get_or_create_stream_for_send(0)"
                   "            client._quic.stop_stream(0, 42)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if len(client._resets) >= 2 or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            same = len(client._resets) >= 2 and all(item == client._resets[0] for item in client._resets)"
                   "            second = client._resets[1] if len(client._resets) > 1 else None"
                   "            print('RESULT count=%s same=%s first=%s second=%s closed=%s' % (len(client._resets), same, client._resets[0] if client._resets else None, second, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-reset-retransmit-test (port)
  "RFC 9000 §13.3. The content of a RESET_STREAM frame does not change
when it is sent again. The client stops stream 0 and drops the first
RESET_STREAM. The retransmission carries the same stream, error code,
and final size."
  (let ((script (quic-reset-retransmit-script)))
    (check "a retransmitted RESET_STREAM keeps the same content"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT count=" out)
                     (search "same=True" out)
                     (not (search "count=0" out))
                     (not (search "count=1" out))
                     (search "closed=None" out)
                     (not (search "first=None" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-retransmit-script ()
  "Drop the first STREAM payload on the response so the server sends
those bytes again. Bytes at the same offset must match."
  (let ((script "/tmp/pazuzu-h3-stream-retransmit.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def stream_spans(payload, sid):"
                   "    buf = Buffer(data=payload)"
                   "    found = []"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type == 0x04:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x05:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x07:"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x11, 0x15):"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x18:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint8())"
                   "            buf.pull_bytes(16)"
                   "            continue"
                   "        if frame_type in (0x1a, 0x1b):"
                   "            buf.pull_bytes(8)"
                   "            continue"
                   "        if frame_type == 0x1c:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x1d:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if 0x08 <= frame_type <= 0x0f:"
                   "            stream_id = buf.pull_uint_var()"
                   "            offset = buf.pull_uint_var() if frame_type & 4 else 0"
                   "            if frame_type & 2:"
                   "                data = buf.pull_bytes(buf.pull_uint_var())"
                   "            else:"
                   "                data = buf.pull_bytes(buf.capacity - buf.tell())"
                   "            if stream_id == sid and data:"
                   "                found.append((offset, data))"
                   "            continue"
                   "        break"
                   "    return found"
                   ""
                   "def datagram_spans(quic, data, sid):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or sid is None or not data or (data[0] & 0x80):"
                   "        return []"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    buf = Buffer(data=data)"
                   "    cid_len = quic._configuration.connection_id_length"
                   "    start = buf.tell()"
                   "    pull_quic_header(buf, host_cid_length=cid_len)"
                   "    encrypted_off = buf.tell() - start"
                   "    _header, payload, _number = crypto.decrypt_packet("
                   "        data, encrypted_off, space.expected_packet_number)"
                   "    return stream_spans(payload, sid)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._bytes = {}"
                   "        self._dropped = False"
                   "        self._overlap = 0"
                   "        self._conflict = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def note(self, spans):"
                   "        for offset, data in spans:"
                   "            for index, byte in enumerate(data):"
                   "                pos = offset + index"
                   "                prev = self._bytes.get(pos)"
                   "                if prev is None:"
                   "                    self._bytes[pos] = byte"
                   "                else:"
                   "                    self._overlap += 1"
                   "                    if prev != byte:"
                   "                        self._conflict += 1"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        try:"
                   "            spans = datagram_spans(self._quic, bytes(data), self._sid)"
                   "        except Exception:"
                   "            spans = []"
                   "        if spans and not self._dropped:"
                   "            self.note(spans)"
                   "            self._dropped = True"
                   "            return"
                   "        if spans:"
                   "            self.note(spans)"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s dropped=%s overlap=%s conflict=%s' % (client._status, body, client._terminated, client._dropped, client._overlap, client._conflict))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-stream-retransmit-test (port)
  "RFC 9000 §2.2. Data at a given stream offset does not change when it
is sent again. The client drops the first response bytes on GET / and
compares them with the retransmission. The response is 200 pazuzu."
  (let ((script (quic-stream-retransmit-script)))
    (check "stream data at a given offset does not change"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None dropped=True " out)
                     (search "conflict=0" out)
                     (not (search "overlap=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-final-size-script ()
  "Record every STREAM frame on the response. No byte is carried at or
beyond the final size named by FIN."
  (let ((script "/tmp/pazuzu-h3-final-size.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def stream_spans(payload, sid):"
                   "    buf = Buffer(data=payload)"
                   "    found = []"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type == 0x04:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x05:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x07:"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x11, 0x15):"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x18:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint8())"
                   "            buf.pull_bytes(16)"
                   "            continue"
                   "        if frame_type in (0x1a, 0x1b):"
                   "            buf.pull_bytes(8)"
                   "            continue"
                   "        if frame_type == 0x1c:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x1d:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if 0x08 <= frame_type <= 0x0f:"
                   "            stream_id = buf.pull_uint_var()"
                   "            offset = buf.pull_uint_var() if frame_type & 4 else 0"
                   "            if frame_type & 2:"
                   "                data = buf.pull_bytes(buf.pull_uint_var())"
                   "            else:"
                   "                data = buf.pull_bytes(buf.capacity - buf.tell())"
                   "            if stream_id == sid:"
                   "                found.append((offset, len(data), frame_type & 1))"
                   "            continue"
                   "        break"
                   "    return found"
                   ""
                   "def datagram_spans(quic, data, sid):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or sid is None or not data or (data[0] & 0x80):"
                   "        return []"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    buf = Buffer(data=data)"
                   "    cid_len = quic._configuration.connection_id_length"
                   "    start = buf.tell()"
                   "    pull_quic_header(buf, host_cid_length=cid_len)"
                   "    encrypted_off = buf.tell() - start"
                   "    _header, payload, _number = crypto.decrypt_packet("
                   "        data, encrypted_off, space.expected_packet_number)"
                   "    return stream_spans(payload, sid)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._spans = []"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        try:"
                   "            spans = datagram_spans(self._quic, bytes(data), self._sid)"
                   "        except Exception:"
                   "            spans = []"
                   "        self._spans.extend(spans)"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            await asyncio.sleep(0.2)"
                   "            fins = sorted({off + length for off, length, fin in client._spans if fin})"
                   "            final = fins[0] if len(fins) == 1 else -1"
                   "            past = 0"
                   "            total = 0"
                   "            if final >= 0:"
                   "                for off, length, fin in client._spans:"
                   "                    total += length"
                   "                    if off + length > final or (length and off >= final):"
                   "                        past += 1"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s fin=%s past=%s final=%s bytes=%s' % (client._status, body, client._terminated, 1 if len(fins) == 1 else 0, past, final, total))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-final-size-test (port)
  "RFC 9000 §4.5. A sender does not carry stream data at or beyond the
final size. GET / is 200 pazuzu, one FIN names that size, and every
STREAM frame on that stream ends at or before it."
  (let ((script (quic-final-size-script)))
    (check "no stream data is sent at or beyond the final size"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None fin=1 past=0 " out)
                     (not (search "final=-1" out))
                     (not (search "final=0 " out))
                     (not (search "bytes=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-send-reserved-script ()
  "Decrypt each server 1-RTT packet and record whether its reserved bits
are clear before header protection."
  (let ((script "/tmp/pazuzu-h3-send-reserved.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_quic_header, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def reserved_set(quic, data):"
                   "    if not data or (data[0] & 0x80):"
                   "        return None"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None:"
                   "        return None"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    buf = Buffer(data=data)"
                   "    start = buf.tell()"
                   "    pull_quic_header(buf, host_cid_length=quic._configuration.connection_id_length)"
                   "    encrypted_off = buf.tell() - start"
                   "    header, _payload, _number = crypto.decrypt_packet("
                   "        data, encrypted_off, space.expected_packet_number)"
                   "    return 1 if (header[0] & 0x18) else 0"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._seen = 0"
                   "        self._bad = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        try:"
                   "            bad = reserved_set(self._quic, bytes(data))"
                   "        except Exception:"
                   "            bad = None"
                   "        if bad is not None:"
                   "            self._seen += 1"
                   "            self._bad += bad"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s seen=%s bad=%s' % (client._status, body, client._terminated, client._seen, client._bad))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-send-reserved-test (port)
  "RFC 9000 §17.3.1. A sender sets the reserved bits of a 1-RTT packet to
zero before header protection. GET / is 200 pazuzu, and every decrypted
1-RTT packet has those bits clear."
  (let ((script (quic-send-reserved-script)))
    (check "a server 1-RTT packet leaves its reserved bits clear"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None " out)
                     (search "bad=0" out)
                     (not (search "seen=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-long-send-reserved-script ()
  "Decrypt each server Initial and Handshake packet and record whether
its reserved bits are clear before header protection."
  (let ((script "/tmp/pazuzu-h3-long-send-reserved.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_quic_header, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def note_long(quic, data, counts, want):"
                   "    if not data or (data[0] & 0x80) == 0:"
                   "        return"
                   "    buf = Buffer(data=data)"
                   "    while not buf.eof():"
                   "        start = buf.tell()"
                   "        if data[start] & 0x80 == 0:"
                   "            return"
                   "        header = pull_quic_header(buf)"
                   "        end = start + header.packet_length"
                   "        crypto = None"
                   "        space = None"
                   "        kind = None"
                   "        if header.packet_type == QuicPacketType.INITIAL:"
                   "            crypto = quic._cryptos_initial.get(QuicProtocolVersion.VERSION_1)"
                   "            space = quic._spaces[Epoch.INITIAL]"
                   "            kind = 'initial'"
                   "        elif header.packet_type == QuicPacketType.HANDSHAKE:"
                   "            crypto = quic._cryptos.get(Epoch.HANDSHAKE)"
                   "            space = quic._spaces[Epoch.HANDSHAKE]"
                   "            kind = 'handshake'"
                   "        if kind == want and crypto is not None and space is not None:"
                   "            try:"
                   "                encrypted_off = buf.tell() - start"
                   "                plain, _payload, _number = crypto.decrypt_packet("
                   "                    data[start:end], encrypted_off, space.expected_packet_number)"
                   "                counts[kind] += 1"
                   "                if plain[0] & 0x0c:"
                   "                    counts['bad'] += 1"
                   "            except Exception as exc:"
                   "                if counts.get('why') is None:"
                   "                    counts['why'] = repr(exc)"
                   "        if end <= start or end > len(data):"
                   "            return"
                   "        buf.seek(end)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._counts = {'initial': 0, 'handshake': 0, 'bad': 0, 'why': None}"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        raw = bytes(data)"
                   "        try:"
                   "            note_long(self._quic, raw, self._counts, 'initial')"
                   "        except Exception:"
                   "            pass"
                   "        super().datagram_received(data, addr)"
                   "        try:"
                   "            note_long(self._quic, raw, self._counts, 'handshake')"
                   "        except Exception:"
                   "            pass"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            counts = client._counts"
                   "            print('RESULT status=%s body=%s closed=%s initial=%s handshake=%s bad=%s why=%s' % (client._status, body, client._terminated, counts['initial'], counts['handshake'], counts['bad'], counts['why']))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-long-send-reserved-test (port)
  "RFC 9000 §17.2. A sender sets the reserved bits of a long-header
packet to zero before header protection. GET / is 200 pazuzu, and every
decrypted Initial and Handshake packet has those bits clear."
  (let ((script (quic-long-send-reserved-script)))
    (check "a server long header leaves its reserved bits clear"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None " out)
                     (search "bad=0" out)
                     (not (search "initial=0" out))
                     (not (search "handshake=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-frame-type-script ()
  "Decrypt server Initial, Handshake, and 1-RTT packets and record
whether each frame type uses the shortest variable-length encoding."
  (let ((script "/tmp/pazuzu-h3-frame-type.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_ack_frame, pull_quic_header, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def frames_short(payload):"
                   "    buf = Buffer(data=payload)"
                   "    seen = 0"
                   "    long = 0"
                   "    while not buf.eof():"
                   "        first = payload[buf.tell()]"
                   "        used = 1 << ((first >> 6) & 3)"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type <= 0x3f:"
                   "            need = 1"
                   "        elif frame_type <= 0x3fff:"
                   "            need = 2"
                   "        elif frame_type <= 0x3fffffff:"
                   "            need = 4"
                   "        else:"
                   "            need = 8"
                   "        seen += 1"
                   "        if used != need:"
                   "            long += 1"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type == 0x04:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x05:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            pull_ack_frame(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x07:"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x11, 0x15):"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x18:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint8())"
                   "            buf.pull_bytes(16)"
                   "            continue"
                   "        if frame_type in (0x1a, 0x1b):"
                   "            buf.pull_bytes(8)"
                   "            continue"
                   "        if frame_type == 0x1c:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x1d:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if 0x08 <= frame_type <= 0x0f:"
                   "            buf.pull_uint_var()"
                   "            if frame_type & 4:"
                   "                buf.pull_uint_var()"
                   "            if frame_type & 2:"
                   "                buf.pull_bytes(buf.pull_uint_var())"
                   "            else:"
                   "                buf.pull_bytes(buf.capacity - buf.tell())"
                   "            continue"
                   "        break"
                   "    return seen, long"
                   ""
                   "def packet_payloads(quic, data, want):"
                   "    found = []"
                   "    if not data:"
                   "        return found"
                   "    if want == '1rtt':"
                   "        if data[0] & 0x80:"
                   "            return found"
                   "        crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "        if crypto is None:"
                   "            return found"
                   "        space = quic._spaces[Epoch.ONE_RTT]"
                   "        buf = Buffer(data=data)"
                   "        start = buf.tell()"
                   "        pull_quic_header(buf, host_cid_length=quic._configuration.connection_id_length)"
                   "        encrypted_off = buf.tell() - start"
                   "        _header, payload, _number = crypto.decrypt_packet("
                   "            data, encrypted_off, space.expected_packet_number)"
                   "        found.append(payload)"
                   "        return found"
                   "    if data[0] & 0x80 == 0:"
                   "        return found"
                   "    buf = Buffer(data=data)"
                   "    while not buf.eof():"
                   "        start = buf.tell()"
                   "        if data[start] & 0x80 == 0:"
                   "            break"
                   "        header = pull_quic_header(buf)"
                   "        end = start + header.packet_length"
                   "        crypto = None"
                   "        space = None"
                   "        if header.packet_type == QuicPacketType.INITIAL and want == 'initial':"
                   "            crypto = quic._cryptos_initial.get(QuicProtocolVersion.VERSION_1)"
                   "            space = quic._spaces[Epoch.INITIAL]"
                   "        elif header.packet_type == QuicPacketType.HANDSHAKE and want == 'handshake':"
                   "            crypto = quic._cryptos.get(Epoch.HANDSHAKE)"
                   "            space = quic._spaces[Epoch.HANDSHAKE]"
                   "        if crypto is not None and space is not None:"
                   "            encrypted_off = buf.tell() - start"
                   "            _header, payload, _number = crypto.decrypt_packet("
                   "                data[start:end], encrypted_off, space.expected_packet_number)"
                   "            found.append(payload)"
                   "        if end <= start or end > len(data):"
                   "            break"
                   "        buf.seek(end)"
                   "    return found"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._seen = 0"
                   "        self._long = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def take(self, data, want):"
                   "        for payload in packet_payloads(self._quic, data, want):"
                   "            seen, long = frames_short(payload)"
                   "            self._seen += seen"
                   "            self._long += long"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        raw = bytes(data)"
                   "        try:"
                   "            self.take(raw, 'initial')"
                   "        except Exception:"
                   "            pass"
                   "        try:"
                   "            self.take(raw, '1rtt')"
                   "        except Exception:"
                   "            pass"
                   "        super().datagram_received(data, addr)"
                   "        try:"
                   "            self.take(raw, 'handshake')"
                   "        except Exception:"
                   "            pass"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s seen=%s long=%s' % (client._status, body, client._terminated, client._seen, client._long))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-frame-type-test (port)
  "RFC 9000 §12.4. A frame type uses the shortest variable-length
encoding. GET / is 200 pazuzu, and every frame in a decrypted server
packet uses that shortest encoding."
  (let ((script (quic-frame-type-script)))
    (check "a server frame type uses the shortest encoding"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None " out)
                     (search "long=0" out)
                     (not (search "seen=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-packet-frames-script ()
  "Decrypt server Initial, Handshake, and 1-RTT packets and record
whether each payload contains a frame."
  (let ((script "/tmp/pazuzu-h3-packet-frames.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_quic_header, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def has_frame(payload):"
                   "    if not payload:"
                   "        return False"
                   "    buf = Buffer(data=payload)"
                   "    if buf.eof():"
                   "        return False"
                   "    buf.pull_uint_var()"
                   "    return True"
                   ""
                   "def packet_payloads(quic, data, want):"
                   "    found = []"
                   "    if not data:"
                   "        return found"
                   "    if want == '1rtt':"
                   "        if data[0] & 0x80:"
                   "            return found"
                   "        crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "        if crypto is None:"
                   "            return found"
                   "        space = quic._spaces[Epoch.ONE_RTT]"
                   "        buf = Buffer(data=data)"
                   "        start = buf.tell()"
                   "        pull_quic_header(buf, host_cid_length=quic._configuration.connection_id_length)"
                   "        encrypted_off = buf.tell() - start"
                   "        _header, payload, _number = crypto.decrypt_packet("
                   "            data, encrypted_off, space.expected_packet_number)"
                   "        found.append(payload)"
                   "        return found"
                   "    if data[0] & 0x80 == 0:"
                   "        return found"
                   "    buf = Buffer(data=data)"
                   "    while not buf.eof():"
                   "        start = buf.tell()"
                   "        if data[start] & 0x80 == 0:"
                   "            break"
                   "        header = pull_quic_header(buf)"
                   "        end = start + header.packet_length"
                   "        crypto = None"
                   "        space = None"
                   "        if header.packet_type == QuicPacketType.INITIAL and want == 'initial':"
                   "            crypto = quic._cryptos_initial.get(QuicProtocolVersion.VERSION_1)"
                   "            space = quic._spaces[Epoch.INITIAL]"
                   "        elif header.packet_type == QuicPacketType.HANDSHAKE and want == 'handshake':"
                   "            crypto = quic._cryptos.get(Epoch.HANDSHAKE)"
                   "            space = quic._spaces[Epoch.HANDSHAKE]"
                   "        if crypto is not None and space is not None:"
                   "            encrypted_off = buf.tell() - start"
                   "            _header, payload, _number = crypto.decrypt_packet("
                   "                data[start:end], encrypted_off, space.expected_packet_number)"
                   "            found.append(payload)"
                   "        if end <= start or end > len(data):"
                   "            break"
                   "        buf.seek(end)"
                   "    return found"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._packets = 0"
                   "        self._empty = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def take(self, data, want):"
                   "        for payload in packet_payloads(self._quic, data, want):"
                   "            self._packets += 1"
                   "            if not has_frame(payload):"
                   "                self._empty += 1"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        raw = bytes(data)"
                   "        try:"
                   "            self.take(raw, 'initial')"
                   "        except Exception:"
                   "            pass"
                   "        try:"
                   "            self.take(raw, '1rtt')"
                   "        except Exception:"
                   "            pass"
                   "        super().datagram_received(data, addr)"
                   "        try:"
                   "            self.take(raw, 'handshake')"
                   "        except Exception:"
                   "            pass"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s packets=%s empty=%s' % (client._status, body, client._terminated, client._packets, client._empty))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-packet-frames-test (port)
  "RFC 9000 §12.4. The payload of a packet that contains frames contains
at least one frame. GET / is 200 pazuzu, and every decrypted Initial,
Handshake, and 1-RTT packet from the server carries a frame."
  (let ((script (quic-packet-frames-script)))
    (check "a server packet contains at least one frame"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None " out)
                     (search "empty=0" out)
                     (not (search "packets=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-handshake-done-order-script ()
  "Record whether each received HANDSHAKE_DONE is in a 1-RTT packet and
arrives only after the client has sent its Handshake flight."
  (let ((script "/tmp/pazuzu-h3-hs-done-order.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.logger import QuicLogger"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "def done_report(trace):"
                   "    sent_hs = False"
                   "    sent = 0"
                   "    done = 0"
                   "    early = 0"
                   "    space = 0"
                   "    if trace is None:"
                   "        return sent, done, early, space"
                   "    for event in trace._events:"
                   "        data = event.get('data') or {}"
                   "        kind = (data.get('header') or {}).get('packet_type')"
                   "        name = event.get('name')"
                   "        if name == 'transport:packet_sent' and kind == 'handshake':"
                   "            sent_hs = True"
                   "            sent += 1"
                   "        if name != 'transport:packet_received':"
                   "            continue"
                   "        for frame in data.get('frames') or []:"
                   "            if frame.get('frame_type') != 'handshake_done':"
                   "                continue"
                   "            done += 1"
                   "            if kind != '1RTT':"
                   "                space += 1"
                   "            if not sent_hs:"
                   "                early += 1"
                   "    return sent, done, early, space"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        quic_logger=QuicLogger(),"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.2)"
                   "            sent, done, early, space = done_report(client._quic._quic_logger)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s sent=%s done=%s early=%s space=%s' % (client._status, body, client._terminated, sent, done, early, space))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-handshake-done-order-test (port)
  "RFC 9000 §19.20. The server does not send HANDSHAKE_DONE before the
handshake is complete. Each one is in a 1-RTT packet and is received
only after the client has sent its Handshake flight. GET / is 200
pazuzu."
  (let ((script (quic-handshake-done-order-script)))
    (check "a HANDSHAKE_DONE frame follows the completed handshake"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "early=0" out)
                     (search "space=0" out)
                     (not (search "done=0" out))
                     (not (search "sent=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ack-order-script ()
  "Decrypt server packets and record whether each ACK range is
non-negative and strictly lower than the range before it."
  (let ((script "/tmp/pazuzu-h3-ack-order.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import pull_quic_header, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def score_ack(buf):"
                   "    largest = buf.pull_uint_var()"
                   "    buf.pull_uint_var()"
                   "    count = buf.pull_uint_var()"
                   "    first = buf.pull_uint_var()"
                   "    bad = 0"
                   "    if first > largest:"
                   "        bad += 1"
                   "        smallest = 0"
                   "    else:"
                   "        smallest = largest - first"
                   "    for _ in range(count):"
                   "        gap = buf.pull_uint_var()"
                   "        length = buf.pull_uint_var()"
                   "        if smallest < gap + 2:"
                   "            bad += 1"
                   "            nxt = 0"
                   "        else:"
                   "            nxt = smallest - gap - 2"
                   "        if nxt >= smallest:"
                   "            bad += 1"
                   "        if length > nxt:"
                   "            bad += 1"
                   "            smallest = 0"
                   "        else:"
                   "            smallest = nxt - length"
                   "    return bad"
                   ""
                   "def score_payload(payload):"
                   "    acks = 0"
                   "    bad = 0"
                   "    buf = Buffer(data=payload)"
                   "    while not buf.eof():"
                   "        frame_type = buf.pull_uint_var()"
                   "        if frame_type in (0x00, 0x01, 0x1e):"
                   "            continue"
                   "        if frame_type in (0x02, 0x03):"
                   "            acks += 1"
                   "            bad += score_ack(buf)"
                   "            if frame_type == 0x03:"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "                buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x04:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x05:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x06:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x07:"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type in (0x11, 0x15):"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            continue"
                   "        if frame_type == 0x18:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint8())"
                   "            buf.pull_bytes(16)"
                   "            continue"
                   "        if frame_type in (0x1a, 0x1b):"
                   "            buf.pull_bytes(8)"
                   "            continue"
                   "        if frame_type == 0x1c:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if frame_type == 0x1d:"
                   "            buf.pull_uint_var()"
                   "            buf.pull_bytes(buf.pull_uint_var())"
                   "            continue"
                   "        if 0x08 <= frame_type <= 0x0f:"
                   "            buf.pull_uint_var()"
                   "            if frame_type & 4:"
                   "                buf.pull_uint_var()"
                   "            if frame_type & 2:"
                   "                buf.pull_bytes(buf.pull_uint_var())"
                   "            else:"
                   "                buf.pull_bytes(buf.capacity - buf.tell())"
                   "            continue"
                   "        bad += 1"
                   "        break"
                   "    return acks, bad"
                   ""
                   "def packet_payloads(quic, data, want):"
                   "    found = []"
                   "    if not data:"
                   "        return found"
                   "    if want == '1rtt':"
                   "        if data[0] & 0x80:"
                   "            return found"
                   "        crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "        if crypto is None:"
                   "            return found"
                   "        space = quic._spaces[Epoch.ONE_RTT]"
                   "        buf = Buffer(data=data)"
                   "        start = buf.tell()"
                   "        pull_quic_header(buf, host_cid_length=quic._configuration.connection_id_length)"
                   "        encrypted_off = buf.tell() - start"
                   "        _header, payload, _number = crypto.decrypt_packet("
                   "            data, encrypted_off, space.expected_packet_number)"
                   "        found.append(payload)"
                   "        return found"
                   "    if data[0] & 0x80 == 0:"
                   "        return found"
                   "    buf = Buffer(data=data)"
                   "    while not buf.eof():"
                   "        start = buf.tell()"
                   "        if data[start] & 0x80 == 0:"
                   "            break"
                   "        header = pull_quic_header(buf)"
                   "        end = start + header.packet_length"
                   "        crypto = None"
                   "        space = None"
                   "        if header.packet_type == QuicPacketType.INITIAL and want == 'initial':"
                   "            crypto = quic._cryptos_initial.get(QuicProtocolVersion.VERSION_1)"
                   "            space = quic._spaces[Epoch.INITIAL]"
                   "        elif header.packet_type == QuicPacketType.HANDSHAKE and want == 'handshake':"
                   "            crypto = quic._cryptos.get(Epoch.HANDSHAKE)"
                   "            space = quic._spaces[Epoch.HANDSHAKE]"
                   "        if crypto is not None and space is not None:"
                   "            encrypted_off = buf.tell() - start"
                   "            _header, payload, _number = crypto.decrypt_packet("
                   "                data[start:end], encrypted_off, space.expected_packet_number)"
                   "            found.append(payload)"
                   "        if end <= start or end > len(data):"
                   "            break"
                   "        buf.seek(end)"
                   "    return found"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._acks = 0"
                   "        self._bad = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def take(self, data, want):"
                   "        for payload in packet_payloads(self._quic, data, want):"
                   "            acks, bad = score_payload(payload)"
                   "            self._acks += acks"
                   "            self._bad += bad"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        raw = bytes(data)"
                   "        try:"
                   "            self.take(raw, 'initial')"
                   "        except Exception:"
                   "            pass"
                   "        try:"
                   "            self.take(raw, '1rtt')"
                   "        except Exception:"
                   "            pass"
                   "        super().datagram_received(data, addr)"
                   "        try:"
                   "            self.take(raw, 'handshake')"
                   "        except Exception:"
                   "            pass"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.2)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s acks=%s bad=%s' % (client._status, body, client._terminated, client._acks, client._bad))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ack-order-test (port)
  "RFC 9000 §19.3.1. Each ACK range names progressively lower packet
numbers, and no computed packet number is negative. GET / is 200
pazuzu."
  (let ((script (quic-ack-order-script)))
    (check "a server ACK range stays non-negative and descends"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "bad=0" out)
                     (not (search "acks=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-pn-length-script ()
  "Decrypt server packets and record whether each packet number is long
enough for the unacknowledged range in its space."
  (let ((script "/tmp/pazuzu-h3-pn-length.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.logger import QuicLogger"
                   "from aioquic.quic.packet import pull_quic_header, QuicPacketType, QuicProtocolVersion"
                   "from aioquic.tls import Epoch"
                   ""
                   "def required_bytes(num_unacked):"
                   "    if num_unacked <= 0:"
                   "        return None"
                   "    base = num_unacked.bit_length()"
                   "    power = (num_unacked & (num_unacked - 1)) == 0"
                   "    if power or (base % 8) != 0:"
                   "        return (base + 7) // 8"
                   "    return (base // 8) + 1"
                   ""
                   "def score_one(pn_len, pn, largest):"
                   "    if pn_len < 1 or pn_len > 4 or pn < 0:"
                   "        return 1"
                   "    if largest is None:"
                   "        if pn >> (8 * pn_len):"
                   "            return 1"
                   "        num_unacked = pn + 1"
                   "    else:"
                   "        if pn <= largest:"
                   "            return 0"
                   "        num_unacked = pn - largest"
                   "    need = required_bytes(num_unacked)"
                   "    if need is None or pn_len < need:"
                   "        return 1"
                   "    return 0"
                   ""
                   "def packet_numbers(quic, data, want):"
                   "    found = []"
                   "    if not data:"
                   "        return found"
                   "    if want == '1rtt':"
                   "        if data[0] & 0x80:"
                   "            return found"
                   "        crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "        if crypto is None:"
                   "            return found"
                   "        space = quic._spaces[Epoch.ONE_RTT]"
                   "        buf = Buffer(data=data)"
                   "        start = buf.tell()"
                   "        pull_quic_header(buf, host_cid_length=quic._configuration.connection_id_length)"
                   "        encrypted_off = buf.tell() - start"
                   "        plain, _payload, number = crypto.decrypt_packet("
                   "            data, encrypted_off, space.expected_packet_number)"
                   "        found.append(((plain[0] & 0x03) + 1, number))"
                   "        return found"
                   "    if data[0] & 0x80 == 0:"
                   "        return found"
                   "    buf = Buffer(data=data)"
                   "    while not buf.eof():"
                   "        start = buf.tell()"
                   "        if data[start] & 0x80 == 0:"
                   "            break"
                   "        header = pull_quic_header(buf)"
                   "        end = start + header.packet_length"
                   "        crypto = None"
                   "        space = None"
                   "        if header.packet_type == QuicPacketType.INITIAL and want == 'initial':"
                   "            crypto = quic._cryptos_initial.get(QuicProtocolVersion.VERSION_1)"
                   "            space = quic._spaces[Epoch.INITIAL]"
                   "        elif header.packet_type == QuicPacketType.HANDSHAKE and want == 'handshake':"
                   "            crypto = quic._cryptos.get(Epoch.HANDSHAKE)"
                   "            space = quic._spaces[Epoch.HANDSHAKE]"
                   "        if crypto is not None and space is not None:"
                   "            encrypted_off = buf.tell() - start"
                   "            plain, _payload, number = crypto.decrypt_packet("
                   "                data[start:end], encrypted_off, space.expected_packet_number)"
                   "            found.append(((plain[0] & 0x03) + 1, number))"
                   "        if end <= start or end > len(data):"
                   "            break"
                   "        buf.seek(end)"
                   "    return found"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._packets = 0"
                   "        self._pre = 0"
                   "        self._bad = 0"
                   "        self._largest = {'initial': None, 'handshake': None, '1rtt': None}"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def refresh_largest(self):"
                   "        trace = self._quic._quic_logger"
                   "        largest = {'initial': None, 'handshake': None, '1rtt': None}"
                   "        if trace is not None:"
                   "            for event in trace._events:"
                   "                if event.get('name') != 'transport:packet_sent':"
                   "                    continue"
                   "                data = event.get('data') or {}"
                   "                kind = (data.get('header') or {}).get('packet_type')"
                   "                space = {'initial': 'initial', 'handshake': 'handshake', '1RTT': '1rtt'}.get(kind)"
                   "                if space is None:"
                   "                    continue"
                   "                for frame in data.get('frames') or []:"
                   "                    if frame.get('frame_type') != 'ack':"
                   "                        continue"
                   "                    for pair in frame.get('acked_ranges') or []:"
                   "                        stop = pair[1]"
                   "                        cur = largest[space]"
                   "                        if cur is None or stop > cur:"
                   "                            largest[space] = stop"
                   "        self._largest = largest"
                   ""
                   "    def take(self, data, want):"
                   "        largest = self._largest.get(want)"
                   "        n = 0"
                   "        for pn_len, number in packet_numbers(self._quic, data, want):"
                   "            n += 1"
                   "            self._packets += 1"
                   "            if largest is None:"
                   "                self._pre += 1"
                   "            self._bad += score_one(pn_len, number, largest)"
                   "        return n"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self.refresh_largest()"
                   "        raw = bytes(data)"
                   "        try:"
                   "            self.take(raw, 'initial')"
                   "        except Exception:"
                   "            pass"
                   "        before = 0"
                   "        try:"
                   "            before = self.take(raw, '1rtt')"
                   "        except Exception:"
                   "            before = 0"
                   "        super().datagram_received(data, addr)"
                   "        try:"
                   "            self.take(raw, 'handshake')"
                   "        except Exception:"
                   "            pass"
                   "        if before == 0:"
                   "            try:"
                   "                self.take(raw, '1rtt')"
                   "            except Exception:"
                   "                pass"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._sid:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == self._sid:"
                   "                self._body += http_event.data"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        quic_logger=QuicLogger(),"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._sid = stream_id"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(50):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.2)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s packets=%s pre=%s bad=%s' % (client._status, body, client._terminated, client._packets, client._pre, client._bad))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

