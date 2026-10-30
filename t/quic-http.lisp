;;; Remaining QUIC and HTTP/3 frame checks.

(in-package #:pazuzu/tests)

(defun quic-pn-length-test (port)
  "RFC 9000 §17.1. Before a packet number space is acknowledged, each
server packet includes its full packet number. After an acknowledgement,
the encoding is wide enough for more than twice the unacknowledged
range. GET / is 200 pazuzu."
  (let ((script (quic-pn-length-script)))
    (check "a server packet number is wide enough for its gap"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "bad=0" out)
                     (not (search "packets=0" out))
                     (not (search "pre=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-response-ric-script ()
  "Record the QPACK Required Insert Count on each HEADERS frame of the
response to GET /."
  (let ((script "/tmp/pazuzu-h3-response-ric.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "original_settings = H3Connection._get_local_settings"
                   "def zero_capacity(self):"
                   "    settings = original_settings(self)"
                   "    settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0"
                   "    return settings"
                   "H3Connection._get_local_settings = zero_capacity"
                   ""
                   "def header_counts(blob):"
                   "    buf = Buffer(data=blob)"
                   "    headers = 0"
                   "    nonzero = 0"
                   "    while not buf.eof():"
                   "        try:"
                   "            frame_type = buf.pull_uint_var()"
                   "            length = buf.pull_uint_var()"
                   "            if buf.tell() + length > len(blob):"
                   "                break"
                   "            payload = buf.pull_bytes(length)"
                   "        except Exception:"
                   "            break"
                   "        if frame_type == 0x01 and payload:"
                   "            headers += 1"
                   "            if Buffer(data=payload).pull_uint_var() != 0:"
                   "                nonzero += 1"
                   "    return headers, nonzero"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._blob = b''"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and event.stream_id == self._sid:"
                   "            self._blob += bytes(event.data)"
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
                   "            headers, nonzero = header_counts(client._blob)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s headers=%s nonzero=%s' % (client._status, body, client._terminated, headers, nonzero))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun h3-response-ric-test (port)
  "RFC 9204 §§2.1.2 and 3.2.3. The client allows no dynamic table, so
the response field section cannot reference one and its Required Insert
Count is zero. GET / is 200 pazuzu."
  (let ((script (h3-response-ric-script)))
    (check "a response field section has a required insert count of zero"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None " out)
                     (search "nonzero=0" out)
                     (not (search "headers=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun h3-response-base-script ()
  "Record the QPACK Sign bit on each HEADERS frame of the response to
GET /. The client allows no dynamic table."
  (let ((script "/tmp/pazuzu-h3-response-base.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "original_settings = H3Connection._get_local_settings"
                   "def zero_capacity(self):"
                   "    settings = original_settings(self)"
                   "    settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0"
                   "    return settings"
                   "H3Connection._get_local_settings = zero_capacity"
                   ""
                   "def pull_prefixed(buf, nbits):"
                   "    limit = (1 << nbits) - 1"
                   "    first = buf.pull_uint8()"
                   "    value = first & limit"
                   "    if value < limit:"
                   "        return first, value"
                   "    shift = 0"
                   "    while True:"
                   "        byte = buf.pull_uint8()"
                   "        value += (byte & 0x7f) << shift"
                   "        shift += 7"
                   "        if (byte & 0x80) == 0:"
                   "            return first, value"
                   "        if shift > 62:"
                   "            raise ValueError('wide')"
                   ""
                   "def base_counts(blob):"
                   "    buf = Buffer(data=blob)"
                   "    headers = 0"
                   "    negative = 0"
                   "    enc = -1"
                   "    sign = -1"
                   "    while not buf.eof():"
                   "        try:"
                   "            frame_type = buf.pull_uint_var()"
                   "            length = buf.pull_uint_var()"
                   "            if buf.tell() + length > len(blob):"
                   "                break"
                   "            payload = buf.pull_bytes(length)"
                   "        except Exception:"
                   "            break"
                   "        if frame_type != 0x01 or not payload:"
                   "            continue"
                   "        headers += 1"
                   "        try:"
                   "            field = Buffer(data=payload)"
                   "            _enc_byte, enc_value = pull_prefixed(field, 8)"
                   "            sign_byte, _delta = pull_prefixed(field, 7)"
                   "        except Exception:"
                   "            negative += 1"
                   "            continue"
                   "        if enc < 0:"
                   "            enc = enc_value"
                   "            sign = (sign_byte >> 7) & 1"
                   "        if ((sign_byte >> 7) & 1) == 1:"
                   "            negative += 1"
                   "    return headers, negative, enc, sign"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._blob = b''"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and event.stream_id == self._sid:"
                   "            self._blob += bytes(event.data)"
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
                   "            headers, negative, enc, sign = base_counts(client._blob)"
                   "            body = client._body.decode('ascii', 'replace')"
                   "            print('RESULT status=%s body=%s closed=%s headers=%s negative=%s enc=%s sign=%s' % (client._status, body, client._terminated, headers, negative, enc, sign))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun h3-response-base-test (port)
  "RFC 9204 §4.5.1.2. The QPACK base is not negative. The client allows
no dynamic table, so the required insert count is zero and a set sign
bit would make that base negative. GET / is 200 pazuzu, and every
HEADERS frame leaves the sign bit clear."
  (let ((script (h3-response-base-script)))
    (check "a response field section does not encode a negative base"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None " out)
                     (search "negative=0" out)
                     (search "sign=0" out)
                     (not (search "headers=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-flow-credit-script ()
  "POST more than the initial stream window. The client sends no blocked
frame. The server still raises MAX_STREAM_DATA and echoes the body."
  (let ((script "/tmp/pazuzu-h3-flow-credit.py"))
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
                   "SIZE = 256 * 1024 + 2048"
                   "INITIAL = 256 * 1024"
                   ""
                   "def stream_limits(payload, sid):"
                   "    buf = Buffer(data=payload)"
                   "    best = None"
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
                   "        if frame_type == 0x11:"
                   "            stream_id = buf.pull_uint_var()"
                   "            limit = buf.pull_uint_var()"
                   "            if stream_id == sid and (best is None or limit > best):"
                   "                best = limit"
                   "            continue"
                   "        if frame_type == 0x15:"
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
                   "        if frame_type == 0x30:"
                   "            break"
                   "        if frame_type == 0x31:"
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
                   "    return best"
                   ""
                   "def datagram_limit(quic, data, sid):"
                   "    crypto = quic._cryptos.get(Epoch.ONE_RTT)"
                   "    if crypto is None or sid is None or not data or (data[0] & 0x80):"
                   "        return None"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    buf = Buffer(data=data)"
                   "    cid_len = quic._configuration.connection_id_length"
                   "    start = buf.tell()"
                   "    pull_quic_header(buf, host_cid_length=cid_len)"
                   "    encrypted_off = buf.tell() - start"
                   "    _header, payload, _number = crypto.decrypt_packet("
                   "        data, encrypted_off, space.expected_packet_number)"
                   "    return stream_limits(payload, sid)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._payload = b'q' * SIZE"
                   "        self._got = 0"
                   "        self._match = True"
                   "        self._status = None"
                   "        self._terminated = None"
                   "        self._blocked = 0"
                   "        self._limit = None"
                   "        original = self._quic._write_application"
                   "        def wrapped(builder, network_path, now, _orig=original):"
                   "            real = builder.start_frame"
                   "            def start_frame(frame_type, capacity=1, handler=None, handler_args=[]):"
                   "                if frame_type in (0x14, 0x15):"
                   "                    self._blocked += 1"
                   "                return real(frame_type, capacity=capacity, handler=handler, handler_args=handler_args)"
                   "            builder.start_frame = start_frame"
                   "            _orig(builder, network_path, now)"
                   "        self._quic._write_application = wrapped"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        try:"
                   "            limit = datagram_limit(self._quic, bytes(data), self._sid)"
                   "        except Exception:"
                   "            limit = None"
                   "        if limit is not None and (self._limit is None or limit > self._limit):"
                   "            self._limit = limit"
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
                   "                data = http_event.data"
                   "                expect = self._payload[self._got:self._got + len(data)]"
                   "                if data != expect:"
                   "                    self._match = False"
                   "                self._got += len(data)"
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
                   "                (b':method', b'POST'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/echo'),"
                   "            ], end_stream=False)"
                   "            client._http.send_data(stream_id, client._payload, end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(80):"
                   "                if client._got == SIZE or client._terminated is not None:"
                   "                    break"
                   "                client.transmit()"
                   "                await asyncio.sleep(0.05)"
                   "            raised = client._limit is not None and client._limit > INITIAL"
                   "            print('RESULT status=%s match=%s length=%s closed=%s blocked=%s raised=%s limit=%s' % (client._status, client._match, client._got, client._terminated, client._blocked, raised, client._limit))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-flow-credit-test (port)
  "RFC 9000 §4.2. A receiver does not wait for STREAM_DATA_BLOCKED or
DATA_BLOCKED before sending more flow-control credit. The client posts
256 KiB plus 2048 bytes to /echo and sends neither blocked frame. The
server raises the stream limit and the body comes back unchanged."
  (let ((script (quic-flow-credit-script)))
    (check "flow control credit is sent without a blocked frame"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 match=True length=264192 closed=None blocked=0 raised=True " out)
                     (not (search "limit=None" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-handshake-frame-script ()
  "Client that adds one frame to a Handshake packet during the handshake.
PING is permitted. STREAM is not."
  (let ((script "/tmp/pazuzu-h3-hs-frame.py"))
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
                   "def build_handshake(quic, stream):"
                   "    crypto = quic._cryptos[Epoch.HANDSHAKE]"
                   "    dcid = quic._peer_cid.cid"
                   "    scid = quic.host_cid"
                   "    pn = 0"
                   "    if stream:"
                   "        payload = bytes([0x08, 0x00]) + b'A' * 32"
                   "    else:"
                   "        payload = bytes([0x01]) + bytes(32)"
                   "    first = encode_long_header_first_byte(QuicProtocolVersion.VERSION_1, QuicPacketType.HANDSHAKE, 1)"
                   "    prefix = bytes([first]) + (1).to_bytes(4, 'big') + bytes([len(dcid)]) + dcid"
                   "    prefix += bytes([len(scid)]) + scid"
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
                   "        self._stream = False"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._build_error = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._quic.receive_datagram(data, addr, now=self._loop.time())"
                   "        self._process_events()"
                   "        quic = self._quic"
                   "        if (not self._sent) and quic._cryptos[Epoch.HANDSHAKE].send.is_valid():"
                   "            try:"
                   "                packet = build_handshake(quic, self._stream)"
                   "                self._transport.sendto(packet, addr)"
                   "                self._sent = True"
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
                   "async def once(port, stream):"
                   "    label = 'STREAM' if stream else 'PING'"
                   "    def create(connection, stream_handler=None):"
                   "        client = Client(connection, stream_handler=stream_handler)"
                   "        client._stream = stream"
                   "        return client"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=create, wait_connected=False) as client:"
                   "        client.transmit()"
                   "        if stream:"
                   "            for _ in range(40):"
                   "                if client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.3)"
                   "        else:"
                   "            await asyncio.wait_for(client.wait_connected(), 3)"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "        body = client._body.decode('ascii', 'replace') or '-'"
                   "        print('RESULT %s status=%s body=%s closed=%s sent=%s err=%s' % (label, client._status, body, client._terminated, client._sent, client._build_error))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    try:"
                   "        await once(port, False)"
                   "        await once(port, True)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-handshake-frame-test (port)
  "RFC 9000 §17.2.4. A Handshake packet may carry CRYPTO, ACK, PING, and
PADDING. Any other frame is PROTOCOL_VIOLATION (0x0a). A PING leaves the
connection able to serve GET /. A STREAM frame closes it."
  (let ((script (quic-handshake-frame-script)))
    (check "a Handshake packet with a STREAM frame is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT PING status=200 body=pazuzu closed=None sent=True err=None" out)
                     (search "RESULT STREAM status=None body=- closed=10 sent=True err=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-coalesced-script ()
  "Client that sends two Handshake packets in one datagram.
Both are PINGs, or the second is a STREAM frame."
  (let ((script "/tmp/pazuzu-h3-coalesced.py"))
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
                   "def build_packet(quic, payload, pn):"
                   "    crypto = quic._cryptos[Epoch.HANDSHAKE]"
                   "    dcid = quic._peer_cid.cid"
                   "    scid = quic.host_cid"
                   "    first = encode_long_header_first_byte(QuicProtocolVersion.VERSION_1, QuicPacketType.HANDSHAKE, 1)"
                   "    prefix = bytes([first]) + (1).to_bytes(4, 'big') + bytes([len(dcid)]) + dcid"
                   "    prefix += bytes([len(scid)]) + scid"
                   "    length = 2 + len(payload) + 16"
                   "    header = prefix + (length | 0x4000).to_bytes(2, 'big') + pn.to_bytes(2, 'big')"
                   "    return crypto.encrypt_packet(header, payload, pn)"
                   ""
                   "def build_datagram(quic, stream):"
                   "    ping = bytes([0x01]) + bytes(32)"
                   "    if stream:"
                   "        second = bytes([0x08, 0x00]) + b'A' * 32"
                   "    else:"
                   "        second = bytes([0x01]) + bytes(32)"
                   "    return build_packet(quic, ping, 0) + build_packet(quic, second, 1)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._sent = False"
                   "        self._stream = False"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._build_error = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._quic.receive_datagram(data, addr, now=self._loop.time())"
                   "        self._process_events()"
                   "        quic = self._quic"
                   "        if (not self._sent) and quic._cryptos[Epoch.HANDSHAKE].send.is_valid():"
                   "            try:"
                   "                packet = build_datagram(quic, self._stream)"
                   "                self._transport.sendto(packet, addr)"
                   "                self._sent = True"
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
                   "async def once(port, stream):"
                   "    label = 'STREAM' if stream else 'PINGS'"
                   "    def create(connection, stream_handler=None):"
                   "        client = Client(connection, stream_handler=stream_handler)"
                   "        client._stream = stream"
                   "        return client"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=create, wait_connected=False) as client:"
                   "        client.transmit()"
                   "        if stream:"
                   "            for _ in range(40):"
                   "                if client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.3)"
                   "        else:"
                   "            await asyncio.wait_for(client.wait_connected(), 3)"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "        body = client._body.decode('ascii', 'replace') or '-'"
                   "        print('RESULT %s status=%s body=%s closed=%s sent=%s err=%s' % (label, client._status, body, client._terminated, client._sent, client._build_error))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    try:"
                   "        await once(port, False)"
                   "        await once(port, True)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-coalesced-test (port)
  "RFC 9000 §12.2. Each coalesced packet is processed on its own.
Two Handshake PINGs in one datagram still serve GET /. A STREAM frame
in the second packet is PROTOCOL_VIOLATION (0x0a)."
  (let ((script (quic-coalesced-script)))
    (check "each coalesced packet is processed"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT PINGS status=200 body=pazuzu closed=None sent=True err=None" out)
                     (search "RESULT STREAM status=None body=- closed=10 sent=True err=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-coalesced-discard-script ()
  "Client that coalesces a Handshake packet whose tag is corrupt with
a second Handshake packet."
  (let ((script "/tmp/pazuzu-h3-coalesced-discard.py"))
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
                   "def build_packet(quic, payload, pn):"
                   "    crypto = quic._cryptos[Epoch.HANDSHAKE]"
                   "    dcid = quic._peer_cid.cid"
                   "    scid = quic.host_cid"
                   "    first = encode_long_header_first_byte(QuicProtocolVersion.VERSION_1, QuicPacketType.HANDSHAKE, 1)"
                   "    prefix = bytes([first]) + (1).to_bytes(4, 'big') + bytes([len(dcid)]) + dcid"
                   "    prefix += bytes([len(scid)]) + scid"
                   "    length = 2 + len(payload) + 16"
                   "    header = prefix + (length | 0x4000).to_bytes(2, 'big') + pn.to_bytes(2, 'big')"
                   "    return crypto.encrypt_packet(header, payload, pn)"
                   ""
                   "def build_datagram(quic, stream):"
                   "    ping = bytes([0x01]) + bytes(32)"
                   "    if stream:"
                   "        second = bytes([0x08, 0x00]) + b'A' * 32"
                   "    else:"
                   "        second = bytes([0x01]) + bytes(32)"
                   "    first = bytearray(build_packet(quic, ping, 0))"
                   "    first[-1] ^= 0xff"
                   "    return bytes(first) + build_packet(quic, second, 1)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._sent = False"
                   "        self._stream = False"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._build_error = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._quic.receive_datagram(data, addr, now=self._loop.time())"
                   "        self._process_events()"
                   "        quic = self._quic"
                   "        if (not self._sent) and quic._cryptos[Epoch.HANDSHAKE].send.is_valid():"
                   "            try:"
                   "                packet = build_datagram(quic, self._stream)"
                   "                self._transport.sendto(packet, addr)"
                   "                self._sent = True"
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
                   "async def once(port, stream):"
                   "    label = 'STREAM' if stream else 'PINGS'"
                   "    def create(connection, stream_handler=None):"
                   "        client = Client(connection, stream_handler=stream_handler)"
                   "        client._stream = stream"
                   "        return client"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=create, wait_connected=False) as client:"
                   "        client.transmit()"
                   "        if stream:"
                   "            for _ in range(40):"
                   "                if client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.3)"
                   "        else:"
                   "            await asyncio.wait_for(client.wait_connected(), 3)"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "        body = client._body.decode('ascii', 'replace') or '-'"
                   "        print('RESULT %s status=%s body=%s closed=%s sent=%s err=%s' % (label, client._status, body, client._terminated, client._sent, client._build_error))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    try:"
                   "        await once(port, False)"
                   "        await once(port, True)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-coalesced-discard-test (port)
  "RFC 9000 §12.2. When decryption of a coalesced packet fails, the
receiver still processes the packets after it. A corrupt Handshake
packet followed by a PING leaves GET / working. The same prefix
followed by a STREAM frame is PROTOCOL_VIOLATION (0x0a)."
  (let ((script (quic-coalesced-discard-script)))
    (check "a discarded coalesced packet does not hide the next packet"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT PINGS status=200 body=pazuzu closed=None sent=True err=None" out)
                     (search "RESULT STREAM status=None body=- closed=10 sent=True err=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-undersized-packet-script ()
  "Client that sends a 20-byte short header carrying this connection's
Destination Connection ID, then GET /."
  (let ((script "/tmp/pazuzu-h3-undersize.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._watch = False"
                   "        self._seen = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        if self._watch:"
                   "            self._seen += 1"
                   "        super().datagram_received(data, addr)"
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
                   "def send_short(client):"
                   "    quic = client._quic"
                   "    dcid = quic._peer_cid.cid"
                   "    packet = bytes([0x40]) + dcid + b'\\x00'"
                   "    if len(packet) >= 21:"
                   "        raise RuntimeError('packet %s' % len(packet))"
                   "    client._transport.sendto(packet, quic._network_paths[0].addr)"
                   "    return len(packet)"
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
                   "            await asyncio.sleep(0.2)"
                   "            client._seen = 0"
                   "            client._watch = True"
                   "            nbytes = send_short(client)"
                   "            await asyncio.sleep(0.4)"
                   "            replies = client._seen"
                   "            client._watch = False"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT bytes=%s replies=%s status=%s body=%s closed=%s' % (nbytes, replies, client._status, body, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-undersized-packet-test (port)
  "RFC 9000 §10.3. A short header smaller than 21 bytes is not a valid
QUIC packet. One that carries this connection's Destination Connection
ID is discarded: it draws no reply and does not close the connection.
GET / still returns pazuzu."
  (let ((script (quic-undersized-packet-script)))
    (check "a short header packet smaller than 21 bytes is discarded"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT " out)
                     (search "bytes=20 " out)
                     (search "replies=0 " out)
                     (search "status=200 " out)
                     (search "body=pazuzu " out)
                     (search "closed=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-size-constraint-script ()
  "Client that sends a 200-byte Initial on a live connection, then GET /."
  (let ((script "/tmp/pazuzu-h3-size.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._watch = False"
                   "        self._seen = 0"
                   "        self._status = None"
                   "        self._body = b''"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        if self._watch:"
                   "            self._seen += 1"
                   "        super().datagram_received(data, addr)"
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
                   "def send_short_initial(client):"
                   "    quic = client._quic"
                   "    dcid = quic._peer_cid.cid"
                   "    header = bytes([0xC0, 0, 0, 0, 1, len(dcid)]) + dcid + bytes([8]) + bytes(8) + bytes([0])"
                   "    packet = header + bytes(200 - len(header))"
                   "    if len(packet) != 200 or len(header) >= 200:"
                   "        raise RuntimeError('packet %s' % len(packet))"
                   "    client._transport.sendto(packet, quic._network_paths[0].addr)"
                   "    return len(packet)"
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
                   "            await asyncio.sleep(0.2)"
                   "            client._seen = 0"
                   "            client._watch = True"
                   "            nbytes = send_short_initial(client)"
                   "            await asyncio.sleep(0.4)"
                   "            replies = client._seen"
                   "            client._watch = False"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT bytes=%s replies=%s status=%s body=%s closed=%s' % (nbytes, replies, client._status, body, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-size-constraint-test (port)
  "RFC 9000 §14. A datagram that does not meet a size constraint is not a
reason to close the connection. A 200-byte Initial on a live connection
draws no reply. GET / still returns pazuzu."
  (let ((script (quic-size-constraint-script)))
    (check "an undersized Initial does not close the connection"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT " out)
                     (search "bytes=200 " out)
                     (search "replies=0 " out)
                     (search "status=200 " out)
                     (search "body=pazuzu " out)
                     (search "closed=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-server-dcid-script ()
  "Client that records the Destination Connection ID on every server packet."
  (let ((script "/tmp/pazuzu-h3-dcid.py"))
    (write-lines script
                 '("import asyncio, binascii, ssl, sys"
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
                   "        self._body = b''"
                   "        self._status = None"
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
                   "def cid_report(trace, host):"
                   "    kinds = []"
                   "    ok = True"
                   "    dropped = 0"
                   "    seen = 0"
                   "    for event in trace._events:"
                   "        name = event['name']"
                   "        data = event.get('data') or {}"
                   "        if name == 'transport:packet_dropped' and data.get('trigger') == 'unknown_connection_id':"
                   "            dropped += 1"
                   "        if name != 'transport:packet_received':"
                   "            continue"
                   "        header = data.get('header') or {}"
                   "        kind = header.get('packet_type')"
                   "        if kind:"
                   "            kinds.append(kind)"
                   "        seen += 1"
                   "        if header.get('dcid') != host:"
                   "            ok = False"
                   "    return ok, dropped, seen, sorted(set(kinds))"
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
                   "            host = binascii.hexlify(client._quic.host_cid).decode('ascii')"
                   "            ok, dropped, seen, kinds = cid_report(client._quic._quic_logger, host)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s dcid_ok=%s dropped=%s seen=%s kinds=%s' % (client._status, body, client._terminated, ok, dropped, seen, ','.join(kinds) or '-'))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-server-dcid-test (port)
  "RFC 9000 §7.2. The server sets the Destination Connection ID of every
packet it sends from the Source Connection ID of the client's first
Initial. A mismatched value is not a packet for this connection. GET /
still returns pazuzu."
  (let ((script (quic-server-dcid-script)))
    (check "server packets use the client's first Source Connection ID"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "dcid_ok=True" out)
                     (search "dropped=0 " out)
                     (not (search "seen=0 " out))
                     (search "kinds=" out)
                     (search "retry" out)
                     (search "initial" out)
                     (search "handshake" out)
                     (search "1RTT" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-coalesced-cid-script ()
  "Client that checks connection IDs inside each coalesced server datagram."
  (let ((script "/tmp/pazuzu-h3-coalcid.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "def read_varint(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    size = 1 << (data[index] >> 6)"
                   "    if index + size > len(data):"
                   "        return None"
                   "    raw = 0"
                   "    for offset in range(size):"
                   "        raw = (raw << 8) | data[index + offset]"
                   "    return raw & ((1 << (8 * size - 2)) - 1), index + size"
                   ""
                   "def packet_cids(data, start):"
                   "    if start + 7 > len(data) or not (data[start] & 0x80):"
                   "        return None"
                   "    kind = (data[start] >> 4) & 3"
                   "    if kind == 3:"
                   "        return None"
                   "    dcid_len = data[start + 5]"
                   "    index = start + 6 + dcid_len"
                   "    if index >= len(data):"
                   "        return None"
                   "    scid_len = data[index]"
                   "    scid_end = index + 1 + scid_len"
                   "    if scid_end > len(data):"
                   "        return None"
                   "    dcid = bytes(data[start + 6:start + 6 + dcid_len])"
                   "    scid = bytes(data[index + 1:scid_end])"
                   "    index = scid_end"
                   "    if kind == 0:"
                   "        token = read_varint(data, index)"
                   "        if token is None:"
                   "            return None"
                   "        token_len, index = token"
                   "        if index + token_len > len(data):"
                   "            return None"
                   "        index += token_len"
                   "    payload = read_varint(data, index)"
                   "    if payload is None:"
                   "        return None"
                   "    payload_len, index = payload"
                   "    end = index + payload_len"
                   "    if end > len(data):"
                   "        return None"
                   "    return dcid, scid, end"
                   ""
                   "def coalesced_cids(data):"
                   "    if not data or not (data[0] & 0x80):"
                   "        return True, 0"
                   "    found = []"
                   "    start = 0"
                   "    while start < len(data) and (data[start] & 0x80):"
                   "        parsed = packet_cids(data, start)"
                   "        if parsed is None:"
                   "            break"
                   "        dcid, scid, end = parsed"
                   "        if end <= start:"
                   "            break"
                   "        found.append((dcid, scid))"
                   "        if end >= len(data) or not (data[end] & 0x80):"
                   "            break"
                   "        start = end"
                   "    if len(found) < 2:"
                   "        return True, 0"
                   "    first = found[0]"
                   "    return all(item == first for item in found), len(found)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._body = b''"
                   "        self._status = None"
                   "        self._terminated = None"
                   "        self._coalesced = 0"
                   "        self._mismatch = 0"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        same, count = coalesced_cids(data)"
                   "        if count:"
                   "            self._coalesced += 1"
                   "            if not same:"
                   "                self._mismatch += 1"
                   "        super().datagram_received(data, addr)"
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
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s coalesced=%s mismatch=%s' % (client._status, body, client._terminated, client._coalesced, client._mismatch))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-coalesced-cid-test (port)
  "RFC 9000 §12.2. A sender does not coalesce QUIC packets that use
different connection IDs into one UDP datagram. Every coalesced server
datagram carries one Destination Connection ID and one Source Connection
ID, and GET / still returns pazuzu."
  (let ((script (quic-coalesced-cid-script)))
    (check "coalesced packets share one connection ID"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "mismatch=0" out)
                     (not (search "coalesced=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-cid-length-script ()
  "Client that records Destination and Source Connection ID lengths on
server long-header packets."
  (let ((script "/tmp/pazuzu-h3-cid-len.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "def read_varint(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    size = 1 << (data[index] >> 6)"
                   "    if index + size > len(data):"
                   "        return None"
                   "    raw = 0"
                   "    for offset in range(size):"
                   "        raw = (raw << 8) | data[index + offset]"
                   "    return raw & ((1 << (8 * size - 2)) - 1), index + size"
                   ""
                   "def score_datagram(data):"
                   "    long_n = 0"
                   "    bad = 0"
                   "    start = 0"
                   "    while start + 7 <= len(data) and (data[start] & 0x80):"
                   "        version = int.from_bytes(data[start + 1:start + 5], 'big')"
                   "        dcid_len = data[start + 5]"
                   "        pos = start + 6 + dcid_len"
                   "        if pos >= len(data):"
                   "            if version != 0 and dcid_len > 20:"
                   "                bad += 1"
                   "            break"
                   "        scid_len = data[pos]"
                   "        scid_end = pos + 1 + scid_len"
                   "        if version != 0 and (dcid_len > 20 or scid_len > 20):"
                   "            bad += 1"
                   "        if scid_end > len(data) or version == 0 or not (data[start] & 0x40):"
                   "            break"
                   "        kind = (data[start] >> 4) & 3"
                   "        if kind == 3:"
                   "            long_n += 1"
                   "            break"
                   "        index = scid_end"
                   "        if kind == 0:"
                   "            token = read_varint(data, index)"
                   "            if token is None:"
                   "                break"
                   "            token_len, index = token"
                   "            if index + token_len > len(data):"
                   "                break"
                   "            index += token_len"
                   "        payload = read_varint(data, index)"
                   "        if payload is None:"
                   "            break"
                   "        payload_len, index = payload"
                   "        end = index + payload_len"
                   "        if end > len(data) or end <= start:"
                   "            break"
                   "        long_n += 1"
                   "        if end >= len(data) or not (data[end] & 0x80):"
                   "            break"
                   "        start = end"
                   "    return long_n, bad"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._body = b''"
                   "        self._status = None"
                   "        self._terminated = None"
                   "        self._long = 0"
                   "        self._bad = 0"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        long_n, bad = score_datagram(data)"
                   "        self._long += long_n"
                   "        self._bad += bad"
                   "        super().datagram_received(data, addr)"
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
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s long=%s bad=%s' % (client._status, body, client._terminated, client._long, client._bad))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-cid-length-test (port)
  "RFC 9000 §17.2. A version 1 long header encodes a Destination
Connection ID length and a Source Connection ID length, and neither
value exceeds 20. GET / still returns pazuzu."
  (let ((script (quic-cid-length-script)))
    (check "a server connection ID length stays within 20 bytes"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "bad=0" out)
                     (not (search "long=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-fixed-bit-send-script ()
  "Client that checks the fixed bit on server long headers and on
datagrams that begin with a short header."
  (let ((script "/tmp/pazuzu-h3-fixed-send.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "def read_varint(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    size = 1 << (data[index] >> 6)"
                   "    if index + size > len(data):"
                   "        return None"
                   "    raw = 0"
                   "    for offset in range(size):"
                   "        raw = (raw << 8) | data[index + offset]"
                   "    return raw & ((1 << (8 * size - 2)) - 1), index + size"
                   ""
                   "def score_datagram(data):"
                   "    long_n = 0"
                   "    short_n = 0"
                   "    bad = 0"
                   "    if not data:"
                   "        return long_n, short_n, bad"
                   "    if data[0] & 0x80 == 0:"
                   "        if data[0] & 0x40:"
                   "            short_n += 1"
                   "        else:"
                   "            bad += 1"
                   "        return long_n, short_n, bad"
                   "    start = 0"
                   "    while start + 7 <= len(data) and (data[start] & 0x80):"
                   "        version = int.from_bytes(data[start + 1:start + 5], 'big')"
                   "        if version == 0:"
                   "            break"
                   "        dcid_len = data[start + 5]"
                   "        if dcid_len > 20:"
                   "            break"
                   "        pos = start + 6 + dcid_len"
                   "        if pos >= len(data):"
                   "            break"
                   "        scid_len = data[pos]"
                   "        if scid_len > 20:"
                   "            break"
                   "        scid_end = pos + 1 + scid_len"
                   "        if scid_end > len(data):"
                   "            break"
                   "        if data[start] & 0x40 == 0:"
                   "            bad += 1"
                   "            break"
                   "        kind = (data[start] >> 4) & 3"
                   "        if kind == 3:"
                   "            long_n += 1"
                   "            break"
                   "        index = scid_end"
                   "        if kind == 0:"
                   "            token = read_varint(data, index)"
                   "            if token is None:"
                   "                break"
                   "            token_len, index = token"
                   "            if index + token_len > len(data):"
                   "                break"
                   "            index += token_len"
                   "        payload = read_varint(data, index)"
                   "        if payload is None:"
                   "            break"
                   "        payload_len, index = payload"
                   "        end = index + payload_len"
                   "        if end > len(data) or end <= start:"
                   "            break"
                   "        long_n += 1"
                   "        if end >= len(data) or not (data[end] & 0x80):"
                   "            break"
                   "        start = end"
                   "    return long_n, short_n, bad"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._body = b''"
                   "        self._status = None"
                   "        self._terminated = None"
                   "        self._long = 0"
                   "        self._short = 0"
                   "        self._bad = 0"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        long_n, short_n, bad = score_datagram(bytes(data))"
                   "        self._long += long_n"
                   "        self._short += short_n"
                   "        self._bad += bad"
                   "        super().datagram_received(data, addr)"
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
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s long=%s short=%s bad=%s' % (client._status, body, client._terminated, client._long, client._short, client._bad))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-fixed-bit-send-test (port)
  "RFC 9000 §§17.2 and 17.3. A version 1 packet sets the fixed bit.
Version Negotiation is excluded. GET / still returns pazuzu."
  (let ((script (quic-fixed-bit-send-script)))
    (check "a server packet sets the fixed bit"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "bad=0" out)
                     (not (search "long=0" out))
                     (not (search "short=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ack-space-script ()
  "Client that checks each server ACK against the packet number space
of the packet that carries it."
  (let ((script "/tmp/pazuzu-h3-ackspace.py"))
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
                   "SPACES = ('initial', 'handshake', '1RTT')"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._body = b''"
                   "        self._status = None"
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
                   "def expand(ranges):"
                   "    nums = set()"
                   "    for start, end in ranges:"
                   "        if end < start or end - start > 10000:"
                   "            return None"
                   "        nums.update(range(start, end + 1))"
                   "    return nums"
                   ""
                   "def ack_report(trace):"
                   "    sent = {kind: set() for kind in SPACES}"
                   "    counts = {kind: 0 for kind in SPACES}"
                   "    ok = True"
                   "    events = list(trace._events)"
                   "    for event in events:"
                   "        if event['name'] != 'transport:packet_sent':"
                   "            continue"
                   "        header = (event.get('data') or {}).get('header') or {}"
                   "        kind = header.get('packet_type')"
                   "        number = header.get('packet_number')"
                   "        if kind in sent and number is not None:"
                   "            sent[kind].add(number)"
                   "    for event in events:"
                   "        if event['name'] != 'transport:packet_received':"
                   "            continue"
                   "        data = event.get('data') or {}"
                   "        header = data.get('header') or {}"
                   "        kind = header.get('packet_type')"
                   "        if kind not in sent:"
                   "            continue"
                   "        for frame in data.get('frames') or []:"
                   "            if frame.get('frame_type') != 'ack':"
                   "                continue"
                   "            counts[kind] += 1"
                   "            nums = expand(frame.get('acked_ranges') or [])"
                   "            if nums is None or not nums or not nums.issubset(sent[kind]):"
                   "                ok = False"
                   "    return ok, counts['initial'], counts['handshake'], counts['1RTT']"
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
                   "            await asyncio.sleep(0.2)"
                   "            ok, initial_acks, handshake_acks, onertt_acks = ack_report(client._quic._quic_logger)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s ack_ok=%s initial_acks=%s handshake_acks=%s onertt_acks=%s' % (client._status, body, client._terminated, ok, initial_acks, handshake_acks, onertt_acks))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ack-space-test (port)
  "RFC 9000 §13.2.6. An ACK frame is carried in the packet number space of
the packets it acknowledges. Initial acknowledgements stay in Initial
packets, Handshake acknowledgements stay in Handshake packets, and 1-RTT
acknowledgements stay in 1-RTT packets. GET / still returns pazuzu."
  (let ((script (quic-ack-space-script)))
    (check "an acknowledgement stays in its packet number space"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "ack_ok=True" out)
                     (not (search "initial_acks=0" out))
                     (not (search "handshake_acks=0" out))
                     (not (search "onertt_acks=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-app-space-script ()
  "Client that records which QUIC frames the server sends before 1-RTT."
  (let ((script "/tmp/pazuzu-h3-appspace.py"))
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
                   "EARLY = {'padding', 'ping', 'crypto', 'ack', 'connection_close'}"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._body = b''"
                   "        self._status = None"
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
                   "def space_report(trace):"
                   "    crypto = {'initial': 0, 'handshake': 0}"
                   "    streams = 0"
                   "    bad = []"
                   "    for event in trace._events:"
                   "        if event['name'] != 'transport:packet_received':"
                   "            continue"
                   "        data = event.get('data') or {}"
                   "        kind = (data.get('header') or {}).get('packet_type')"
                   "        for frame in data.get('frames') or []:"
                   "            name = frame.get('frame_type')"
                   "            if kind in crypto and name == 'crypto':"
                   "                crypto[kind] += 1"
                   "            if kind == '1RTT' and name == 'stream':"
                   "                streams += 1"
                   "            if kind in crypto and (name not in EARLY or (name == 'connection_close' and frame.get('error_space') == 'application')):"
                   "                bad.append('%s:%s' % (kind, name))"
                   "    return crypto['initial'], crypto['handshake'], streams, bad"
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
                   "            await asyncio.sleep(0.2)"
                   "            initial_crypto, handshake_crypto, streams, bad = space_report(client._quic._quic_logger)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s initial_crypto=%s handshake_crypto=%s streams=%s bad=%s' % (client._status, body, client._terminated, initial_crypto, handshake_crypto, streams, ','.join(bad) or '-'))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-app-space-test (port)
  "RFC 9000 §12.5. PADDING, PING, CRYPTO, ACK, and a transport
CONNECTION_CLOSE may appear before 1-RTT. Every other frame is sent
only in an application-data packet. GET / still returns pazuzu."
  (let ((script (quic-app-space-script)))
    (check "application frames are sent only in 1-RTT packets"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "bad=-" out)
                     (not (search "initial_crypto=0" out))
                     (not (search "handshake_crypto=0" out))
                     (not (search "streams=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-close-space-script ()
  "Client that finishes the handshake, then sends an unknown 1-RTT frame.
The server's CONNECTION_CLOSE is recorded with its packet type."
  (let ((script "/tmp/pazuzu-h3-closespace.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.logger import QuicLogger"
                   "from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "def arm_frame(quic):"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            builder.start_frame(0x20, capacity=1)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   "    return state"
                   ""
                   "def close_report(trace):"
                   "    early = 0"
                   "    onertt = 0"
                   "    codes = []"
                   "    spaces = []"
                   "    for event in list(trace._events):"
                   "        if event.get('name') != 'transport:packet_received':"
                   "            continue"
                   "        data = event.get('data') or {}"
                   "        kind = (data.get('header') or {}).get('packet_type')"
                   "        for frame in data.get('frames') or []:"
                   "            if frame.get('frame_type') != 'connection_close':"
                   "                continue"
                   "            spaces.append(kind or '-')"
                   "            codes.append(frame.get('error_code'))"
                   "            if kind == '1RTT':"
                   "                onertt += 1"
                   "            else:"
                   "                early += 1"
                   "    ok = early == 0 and onertt > 0 and bool(codes) and all(code == 7 for code in codes) and all(space == '1RTT' for space in spaces)"
                   "    return early, onertt, ok, ','.join(spaces) or '-'"
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
                   "            trace = client._quic._quic_logger"
                   "            state = arm_frame(client._quic)"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            try:"
                   "                code = await asyncio.wait_for(client._done, 3)"
                   "            except TimeoutError:"
                   "                code = client._terminated"
                   "            await asyncio.sleep(0.2)"
                   "            early, onertt, ok, spaces = close_report(trace)"
                   "            print('RESULT closed=%s sent=%s early=%s onertt=%s close_ok=%s spaces=%s' % (code, state['sent'], early, onertt, ok, spaces))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-close-space-test (port)
  "RFC 9000 §10.2.3. After the handshake is confirmed, a CONNECTION_CLOSE
is sent in a 1-RTT packet. An unknown frame after the handshake closes
with FRAME_ENCODING_ERROR (7), and that close is not carried in an
Initial or Handshake packet."
  (let ((script (quic-close-space-script)))
    (check "a confirmed handshake closes in a 1-RTT packet"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT closed=7 " out)
                     (search "sent=True" out)
                     (search "early=0 " out)
                     (search "close_ok=True" out)
                     (not (search "onertt=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-crypto-buffer-script ()
  "Client that, after Retry, sends 4096 bytes of Initial CRYPTO at an
offset past the ClientHello. The handshake must still finish."
  (let ((script "/tmp/pazuzu-h3-cryptobuf.py"))
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
                   "def varint(n):"
                   "    if n < 64:"
                   "        return bytes([n])"
                   "    if n < 16384:"
                   "        return (n | 0x4000).to_bytes(2, 'big')"
                   "    return (n | 0x80000000).to_bytes(4, 'big')"
                   ""
                   "def build_initial(quic, offset, data):"
                   "    crypto = quic._cryptos[Epoch.INITIAL]"
                   "    dcid = quic._peer_cid.cid"
                   "    scid = quic.host_cid"
                   "    token = quic._peer_token or b''"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    payload = bytes([0x06]) + varint(offset) + varint(len(data)) + data"
                   "    token_field = varint(len(token)) + token"
                   "    overhead = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + len(token_field) + 2 + 2 + 16"
                   "    pad = 1200 - overhead - len(payload)"
                   "    if pad > 0:"
                   "        payload += bytes(pad)"
                   "    first = encode_long_header_first_byte(QuicProtocolVersion.VERSION_1, QuicPacketType.INITIAL, 1)"
                   "    prefix = bytes([first]) + (1).to_bytes(4, 'big') + bytes([len(dcid)]) + dcid"
                   "    prefix += bytes([len(scid)]) + scid + token_field"
                   "    length = 2 + len(payload) + 16"
                   "    header = prefix + varint(length) + pn.to_bytes(2, 'big')"
                   "    return crypto.encrypt_packet(header, payload, pn)"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._sent = False"
                   "        self._build_error = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        super().datagram_received(data, addr)"
                   "        quic = self._quic"
                   "        if self._sent or not quic._retry_count:"
                   "            return"
                   "        if not quic._cryptos[Epoch.INITIAL].send.is_valid():"
                   "            return"
                   "        try:"
                   "            for offset in (12000, 13024, 14048, 15072):"
                   "                packet = build_initial(quic, offset, bytes(1024))"
                   "                self._transport.sendto(packet, addr)"
                   "            self._sent = True"
                   "        except Exception as exc:"
                   "            self._build_error = repr(exc)"
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
                   "            await asyncio.sleep(0.2)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s sent=%s err=%s offset=12000 chunks=4 bytes=4096' % (client._status, body, client._terminated, client._sent, client._build_error))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-crypto-buffer-test (port)
  "RFC 9000 §7.5. An endpoint buffers at least 4096 bytes of out-of-order
CRYPTO data. A 4096-byte Initial CRYPTO frame at offset 12000, past the
ClientHello, does not close the connection, and GET / still returns pazuzu."
  (let ((script (quic-crypto-buffer-script)))
    (check "out-of-order CRYPTO data is buffered"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "sent=True" out)
                     (search "offset=12000" out)
                     (search "chunks=4" out)
                     (search "bytes=4096" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-reorder-script ()
  "Client that places the tail of an HTTP/3 GET on a STREAM frame before
the bytes at offset zero."
  (let ((script "/tmp/pazuzu-h3-stream-reorder.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "def request_frame():"
                   "    authority = b'127.0.0.1'"
                   "    block = bytes([0, 0, 0xD1, 0xD7, 0xC1, 0x50, len(authority)]) + authority"
                   "    return bytes([0x01, len(block)]) + block"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._frame = None"
                   "        self._reason = None"
                   "        self._status = None"
                   "        self._body = b''"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            self._frame = event.frame_type"
                   "            self._reason = event.reason_phrase"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def arm(quic, head, tail, split):"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.STREAM_BASE | 7, capacity=16 + len(tail))"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint_var(split)"
                   "            buf.push_uint_var(len(tail))"
                   "            buf.push_bytes(tail)"
                   "            buf = builder.start_frame(QuicFrameType.STREAM_BASE | 6, capacity=16 + len(head))"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint_var(len(head))"
                   "            buf.push_bytes(head)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   "    return state"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    frame = request_frame()"
                   "    split = 8"
                   "    head, tail = frame[:split], frame[split:]"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "            state = arm(client._quic, head, tail, split)"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._quic._get_or_create_stream_for_send(stream_id)"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.2)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            reason = (client._reason or '-').replace(' ', '_')"
                   "            print('RESULT status=%s body=%s closed=%s sent=%s split=%s head=%s tail=%s stream=%s frame=%s reason=%s' % (client._status, body, client._terminated, state['sent'], split, len(head), len(tail), stream_id, client._frame, reason))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-stream-reorder-test (port)
  "RFC 9000 §2.2. Stream data is an ordered byte stream. The endpoint
buffers bytes that arrive at a higher offset and delivers them only
after the gap is filled. The tail and FIN of an HTTP/3 GET / arrive
before offset zero. The origin still answers 200 with body pazuzu."
  (let ((script (quic-stream-reorder-script)))
    (check "out-of-order STREAM data is delivered in order"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "sent=True" out)
                     (search "split=8 " out)
                     (search "head=8 " out)
                     (search "stream=0 " out)
                     (not (search "tail=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-gap-script ()
  "Client whose first request STREAM uses id 4, then requests on id 0."
  (let ((script "/tmp/pazuzu-h3-stream-gap.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "HEADERS = ["
                   "    (b':method', b'GET'),"
                   "    (b':scheme', b'https'),"
                   "    (b':authority', b'127.0.0.1'),"
                   "    (b':path', b'/'),"
                   "]"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = {}"
                   "        self._body = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status[http_event.stream_id] = int(value)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                sid = http_event.stream_id"
                   "                self._body[sid] = self._body.get(sid, b'') + http_event.data"
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
                   "            nxt = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(4, HEADERS, end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body.get(4) == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            client._http.send_headers(0, HEADERS, end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body.get(0) == b'pazuzu' or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.2)"
                   "            def text(sid):"
                   "                raw = client._body.get(sid, b'')"
                   "                return raw.decode('ascii', 'replace') or '-'"
                   "            print('RESULT next=%s s4=%s b4=%s s0=%s b0=%s closed=%s' % (nxt, client._status.get(4), text(4), client._status.get(0), text(0), client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-stream-gap-test (port)
  "RFC 9000 §3.2. Before a stream is created, every stream of the same
type with a lower id is created. The first request STREAM is client
stream 4. The origin still answers that GET / and a later GET / on
stream 0, both 200 with body pazuzu."
  (let ((script (quic-stream-gap-script)))
    (check "a higher stream id opens the lower streams"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT next=0 " out)
                     (search "s4=200 " out)
                     (search "b4=pazuzu " out)
                     (search "s0=200 " out)
                     (search "b0=pazuzu " out)
                     (search "closed=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reset-credit-script ()
  "Client that resets five streams at the stream data limit and sends
no stream bytes."
  (let ((script "/tmp/pazuzu-h3-reset-credit.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "FINAL = 256 * 1024"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "def arm(quic):"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            for sid in (0, 4, 8, 12, 16):"
                   "                buf = builder.start_frame(QuicFrameType.RESET_STREAM, capacity=16)"
                   "                buf.push_uint_var(sid)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(FINAL)"
                   "            state['sent'] = True"
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
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            try:"
                   "                code = await asyncio.wait_for(client._done, 3)"
                   "            except TimeoutError:"
                   "                code = client._terminated"
                   "            print('RESULT closed=%s sent=%s streams=5 size=%s' % (code, state['sent'], FINAL))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-reset-credit-test (port)
  "RFC 9000 §4.5. The receiver counts each stream final size in the
connection flow controller. Five RESET_STREAM frames carry no stream
data. Each final size is the 256 KiB stream limit. Their sum is past
the 1 MiB connection limit, so the origin closes with FLOW_CONTROL_ERROR."
  (let ((script (quic-reset-credit-script)))
    (check "RESET_STREAM final sizes count toward the connection limit"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT closed=3 " out)
                     (search "sent=True" out)
                     (search "streams=5 " out)
                     (search "size=262144" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-fin-credit-script ()
  "Five empty STREAM frames with FIN at the stream data limit. Their
final sizes sum past the connection limit."
  (let ((script "/tmp/pazuzu-h3-fin-credit.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "FINAL = 256 * 1024"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "def arm(quic):"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            for sid in (0, 4, 8, 12, 16):"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 7, capacity=16)"
                   "                buf.push_uint_var(sid)"
                   "                buf.push_uint_var(FINAL)"
                   "                buf.push_uint_var(0)"
                   "            state['sent'] = True"
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
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            try:"
                   "                code = await asyncio.wait_for(client._done, 3)"
                   "            except TimeoutError:"
                   "                code = client._terminated"
                   "            print('RESULT closed=%s sent=%s streams=5 size=%s' % (code, state['sent'], FINAL))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-fin-credit-test (port)
  "RFC 9000 §4.5. A STREAM frame with FIN communicates the final size as
the sum of its offset and length. Five empty frames use offset 256 KiB.
That final size is inside each stream limit, and the five final sizes
together pass the 1 MiB connection limit, so the origin closes with
FLOW_CONTROL_ERROR."
  (let ((script (quic-fin-credit-script)))
    (check "a FIN offset counts toward the connection limit"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT closed=3 " out)
                     (search "sent=True" out)
                     (search "streams=5 " out)
                     (search "size=262144" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-zero-script ()
  "Client that advertises a QPACK maximum table capacity of zero and
records the server's encoder stream."
  (let ((script "/tmp/pazuzu-h3-qpack0.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "original_settings = H3Connection._get_local_settings"
                   "def zero_capacity(self):"
                   "    settings = original_settings(self)"
                   "    settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0"
                   "    return settings"
                   "H3Connection._get_local_settings = zero_capacity"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
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
                   "            await asyncio.sleep(0.2)"
                   "            encoders = [data for data in client._uni.values() if data[:1] == b'\\x02']"
                   "            encoder = encoders[0].hex() if len(encoders) == 1 else '-'"
                   "            cap = client._http._sent_settings.get(Setting.QPACK_MAX_TABLE_CAPACITY)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s cap=%s encoders=%s encoder_ok=%s' % (client._status, body, client._terminated, cap, len(encoders), encoder == '02'))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-zero-test (port)
  "RFC 9204 §3.2.3. When the peer's maximum dynamic table capacity is
zero, the encoder sends no dynamic-table instructions. The server's
QPACK encoder stream carries only its stream type, and GET / still
returns pazuzu."
  (let ((script (quic-qpack-zero-script)))
    (check "a zero QPACK capacity sends no encoder instructions"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "cap=0 " out)
                     (search "encoders=1 " out)
                     (search "encoder_ok=True" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-capacity-script ()
  "Client that advertises a positive QPACK table capacity and records
every Set Dynamic Table Capacity on the server encoder stream."
  (let ((script "/tmp/pazuzu-h3-qpack-cap.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "def pull_prefix(data, index, nbits):"
                   "    if index >= len(data):"
                   "        return None, index"
                   "    limit = (1 << nbits) - 1"
                   "    value = data[index] & limit"
                   "    index += 1"
                   "    if value < limit:"
                   "        return value, index"
                   "    shift = 0"
                   "    while True:"
                   "        if index >= len(data) or shift > 62:"
                   "            return None, index"
                   "        byte = data[index]"
                   "        index += 1"
                   "        value += (byte & 127) << shift"
                   "        shift += 7"
                   "        if (byte & 128) == 0:"
                   "            return value, index"
                   ""
                   "def skip_string(data, index, nbits):"
                   "    length, index = pull_prefix(data, index, nbits)"
                   "    if length is None or index + length > len(data):"
                   "        return None"
                   "    return index + length"
                   ""
                   "def capacity_report(blob, peer):"
                   "    if not blob or blob[0] != 2:"
                   "        return 0, 0, 1"
                   "    index = 1"
                   "    caps = 0"
                   "    over = 0"
                   "    while index < len(blob):"
                   "        byte = blob[index]"
                   "        if (byte & 0xe0) == 0x20 or (byte & 0xe0) == 0x00:"
                   "            value, index = pull_prefix(blob, index, 5)"
                   "            if value is None:"
                   "                return caps, over, 1"
                   "            if (byte & 0xe0) == 0x20:"
                   "                caps += 1"
                   "                if value > peer:"
                   "                    over += 1"
                   "        elif (byte & 0xc0) == 0x40:"
                   "            index = skip_string(blob, index, 5)"
                   "            if index is None:"
                   "                return caps, over, 1"
                   "            index = skip_string(blob, index, 7)"
                   "            if index is None:"
                   "                return caps, over, 1"
                   "        elif byte & 0x80:"
                   "            _name, index = pull_prefix(blob, index, 6)"
                   "            if index is None or _name is None:"
                   "                return caps, over, 1"
                   "            index = skip_string(blob, index, 7)"
                   "            if index is None:"
                   "                return caps, over, 1"
                   "        else:"
                   "            return caps, over, 1"
                   "    return caps, over, 0"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
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
                   "            await asyncio.sleep(0.2)"
                   "            encoders = [data for data in client._uni.values() if data[:1] == b'\\x02']"
                   "            peer = client._http._sent_settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, -1)"
                   "            if len(encoders) == 1 and isinstance(peer, int) and peer > 0:"
                   "                caps, over, bad = capacity_report(encoders[0], peer)"
                   "                shown = encoders[0].hex()"
                   "            else:"
                   "                caps, over, bad, shown = 0, 0, 1, '-'"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s peer=%s encoders=%s caps=%s over=%s bad=%s encoder=%s' % (client._status, body, client._terminated, peer, len(encoders), caps, over, bad, shown))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-evict-script ()
  "Client that allows one small QPACK entry and sends no decoder
instructions, so nothing the server inserts is acknowledged."
  (let ((script "/tmp/pazuzu-h3-qpack-evict.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "original_settings = H3Connection._get_local_settings"
                   "def tiny_table(self):"
                   "    settings = original_settings(self)"
                   "    settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 48"
                   "    settings[Setting.QPACK_BLOCKED_STREAMS] = 0"
                   "    return settings"
                   "H3Connection._get_local_settings = tiny_table"
                   ""
                   "def pull_prefix(data, index, nbits):"
                   "    if index >= len(data):"
                   "        return None, index"
                   "    limit = (1 << nbits) - 1"
                   "    value = data[index] & limit"
                   "    index += 1"
                   "    if value < limit:"
                   "        return value, index"
                   "    shift = 0"
                   "    while True:"
                   "        if index >= len(data) or shift > 62:"
                   "            return None, index"
                   "        byte = data[index]"
                   "        index += 1"
                   "        value += (byte & 127) << shift"
                   "        shift += 7"
                   "        if (byte & 128) == 0:"
                   "            return value, index"
                   ""
                   "def skip_string(data, index, nbits):"
                   "    length, index = pull_prefix(data, index, nbits)"
                   "    if length is None or index + length > len(data):"
                   "        return None"
                   "    return index + length"
                   ""
                   "def count_inserts(blob):"
                   "    if not blob or blob[0] != 2:"
                   "        return -1"
                   "    index = 1"
                   "    inserts = 0"
                   "    while index < len(blob):"
                   "        byte = blob[index]"
                   "        if byte & 0x80:"
                   "            inserts += 1"
                   "            _name, index = pull_prefix(blob, index, 6)"
                   "            if _name is None:"
                   "                return -1"
                   "            index = skip_string(blob, index, 7)"
                   "            if index is None:"
                   "                return -1"
                   "        elif (byte & 0xc0) == 0x40:"
                   "            inserts += 1"
                   "            index = skip_string(blob, index, 5)"
                   "            if index is None:"
                   "                return -1"
                   "            index = skip_string(blob, index, 7)"
                   "            if index is None:"
                   "                return -1"
                   "        elif (byte & 0xe0) == 0x20:"
                   "            value, index = pull_prefix(blob, index, 5)"
                   "            if value is None:"
                   "                return -1"
                   "        elif (byte & 0xe0) == 0x00:"
                   "            inserts += 1"
                   "            value, index = pull_prefix(blob, index, 5)"
                   "            if value is None:"
                   "                return -1"
                   "        else:"
                   "            return -1"
                   "    return inserts"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        decoder = self._http._local_decoder_stream_id"
                   "        orig = self._quic.send_stream_data"
                   "        def filtered(stream_id, data, end_stream=False):"
                   "            if stream_id == decoder:"
                   "                return"
                   "            return orig(stream_id, data, end_stream=end_stream)"
                   "        self._quic.send_stream_data = filtered"
                   "        self._terminated = None"
                   "        self._bodies = {}"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, DataReceived):"
                   "                self._bodies[http_event.stream_id] = self._bodies.get(http_event.stream_id, b'') + http_event.data"
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
                   "            ids = []"
                   "            for path in (b'/qpack-a', b'/qpack-b'):"
                   "                stream_id = client._quic.get_next_available_stream_id()"
                   "                ids.append(stream_id)"
                   "                client._http.send_headers(stream_id, ["
                   "                    (b':method', b'GET'),"
                   "                    (b':scheme', b'https'),"
                   "                    (b':authority', b'127.0.0.1'),"
                   "                    (b':path', path),"
                   "                ], end_stream=True)"
                   "                client.transmit()"
                   "            for _ in range(50):"
                   "                if all(client._bodies.get(stream_id) for stream_id in ids) or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.3)"
                   "            encoders = [data for data in client._uni.values() if data[:1] == b'\\x02']"
                   "            inserts = count_inserts(encoders[0]) if len(encoders) == 1 else -1"
                   "            shown = encoders[0].hex() if len(encoders) == 1 else '-'"
                   "            cap = client._http._sent_settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, -1)"
                   "            bodies = [client._bodies.get(stream_id, b'').decode('ascii', 'replace') or '-' for stream_id in ids]"
                   "            print('RESULT closed=%s cap=%s encoders=%s inserts=%s bodies=%s encoder=%s' % (client._terminated, cap, len(encoders), inserts, ','.join(bodies), shown))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-evict-test (port)
  "RFC 9204 §2.1.1. An insert that would evict an entry the decoder has
not acknowledged is not performed. The peer allows 48 bytes, which holds
one of these content-type entries and not both, and this client sends
no decoder-stream instruction. At most one encoder insert is present.
Both responses are still delivered and the connection stays open."
  (let ((script (quic-qpack-evict-script)))
    (check "an unacknowledged QPACK entry is not evicted"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT closed=None" out)
                     (search "cap=48 " out)
                     (search "encoders=1 " out)
                     (search "bodies=a,b" out)
                     (or (search "inserts=0 " out) (search "inserts=1 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-capacity-test (port)
  "RFC 9204 §§3.2.3 and 4.3.1. The encoder does not set a dynamic table
capacity above the maximum the peer advertised. GET / is 200 pazuzu,
and every Set Dynamic Table Capacity on the server encoder stream is
within that advertised maximum."
  (let ((script (quic-qpack-capacity-script)))
    (check "a server QPACK table capacity stays within the advertised maximum"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "encoders=1 " out)
                     (search "over=0" out)
                     (search "bad=0" out)
                     (not (search "caps=0" out))
                     (not (search "peer=0" out))
                     (not (search "peer=-1" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-blocked-script ()
  "Client that allows a QPACK dynamic table but no blocked streams, and
records the Required Insert Count of each response field section."
  (let ((script "/tmp/pazuzu-h3-qpack-blocked.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.buffer import Buffer"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "original_settings = H3Connection._get_local_settings"
                   "def zero_blocked(self):"
                   "    settings = original_settings(self)"
                   "    settings[Setting.QPACK_BLOCKED_STREAMS] = 0"
                   "    return settings"
                   "H3Connection._get_local_settings = zero_blocked"
                   ""
                   "def header_counts(blob):"
                   "    buf = Buffer(data=blob)"
                   "    headers = 0"
                   "    nonzero = 0"
                   "    while not buf.eof():"
                   "        try:"
                   "            frame_type = buf.pull_uint_var()"
                   "            length = buf.pull_uint_var()"
                   "            if buf.tell() + length > len(blob):"
                   "                break"
                   "            payload = buf.pull_bytes(length)"
                   "        except Exception:"
                   "            break"
                   "        if frame_type == 0x01 and payload:"
                   "            headers += 1"
                   "            if Buffer(data=payload).pull_uint_var() != 0:"
                   "                nonzero += 1"
                   "    return headers, nonzero"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._sid = None"
                   "        self._blob = b''"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._terminated = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and event.stream_id == self._sid:"
                   "            self._blob += bytes(event.data)"
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
                   "            headers, nonzero = header_counts(client._blob)"
                   "            sent = client._http._sent_settings"
                   "            blocked = sent.get(Setting.QPACK_BLOCKED_STREAMS, -1)"
                   "            cap = sent.get(Setting.QPACK_MAX_TABLE_CAPACITY, -1)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s headers=%s nonzero=%s blocked=%s cap=%s' % (client._status, body, client._terminated, headers, nonzero, blocked, cap))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-blocked-test (port)
  "RFC 9204 §2.1.2. The encoder does not risk more blocked streams than
SETTINGS_QPACK_BLOCKED_STREAMS. With that limit at zero and a positive
table capacity, every response field section has Required Insert Count
zero. GET / is 200 pazuzu."
  (let ((script (quic-qpack-blocked-script)))
    (check "a zero QPACK blocked-streams limit keeps the response unblocked"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "nonzero=0" out)
                     (search "blocked=0" out)
                     (not (search "headers=0" out))
                     (not (search "cap=0" out))
                     (not (search "cap=-1" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-open-script ()
  "Client that records whether the server ends its QPACK encoder or
decoder stream."
  (let ((script "/tmp/pazuzu-h3-qpack-open.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   "        self._ended = set()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "            if event.end_stream:"
                   "                self._ended.add(event.stream_id)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def critical(uni, ended):"
                   "    encoder = [sid for sid, data in uni.items() if data[:1] == b'\\x02']"
                   "    decoder = [sid for sid, data in uni.items() if data[:1] == b'\\x03']"
                   "    closed = [sid for sid in ended if sid in encoder or sid in decoder]"
                   "    return len(encoder), len(decoder), len(closed)"
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
                   "            await asyncio.sleep(0.2)"
                   "            encoders, decoders, closed = critical(client._uni, client._ended)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s encoders=%s decoders=%s ended=%s' % (client._status, body, client._terminated, encoders, decoders, closed))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-open-test (port)
  "RFC 9204 §4.2. The sender does not close its QPACK encoder stream or
its QPACK decoder stream. Both streams are open after GET / returns
pazuzu."
  (let ((script (quic-qpack-open-script)))
    (check "the QPACK encoder and decoder streams stay open"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "encoders=1 " out)
                     (search "decoders=1 " out)
                     (search "ended=0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-nostop-script ()
  "Client that records STOP_SENDING on its own QPACK encoder and decoder
streams."
  (let ((script "/tmp/pazuzu-h3-qpack-nostop.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._stops = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StopSendingReceived):"
                   "            self._stops.append(event.stream_id)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def streams_ready(quic, encoder, decoder):"
                   "    if not isinstance(encoder, int) or not isinstance(decoder, int):"
                   "        return False"
                   "    if encoder == decoder or (encoder & 3) != 2 or (decoder & 3) != 2:"
                   "        return False"
                   "    for stream_id in (encoder, decoder):"
                   "        stream = quic._streams.get(stream_id)"
                   "        if stream is None or stream.sender.highest_offset < 1:"
                   "            return False"
                   "    return True"
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
                   "            encoder = client._http._local_encoder_stream_id"
                   "            decoder = client._http._local_decoder_stream_id"
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
                   "            await asyncio.sleep(0.2)"
                   "            ready = streams_ready(client._quic, encoder, decoder)"
                   "            asked = sum(1 for sid in client._stops if sid in (encoder, decoder))"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s streams_ok=%s stops=%s' % (client._status, body, client._terminated, ready, asked))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-nostop-test (port)
  "RFC 9204 §4.2. The receiver does not request that the sender close
the QPACK encoder stream or the QPACK decoder stream. After the client
opens both streams, GET / still returns pazuzu and neither stream
receives STOP_SENDING."
  (let ((script (quic-qpack-nostop-script)))
    (check "the server does not request that a QPACK stream close"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "streams_ok=True" out)
                     (search "stops=0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-qpack-allow-script ()
  "Client that opens QPACK streams while the server advertises a zero
table capacity."
  (let ((script "/tmp/pazuzu-h3-qpack-allow.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection, Setting"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._stops = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StopSendingReceived):"
                   "            self._stops.append(event.stream_id)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def streams_ready(quic, encoder, decoder):"
                   "    if not isinstance(encoder, int) or not isinstance(decoder, int):"
                   "        return False"
                   "    if encoder == decoder or (encoder & 3) != 2 or (decoder & 3) != 2:"
                   "        return False"
                   "    for stream_id in (encoder, decoder):"
                   "        stream = quic._streams.get(stream_id)"
                   "        if stream is None or stream.sender.highest_offset < 1:"
                   "            return False"
                   "    return True"
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
                   "            encoder = client._http._local_encoder_stream_id"
                   "            decoder = client._http._local_decoder_stream_id"
                   "            stream_id = client._quic.get_next_available_stream_id()"
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body == b'pazuzu' and client._http._settings_received:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.2)"
                   "            received = client._http._settings_received"
                   "            settings = client._http._received_settings or {}"
                   "            cap = settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0) if received else -1"
                   "            ready = streams_ready(client._quic, encoder, decoder)"
                   "            asked = sum(1 for sid in client._stops if sid in (encoder, decoder))"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s cap=%s settings=%s streams_ok=%s stops=%s' % (client._status, body, client._terminated, cap, received, ready, asked))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-qpack-allow-test (port)
  "RFC 9204 §4.2. An endpoint allows its peer to create an encoder
stream and a decoder stream even when its QPACK maximum table capacity
is zero. GET / still returns pazuzu, and neither stream receives
STOP_SENDING."
  (let ((script (quic-qpack-allow-script)))
    (check "a zero table capacity still accepts the peer QPACK streams"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "cap=0 " out)
                     (search "settings=True" out)
                     (search "streams_ok=True" out)
                     (search "stops=0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-control-open-script ()
  "Client that records whether the server ends its HTTP/3 control stream."
  (let ((script "/tmp/pazuzu-h3-control-open.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   "        self._ended = set()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "            if event.end_stream:"
                   "                self._ended.add(event.stream_id)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def control_open(uni, ended):"
                   "    controls = [sid for sid, data in uni.items() if data[:1] == b'\\x00']"
                   "    closed = [sid for sid in controls if sid in ended]"
                   "    return len(controls), len(closed)"
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
                   "            await asyncio.sleep(0.2)"
                   "            controls, closed = control_open(client._uni, client._ended)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s controls=%s ended=%s' % (client._status, body, client._terminated, controls, closed))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-control-open-test (port)
  "RFC 9114 §6.2.1. The sender does not close its HTTP/3 control stream.
After GET / returns pazuzu, that stream is still open."
  (let ((script (quic-control-open-script)))
    (check "the HTTP/3 control stream stays open"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "controls=1 " out)
                     (search "ended=0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-control-settings-script ()
  "Client that reads the first frame on the server's HTTP/3 control stream."
  (let ((script "/tmp/pazuzu-h3-control-settings.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def varint_at(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    if index + length > len(data):"
                   "        return None"
                   "    value = data[index] & 0x3f"
                   "    for byte in data[index + 1:index + length]:"
                   "        value = (value << 8) | byte"
                   "    return value, index + length"
                   ""
                   "def first_frame(data):"
                   "    if not data or data[0] != 0:"
                   "        return None"
                   "    opened = varint_at(data, 1)"
                   "    if opened is None:"
                   "        return None"
                   "    frame_type, index = opened"
                   "    sized = varint_at(data, index)"
                   "    if sized is None:"
                   "        return None"
                   "    length, index = sized"
                   "    if index + length > len(data):"
                   "        return None"
                   "    return frame_type"
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
                   "            await asyncio.sleep(0.2)"
                   "            controls = [data for data in client._uni.values() if data[:1] == b'\\x00']"
                   "            frame = first_frame(controls[0]) if len(controls) == 1 else None"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s controls=%s first=%s tail=1' % (client._status, body, client._terminated, len(controls), -1 if frame is None else frame))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-control-settings-test (port)
  "RFC 9114 §6.2.1. The server's control stream carries SETTINGS as its
first frame. GET / still returns pazuzu."
  (let ((script (quic-control-settings-script)))
    (check "the control stream starts with SETTINGS"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "controls=1 " out)
                     (search "first=4 " out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-settings-before-request-test (port)
  "RFC 9114 §7.2.4.2. The server sends SETTINGS as soon as the transport
can send. The client completes the handshake and sends no HTTP/3 stream
data. The server control stream still begins with SETTINGS."
  (check "SETTINGS is sent before an HTTP/3 request"
    (let ((script "/tmp/pazuzu-h3-settings-before.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._uni = {}"
                     "        self._terminated = None"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                     "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                     ""
                     "def varint_at(data, index):"
                     "    if index >= len(data):"
                     "        return None"
                     "    prefix = data[index] >> 6"
                     "    length = 1 << prefix"
                     "    if index + length > len(data):"
                     "        return None"
                     "    value = data[index] & 0x3f"
                     "    for byte in data[index + 1:index + length]:"
                     "        value = (value << 8) | byte"
                     "    return value, index + length"
                     ""
                     "def first_frame(data):"
                     "    if not data or data[0] != 0:"
                     "        return None"
                     "    opened = varint_at(data, 1)"
                     "    if opened is None:"
                     "        return None"
                     "    frame_type, index = opened"
                     "    sized = varint_at(data, index)"
                     "    if sized is None:"
                     "        return None"
                     "    length, index = sized"
                     "    if index + length > len(data):"
                     "        return None"
                     "    return frame_type"
                     ""
                     "def client_sent(quic):"
                     "    count = 0"
                     "    for sid, stream in quic._streams.items():"
                     "        if (sid & 1) == 0 and stream.sender.highest_offset > 0:"
                     "            count += 1"
                     "    return count"
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
                     "            frame = None"
                     "            for _ in range(40):"
                     "                controls = [data for data in client._uni.values() if data[:1] == b'\\x00']"
                     "                if len(controls) == 1:"
                     "                    frame = first_frame(controls[0])"
                     "                    if frame == 4:"
                     "                        break"
                     "                await asyncio.sleep(0.05)"
                     "            controls = [data for data in client._uni.values() if data[:1] == b'\\x00']"
                     "            sent = client_sent(client._quic)"
                     "            print('FIRST=%s' % (-1 if frame is None else frame))"
                     "            print('CONTROLS=%d' % len(controls))"
                     "            print('SENT=%d' % sent)"
                     "            print('CLOSED %s' % client._terminated)"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "FIRST=4" out)
                     (search "CONTROLS=1" out)
                     (search "SENT=0" out)
                     (search "CLOSED None" out)
                     (not (search "FIRST=-1" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-request-rejected-test (port)
  "RFC 9114 §4.1.1. A request the application has processed is not reset
with H3_REQUEST_REJECTED (267). GET / returns pazuzu and the connection
stays open."
  (check "a processed request is not H3_REQUEST_REJECTED"
    (let ((script "/tmp/pazuzu-h3-request-rejected.py"))
      (write-lines script
                   '("import asyncio, ssl, sys"
                     "from aioquic.asyncio.client import connect"
                     "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                     "from aioquic.h3.connection import H3_ALPN, H3Connection"
                     "from aioquic.h3.events import DataReceived, HeadersReceived"
                     "from aioquic.quic.configuration import QuicConfiguration"
                     "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset"
                     "from aioquic.quic.packet import QuicProtocolVersion"
                     ""
                     "H3_REQUEST_REJECTED = 0x010b"
                     ""
                     "class Client(QuicConnectionProtocol):"
                     "    def __init__(self, *args, **kwargs):"
                     "        super().__init__(*args, **kwargs)"
                     "        self._http = H3Connection(self._quic)"
                     "        self._terminated = None"
                     "        self._status = None"
                     "        self._body = b''"
                     "        self._sid = None"
                     "        self._reset = None"
                     "        self._stop = None"
                     "        self._rejected = False"
                     ""
                     "    def note(self, code):"
                     "        if code == H3_REQUEST_REJECTED:"
                     "            self._rejected = True"
                     ""
                     "    def quic_event_received(self, event):"
                     "        if isinstance(event, ConnectionTerminated):"
                     "            self._terminated = event.error_code"
                     "            self.note(event.error_code)"
                     "        elif isinstance(event, StreamReset) and event.stream_id == self._sid:"
                     "            self._reset = event.error_code"
                     "            self.note(event.error_code)"
                     "        elif isinstance(event, StopSendingReceived) and event.stream_id == self._sid:"
                     "            self._stop = event.error_code"
                     "            self.note(event.error_code)"
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
                     "            for _ in range(40):"
                     "                if client._body == b'pazuzu':"
                     "                    break"
                     "                await asyncio.sleep(0.05)"
                     "            await asyncio.sleep(0.2)"
                     "            body = client._body.decode('ascii', 'replace') or '-'"
                     "            print('REJECTED=%s' % ('True' if client._rejected else 'False'))"
                     "            print('RESULT status=%s body=%s reset=%s stop=%s closed=%s' % (client._status, body, client._reset, client._stop, client._terminated))"
                     "    except Exception as exc:"
                     "        print('ERR %r' % exc)"
                     ""
                     "asyncio.run(main())"))
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "REJECTED=False" out)
                     (not (search "REJECTED=True" out))
                     (search "RESULT status=200 body=pazuzu " out)
                     (search " closed=None" out)
                     (not (search "reset=267" out))
                     (not (search "stop=267" out))
                     (not (search "closed=267" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-max-push-id-script ()
  "Client that reads every frame on the server's HTTP/3 control stream."
  (let ((script "/tmp/pazuzu-h3-max-push.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def varint_at(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    if index + length > len(data):"
                   "        return None"
                   "    value = data[index] & 0x3f"
                   "    for byte in data[index + 1:index + length]:"
                   "        value = (value << 8) | byte"
                   "    return value, index + length"
                   ""
                   "def control_frames(data):"
                   "    if not data or data[0] != 0:"
                   "        return None"
                   "    index = 1"
                   "    types = []"
                   "    while index < len(data):"
                   "        opened = varint_at(data, index)"
                   "        if opened is None:"
                   "            return None"
                   "        frame_type, index = opened"
                   "        sized = varint_at(data, index)"
                   "        if sized is None:"
                   "            return None"
                   "        length, index = sized"
                   "        if index + length > len(data):"
                   "            return None"
                   "        types.append(frame_type)"
                   "        index += length"
                   "    return types"
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
                   "            await asyncio.sleep(0.2)"
                   "            controls = [data for data in client._uni.values() if data[:1] == b'\\x00']"
                   "            types = control_frames(controls[0]) if len(controls) == 1 else None"
                   "            settings = 1 if types and types[0] == 4 else 0"
                   "            push = types.count(0x0d) if types is not None else -1"
                   "            frames = len(types) if types is not None else -1"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s controls=%s settings=%s push=%s frames=%s tail=1' % (client._status, body, client._terminated, len(controls), settings, push, frames))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-max-push-id-test (port)
  "RFC 9114 §7.2.7. A server does not send a MAX_PUSH_ID frame. The
control stream still begins with SETTINGS, and GET / returns pazuzu."
  (let ((script (quic-max-push-id-script)))
    (check "the server sends no MAX_PUSH_ID frame"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "controls=1 " out)
                     (search "settings=1 " out)
                     (search "push=0 " out)
                     (not (search "frames=0 " out))
                     (not (search "frames=-1 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-control-nostop-script ()
  "Client that records STOP_SENDING on its own HTTP/3 control stream."
  (let ((script "/tmp/pazuzu-h3-control-nostop.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StopSendingReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._stops = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StopSendingReceived):"
                   "            self._stops.append(event.stream_id)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def control_ready(quic, stream_id):"
                   "    if not isinstance(stream_id, int) or (stream_id & 3) != 2:"
                   "        return False"
                   "    stream = quic._streams.get(stream_id)"
                   "    return stream is not None and stream.sender.highest_offset >= 1"
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
                   "            control = client._http._local_control_stream_id"
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
                   "            await asyncio.sleep(0.2)"
                   "            ready = control_ready(client._quic, control)"
                   "            asked = sum(1 for sid in client._stops if sid == control)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s control_ok=%s stops=%s tail=1' % (client._status, body, client._terminated, ready, asked))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-control-nostop-test (port)
  "RFC 9114 §6.2.1. The receiver does not request that the sender close
the control stream. After the client opens its control stream, GET /
returns pazuzu and that stream receives no STOP_SENDING."
  (let ((script (quic-control-nostop-script)))
    (check "the server does not request that the control stream close"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "control_ok=True" out)
                     (search "stops=0 " out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-settings-once-script ()
  "Client that counts SETTINGS frames on the server's control stream."
  (let ((script "/tmp/pazuzu-h3-settings-once.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def varint_at(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    if index + length > len(data):"
                   "        return None"
                   "    value = data[index] & 0x3f"
                   "    for byte in data[index + 1:index + length]:"
                   "        value = (value << 8) | byte"
                   "    return value, index + length"
                   ""
                   "def control_frames(data):"
                   "    if not data or data[0] != 0:"
                   "        return None"
                   "    index = 1"
                   "    types = []"
                   "    while index < len(data):"
                   "        opened = varint_at(data, index)"
                   "        if opened is None:"
                   "            return None"
                   "        frame_type, index = opened"
                   "        sized = varint_at(data, index)"
                   "        if sized is None:"
                   "            return None"
                   "        length, index = sized"
                   "        if index + length > len(data):"
                   "            return None"
                   "        types.append(frame_type)"
                   "        index += length"
                   "    return types"
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
                   "            await asyncio.sleep(0.2)"
                   "            controls = [data for data in client._uni.values() if data[:1] == b'\\x00']"
                   "            types = control_frames(controls[0]) if len(controls) == 1 else None"
                   "            settings = types.count(4) if types is not None else -1"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s controls=%s settings=%s tail=1' % (client._status, body, client._terminated, len(controls), settings))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-settings-once-test (port)
  "RFC 9114 §7.2.4. The server sends one SETTINGS frame on its control
stream and does not send another. GET / still returns pazuzu."
  (let ((script (quic-settings-once-script)))
    (check "the server sends SETTINGS only once"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "controls=1 " out)
                     (search "settings=1 " out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-settings-ids-script ()
  "Client that reads identifiers from the server's one SETTINGS payload."
  (let ((script "/tmp/pazuzu-h3-settings-ids.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 3:"
                   "            self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def varint_at(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    if index + length > len(data):"
                   "        return None"
                   "    value = data[index] & 0x3f"
                   "    for byte in data[index + 1:index + length]:"
                   "        value = (value << 8) | byte"
                   "    return value, index + length"
                   ""
                   "def settings_ids(data):"
                   "    if not data or data[0] != 0:"
                   "        return None"
                   "    index = 1"
                   "    payloads = []"
                   "    while index < len(data):"
                   "        opened = varint_at(data, index)"
                   "        if opened is None:"
                   "            return None"
                   "        frame_type, index = opened"
                   "        sized = varint_at(data, index)"
                   "        if sized is None:"
                   "            return None"
                   "        length, index = sized"
                   "        if index + length > len(data):"
                   "            return None"
                   "        if frame_type == 4:"
                   "            payloads.append(data[index:index + length])"
                   "        index += length"
                   "    if len(payloads) != 1:"
                   "        return None"
                   "    payload = payloads[0]"
                   "    ids = []"
                   "    cursor = 0"
                   "    while cursor < len(payload):"
                   "        named = varint_at(payload, cursor)"
                   "        if named is None:"
                   "            return None"
                   "        identifier, cursor = named"
                   "        valued = varint_at(payload, cursor)"
                   "        if valued is None:"
                   "            return None"
                   "        setting, cursor = valued"
                   "        ids.append((identifier, setting))"
                   "    return ids"
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
                   "            await asyncio.sleep(0.2)"
                   "            controls = [data for data in client._uni.values() if data[:1] == b'\\x00']"
                   "            pairs = settings_ids(controls[0]) if len(controls) == 1 else None"
                   "            reserved = {0, 2, 3, 4, 5}"
                   "            identifiers = [item[0] for item in pairs] if pairs else None"
                   "            empty = 0 if identifiers else 1"
                   "            dup = 0 if identifiers is not None and len(identifiers) == len(set(identifiers)) else 1"
                   "            bad = 0 if identifiers is not None and not any(item in reserved for item in identifiers) else 1"
                   "            shown = ','.join(str(item) for item in identifiers) if identifiers else '-'"
                   "            paired = (','.join('%d:%d' % item for item in pairs) + ',') if pairs else '-'"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s controls=%s ids=%s values=%s empty=%s dup=%s reserved=%s' % (client._status, body, client._terminated, len(controls), shown, paired, empty, dup, bad))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-settings-ids-test (port)
  "RFC 9114 §7.2.4 and §7.2.4.1. The server's SETTINGS frame uses each
identifier once and does not send reserved identifiers 0x00, 0x02,
0x03, 0x04, or 0x05. GET / still returns pazuzu."
  (let ((script (quic-settings-ids-script)))
    (check "server SETTINGS identifiers are unique and not reserved"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "controls=1 " out)
                     (search "empty=0 " out)
                     (search "dup=0 " out)
                     (search "reserved=0" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-settings-defaults-test (port)
  "RFC 9114 §7.2.4.2. The server includes each setting that differs from
its default. The field-section limit is 65536, not unlimited, and
extended CONNECT is enabled. GET / still returns pazuzu."
  (let ((script (quic-settings-ids-script)))
    (check "server SETTINGS include non-default values"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "6:65536," out)
                     (search "8:1," out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-settings-place-script ()
  "Client that counts SETTINGS frames on the response stream and on any
push stream."
  (let ((script "/tmp/pazuzu-h3-settings-place.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._bidi = {}"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived):"
                   "            if (event.stream_id & 3) == 0:"
                   "                self._bidi[event.stream_id] = self._bidi.get(event.stream_id, b'') + event.data"
                   "            elif (event.stream_id & 3) == 3:"
                   "                self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def varint_at(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    if index + length > len(data):"
                   "        return None"
                   "    value = data[index] & 0x3f"
                   "    for byte in data[index + 1:index + length]:"
                   "        value = (value << 8) | byte"
                   "    return value, index + length"
                   ""
                   "def http_frames(data, index):"
                   "    types = []"
                   "    while index < len(data):"
                   "        opened = varint_at(data, index)"
                   "        if opened is None:"
                   "            return None"
                   "        frame_type, index = opened"
                   "        sized = varint_at(data, index)"
                   "        if sized is None:"
                   "            return None"
                   "        length, index = sized"
                   "        if index + length > len(data):"
                   "            return None"
                   "        types.append(frame_type)"
                   "        index += length"
                   "    return types"
                   ""
                   "def count_settings(bidi, uni):"
                   "    frames = 0"
                   "    settings = 0"
                   "    for data in bidi.values():"
                   "        types = http_frames(data, 0)"
                   "        if types is None:"
                   "            return None"
                   "        frames += len(types)"
                   "        settings += types.count(4)"
                   "    for data in uni.values():"
                   "        if not data or data[0] != 1:"
                   "            continue"
                   "        opened = varint_at(data, 1)"
                   "        if opened is None:"
                   "            return None"
                   "        _push_id, index = opened"
                   "        types = http_frames(data, index)"
                   "        if types is None:"
                   "            return None"
                   "        frames += len(types)"
                   "        settings += types.count(4)"
                   "    return frames, settings"
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
                   "            await asyncio.sleep(0.2)"
                   "            counted = count_settings(client._bidi, client._uni)"
                   "            if counted is None:"
                   "                frames, settings = -1, -1"
                   "            else:"
                   "                frames, settings = counted"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s frames=%s settings=%s tail=1' % (client._status, body, client._terminated, frames, settings))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-settings-place-test (port)
  "RFC 9114 §7.2.4. A SETTINGS frame is not sent on a request stream or a
push stream. GET / still returns pazuzu."
  (let ((script (quic-settings-place-script)))
    (check "the server sends SETTINGS only on the control stream"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "settings=0 " out)
                     (not (search "frames=0 " out))
                     (not (search "frames=-1 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retry-integrity-script ()
  "Client that returns the server's Retry token with one byte changed."
  (let ((script "/tmp/pazuzu-h3-retry-integrity.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "state = {'ok': False, 'magic': -1, 'length': 0}"
                   "original = QuicConnection._receive_retry_packet"
                   "def wrapped(self, header, packet_without_tag, now):"
                   "    token = bytes(header.token or b'')"
                   "    if token and not state['ok']:"
                   "        state['magic'] = token[0]"
                   "        state['length'] = len(token)"
                   "        flipped = bytearray(token)"
                   "        flipped[-1] ^= 255"
                   "        header.token = bytes(flipped)"
                   "        state['ok'] = True"
                   "    return original(self, header, packet_without_tag, now)"
                   "QuicConnection._receive_retry_packet = wrapped"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._handshake = False"
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, HandshakeCompleted):"
                   "            self._handshake = True"
                   "            if not self._done.done():"
                   "                self._done.set_result(None)"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=['h3'],"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client, wait_connected=False) as client:"
                   "            client.transmit()"
                   "            try:"
                   "                await asyncio.wait_for(client._done, 2)"
                   "            except TimeoutError:"
                   "                pass"
                   "            print('RESULT tampered=%s magic=%s length=%s retry=%s handshake=%s closed=%s tail=1' % (state['ok'], state['magic'], state['length'], client._quic._retry_count, client._handshake, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-retry-integrity-test (port)
  "RFC 9000 §§8.1.3 and 8.1.4. An address-validation token is integrity
protected, and an Initial that carries one is validated. The client
returns the Retry token with one byte changed. The server rejects it
with INVALID_TOKEN (11) and does not complete the handshake."
  (let ((script (quic-retry-integrity-script)))
    (check "a modified Retry token is not accepted"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "tampered=True" out)
                     (search "magic=183 " out)
                     (search "retry=1 " out)
                     (search "handshake=False" out)
                     (search "closed=11 " out)
                     (not (search "length=0 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-push-id-script ()
  "Client that compares server PUSH_PROMISE push IDs with its MAX_PUSH_ID."
  (let ((script "/tmp/pazuzu-h3-push-id.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._bidi = {}"
                   "        self._uni = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived):"
                   "            if (event.stream_id & 3) == 0:"
                   "                self._bidi[event.stream_id] = self._bidi.get(event.stream_id, b'') + event.data"
                   "            elif (event.stream_id & 3) == 3:"
                   "                self._uni[event.stream_id] = self._uni.get(event.stream_id, b'') + event.data"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
                   ""
                   "def varint_at(data, index):"
                   "    if index >= len(data):"
                   "        return None"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    if index + length > len(data):"
                   "        return None"
                   "    value = data[index] & 0x3f"
                   "    for byte in data[index + 1:index + length]:"
                   "        value = (value << 8) | byte"
                   "    return value, index + length"
                   ""
                   "def collect(data, index, frames, ids):"
                   "    while index < len(data):"
                   "        opened = varint_at(data, index)"
                   "        if opened is None:"
                   "            return None"
                   "        frame_type, index = opened"
                   "        sized = varint_at(data, index)"
                   "        if sized is None:"
                   "            return None"
                   "        length, index = sized"
                   "        if index + length > len(data):"
                   "            return None"
                   "        payload = data[index:index + length]"
                   "        index += length"
                   "        frames += 1"
                   "        if frame_type == 5:"
                   "            got = varint_at(payload, 0)"
                   "            if got is None:"
                   "                return None"
                   "            push_id, _used = got"
                   "            ids.append(push_id)"
                   "    return frames"
                   ""
                   "def survey(bidi, uni, limit):"
                   "    frames = 0"
                   "    ids = []"
                   "    for data in bidi.values():"
                   "        frames = collect(data, 0, frames, ids)"
                   "        if frames is None:"
                   "            return None"
                   "    for data in uni.values():"
                   "        if not data or data[0] != 1:"
                   "            continue"
                   "        opened = varint_at(data, 1)"
                   "        if opened is None:"
                   "            return None"
                   "        _push_id, index = opened"
                   "        frames = collect(data, index, frames, ids)"
                   "        if frames is None:"
                   "            return None"
                   "    over = sum(1 for push_id in ids if limit is None or push_id > limit)"
                   "    return frames, len(ids), over"
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
                   "            limit = client._http._max_push_id"
                   "            control_id = client._http._local_control_stream_id"
                   "            control = client._quic._streams.get(control_id)"
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
                   "            await asyncio.sleep(0.2)"
                   "            advertised = isinstance(limit, int) and limit >= 0 and control is not None and control.sender.highest_offset >= 1"
                   "            counted = survey(client._bidi, client._uni, limit)"
                   "            if counted is None:"
                   "                frames, promises, over = -1, -1, -1"
                   "            else:"
                   "                frames, promises, over = counted"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s advertised=%s frames=%s promises=%s over=%s tail=1' % (client._status, body, client._terminated, advertised, frames, promises, over))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-push-id-test (port)
  "RFC 9114 §7.2.5. The server does not use a push ID larger than the
MAX_PUSH_ID the client has sent. GET / still returns pazuzu."
  (let ((script (quic-push-id-script)))
    (check "the server stays within the client's maximum push ID"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "advertised=True" out)
                     (search "over=0 " out)
                     (not (search "frames=0 " out))
                     (not (search "frames=-1 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retry-type-script ()
  "Client that returns the Retry token with its type marker replaced."
  (let ((script "/tmp/pazuzu-h3-retry-type.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "state = {'ok': False, 'magic': -1, 'length': 0}"
                   "original = QuicConnection._receive_retry_packet"
                   "def wrapped(self, header, packet_without_tag, now):"
                   "    token = bytes(header.token or b'')"
                   "    if token and not state['ok']:"
                   "        state['magic'] = token[0]"
                   "        state['length'] = len(token)"
                   "        flipped = bytearray(token)"
                   "        flipped[0] = 0x36"
                   "        header.token = bytes(flipped)"
                   "        state['ok'] = True"
                   "    return original(self, header, packet_without_tag, now)"
                   "QuicConnection._receive_retry_packet = wrapped"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._handshake = False"
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, HandshakeCompleted):"
                   "            self._handshake = True"
                   "            if not self._done.done():"
                   "                self._done.set_result(None)"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=['h3'],"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client, wait_connected=False) as client:"
                   "            client.transmit()"
                   "            try:"
                   "                await asyncio.wait_for(client._done, 2)"
                   "            except TimeoutError:"
                   "                pass"
                   "            print('RESULT tampered=%s magic=%s length=%s retry=%s handshake=%s closed=%s tail=1' % (state['ok'], state['magic'], state['length'], client._quic._retry_count, client._handshake, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-retry-type-test (port)
  "RFC 9000 §8.1.1. A Retry token is constructed so the server can tell
it was provided in a Retry packet. Replacing that marker with the marker
of another token is rejected with INVALID_TOKEN (11)."
  (let ((script (quic-retry-type-script)))
    (check "a retagged Retry token is not accepted"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "tampered=True" out)
                     (search "magic=183 " out)
                     (search "retry=1 " out)
                     (search "handshake=False" out)
                     (search "closed=11 " out)
                     (not (search "length=0 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-response-fin-script ()
  "Client that records whether the final HTTP/3 response ends the
server's sending side of the request stream."
  (let ((script "/tmp/pazuzu-h3-response-fin.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._fin = False"
                   "        self._stream = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and (event.stream_id & 3) == 0 and event.end_stream:"
                   "            self._fin = True"
                   "            self._stream = event.stream_id"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
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
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body == b'pazuzu' and client._fin:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s fin=%s stream=%s tail=1' % (client._status, body, client._terminated, client._fin, client._stream if client._stream is not None else -1))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-response-fin-test (port)
  "RFC 9114 §4.1. After the final response, the server closes its
sending side of the request stream. GET / still returns pazuzu and the
connection stays open."
  (let ((script (quic-response-fin-script)))
    (check "a final HTTP/3 response closes the request stream"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "fin=True " out)
                     (search "stream=0 " out)
                     (not (search "fin=False" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-field-order-script ()
  "Client that sends three literal field lines in a non-sorted order."
  (let ((script "/tmp/pazuzu-h3-field-order.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
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
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/field-order'),"
                   "                (b'x-order-c', b'3'),"
                   "                (b'x-order-a', b'1'),"
                   "                (b'x-order-b', b'2'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s tail=1' % (client._status, body, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-field-order-test (port)
  "RFC 9204 §2.2. The QPACK decoder emits field lines in the order their
representations appear in the encoded field section."
  (let ((script (quic-field-order-script)))
    (check "QPACK field lines keep their encoded order"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=x-order-c,x-order-a,x-order-b closed=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-response-field-order-script ()
  "Client that records the response field names in the order received."
  (let ((script "/tmp/pazuzu-h3-response-fields.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._status = None"
                   "        self._body = b''"
                   "        self._names = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                self._names = [name.decode('ascii') for name, value in http_event.headers]"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
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
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if client._body == b'pazuzu' and client._names:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            await asyncio.sleep(0.1)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            names = ','.join(client._names) or '-'"
                   "            print('RESULT status=%s body=%s names=%s closed=%s tail=1' % (client._status, body, names, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun comma-split (text)
  (loop with start = 0
        for comma = (position #\, text :start start)
        collect (subseq text start (or comma (length text)))
        while comma
        do (setf start (1+ comma))))

(defun ordered-subsequence-p (need have)
  "True when every token in NEED occurs in HAVE, in that order."
  (loop with rest = have
        for token in need
        for found = (member token rest :test #'string=)
        unless found
          return nil
        do (setf rest (rest found))
        finally (return t)))

(defun quic-response-field-order-test (port)
  "RFC 9204 §2.1. The QPACK encoder emits field representations in the
order they appear in the response field section. GET / returns pazuzu.
HSTS may sit between Accept-Ranges and Alt-Svc when it is enabled."
  (let ((script (quic-response-field-order-script)))
    (check "QPACK response fields keep their input order"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (let* ((mark (search "names=" out))
               (end (and mark (position #\Space out :start (+ mark 6))))
               (names (and mark end (comma-split (subseq out (+ mark 6) end)))))
          (unless (and code (zerop code)
                       (search "RESULT status=200 body=pazuzu " out)
                       (search "closed=None " out)
                       names
                       (string= (first names) ":status")
                       (ordered-subsequence-p
                        '(":status" "accept-ranges" "alt-svc" "content-type"
                          "server" "date" "content-length")
                        names)
                       (not (search "ERR " out)))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun quic-response-pseudo-test (port)
  "RFC 9114 §4.3. A response carries one :status pseudo-header before the
regular fields and does not carry a request pseudo-header. GET / still
returns pazuzu."
  (let ((script (quic-response-field-order-script)))
    (check "an HTTP/3 response carries only :status"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (let* ((mark (search "names=" out))
               (end (and mark (position #\Space out :start (+ mark 6))))
               (names (and mark end (comma-split (subseq out (+ mark 6) end))))
               (pseudos (and names
                             (remove-if-not (lambda (name)
                                              (and (plusp (length name))
                                                   (char= (char name 0) #\:)))
                                            names))))
          (unless (and code (zerop code)
                       (search "RESULT status=200 body=pazuzu " out)
                       (search "closed=None " out)
                       names
                       (equal pseudos '(":status"))
                       (string= (first names) ":status")
                       (not (search "ERR " out)))
            (fail "exit ~s out ~s err ~s" code out err)))))))

(defun quic-unknown-transport-parameter-script ()
  "Client Initial that carries transport parameter 27, which is reserved
so peers exercise ignoring an unknown parameter."
  (let ((script "/tmp/pazuzu-h3-unknown-tp.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "injected = False"
                   "original = QuicConnection._serialize_transport_parameters"
                   "def wrapped(self):"
                   "    global injected"
                   "    data = original(self)"
                   "    if self._is_client:"
                   "        data += bytes([0x1b, 0x04]) + b'test'"
                   "        injected = True"
                   "    return data"
                   "QuicConnection._serialize_transport_parameters = wrapped"
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
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s injected=%s' % (client._status, body, client._terminated, injected))"
                   "    except Exception as exc:"
                   "        print('RESULT status=None body=- closed=None injected=%s' % injected)"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-unknown-transport-parameter-test (port)
  "RFC 9000 §§7.4.2 and 18.1. Transport parameter 27 is 31 * 0 + 27.
An endpoint that does not support a transport parameter ignores it.
The handshake still serves GET /."
  (let ((script (quic-unknown-transport-parameter-script)))
    (check "an unknown transport parameter is ignored"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None injected=True" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-handshake-app-close-script ()
  "Client that puts one CONNECTION_CLOSE frame in a Handshake packet.
Type 0x1c is permitted. Type 0x1d is not."
  (let ((script "/tmp/pazuzu-h3-hs-app-close.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion, encode_long_header_first_byte"
                   "from aioquic.tls import Epoch"
                   ""
                   "def build_handshake(quic, app):"
                   "    crypto = quic._cryptos[Epoch.HANDSHAKE]"
                   "    dcid = quic._peer_cid.cid"
                   "    scid = quic.host_cid"
                   "    pn = 0"
                   "    if app:"
                   "        payload = bytes([0x1d, 0x00, 0x00])"
                   "    else:"
                   "        payload = bytes([0x1c, 0x2a, 0x00, 0x00])"
                   "    first = encode_long_header_first_byte(QuicProtocolVersion.VERSION_1, QuicPacketType.HANDSHAKE, 1)"
                   "    prefix = bytes([first]) + (1).to_bytes(4, 'big') + bytes([len(dcid)]) + dcid"
                   "    prefix += bytes([len(scid)]) + scid"
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
                   "        self._app = False"
                   "        self._build_error = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        self._quic.receive_datagram(data, addr, now=self._loop.time())"
                   "        self._process_events()"
                   "        quic = self._quic"
                   "        if (not self._sent) and quic._cryptos[Epoch.HANDSHAKE].send.is_valid():"
                   "            try:"
                   "                packet = build_handshake(quic, self._app)"
                   "                self._transport.sendto(packet, addr)"
                   "                self._sent = True"
                   "            except Exception as exc:"
                   "                self._build_error = repr(exc)"
                   "        self.transmit()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def configuration():"
                   "    return QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   ""
                   "async def once(port, app):"
                   "    label = 'APP' if app else 'TRANSPORT'"
                   "    def create(connection, stream_handler=None):"
                   "        client = Client(connection, stream_handler=stream_handler)"
                   "        client._app = app"
                   "        return client"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=create, wait_connected=False) as client:"
                   "        client.transmit()"
                   "        for _ in range(40):"
                   "            if client._terminated is not None:"
                   "                break"
                   "            await asyncio.sleep(0.05)"
                   "        await asyncio.sleep(0.3)"
                   "        print('RESULT %s status=None body=- closed=%s sent=%s err=%s' % (label, client._terminated, client._sent, client._build_error))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    try:"
                   "        await once(port, False)"
                   "        await once(port, True)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-handshake-app-close-test (port)
  "RFC 9000 §§12.4 and 12.5. A CONNECTION_CLOSE that signals an
application error (type 0x1d) is permitted only in an application-data
packet. The same frame in a Handshake packet is PROTOCOL_VIOLATION
(0x0a). A transport CONNECTION_CLOSE (type 0x1c) is permitted there, so
it does not close the connection with that error."
  (let ((script (quic-handshake-app-close-script)))
    (check "an application CONNECTION_CLOSE in a Handshake packet is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT TRANSPORT status=None body=- closed=None sent=True err=None" out)
                     (search "RESULT APP status=None body=- closed=10 sent=True err=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-handshake-ack-script ()
  "Client that records whether its ack-eliciting Initial and Handshake
packets are still unacknowledged when those packet spaces are discarded."
  (let ((script "/tmp/pazuzu-h3-hs-ack.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   "from aioquic.quic.recovery import QuicPacketRecovery"
                   "from aioquic.tls import Epoch"
                   ""
                   "counts = {}"
                   "record = {}"
                   "original_sent = QuicPacketRecovery.on_packet_sent"
                   "def sent_wrapped(self, *, packet, space):"
                   "    if packet.is_ack_eliciting and packet.epoch in (Epoch.INITIAL, Epoch.HANDSHAKE):"
                   "        counts[id(space)] = counts.get(id(space), 0) + 1"
                   "    return original_sent(self, packet=packet, space=space)"
                   "QuicPacketRecovery.on_packet_sent = sent_wrapped"
                   "original_discard = QuicConnection._discard_epoch"
                   "def discard_wrapped(self, epoch):"
                   "    if ("
                   "        self._is_client"
                   "        and epoch in (Epoch.INITIAL, Epoch.HANDSHAKE)"
                   "        and not self._spaces[epoch].discarded"
                   "    ):"
                   "        space = self._spaces[epoch]"
                   "        pending = [pn for pn, pkt in space.sent_packets.items() if pkt.is_ack_eliciting]"
                   "        record[epoch.name] = (counts.get(id(space), 0), pending)"
                   "    return original_discard(self, epoch)"
                   "QuicConnection._discard_epoch = discard_wrapped"
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
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            initial = record.get('INITIAL', (None, None))"
                   "            handshake = record.get('HANDSHAKE', (None, None))"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT initial_sent=%s initial_pending=%s handshake_sent=%s handshake_pending=%s status=%s body=%s closed=%s' % (initial[0], initial[1], handshake[0], handshake[1], client._status, body, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-handshake-ack-test (port)
  "RFC 9000 §13.2.1. An endpoint acknowledges every ack-eliciting Initial
and Handshake packet immediately. By the time the client discards each
of those packet number spaces, none of its ack-eliciting packets in that
space are still unacknowledged, and GET / still returns pazuzu."
  (let ((script (quic-handshake-ack-script)))
    (check "an ack-eliciting Initial or Handshake packet is acknowledged immediately"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "initial_pending=[]" out)
                     (search "handshake_pending=[]" out)
                     (not (search "initial_sent=0 " out))
                     (not (search "initial_sent=None " out))
                     (not (search "handshake_sent=0 " out))
                     (not (search "handshake_sent=None " out))
                     (search "status=200 body=pazuzu closed=None" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ack-ecn-script ()
  "Client that sends ACK frames of type 0x03, which carry ECN counts."
  (let ((script "/tmp/pazuzu-h3-ack-ecn.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicProtocolVersion, push_ack_frame"
                   ""
                   "ecn_acks = {'n': 0}"
                   "def write_ack_ecn(self, builder, space, now):"
                   "    ecn_acks['n'] += 1"
                   "    ack_delay = now - space.largest_received_time"
                   "    ack_delay_encoded = int(ack_delay * 1000000) >> self._local_ack_delay_exponent"
                   "    buf = builder.start_frame("
                   "        QuicFrameType.ACK_ECN,"
                   "        capacity=64,"
                   "        handler=self._on_ack_delivery,"
                   "        handler_args=(space, space.largest_received_packet),"
                   "    )"
                   "    push_ack_frame(buf, space.ack_queue, ack_delay_encoded)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    buf.push_uint_var(0)"
                   "    space.ack_at = None"
                   "QuicConnection._write_ack_frame = write_ack_ecn"
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
                   "            client._http.send_headers(stream_id, ["
                   "                (b':method', b'GET'),"
                   "                (b':scheme', b'https'),"
                   "                (b':authority', b'127.0.0.1'),"
                   "                (b':path', b'/'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s ecn_acks=%s' % (client._status, body, client._terminated, ecn_acks['n']))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ack-ecn-test (port)
  "RFC 9000 §19.3. An implementation handles both ACK frame types. Type
0x03 carries ECN counts. Those counts do not close the connection, and
GET / still returns pazuzu."
  (let ((script (quic-ack-ecn-script)))
    (check "an ACK frame with ECN counts is accepted"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (not (search "ecn_acks=0" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-packet-number-script ()
  "Client that records every server packet number while reading /flow-conn."
  (let ((script "/tmp/pazuzu-h3-pn.py"))
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
                   "        self._body = b''"
                   "        self._status = None"
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
                   "def packet_numbers(trace):"
                   "    groups = {}"
                   "    for event in trace._events:"
                   "        if event['name'] != 'transport:packet_received':"
                   "            continue"
                   "        header = event['data'].get('header') or {}"
                   "        kind = header.get('packet_type')"
                   "        number = header.get('packet_number')"
                   "        if kind not in ('initial', 'handshake', '1RTT') or number is None:"
                   "            continue"
                   "        groups.setdefault(kind, []).append(number)"
                   "    return groups"
                   ""
                   "def increasing(numbers):"
                   "    return all(b > a for a, b in zip(numbers, numbers[1:]))"
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
                   "                (b':path', b'/flow-conn'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            for _ in range(40):"
                   "                if len(client._body) >= 65536:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            groups = packet_numbers(client._quic._quic_logger)"
                   "            one = groups.get('1RTT', [])"
                   "            spaces_ok = all(increasing(nums) for nums in groups.values())"
                   "            grew = len(one) >= 2 and increasing(one) and spaces_ok"
                   "            sample = ','.join(str(n) for n in one[:8])"
                   "            print('RESULT status=%s bodylen=%s closed=%s packets=%s increasing=%s spaces_ok=%s sample=%s' % (client._status, len(client._body), client._terminated, len(one), grew, spaces_ok, sample or '-'))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-packet-number-test (port)
  "RFC 9000 §12.3. Packet numbers in one space start at any value and each
later packet uses a number at least one higher. A number is not reused.
GET /flow-conn draws more than one 1-RTT packet."
  (let ((script (quic-packet-number-script)))
    (check "server packet numbers in one space increase and are not reused"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 bodylen=65536 closed=None" out)
                     (search "increasing=True" out)
                     (search "spaces_ok=True" out)
                     (not (search "packets=0 " out))
                     (not (search "packets=1 " out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ack-only-script ()
  "Client that sends one PING after GET / and counts ACK-only replies."
  (let ((script "/tmp/pazuzu-h3-ack-only.py"))
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
                   "        self._body = b''"
                   "        self._status = None"
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
                   "def reply_counts(events):"
                   "    ack_only = 0"
                   "    acked = 0"
                   "    for event in events:"
                   "        if event['name'] != 'transport:packet_received':"
                   "            continue"
                   "        frames = event['data'].get('frames') or []"
                   "        types = [frame.get('frame_type') for frame in frames]"
                   "        if 'ack' in types:"
                   "            acked += 1"
                   "        if types and all(kind in ('ack', 'padding') for kind in types):"
                   "            ack_only += 1"
                   "    return ack_only, acked"
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
                   "            await asyncio.sleep(0.2)"
                   "            trace = client._quic._quic_logger"
                   "            mark = len(trace._events)"
                   "            client._quic.send_ping(7)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.4)"
                   "            ack_only, acked = reply_counts(list(trace._events)[mark:])"
                   "            ok = ack_only <= 1 and acked >= 1"
                   "            body = client._body.decode('ascii', 'replace') or '-'"
                   "            print('RESULT status=%s body=%s closed=%s ack_only=%s acked=%s ack_only_ok=%s' % (client._status, body, client._terminated, ack_only, acked, ok))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ack-only-test (port)
  "RFC 9000 §13.2.1. An ack-eliciting packet draws at most one packet that
contains only ACK frames. The acknowledgement still arrives."
  (let ((script (quic-ack-only-script)))
    (check "an ack-eliciting packet draws at most one ACK-only packet"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT status=200 body=pazuzu closed=None" out)
                     (search "ack_only_ok=True" out)
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ack-feedback-script ()
  "Client that sends one ACK of a packet the server already sent."
  (let ((script "/tmp/pazuzu-h3-ack-feedback.py"))
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
                   "        self._watch = False"
                   "        self._seen = 0"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        if self._watch:"
                   "            self._seen += 1"
                   "        super().datagram_received(data, addr)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def send_ack(client):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    space = quic._spaces[Epoch.ONE_RTT]"
                   "    largest = space.largest_received_packet"
                   "    if largest < 0 or largest >= 64:"
                   "        raise RuntimeError('largest %s' % largest)"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    payload = bytes([0x02, largest, 0x00, 0x00, 0x00])"
                   "    packet = crypto.encrypt_packet(header, payload, pn)"
                   "    client._transport.sendto(packet, quic._network_paths[0].addr)"
                   "    return largest"
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
                   "            await asyncio.sleep(0.2)"
                   "            client._seen = 0"
                   "            client._watch = True"
                   "            largest = send_ack(client)"
                   "            await asyncio.sleep(0.4)"
                   "            print('RESULT largest=%s replies=%s closed=%s' % (largest, client._seen, client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ack-feedback-test (port)
  "RFC 9000 §13.2.1. A packet that is not ack-eliciting does not draw a
non-ack-eliciting packet. An ACK of a packet the server sent leaves the
connection idle and open."
  (let ((script (quic-ack-feedback-script)))
    (check "a non-ack-eliciting packet draws no further packet"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT " out)
                     (search "replies=0 " out)
                     (search "closed=None" out)
                     (not (search "largest=-1" out))
                     (not (search "ERR " out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-unsupported-packet (&optional (total 1200))
  "A long header of TOTAL bytes. Version is 0x0a0a0a0a, DCID is 1..8, SCID is 9..16."
  (let ((packet (make-array total :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace packet #(#xc0 #x0a #x0a #x0a #x0a
                      8 1 2 3 4 5 6 7 8
                      8 9 10 11 12 13 14 15 16))
    packet))

(defun quic-version-negotiation-packet ()
  "A 1200-byte Version Negotiation packet. The version field is 0."
  (let ((packet (make-array 1200 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace packet #(#xc0 0 0 0 0
                      8 1 2 3 4 5 6 7 8
                      8 9 10 11 12 13 14 15 16
                      0 0 0 1))
    packet))

(defun quic-vn-cids (packet)
  "DCID, SCID, and the supported-version list of a Version Negotiation packet."
  (when (and packet (>= (length packet) 7)
             (logtest (aref packet 0) #x80)
             (zerop (aref packet 1)) (zerop (aref packet 2))
             (zerop (aref packet 3)) (zerop (aref packet 4)))
    (let* ((dcid-len (aref packet 5))
           (dcid-end (+ 6 dcid-len)))
      (when (and (<= dcid-end (1- (length packet))))
        (let* ((scid-len (aref packet dcid-end))
               (scid-end (+ dcid-end 1 scid-len)))
          (when (and (<= scid-end (length packet))
                     (zerop (mod (- (length packet) scid-end) 4)))
            (values (subseq packet 6 dcid-end)
                    (subseq packet (1+ dcid-end) scid-end)
                    (loop for index from scid-end below (length packet) by 4
                          collect (logior (ash (aref packet index) 24)
                                          (ash (aref packet (+ index 1)) 16)
                                          (ash (aref packet (+ index 2)) 8)
                                          (aref packet (+ index 3)))))))))))

(defun quic-unsupported-cids (dcid scid)
  "A 1200-byte long header, version 0x0a0a0a0a, with these connection IDs."
  (let* ((head (concatenate '(vector (unsigned-byte 8))
                            #(#xc0 #x0a #x0a #x0a #x0a)
                            (vector (length dcid))
                            dcid
                            (vector (length scid))
                            scid))
         (packet (make-array 1200 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace packet head)
    packet))

(defun quic-version-negotiation-length-test (port)
  "RFC 9000 §17.2.1. A connection ID shorter than 8 bytes, longer than 20
bytes, or empty still receives a Version Negotiation packet."
  (check "Version Negotiation ignores connection ID length limits"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
          (empty (make-array 0 :element-type '(unsigned-byte 8)))
          (one-a (coerce #(#x11) '(vector (unsigned-byte 8))))
          (one-b (coerce #(#x22) '(vector (unsigned-byte 8))))
          (long-a (coerce (loop for index below 21 collect index)
                          '(vector (unsigned-byte 8))))
          (long-b (coerce (loop for index from 50 below 71 collect index)
                          '(vector (unsigned-byte 8)))))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (dolist (pair (list (list empty empty)
                                 (list one-a one-b)
                                 (list long-a long-b)))
               (destructuring-bind (dcid scid) pair
                 (sb-bsd-sockets:socket-send socket (quic-unsupported-cids dcid scid) nil
                                             :address (list #(127 0 0 1) port))
                 (let ((reply (quic-recv-packet socket :seconds 2)))
                   (multiple-value-bind (reply-dcid reply-scid versions) (quic-vn-cids reply)
                     (unless (and reply-dcid
                                  (equalp reply-dcid scid)
                                  (equalp reply-scid dcid)
                                  (member 1 versions))
                       (fail "dcid ~s scid ~s reply-dcid ~s reply-scid ~s versions ~s packet ~s"
                             dcid scid reply-dcid reply-scid versions reply))))
                 (when (quic-recv-packet socket :seconds 0.2)
                   (fail "a second datagram followed a ~d-byte connection ID"
                         (length dcid))))))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-version-negotiation-cid-test (port)
  "RFC 9000 §17.2.1. Destination Connection ID is the client's Source
Connection ID. Source Connection ID is the client's Destination Connection
ID. One request datagram produces one Version Negotiation packet."
  (check "a Version Negotiation packet echoes connection IDs"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-unsupported-packet) nil
                                         :address (list #(127 0 0 1) port))
             (let ((reply (quic-recv-packet socket :seconds 2)))
               (multiple-value-bind (dcid scid versions) (quic-vn-cids reply)
                 (unless (and dcid
                              (equalp dcid #(9 10 11 12 13 14 15 16))
                              (equalp scid #(1 2 3 4 5 6 7 8))
                              (member 1 versions))
                   (fail "reply ~s dcid ~s scid ~s versions ~s"
                         reply dcid scid versions))))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "a second datagram followed Version Negotiation")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-expect-version-negotiation (socket port)
  "Send a full-size unsupported version and require one Version Negotiation packet."
  (sb-bsd-sockets:socket-send socket (quic-unsupported-packet) nil
                              :address (list #(127 0 0 1) port))
  (let ((reply (quic-recv-packet socket :seconds 2)))
    (multiple-value-bind (dcid scid versions) (quic-vn-cids reply)
      (declare (ignore scid versions))
      dcid)))

(defun quic-short-version-test (port)
  "RFC 9000 §5.2.2. An unsupported version in a datagram under 1200 bytes is dropped."
  (check "a short unsupported QUIC version is discarded"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-unsupported-packet 1199) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "short unsupported version was answered"))
             (unless (quic-expect-version-negotiation socket port)
               (fail "full unsupported version was not answered")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-version-negotiation-reply-test (port)
  "RFC 9000 §6.1. A Version Negotiation packet is not answered with another."
  (check "a Version Negotiation packet is not answered"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-version-negotiation-packet) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "Version Negotiation packet was answered"))
             (unless (quic-expect-version-negotiation socket port)
               (fail "listener did not answer an unsupported version")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-incoming-retry-packet ()
  "A 1200-byte QUIC v1 Retry. DCID is 1..8 and SCID is 9..16. The last
16 octets are the integrity tag."
  (let ((packet (make-array 1200 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace packet #(#xf0 0 0 0 1
                      8 1 2 3 4 5 6 7 8
                      8 9 10 11 12 13 14 15 16))
    packet))

(defun quic-incoming-retry-test (port)
  "RFC 9000 §5.2.2. A version-1 Retry packet is not an Initial and matches
no connection, so the server drops it. A later Initial is answered."
  (check "an incoming Retry packet is dropped"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket (quic-incoming-retry-packet) nil
                                         :address (list #(127 0 0 1) port))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "an incoming Retry packet was answered"))
             (unless (quic-answered-initial-p socket port)
               (fail "an Initial after a dropped Retry was not answered")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-application-protocol-script ()
  "Offer h2 on the QUIC listener, then complete an HTTP/3 GET."
  (let ((script "/tmp/pazuzu-h3-alpn.py"))
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
                   "class Probe(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.terminated = None"
                   "        self.handshake = False"
                   "        self.status = None"
                   "        self.body = b''"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.terminated = event.error_code"
                   "        elif isinstance(event, HandshakeCompleted):"
                   "            self.handshake = True"
                   "        if self.handshake and self._quic.configuration.alpn_protocols == H3_ALPN:"
                   "            if not hasattr(self, '_http'):"
                   "                self._http = H3Connection(self._quic)"
                   "                self._http.send_headers(0, ["
                   "                    (b':method', b'GET'),"
                   "                    (b':scheme', b'https'),"
                   "                    (b':authority', b'127.0.0.1'),"
                   "                    (b':path', b'/'),"
                   "                ], end_stream=True)"
                   "                self.transmit()"
                   "            for http_event in self._http.handle_event(event):"
                   "                if isinstance(http_event, HeadersReceived):"
                   "                    for name, value in http_event.headers:"
                   "                        if name == b':status':"
                   "                            self.status = int(value)"
                   "                elif isinstance(http_event, DataReceived):"
                   "                    self.body += http_event.data"
                   ""
                   "async def attempt(port, alpn, label):"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=alpn,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    holder = {}"
                   "    def factory(connection, stream_handler=None):"
                   "        client = Probe(connection, stream_handler=stream_handler)"
                   "        holder['client'] = client"
                   "        return client"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration,"
                   "                           create_protocol=factory, wait_connected=True) as client:"
                   "            for _ in range(40):"
                   "                if client.status is not None or client.terminated is not None:"
                   "                    break"
                   "                client.transmit()"
                   "                await asyncio.sleep(0.05)"
                   "    except Exception as exc:"
                   "        print('EXC %s %s' % (label, type(exc).__name__))"
                   "    client = holder.get('client')"
                   "    if client is None:"
                   "        print('RESULT %s missing' % label)"
                   "    else:"
                   "        print('RESULT %s handshake=%s closed=%s status=%s body=%s' % ("
                   "            label, client.handshake, client.terminated, client.status, client.body))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    await attempt(port, ['h2'], 'H2')"
                   "    await attempt(port, H3_ALPN, 'H3')"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-application-protocol-test (port)
  "RFC 9000 §7. Endpoints must negotiate an application protocol. The QUIC
listener selects only h3, so an offer of h2 does not complete the handshake
and closes with PROTOCOL_VIOLATION (0x0a). A later HTTP/3 GET still returns
pazuzu."
  (let ((script (quic-application-protocol-script)))
    (check "a QUIC handshake that offers only h2 does not complete"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "RESULT H2 handshake=False closed=10" out)
                     (search "RESULT H3 handshake=True" out)
                     (search "status=200" out)
                     (search "body=b'pazuzu'" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retry-cids (packet)
  "DCID and SCID of a QUIC v1 Retry packet, or NIL."
  (when (and packet (>= (length packet) 7)
             (= (logand (aref packet 0) #xf0) #xf0)
             (zerop (aref packet 1)) (zerop (aref packet 2))
             (zerop (aref packet 3)) (= (aref packet 4) 1))
    (let* ((dcid-len (aref packet 5))
           (dcid-end (+ 6 dcid-len)))
      (when (<= dcid-end (1- (length packet)))
        (let* ((scid-len (aref packet dcid-end))
               (scid-end (+ dcid-end 1 scid-len)))
          (when (<= scid-end (length packet))
            (values (subseq packet 6 dcid-end)
                    (subseq packet (1+ dcid-end) scid-end))))))))

(defun quic-retry-test (port)
  "RFC 9000 §17.2.5.1. Retry Destination Connection ID is the client's
Source Connection ID. The server's Source Connection ID is not the
client's Destination Connection ID. One Initial produces one Retry, and
that Retry is at most three times the Initial (RFC 9000 §8.1)."
  (check "a Retry packet chooses a new Source Connection ID"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
          (initial (quic-initial-packet 1200)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             (sb-bsd-sockets:socket-send socket initial nil
                                         :address (list #(127 0 0 1) port))
             (let ((reply (quic-recv-packet socket :seconds 2)))
               (multiple-value-bind (dcid scid) (quic-retry-cids reply)
                 (unless (and reply dcid
                              (equalp dcid #(9 10 11 12 13 14 15 16))
                              (plusp (length scid))
                              (not (equalp scid #(1 2 3 4 5 6 7 8)))
                              (<= (length reply) (* 3 (length initial))))
                   (fail "reply ~s dcid ~s scid ~s" reply dcid scid))))
             (when (quic-recv-packet socket :seconds 0.4)
               (fail "a second datagram followed Retry")))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun quic-version-negotiation-test (port)
  (check "QUIC version negotiation"
    (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp))
          (packet (make-array 1200 :element-type '(unsigned-byte 8) :initial-element 0)))
      (unwind-protect
           (progn
             (setf (sb-bsd-sockets:non-blocking-mode socket) t)
             ;; RFC 9000: a Version Negotiation packet is sent only for a
             ;; long-header datagram of at least 1200 bytes.
             (replace packet #(#xc0 #x0a #x0a #x0a #x0a
                               8 1 2 3 4 5 6 7 8
                               8 9 10 11 12 13 14 15 16))
             (sb-bsd-sockets:socket-send socket packet nil
                                         :address (list #(127 0 0 1) port))
             (let ((buffer (make-array 1500 :element-type '(unsigned-byte 8)))
                   (deadline (+ (get-internal-real-time) (* 2 internal-time-units-per-second)))
                   (got nil))
               (loop while (< (get-internal-real-time) deadline)
                     do (multiple-value-bind (buf len)
                            (handler-case
                                (sb-bsd-sockets:socket-receive socket buffer nil
                                                               :dontwait t
                                                               :element-type '(unsigned-byte 8))
                              (sb-bsd-sockets:interrupted-error ()
                                (values nil 0)))
                          (when (and buf len (>= len 7) (logtest (aref buf 0) #x80)
                                     (zerop (aref buf 1)) (zerop (aref buf 2))
                                     (zerop (aref buf 3)) (zerop (aref buf 4)))
                            (setf got buf)
                            (return)))
                        (sleep 0.02))
               (unless got
                 (fail "no version negotiation packet"))))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

