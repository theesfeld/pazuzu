;;; QUIC client scripts and early transport checks.

(in-package #:pazuzu/tests)

(defun quic-client-frame-script ()
  "Client that sends one forbidden 1-RTT frame named by argv[2]."
  (let ((script "/tmp/pazuzu-h3-new-token.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "MODE = sys.argv[2] if len(sys.argv) > 2 else 'new-token'"
                   "LABEL = {'new-token': 'TOKEN', 'crypto-offset': 'CRYPTO', 'stream-offset': 'STREAM', 'stream-limit': 'STREAMLIM', 'reset-limit': 'RESETLIM', 'stream-count': 'SCOUNT', 'uni-count': 'UCOUNT', 'conn-data': 'CONNDATA', 'unknown-frame': 'UNKFRAME', 'ack-range': 'ACKRANGE', 'stream-sendonly': 'SENDONLY', 'reset-sendonly': 'RESETSEND', 'stop-sending': 'STOP', 'max-stream-data': 'MSD', 'msd-local': 'MSDLOCAL', 'stream-data-blocked': 'SDB', 'retire-prior': 'RETIRE', 'cid-len0': 'CID0', 'cid-len21': 'CID21', 'retire-seq': 'RSEQ', 'max-streams': 'MAXSTREAMS', 'streams-blocked': 'SBLOCKED', 'local-stream': 'LOCAL', 'stop-local': 'STOPLOCAL'}.get(MODE, 'DONE')"
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
                   "            if MODE == 'new-token':"
                   "                buf = builder.start_frame(QuicFrameType.NEW_TOKEN, capacity=8)"
                   "                buf.push_uint_var(2)"
                   "                buf.push_bytes(b'ab')"
                   "            elif MODE == 'crypto-offset':"
                   "                buf = builder.start_frame(QuicFrameType.CRYPTO, capacity=11)"
                   "                buf.push_uint_var((1 << 62) - 1)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'stream-offset':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 6, capacity=12)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var((1 << 62) - 1)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'stream-limit':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 6, capacity=8)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(256 * 1024)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'reset-limit':"
                   "                buf = builder.start_frame(QuicFrameType.RESET_STREAM, capacity=7)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(256 * 1024 + 1)"
                   "            elif MODE == 'stream-count':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=5)"
                   "                buf.push_uint_var(400)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'uni-count':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=4)"
                   "                buf.push_uint_var(34)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'conn-data':"
                   "                for sid in (0, 4, 8, 12):"
                   "                    buf = builder.start_frame(QuicFrameType.STREAM_BASE | 6, capacity=8)"
                   "                    buf.push_uint_var(sid)"
                   "                    buf.push_uint_var(256 * 1024 - 1)"
                   "                    buf.push_uint_var(1)"
                   "                    buf.push_bytes(b'x')"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=4)"
                   "                buf.push_uint_var(16)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'unknown-frame':"
                   "                builder.start_frame(0x20, capacity=1)"
                   "            elif MODE == 'ack-range':"
                   "                buf = builder.start_frame(QuicFrameType.ACK, capacity=5)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(1)"
                   "            elif MODE == 'stream-sendonly':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=4)"
                   "                buf.push_uint_var(3)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'reset-sendonly':"
                   "                buf = builder.start_frame(QuicFrameType.RESET_STREAM, capacity=8)"
                   "                buf.push_uint_var(3)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(0)"
                   "            elif MODE == 'stop-sending':"
                   "                buf = builder.start_frame(QuicFrameType.STOP_SENDING, capacity=3)"
                   "                buf.push_uint_var(2)"
                   "                buf.push_uint_var(0)"
                   "            elif MODE == 'max-stream-data':"
                   "                buf = builder.start_frame(QuicFrameType.MAX_STREAM_DATA, capacity=3)"
                   "                buf.push_uint_var(2)"
                   "                buf.push_uint_var(1)"
                   "            elif MODE == 'msd-local':"
                   "                buf = builder.start_frame(QuicFrameType.MAX_STREAM_DATA, capacity=3)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_uint_var(1)"
                   "            elif MODE == 'stream-data-blocked':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_DATA_BLOCKED, capacity=3)"
                   "                buf.push_uint_var(3)"
                   "                buf.push_uint_var(0)"
                   "            elif MODE == 'retire-prior':"
                   "                buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=28)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_uint8(8)"
                   "                buf.push_bytes(b'abcdefgh')"
                   "                buf.push_bytes(b'0123456789abcdef')"
                   "            elif MODE == 'cid-len0':"
                   "                buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=20)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint8(0)"
                   "                buf.push_bytes(b'0123456789abcdef')"
                   "            elif MODE == 'cid-len21':"
                   "                buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=20)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_uint_var(0)"
                   "                buf.push_uint8(21)"
                   "                buf.push_bytes(b'0123456789abcdef')"
                   "            elif MODE == 'retire-seq':"
                   "                buf = builder.start_frame(QuicFrameType.RETIRE_CONNECTION_ID, capacity=3)"
                   "                buf.push_uint_var(100)"
                   "            elif MODE == 'max-streams':"
                   "                buf = builder.start_frame(QuicFrameType.MAX_STREAMS_BIDI, capacity=9)"
                   "                buf.push_uint_var((1 << 60) + 1)"
                   "            elif MODE == 'streams-blocked':"
                   "                buf = builder.start_frame(QuicFrameType.STREAMS_BLOCKED_BIDI, capacity=9)"
                   "                buf.push_uint_var((1 << 60) + 1)"
                   "            elif MODE == 'local-stream':"
                   "                buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=4)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_bytes(b'x')"
                   "            elif MODE == 'stop-local':"
                   "                buf = builder.start_frame(QuicFrameType.STOP_SENDING, capacity=3)"
                   "                buf.push_uint_var(1)"
                   "                buf.push_uint_var(0)"
                   "            else:"
                   "                builder.start_frame(QuicFrameType.HANDSHAKE_DONE, capacity=1)"
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
                   "            state = arm_frame(client._quic)"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            print('SENT %s' % state['sent'])"
                   "            try:"
                   "                code = await asyncio.wait_for(client._done, 3)"
                   "            except TimeoutError:"
                   "                code = client._terminated"
                   "            print('%s closed=%s' % (LABEL, code))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-client-new-token-test (port)
  "RFC 9000 §19.7. A client NEW_TOKEN frame is PROTOCOL_VIOLATION (0x0a)."
  (let ((script (quic-client-frame-script)))
    (check "a client NEW_TOKEN frame is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "new-token")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "TOKEN closed=10" out))
          (fail "exit ~s out ~s err ~s" code out err))))
    (check "a client HANDSHAKE_DONE frame is a connection error"
      ;; RFC 9000 §19.20. Only a server sends HANDSHAKE_DONE.
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "handshake-done")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "DONE closed=10" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-crypto-offset-test (port)
  "RFC 9000 §19.6. A CRYPTO frame whose offset plus length passes 2^62-1
is FRAME_ENCODING_ERROR (0x07)."
  (let ((script (quic-client-frame-script)))
    (check "a CRYPTO offset past 2^62-1 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "crypto-offset")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "CRYPTO closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-uni-count-test (port)
  "RFC 9000 §§4.6 and 19.11. A STREAM frame above the advertised
unidirectional stream limit (8) is STREAM_LIMIT_ERROR (0x04).
Stream 34 is the 9th client-initiated unidirectional stream."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM frame above the unidirectional stream limit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "uni-count")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "UCOUNT closed=4" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-connection-data-test (port)
  "RFC 9000 §§4.1 and 19.9. The sum of received STREAM offsets past the
advertised connection data limit (1 MiB) is FLOW_CONTROL_ERROR (0x03).
Each stream ends at the 256 KiB stream window, so four of them fill the
connection window and a fifth byte exceeds it."
  (let ((script (quic-client-frame-script)))
    (check "a sum of STREAM offsets past the connection data limit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "conn-data")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "CONNDATA closed=3" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-unknown-frame-test (port)
  "RFC 9000 §12.4. A frame type this version does not define is
FRAME_ENCODING_ERROR (0x07). Type 0x20 is not a QUIC v1 frame."
  (let ((script (quic-client-frame-script)))
    (check "an unknown QUIC frame type is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "unknown-frame")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "UNKFRAME closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ack-range-test (port)
  "RFC 9000 §19.3.1. An ACK First ACK Range larger than Largest
Acknowledged makes the smallest packet number negative and is
FRAME_ENCODING_ERROR (0x07)."
  (let ((script (quic-client-frame-script)))
    (check "an ACK range below packet number 0 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "ack-range")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "ACKRANGE closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-connection-id-sequence-script ()
  "Client that records the sequence numbers of connection IDs the server issues."
  (let ((script "/tmp/pazuzu-h3-cid-sequence.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import QuicProtocolVersion"
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
                   "        async with connect('127.0.0.1', port, configuration=configuration) as client:"
                   "            seqs = sorted(client._quic._peer_cid_sequence_numbers)"
                   "            limit = client._quic._local_active_connection_id_limit"
                   "            step = (len(seqs) >= 2 and seqs[0] == 0 and"
                   "                    all(b == a + 1 for a, b in zip(seqs, seqs[1:])))"
                   "            print('SEQS %s' % seqs)"
                   "            print('STEP %s' % step)"
                   "            print('COUNT %s' % len(seqs))"
                   "            print('LIMIT %s' % limit)"
                   "            print('WITHIN %s' % (len(seqs) <= limit))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-connection-id-sequence-test (port)
  "RFC 9000 §5.1.1. The initial connection ID is sequence 0. Each
connection ID the server issues after that increases the sequence
number by 1. The server does not issue more connection IDs than the
client's active_connection_id_limit."
  (let ((script (quic-connection-id-sequence-script)))
    (multiple-value-bind (out err code)
        (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                          :output :string :error-output :string :ignore-error-status t)
      (check "issued connection ID sequence numbers increase by 1"
        (unless (and code (zerop code)
                     (search "STEP True" out))
          (fail "exit ~s out ~s err ~s" code out err)))
      (check "issued connection IDs stay within the peer limit"
        (unless (and code (zerop code)
                     (search "WITHIN True" out)
                     (search "STEP True" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-issued-connection-id-script ()
  "Client that sends one HTTP/3 request using a server-issued connection
ID that it has not retired."
  (let ((script "/tmp/pazuzu-h3-issued-cid.py"))
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
                   "        self._events = {}"
                   "        self._waiters = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            stream_id = getattr(http_event, 'stream_id', None)"
                   "            if stream_id is None:"
                   "                continue"
                   "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        bucket['status'] = int(value)"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                bucket['data'] += http_event.data"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   ""
                   "    def _finish(self, stream_id):"
                   "        waiter = self._waiters.get(stream_id)"
                   "        if waiter is not None and not waiter.done():"
                   "            waiter.set_result(self._events[stream_id])"
                   ""
                   "    async def request(self):"
                   "        stream_id = self._quic.get_next_available_stream_id()"
                   "        waiter = self._loop.create_future()"
                   "        self._waiters[stream_id] = waiter"
                   "        self._http.send_headers(stream_id, ["
                   "            (b':method', b'GET'),"
                   "            (b':scheme', b'https'),"
                   "            (b':authority', b'127.0.0.1'),"
                   "            (b':path', b'/'),"
                   "        ], end_stream=True)"
                   "        self.transmit()"
                   "        return await asyncio.wait_for(waiter, 5)"
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
                   "            old = quic._peer_cid"
                   "            spare = next(cid for cid in quic._peer_cid_available if cid.cid != old.cid)"
                   "            quic._peer_cid_available.remove(spare)"
                   "            quic._peer_cid = spare"
                   "            different = spare.cid != old.cid and spare.sequence_number != old.sequence_number"
                   "            got = await client.request()"
                   "            print('FROM %s' % old.sequence_number)"
                   "            print('TO %s' % spare.sequence_number)"
                   "            print('DIFFERENT %s' % different)"
                   "            print('UNRETIRED %s' % (not quic._retire_connection_ids))"
                   "            print('GET %s %s' % (got['status'], got['data'].decode()))"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-issued-connection-id-test (port)
  "RFC 9000 §5.1.1. A connection ID the server has issued is accepted
on a 1-RTT packet until the client retires it. The request uses an
issued connection ID other than the handshake destination, and the
client does not send RETIRE_CONNECTION_ID."
  (let ((script (quic-issued-connection-id-script)))
    (check "an issued connection ID is accepted before retirement"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "DIFFERENT True" out)
                     (search "UNRETIRED True" out)
                     (search "GET 200 pazuzu" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retire-late-sequence-script ()
  "Client that sends a NEW_CONNECTION_ID with a high Retire Prior To, then one
whose sequence number is below that value and was not issued before, and
records the retirement."
  (let ((script "/tmp/pazuzu-h3-retire-late.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnectionId"
                   "from aioquic.quic.events import ConnectionIdRetired, ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "LATE = b'ijklmnop'"
                   "FRESH = b'abcdefgh'"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._retired = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        elif isinstance(event, ConnectionIdRetired):"
                   "            self._retired.append(event.connection_id)"
                   ""
                   "def arm(quic):"
                   "    late_seq = quic._host_cid_seq"
                   "    fresh_seq = late_seq + 1"
                   "    quic._remote_active_connection_id_limit = 2"
                   "    quic._host_cids.append(QuicConnectionId(cid=LATE, sequence_number=late_seq, stateless_reset_token=b'1'*16, was_sent=True))"
                   "    quic._host_cids.append(QuicConnectionId(cid=FRESH, sequence_number=fresh_seq, stateless_reset_token=b'5'*16, was_sent=True))"
                   "    quic._host_cid_seq = fresh_seq + 1"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(fresh_seq)"
                   "            buf.push_uint_var(fresh_seq)"
                   "            buf.push_uint8(8)"
                   "            buf.push_bytes(FRESH)"
                   "            buf.push_bytes(b'0123456789abcdef')"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(late_seq)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint8(8)"
                   "            buf.push_bytes(LATE)"
                   "            buf.push_bytes(b'fedcba9876543210')"
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
                   "            for _ in range(20):"
                   "                if LATE in client._retired or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            print('SENT %s' % state['sent'])"
                   "            print('LATE %s' % (LATE in client._retired))"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-retire-late-sequence-test (port)
  "RFC 9000 §19.15. A NEW_CONNECTION_ID whose sequence number is smaller
than the Retire Prior To of a NEW_CONNECTION_ID already received is
answered with RETIRE_CONNECTION_ID for that sequence number."
  (let ((script (quic-retire-late-sequence-script)))
    (check "a NEW_CONNECTION_ID below Retire Prior To is retired"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "LATE True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-empty-packet-script ()
  "Client that sends one 1-RTT packet whose payload contains no frames."
  (let ((script "/tmp/pazuzu-h3-empty-packet.py"))
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
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "def send_empty(client):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    packet = crypto.encrypt_packet(header, b'', pn)"
                   "    client._transport.sendto(packet, quic._network_paths[0].addr)"
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
                   "            sent = send_empty(client)"
                   "            print('SENT %s' % sent)"
                   "            try:"
                   "                code = await asyncio.wait_for(client._done, 3)"
                   "            except TimeoutError:"
                   "                code = client._terminated"
                   "            print('EMPTY closed=%s' % code)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-empty-packet-test (port)
  "RFC 9000 §12.4. A 1-RTT packet whose payload contains no frames is
PROTOCOL_VIOLATION (0x0a)."
  (let ((script (quic-empty-packet-script)))
    (check "a 1-RTT packet containing no frames is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "EMPTY closed=10" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reserved-bits-script ()
  "Client that sends a 1-RTT PING, then one whose reserved bits are set."
  (let ((script "/tmp/pazuzu-h3-reserved-bits.py"))
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
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "def send_ping(client, reserved):"
                   "    quic = client._quic"
                   "    crypto = quic._cryptos[Epoch.ONE_RTT]"
                   "    pn = quic._packet_number"
                   "    quic._packet_number = pn + 1"
                   "    first = 0x40 | ((crypto.key_phase & 1) << 2) | 0x03"
                   "    if reserved:"
                   "        first = first | 0x08"
                   "    header = bytes([first]) + quic._peer_cid.cid + pn.to_bytes(4, 'big')"
                   "    packet = crypto.encrypt_packet(header, bytes([0x01]), pn)"
                   "    client._transport.sendto(packet, quic._network_paths[0].addr)"
                   "    return True"
                   ""
                   "async def once(port, reserved):"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    label = 'RESERVED' if reserved else 'PLAIN'"
                   "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "        sent = send_ping(client, reserved)"
                   "        print('SENT %s %s' % (label, sent))"
                   "        try:"
                   "            code = await asyncio.wait_for(client._done, 2.5 if reserved else 0.8)"
                   "        except TimeoutError:"
                   "            code = client._terminated"
                   "        print('%s closed=%s' % (label, code))"
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

(defun quic-reserved-bits-test (port)
  "RFC 9000 §17.3.1. The reserved bits of a 1-RTT packet (mask 0x18) are
zero before header protection. After that protection is removed, a
non-zero value is PROTOCOL_VIOLATION (0x0a). A PING with those bits
clear does not close the connection."
  (let ((script (quic-reserved-bits-script)))
    (check "a 1-RTT packet with a non-zero reserved bit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT PLAIN True" out)
                     (search "PLAIN closed=None" out)
                     (search "SENT RESERVED True" out)
                     (search "RESERVED closed=10" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-long-reserved-bits-script ()
  "Client that sets a reserved bit on its first Handshake packet."
  (let ((script "/tmp/pazuzu-h3-long-reserved.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicPacketType, QuicProtocolVersion"
                   "import aioquic.quic.packet_builder as packet_builder"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._done = self._loop.create_future()"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "            if not self._done.done():"
                   "                self._done.set_result(event.error_code)"
                   ""
                   "def configuration():"
                   "    return QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   ""
                   "def arm_handshake_bit():"
                   "    state = {'armed': False}"
                   "    orig = packet_builder.encode_long_header_first_byte"
                   "    def encode(version, packet_type, bits):"
                   "        value = orig(version, packet_type, bits)"
                   "        if not state['armed'] and packet_type == QuicPacketType.HANDSHAKE:"
                   "            state['armed'] = True"
                   "            value = value | 0x04"
                   "        return value"
                   "    packet_builder.encode_long_header_first_byte = encode"
                   "    return state"
                   ""
                   "async def plain(port):"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=Client) as client:"
                   "        print('PLAIN closed=%s' % client._terminated)"
                   ""
                   "async def reserved(port):"
                   "    state = arm_handshake_bit()"
                   "    async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=Client, wait_connected=False) as client:"
                   "        client.transmit()"
                   "        try:"
                   "            code = await asyncio.wait_for(client._done, 3)"
                   "        except TimeoutError:"
                   "            code = client._terminated"
                   "        print('RESERVED closed=%s armed=%s' % (code, state['armed']))"
                   ""
                   "async def main():"
                   "    port = int(sys.argv[1])"
                   "    try:"
                   "        await plain(port)"
                   "        await reserved(port)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-long-reserved-bits-test (port)
  "RFC 9000 §17.2. The reserved bits of a long-header packet (mask 0x0c)
are zero before header protection. After that protection is removed, a
non-zero value is PROTOCOL_VIOLATION (0x0a). A handshake with those bits
clear leaves the connection open."
  (let ((script (quic-long-reserved-bits-script)))
    (check "a Handshake packet with a non-zero reserved bit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "PLAIN closed=None" out)
                     (search "RESERVED closed=10" out)
                     (search "armed=True" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-duplicate-connection-id-script ()
  "Client that repeats a NEW_CONNECTION_ID it already sent."
  (let ((script "/tmp/pazuzu-h3-duplicate-cid.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
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
                   "def arm(quic):"
                   "    issued = next(c for c in quic._host_cids if c.sequence_number > 0 and c.stateless_reset_token)"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(issued.sequence_number)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint8(len(issued.cid))"
                   "            buf.push_bytes(issued.cid)"
                   "            buf.push_bytes(issued.stateless_reset_token)"
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
                   "            await asyncio.wait_for(client.ping(), 3)"
                   "            print('SENT %s' % state['sent'])"
                   "            print('PING True')"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-duplicate-connection-id-test (port)
  "RFC 9000 §19.15. Receiving the same NEW_CONNECTION_ID frame again is
not a connection error."
  (let ((script (quic-duplicate-connection-id-script)))
    (check "a repeated NEW_CONNECTION_ID frame is not a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "PING True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-connection-id-limit-script ()
  "Client that has already filled the server's active connection ID limit,
then sends one more NEW_CONNECTION_ID with Retire Prior To 0."
  (let ((script "/tmp/pazuzu-h3-cid-limit.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "CID = b'limitcid'"
                   "TOKEN = b'0123456789abcdef'"
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
                   "def arm(quic):"
                   "    seq = quic._host_cid_seq"
                   "    have = len(quic._host_cids)"
                   "    limit = quic._remote_active_connection_id_limit"
                   "    flags = [bool(c.was_sent) for c in quic._host_cids]"
                   "    fresh = CID not in [c.cid for c in quic._host_cids]"
                   "    filled = have == limit and have >= 2 and all(flags) and seq == have and fresh"
                   "    original = quic._write_application"
                   "    state = {'sent': False, 'filled': filled}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(seq)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint8(len(CID))"
                   "            buf.push_bytes(CID)"
                   "            buf.push_bytes(TOKEN)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   "    return state"
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
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=Client) as client:"
                   "            await asyncio.wait_for(client.ping(), 3)"
                   "            state = arm(client._quic)"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.5)"
                   "            print('CIDLIMIT sent=%s filled=%s closed=%s' % (state['sent'], state['filled'], client._terminated))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   "    try:"
                   "        async with connect('127.0.0.1', port, configuration=configuration(), create_protocol=Client) as client:"
                   "            await asyncio.wait_for(client.ping(), 3)"
                   "            print('LATER closed=%s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('LATERERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-connection-id-limit-test (port)
  "RFC 9000 §5.1.1. After a NEW_CONNECTION_ID is processed, more active
connection IDs than the server's advertised active_connection_id_limit
is CONNECTION_ID_LIMIT_ERROR (0x09). The next connection still answers."
  (let ((script (quic-connection-id-limit-script)))
    (check "a NEW_CONNECTION_ID past the active connection ID limit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "CIDLIMIT sent=True filled=True closed=9" out)
                     (search "LATER closed=None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retire-prior-stop-script ()
  "Client that raises Retire Prior To and watches which connection IDs
the server still uses."
  (let ((script "/tmp/pazuzu-h3-retire-stop.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnectionId"
                   "from aioquic.quic.events import ConnectionIdRetired, ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "FRESH = b'abcdefgh'"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._retired = []"
                   "        self._dcids = []"
                   "        original = self._quic.receive_datagram"
                   "        def receive(data, addr, now):"
                   "            if data and not (data[0] & 0x80):"
                   "                n = self._quic._configuration.connection_id_length"
                   "                self._dcids.append(data[1:1 + n])"
                   "            return original(data, addr, now)"
                   "        self._quic.receive_datagram = receive"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        elif isinstance(event, ConnectionIdRetired):"
                   "            self._retired.append(event.connection_id)"
                   ""
                   "def arm(quic):"
                   "    old = [c.cid for c in quic._host_cids]"
                   "    fresh_seq = quic._host_cid_seq"
                   "    quic._remote_active_connection_id_limit = 2"
                   "    quic._host_cids.append(QuicConnectionId(cid=FRESH, sequence_number=fresh_seq, stateless_reset_token=b'5'*16, was_sent=True))"
                   "    quic._host_cid_seq = fresh_seq + 1"
                   "    original = quic._write_application"
                   "    state = {'sent': False, 'old': old}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(fresh_seq)"
                   "            buf.push_uint_var(fresh_seq)"
                   "            buf.push_uint8(len(FRESH))"
                   "            buf.push_bytes(FRESH)"
                   "            buf.push_bytes(b'0123456789abcdef')"
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
                   "            client._dcids.clear()"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            old = state['old']"
                   "            for _ in range(30):"
                   "                if client._terminated is not None or (old and all(cid in client._retired for cid in old)):"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            seen = False"
                   "            later = []"
                   "            for dcid in client._dcids:"
                   "                if dcid == FRESH:"
                   "                    seen = True"
                   "                if seen:"
                   "                    later.append(dcid)"
                   "            stopped = seen and bool(later) and all(dcid == FRESH for dcid in later)"
                   "            retired = bool(old) and all(cid in client._retired for cid in old)"
                   "            print('SENT %s' % state['sent'])"
                   "            print('STOPPED %s' % stopped)"
                   "            print('RETIRED %s' % retired)"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-retire-prior-stop-test (port)
  "RFC 9000 §5.1.2. An increased Retire Prior To makes the server stop
using the covered connection IDs and retire them."
  (let ((script (quic-retire-prior-stop-script)))
    (check "an increased Retire Prior To retires and stops use of those connection IDs"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "STOPPED True" out)
                     (search "RETIRED True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stateless-reset-script ()
  "Client that advertises an unused connection ID, switches to one and
then another, and sends a Stateless Reset for each token."
  (let ((script "/tmp/pazuzu-h3-stateless-reset.py"))
    (write-lines script
                 '("import asyncio, os, socket, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnectionId"
                   "from aioquic.quic.events import ConnectionIdRetired, ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "UNUSED = b'unused!!'"
                   "UNUSED_TOK = b'uuuuuuuuuuuuuuuu'"
                   "OLD = b'oldcid!!'"
                   "OLD_TOK = b'oooooooooooooooo'"
                   "NEW = b'newcid!!'"
                   "NEW_TOK = b'nnnnnnnnnnnnnnnn'"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.closed = None"
                   "        self.retired = []"
                   "        self.dcids = []"
                   "        self.after = 0"
                   "        self.watch = False"
                   "        original = self._quic.receive_datagram"
                   "        def receive(data, addr, now):"
                   "            if data and not (data[0] & 0x80):"
                   "                n = self._quic._configuration.connection_id_length"
                   "                self.dcids.append(data[1 : 1 + n])"
                   "            if self.watch:"
                   "                self.after += 1"
                   "            return original(data, addr, now)"
                   "        self._quic.receive_datagram = receive"
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   "        elif isinstance(event, ConnectionIdRetired):"
                   "            self.retired.append(event.connection_id)"
                   ""
                   "def remember(quic, cid, seq, token):"
                   "    quic._host_cids.append(QuicConnectionId(cid=cid, sequence_number=seq, stateless_reset_token=token, was_sent=True))"
                   ""
                   "def inject(quic, frames):"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            for seq, retire, cid, token in frames:"
                   "                buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "                buf.push_uint_var(seq)"
                   "                buf.push_uint_var(retire)"
                   "                buf.push_uint8(len(cid))"
                   "                buf.push_bytes(cid)"
                   "                buf.push_bytes(token)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "        quic._write_application = original"
                   "    quic._write_application = wrapped"
                   "    return state"
                   ""
                   "def forge(token):"
                   "    body = bytes([0x43]) + os.urandom(18) + os.urandom(8) + token"
                   "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
                   "    sock.sendto(body, ('127.0.0.1', port))"
                   "    sock.close()"
                   ""
                   "async def ping(client):"
                   "    try:"
                   "        await asyncio.wait_for(client.ping(), 0.8)"
                   "        return 'ok'"
                   "    except Exception as exc:"
                   "        return type(exc).__name__"
                   ""
                   "async def wait_dcid(client, cid):"
                   "    for _ in range(25):"
                   "        if client.closed is not None:"
                   "            return False"
                   "        if client.dcids and client.dcids[-1] == cid:"
                   "            return True"
                   "        await asyncio.sleep(0.1)"
                   "    return bool(client.dcids) and client.dcids[-1] == cid"
                   ""
                   "async def main():"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "        quic = client._quic"
                   "        base = quic._host_cid_seq"
                   "        quic._remote_active_connection_id_limit = 2"
                   "        remember(quic, OLD, base, OLD_TOK)"
                   "        remember(quic, UNUSED, base + 1, UNUSED_TOK)"
                   "        remember(quic, NEW, base + 2, NEW_TOK)"
                   "        quic._host_cid_seq = base + 3"
                   "        first = inject(quic, [(base, base, OLD, OLD_TOK), (base + 1, base, UNUSED, UNUSED_TOK)])"
                   "        client.dcids.clear()"
                   "        quic.send_ping(1)"
                   "        client.transmit()"
                   "        old_used = await wait_dcid(client, OLD)"
                   "        client.watch = True"
                   "        mark = client.after"
                   "        forge(UNUSED_TOK)"
                   "        await asyncio.sleep(0.15)"
                   "        unused_ping = await ping(client)"
                   "        unused_after = client.after - mark"
                   "        unused_closed = client.closed"
                   "        client.watch = False"
                   "        second = inject(quic, [(base + 2, base + 2, NEW, NEW_TOK)])"
                   "        quic.send_ping(1)"
                   "        client.transmit()"
                   "        new_used = await wait_dcid(client, NEW)"
                   "        retired = OLD in client.retired"
                   "        client.watch = True"
                   "        mark = client.after"
                   "        forge(OLD_TOK)"
                   "        await asyncio.sleep(0.15)"
                   "        retired_ping = await ping(client)"
                   "        retired_after = client.after - mark"
                   "        retired_closed = client.closed"
                   "        mark = client.after"
                   "        forge(NEW_TOK)"
                   "        await asyncio.sleep(0.15)"
                   "        used_ping = await ping(client)"
                   "        print('FIRST %s' % first['sent'])"
                   "        print('SECOND %s' % second['sent'])"
                   "        print('OLD %s' % old_used)"
                   "        print('NEW %s' % new_used)"
                   "        print('RETIRED %s' % retired)"
                   "        print('UNUSED ping=%s closed=%s after=%s' % (unused_ping, unused_closed, unused_after))"
                   "        print('OLDTOK ping=%s closed=%s after=%s' % (retired_ping, retired_closed, retired_after))"
                   "        print('NEWTOK ping=%s closed=%s after=%s' % (used_ping, client.closed, client.after - mark))"
                   ""
                   "port = int(sys.argv[1])"
                   "asyncio.run(main())"))
    script))

(defun quic-stateless-reset-test (port)
  "RFC 9000 §10.3.1. A datagram whose last 16 bytes equal a stateless
reset token for a destination connection ID in use enters draining and
draws no further packets. Tokens for an unused or retired connection ID
are not checked."
  (let ((script (quic-stateless-reset-script)))
    (check "a stateless reset drains only a connection ID that is in use"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "FIRST True" out)
                     (search "SECOND True" out)
                     (search "OLD True" out)
                     (search "NEW True" out)
                     (search "RETIRED True" out)
                     (search "UNUSED ping=ok closed=None" out)
                     (search "OLDTOK ping=ok closed=None" out)
                     (search "NEWTOK ping=TimeoutError closed=None after=0" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-long-header-reset-script ()
  "Client that switches to one connection ID and then sends a long-header
datagram ending in that identifier's stateless reset token."
  (let ((script "/tmp/pazuzu-h3-long-reset.py"))
    (write-lines script
                 '("import asyncio, os, socket, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnectionId"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "OLD = b'oldcid!!'"
                   "OLD_TOK = b'oooooooooooooooo'"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self.closed = None"
                   "        self.dcids = []"
                   "        self.after = 0"
                   "        self.watch = False"
                   "        original = self._quic.receive_datagram"
                   "        def receive(data, addr, now):"
                   "            if data and not (data[0] & 0x80):"
                   "                n = self._quic._configuration.connection_id_length"
                   "                self.dcids.append(data[1 : 1 + n])"
                   "            if self.watch:"
                   "                self.after += 1"
                   "            return original(data, addr, now)"
                   "        self._quic.receive_datagram = receive"
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.closed = event.error_code"
                   ""
                   "def inject(quic):"
                   "    base = quic._host_cid_seq"
                   "    quic._remote_active_connection_id_limit = 1"
                   "    quic._host_cids.append(QuicConnectionId(cid=OLD, sequence_number=base, stateless_reset_token=OLD_TOK, was_sent=True))"
                   "    quic._host_cid_seq = base + 1"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(base)"
                   "            buf.push_uint_var(base)"
                   "            buf.push_uint8(len(OLD))"
                   "            buf.push_bytes(OLD)"
                   "            buf.push_bytes(OLD_TOK)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "        quic._write_application = original"
                   "    quic._write_application = wrapped"
                   "    return state"
                   ""
                   "def forge(token):"
                   "    dcid = os.urandom(8)"
                   "    head = bytes([0xE0, 0x00, 0x00, 0x00, 0x01, 8]) + dcid + bytes([0])"
                   "    body = head + os.urandom(8) + token"
                   "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
                   "    sock.sendto(body, ('127.0.0.1', port))"
                   "    sock.close()"
                   "    return len(body)"
                   ""
                   "async def main():"
                   "    configuration = QuicConfiguration("
                   "        is_client=True,"
                   "        alpn_protocols=H3_ALPN,"
                   "        verify_mode=ssl.CERT_NONE,"
                   "        supported_versions=[QuicProtocolVersion.VERSION_1],"
                   "    )"
                   "    async with connect('127.0.0.1', port, configuration=configuration, create_protocol=Client) as client:"
                   "        quic = client._quic"
                   "        state = inject(quic)"
                   "        client.dcids.clear()"
                   "        quic.send_ping(1)"
                   "        client.transmit()"
                   "        used = False"
                   "        for _ in range(25):"
                   "            if client.closed is not None:"
                   "                break"
                   "            if client.dcids and client.dcids[-1] == OLD:"
                   "                used = True"
                   "                break"
                   "            await asyncio.sleep(0.1)"
                   "        client.watch = True"
                   "        mark = client.after"
                   "        length = forge(OLD_TOK)"
                   "        await asyncio.sleep(0.15)"
                   "        try:"
                   "            await asyncio.wait_for(client.ping(), 0.8)"
                   "            ping = 'ok'"
                   "        except Exception as exc:"
                   "            ping = type(exc).__name__"
                   "        print('SENT %s' % state['sent'])"
                   "        print('USED %s' % used)"
                   "        print('LEN %d' % length)"
                   "        print('PING %s' % ping)"
                   "        print('CLOSED %s' % client.closed)"
                   "        print('AFTER %s' % (client.after - mark))"
                   ""
                   "port = int(sys.argv[1])"
                   "asyncio.run(main())"))
    script))

(defun quic-long-header-reset-test (port)
  "RFC 9000 §10.3. A long-header datagram that ends in a stateless reset
token for a destination connection ID in use drains the connection and
draws no further packet."
  (let ((script (quic-long-header-reset-script)))
    (check "a long header ending in a used stateless reset token drains the connection"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "USED True" out)
                     (search "PING TimeoutError" out)
                     (search "CLOSED None" out)
                     (search "AFTER 0" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-duplicate-packet-script ()
  "Client that replays a 1-RTT datagram and then pings again."
  (let ((script "/tmp/pazuzu-h3-duplicate-packet.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._sent = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def capture(client):"
                   "    original = client._transport.sendto"
                   "    def sendto(data, addr=None):"
                   "        client._sent.append((bytes(data), addr))"
                   "        return original(data, addr)"
                   "    client._transport.sendto = sendto"
                   "    return original"
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
                   "            original = capture(client)"
                   "            await asyncio.wait_for(client.ping(), 3)"
                   "            shorts = [item for item in client._sent if item[0] and not (item[0][0] & 0x80)]"
                   "            replayed = False"
                   "            if shorts:"
                   "                data, addr = shorts[-1]"
                   "                original(data, addr)"
                   "                replayed = True"
                   "            await asyncio.sleep(0.2)"
                   "            await asyncio.wait_for(client.ping(), 3)"
                   "            print('REPLAY %s' % replayed)"
                   "            print('PING True')"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-duplicate-packet-test (port)
  "RFC 9000 §12.3. A packet number that was already processed is
discarded. The connection stays open."
  (let ((script (quic-duplicate-packet-script)))
    (check "a duplicate packet number is discarded"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "REPLAY True" out)
                     (search "PING True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ignore-retire-prior-script ()
  "Client that sends a lower Retire Prior To after a higher one, then a
sequence that is still below the higher value."
  (let ((script "/tmp/pazuzu-h3-ignore-rpt.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnectionId"
                   "from aioquic.quic.events import ConnectionIdRetired, ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "LATE = b'ijklmnop'"
                   "FRESH = b'abcdefgh'"
                   "MID = b'qrstuvwx'"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._retired = []"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        elif isinstance(event, ConnectionIdRetired):"
                   "            self._retired.append(event.connection_id)"
                   ""
                   "def arm(quic):"
                   "    late_seq = quic._host_cid_seq"
                   "    fresh_seq = late_seq + 1"
                   "    mid_seq = late_seq + 2"
                   "    quic._remote_active_connection_id_limit = 2"
                   "    quic._host_cids.append(QuicConnectionId(cid=LATE, sequence_number=late_seq, stateless_reset_token=b'1'*16, was_sent=True))"
                   "    quic._host_cids.append(QuicConnectionId(cid=FRESH, sequence_number=fresh_seq, stateless_reset_token=b'5'*16, was_sent=True))"
                   "    quic._host_cids.append(QuicConnectionId(cid=MID, sequence_number=mid_seq, stateless_reset_token=b'9'*16, was_sent=True))"
                   "    quic._host_cid_seq = mid_seq + 1"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(fresh_seq)"
                   "            buf.push_uint_var(fresh_seq)"
                   "            buf.push_uint8(8)"
                   "            buf.push_bytes(FRESH)"
                   "            buf.push_bytes(b'0123456789abcdef')"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(mid_seq)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint8(8)"
                   "            buf.push_bytes(MID)"
                   "            buf.push_bytes(b'fedcba9876543210')"
                   "            buf = builder.start_frame(QuicFrameType.NEW_CONNECTION_ID, capacity=48)"
                   "            buf.push_uint_var(late_seq)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint8(8)"
                   "            buf.push_bytes(LATE)"
                   "            buf.push_bytes(b'abcdef0123456789')"
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
                   "            await asyncio.wait_for(client.ping(), 3)"
                   "            for _ in range(20):"
                   "                if LATE in client._retired or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            print('SENT %s' % state['sent'])"
                   "            print('LATE %s' % (LATE in client._retired))"
                   "            print('PING True')"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ignore-retire-prior-test (port)
  "RFC 9000 §19.15. A Retire Prior To that does not increase the largest
value already received is ignored, so a sequence below that largest
value is still retired."
  (let ((script (quic-ignore-retire-prior-script)))
    (check "a Retire Prior To that does not increase is ignored"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "LATE True" out)
                     (search "PING True" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-draining-script ()
  "Client that sends CONNECTION_CLOSE and counts later server datagrams."
  (let ((script "/tmp/pazuzu-h3-draining.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._replies = 0"
                   "        self._count = False"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        if self._count:"
                   "            self._replies += 1"
                   "        super().datagram_received(data, addr)"
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
                   "            await asyncio.sleep(0.3)"
                   "            client._count = True"
                   "            client.close()"
                   "            await asyncio.sleep(1.0)"
                   "            print('REPLIES %d.' % client._replies)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-draining-test (port)
  "RFC 9000 §10.2.2. After a CONNECTION_CLOSE, the server sends at most
one packet and then nothing further."
  (let ((script (quic-draining-script)))
    (check "a CONNECTION_CLOSE is not answered more than once"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (or (search "REPLIES 0." out)
                         (search "REPLIES 1." out)))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ignore-max-streams-script ()
  "Client whose transport parameter allows no server unidirectional streams.
The first 1-RTT packet raises that limit to 3 and then offers 0."
  (let ((script "/tmp/pazuzu-h3-ignore-max-streams.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN, H3Connection"
                   "from aioquic.h3.events import DataReceived, HeadersReceived"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated, StreamDataReceived"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "def arm(quic):"
                   "    limit = quic._local_max_streams_uni"
                   "    limit.value = 0"
                   "    limit.sent = 0"
                   "    original = quic._write_application"
                   "    original_limits = quic._write_connection_limits"
                   "    state = {'sent': False}"
                   "    def frozen(builder, space):"
                   "        used = limit.used"
                   "        limit.used = 0"
                   "        try:"
                   "            original_limits(builder, space)"
                   "        finally:"
                   "            limit.used = used"
                   "    quic._write_connection_limits = frozen"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            limit.value = 3"
                   "            limit.sent = 3"
                   "            buf = builder.start_frame(QuicFrameType.MAX_STREAMS_UNI, capacity=2)"
                   "            buf.push_uint_var(3)"
                   "            buf = builder.start_frame(QuicFrameType.MAX_STREAMS_UNI, capacity=2)"
                   "            buf.push_uint_var(0)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = None"
                   "        self._buffered = []"
                   "        self._server_uni = set()"
                   "        self._terminated = None"
                   "        self._events = {}"
                   "        self._waiters = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 3:"
                   "            self._server_uni.add(event.stream_id)"
                   "        if self._http is None:"
                   "            if isinstance(event, StreamDataReceived):"
                   "                self._buffered.append(event)"
                   "            return"
                   "        self._dispatch(event)"
                   ""
                   "    def _dispatch(self, event):"
                   "        for http_event in self._http.handle_event(event):"
                   "            stream_id = getattr(http_event, 'stream_id', None)"
                   "            if stream_id is None:"
                   "                continue"
                   "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        bucket['status'] = int(value)"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                bucket['data'] += http_event.data"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   ""
                   "    def _finish(self, stream_id):"
                   "        waiter = self._waiters.get(stream_id)"
                   "        if waiter is not None and not waiter.done():"
                   "            waiter.set_result(self._events[stream_id])"
                   ""
                   "    def start_http(self):"
                   "        self._http = H3Connection(self._quic)"
                   "        buffered = self._buffered"
                   "        self._buffered = []"
                   "        for event in buffered:"
                   "            self._dispatch(event)"
                   "        self.transmit()"
                   ""
                   "    async def request(self):"
                   "        stream_id = self._quic.get_next_available_stream_id()"
                   "        waiter = self._loop.create_future()"
                   "        self._waiters[stream_id] = waiter"
                   "        self._http.send_headers(stream_id, ["
                   "            (b':method', b'GET'),"
                   "            (b':scheme', b'https'),"
                   "            (b':authority', b'127.0.0.1'),"
                   "            (b':path', b'/'),"
                   "        ], end_stream=True)"
                   "        self.transmit()"
                   "        return await asyncio.wait_for(waiter, 5)"
                   ""
                   "def create(connection, stream_handler=None):"
                   "    arm(connection)"
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
                   "            for _ in range(40):"
                   "                if {3, 7, 11} <= client._server_uni:"
                   "                    break"
                   "                await asyncio.sleep(0.05)"
                   "            print('SENT True')"
                   "            print('STREAMS %s' % sorted(client._server_uni))"
                   "            client.start_http()"
                   "            got = await client.request()"
                   "            print('GET %s %s' % (got['status'], got['data'].decode()))"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ignore-max-streams-test (port)
  "RFC 9000 §19.11. The client's transport parameter allows the server no
unidirectional streams. The first 1-RTT packet contains MAX_STREAMS_UNI 3
and then MAX_STREAMS_UNI 0. The 0 does not increase the limit, so the
server still opens streams 3, 7, and 11 and answers GET /."
  (let ((script (quic-ignore-max-streams-script)))
    (check "a MAX_STREAMS frame that does not increase the stream limit is ignored"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "STREAMS [3, 7, 11]" out)
                     (search "GET 200 pazuzu" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-ignore-max-data-script ()
  "Client that offers a MAX_DATA and MAX_STREAM_DATA of 0 after the handshake,
then requests GET /."
  (let ((script "/tmp/pazuzu-h3-ignore-max-data.py"))
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
                   "def arm(quic):"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.MAX_DATA, capacity=2)"
                   "            buf.push_uint_var(0)"
                   "            buf = builder.start_frame(QuicFrameType.MAX_STREAM_DATA, capacity=3)"
                   "            buf.push_uint_var(0)"
                   "            buf.push_uint_var(0)"
                   "            state['sent'] = True"
                   "        builder.start_packet = start_packet"
                   "        original(builder, network_path, now)"
                   "    quic._write_application = wrapped"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._events = {}"
                   "        self._waiters = {}"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        for http_event in self._http.handle_event(event):"
                   "            stream_id = getattr(http_event, 'stream_id', None)"
                   "            if stream_id is None:"
                   "                continue"
                   "            bucket = self._events.setdefault(stream_id, {'status': None, 'data': b''})"
                   "            if isinstance(http_event, HeadersReceived):"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        bucket['status'] = int(value)"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   "            elif isinstance(http_event, DataReceived):"
                   "                bucket['data'] += http_event.data"
                   "                if http_event.stream_ended:"
                   "                    self._finish(stream_id)"
                   ""
                   "    def _finish(self, stream_id):"
                   "        waiter = self._waiters.get(stream_id)"
                   "        if waiter is not None and not waiter.done():"
                   "            waiter.set_result(self._events[stream_id])"
                   ""
                   "    async def request(self):"
                   "        stream_id = self._quic.get_next_available_stream_id()"
                   "        waiter = self._loop.create_future()"
                   "        self._waiters[stream_id] = waiter"
                   "        self._http.send_headers(stream_id, ["
                   "            (b':method', b'GET'),"
                   "            (b':scheme', b'https'),"
                   "            (b':authority', b'127.0.0.1'),"
                   "            (b':path', b'/'),"
                   "        ], end_stream=True)"
                   "        self.transmit()"
                   "        return await asyncio.wait_for(waiter, 5)"
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
                   "            arm(client._quic)"
                   "            await client.ping()"
                   "            print('PING True')"
                   "            got = await client.request()"
                   "            print('GET %s %s' % (got['status'], got['data'].decode()))"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-ignore-max-data-test (port)
  "RFC 9000 §4.1. A MAX_DATA of 0 and a MAX_STREAM_DATA of 0 on stream 0
do not increase the limits advertised in the transport parameters. The
server still sends the GET / body."
  (let ((script (quic-ignore-max-data-script)))
    (check "a MAX_DATA frame that does not increase the flow-control limit is ignored"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "PING True" out)
                     (search "GET 200 pazuzu" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-budget-script ()
  "Client that advertises 256 bytes of stream credit on the streams it opens
and does not raise that credit."
  (let ((script "/tmp/pazuzu-h3-stream-budget.py"))
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
                   "LIMIT = 256"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._stream0 = 0"
                   "        self._body = b''"
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
                   "        if isinstance(event, StreamDataReceived) and event.stream_id == 0:"
                   "            self._stream0 += len(event.data)"
                   "        for http_event in self._http.handle_event(event):"
                   "            if isinstance(http_event, HeadersReceived) and http_event.stream_id == 0:"
                   "                for name, value in http_event.headers:"
                   "                    if name == b':status':"
                   "                        self._status = int(value)"
                   "            elif isinstance(http_event, DataReceived) and http_event.stream_id == 0:"
                   "                self._body += http_event.data"
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
                   "                (b':path', b'/flow-body'),"
                   "            ], end_stream=True)"
                   "            client.transmit()"
                   "            await asyncio.sleep(0.6)"
                   "            print('STREAM0 %d' % client._stream0)"
                   "            print('WITHIN %s' % (0 < client._stream0 <= LIMIT))"
                   "            print('FULL %s' % (len(client._body) >= 4096))"
                   "            print('STATUS %s' % client._status)"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-stream-budget-test (port)
  "RFC 9000 §4.1. The data the server sends on a stream must not exceed the
largest maximum stream data the client has advertised. The client allows
256 bytes on streams it opens and does not raise that limit. GET /flow-body
is 4096 bytes, so a sender that stays inside the limit cannot finish it."
  (let ((script (quic-stream-budget-script)))
    (check "a response stays within the peer's stream data limit"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "STATUS 200" out)
                     (search "WITHIN True" out)
                     (search "FULL False" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-connection-budget-script ()
  "Client that advertises 16384 bytes of connection credit and does not
raise it. The unidirectional setup and a 65536-byte body cannot both fit."
  (let ((script "/tmp/pazuzu-h3-connection-budget.py"))
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
                   "LIMIT = 16384"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._http = H3Connection(self._quic)"
                   "        self._terminated = None"
                   "        self._total = 0"
                   "        self._stream0 = 0"
                   "        self._body = b''"
                   "        self._status = None"
                   "        original = self._quic._write_connection_limits"
                   "        def frozen(builder, space, _orig=original):"
                   "            limit = self._quic._local_max_data"
                   "            used = limit.used"
                   "            limit.used = 0"
                   "            try:"
                   "                _orig(builder, space)"
                   "            finally:"
                   "                limit.used = used"
                   "        self._quic._write_connection_limits = frozen"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   "        if isinstance(event, StreamDataReceived):"
                   "            self._total += len(event.data)"
                   "            if event.stream_id == 0:"
                   "                self._stream0 += len(event.data)"
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
                   "        max_data=LIMIT,"
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
                   "            await asyncio.sleep(1.0)"
                   "            print('STREAM0 %d' % client._stream0)"
                   "            print('TOTAL %d' % client._total)"
                   "            print('BODY %d' % len(client._body))"
                   "            print('STATUS %s' % client._status)"
                   "            print('WITHIN %s' % (500 < client._stream0 and client._total <= LIMIT))"
                   "            print('FULL %s' % (len(client._body) >= 65536))"
                   "            print('CLOSED %s' % client._terminated)"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-connection-budget-test (port)
  "RFC 9000 §4.1. The sum of stream data the server sends must not exceed
the connection data limit the client advertised. The client allows 16384
bytes in total and does not raise that limit. GET /flow-conn is 65536
bytes, so a sender that stays inside the limit cannot finish it."
  (let ((script (quic-connection-budget-script)))
    (check "a response stays within the peer's connection data limit"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port))
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "STATUS 200" out)
                     (search "WITHIN True" out)
                     (search "FULL False" out)
                     (search "CLOSED None" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-count-test (port)
  "RFC 9000 §§4.6 and 19.11. A STREAM frame above the advertised
bidirectional stream limit (100) is STREAM_LIMIT_ERROR (0x04).
Stream 400 is the 101st client-initiated bidirectional stream."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM frame above the bidirectional stream limit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stream-count")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "SCOUNT closed=4" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reset-limit-test (port)
  "RFC 9000 §§4.1 and 4.5. A RESET_STREAM final size past the advertised
stream data limit (256 KiB) is FLOW_CONTROL_ERROR (0x03)."
  (let ((script (quic-client-frame-script)))
    (check "a RESET_STREAM final size past the stream data limit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "reset-limit")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "RESETLIM closed=3" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-limit-test (port)
  "RFC 9000 §§4.1 and 19.10. A STREAM frame past the advertised stream
data limit (256 KiB) is FLOW_CONTROL_ERROR (0x03)."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM frame past the stream data limit is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stream-limit")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "STREAMLIM closed=3" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-offset-test (port)
  "RFC 9000 §19.8. A STREAM frame whose offset plus length passes 2^62-1
is FLOW_CONTROL_ERROR (0x03)."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM offset past 2^62-1 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stream-offset")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "STREAM closed=3" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stop-sending-local-test (port)
  "RFC 9000 §19.5. STOP_SENDING for a locally initiated stream that has not
been created is STREAM_STATE_ERROR (0x05)."
  (let ((script (quic-client-frame-script)))
    (check "a STOP_SENDING frame on an uncreated local stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stop-local")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "STOPLOCAL closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-local-stream-test (port)
  "RFC 9000 §19.8. A STREAM frame for a locally initiated stream that has
not been created is STREAM_STATE_ERROR (0x05). Stream 1 is the first
server-initiated bidirectional stream."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM frame on an uncreated local stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "local-stream")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "LOCAL closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-streams-blocked-test (port)
  "RFC 9000 §19.14. A STREAMS_BLOCKED value above 2^60 is
FRAME_ENCODING_ERROR (0x07) or STREAM_LIMIT_ERROR."
  (let ((script (quic-client-frame-script)))
    (check "a STREAMS_BLOCKED value above 2^60 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "streams-blocked")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "SBLOCKED closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-max-streams-test (port)
  "RFC 9000 §19.11. A MAX_STREAMS value above 2^60 is FRAME_ENCODING_ERROR (0x07)."
  (let ((script (quic-client-frame-script)))
    (check "a MAX_STREAMS value above 2^60 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "max-streams")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "MAXSTREAMS closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retire-sequence-test (port)
  "RFC 9000 §19.16. A RETIRE_CONNECTION_ID sequence number greater than any
connection ID the server has sent is PROTOCOL_VIOLATION (0x0a)."
  (let ((script (quic-client-frame-script)))
    (check "a RETIRE_CONNECTION_ID sequence above those issued is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "retire-seq")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "RSEQ closed=10" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-connection-id-length-test (port)
  "RFC 9000 §19.15. A NEW_CONNECTION_ID length below 1 or above 20 is
FRAME_ENCODING_ERROR (0x07)."
  (let ((script (quic-client-frame-script)))
    (check "a NEW_CONNECTION_ID length of 0 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "cid-len0")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "CID0 closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))
    (check "a NEW_CONNECTION_ID length above 20 is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "cid-len21")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "CID21 closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-retire-prior-to-test (port)
  "RFC 9000 §19.15. Retire Prior To greater than the sequence number is
FRAME_ENCODING_ERROR (0x07)."
  (let ((script (quic-client-frame-script)))
    (check "a NEW_CONNECTION_ID Retire Prior To above its sequence number is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "retire-prior")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "RETIRE closed=7" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-data-blocked-test (port)
  "RFC 9000 §19.13. STREAM_DATA_BLOCKED on a send-only stream is
STREAM_STATE_ERROR (0x05). Stream 3 is server-initiated and unidirectional."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM_DATA_BLOCKED frame on a send-only stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stream-data-blocked")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "SDB closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-max-stream-data-test (port)
  "RFC 9000 §19.10. MAX_STREAM_DATA on a receive-only stream is
STREAM_STATE_ERROR (0x05). Stream 2 is client-initiated and unidirectional."
  (let ((script (quic-client-frame-script)))
    (check "a MAX_STREAM_DATA frame on a receive-only stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "max-stream-data")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "MSD closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-max-stream-data-local-test (port)
  "RFC 9000 §19.10. MAX_STREAM_DATA for a locally initiated stream that
has not been created is STREAM_STATE_ERROR (0x05). Stream 1 is the first
server-initiated bidirectional stream."
  (let ((script (quic-client-frame-script)))
    (check "a MAX_STREAM_DATA frame on an uncreated local stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "msd-local")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "MSDLOCAL closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stop-sending-test (port)
  "RFC 9000 §19.5. STOP_SENDING on a receive-only stream is
STREAM_STATE_ERROR (0x05). Stream 2 is client-initiated and unidirectional."
  (let ((script (quic-client-frame-script)))
    (check "a STOP_SENDING frame on a receive-only stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stop-sending")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "STOP closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-stream-send-only-test (port)
  "RFC 9000 §19.8. A STREAM frame for a send-only stream is
STREAM_STATE_ERROR (0x05). Stream 3 is server-initiated and unidirectional."
  (let ((script (quic-client-frame-script)))
    (check "a STREAM frame on a send-only stream is a connection error"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "stream-sendonly")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "SENDONLY closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-reset-send-only-test (port)
  "RFC 9000 §19.4. RESET_STREAM for a send-only stream is
STREAM_STATE_ERROR (0x05). Stream 3 is server-initiated and unidirectional."
  (let ((script (quic-client-frame-script)))
    (check "a RESET_STREAM frame on a send-only stream is STREAM_STATE_ERROR"
      (multiple-value-bind (out err code)
          (uiop:run-program (list (aioquic-python) script (princ-to-string port) "reset-sendonly")
                            :output :string :error-output :string :ignore-error-status t)
        (unless (and code (zerop code)
                     (search "SENT True" out)
                     (search "RESETSEND closed=5" out))
          (fail "exit ~s out ~s err ~s" code out err))))))

(defun quic-server-transport-script ()
  "Client Initial that appends one server-only transport parameter."
  (let ((script "/tmp/pazuzu-h3-server-tp.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.connection import QuicConnection"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicProtocolVersion"
                   ""
                   "MODE = sys.argv[2]"
                   "EXTRA = {"
                   "    'odcid': bytes([0x00, 0x08]) + b'abcdefgh',"
                   "    'reset': bytes([0x02, 0x10]) + b'0123456789abcdef',"
                   "    'preferred': bytes([0x0d, 49]) + bytes(4) + bytes(2) + bytes(16) + bytes(2) + bytes([8]) + b'abcdefgh' + b'0123456789abcdef',"
                   "    'retry': bytes([0x10, 0x08]) + b'abcdefgh',"
                   "    'payload': bytes([0x03, 0x02, 0x44, 0xAF]),"
                   "    'migration': bytes([0x0c, 0x01, 0x00]),"
                   "}"
                   "def pull_varint(data, index):"
                   "    prefix = data[index] >> 6"
                   "    length = 1 << prefix"
                   "    raw = int.from_bytes(data[index:index + length], 'big')"
                   "    return raw & ((1 << (8 * length - 2)) - 1), index + length"
                   "def edit_param(data, want, flip):"
                   "    out = bytearray()"
                   "    index = 0"
                   "    found = False"
                   "    while index < len(data):"
                   "        start = index"
                   "        ident, index = pull_varint(data, index)"
                   "        size, index = pull_varint(data, index)"
                   "        index += size"
                   "        if ident == want:"
                   "            found = True"
                   "            if flip:"
                   "                body = bytearray(data[start:index])"
                   "                body[-1] ^= 0xff"
                   "                out += body"
                   "            continue"
                   "        out += data[start:index]"
                   "    if not found:"
                   "        raise RuntimeError('transport parameter missing')"
                   "    return bytes(out)"
                   "holder = {}"
                   "original = QuicConnection._serialize_transport_parameters"
                   "def wrapped(self):"
                   "    if self._is_client and MODE == 'limit0':"
                   "        self._local_active_connection_id_limit = 0"
                   "    elif self._is_client and MODE == 'limit1':"
                   "        self._local_active_connection_id_limit = 1"
                   "    elif self._is_client and MODE == 'exp':"
                   "        self._local_ack_delay_exponent = 21"
                   "    elif self._is_client and MODE == 'streams':"
                   "        self._local_max_streams_bidi.value = 2 ** 60 + 1"
                   "    elif self._is_client and MODE == 'uni':"
                   "        self._local_max_streams_uni.value = 2 ** 60 + 1"
                   "    data = original(self)"
                   "    if self._is_client and MODE in EXTRA:"
                   "        data += EXTRA[MODE]"
                   "    if self._is_client and MODE == 'delay':"
                   "        needle = bytes([0x0b, 0x01, 0x19])"
                   "        if data.count(needle) != 1:"
                   "            raise RuntimeError('max_ack_delay encoding changed')"
                   "        data = data.replace(needle, bytes([0x0b, 0x04, 0x80, 0x00, 0x40, 0x00]), 1)"
                   "    if self._is_client and MODE == 'nosrc':"
                   "        data = edit_param(data, 0x0f, False)"
                   "    elif self._is_client and MODE == 'badsrc':"
                   "        data = edit_param(data, 0x0f, True)"
                   "    return data"
                   "QuicConnection._serialize_transport_parameters = wrapped"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        holder['client'] = self"
                   "        self.code = None"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self.code = event.error_code"
                   "        super().quic_event_received(event)"
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
                   "            print('UP')"
                   "    except Exception as exc:"
                   "        code = holder['client'].code if 'client' in holder else None"
                   "        print('TP closed=%s' % code)"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

(defun quic-server-transport-parameter-test (port)
  "RFC 9000 §§4.6 and 18.2. A server-only transport parameter, an active
connection ID limit below 2, a max UDP payload below 1200, an ack delay
exponent above 20, a max ack delay of 2^14, a bidirectional or
unidirectional max streams value above 2^60, a non-empty
disable_active_migration, or a missing or mismatched
initial_source_connection_id from a client is TRANSPORT_PARAMETER_ERROR
(0x08). RFC 9000 §§7.4 and 18.2 require a zero-length value for
disable_active_migration and a close on an invalid value."
  (let ((script (quic-server-transport-script)))
    (loop for (mode name) in '(("odcid" "original_destination_connection_id")
                               ("reset" "stateless_reset_token")
                               ("preferred" "preferred_address")
                               ("retry" "retry_source_connection_id")
                               ("limit0" "active_connection_id_limit of 0")
                               ("limit1" "active_connection_id_limit of 1")
                               ("payload" "max_udp_payload_size below 1200")
                               ("exp" "ack_delay_exponent above 20")
                               ("delay" "max_ack_delay of 2^14")
                               ("streams" "max_streams above 2^60")
                               ("uni" "max_streams_uni above 2^60")
                               ("migration" "non-empty disable_active_migration")
                               ("nosrc" "missing initial_source_connection_id")
                               ("badsrc" "mismatched initial_source_connection_id"))
          do (check (format nil "a client ~a transport parameter is an error" name)
               (multiple-value-bind (out err code)
                   (uiop:run-program (list (aioquic-python) script (princ-to-string port) mode)
                                     :output :string :error-output :string :ignore-error-status t)
                 (unless (and code (zerop code) (search "TP closed=8" out))
                   (fail "exit ~s out ~s err ~s" code out err)))))))

(defun quic-path-challenge-script ()
  "Client that sends one PATH_CHALLENGE and records the matching PATH_RESPONSE."
  (let ((script "/tmp/pazuzu-h3-path-challenge.py"))
    (write-lines script
                 '("import asyncio, ssl, sys"
                   "from aioquic.asyncio.client import connect"
                   "from aioquic.asyncio.protocol import QuicConnectionProtocol"
                   "from aioquic.h3.connection import H3_ALPN"
                   "from aioquic.quic.configuration import QuicConfiguration"
                   "from aioquic.quic.events import ConnectionTerminated"
                   "from aioquic.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion"
                   ""
                   "CHALLENGE = b'abcdefgh'"
                   ""
                   "class Client(QuicConnectionProtocol):"
                   "    def __init__(self, *args, **kwargs):"
                   "        super().__init__(*args, **kwargs)"
                   "        self._terminated = None"
                   "        self._watch = False"
                   "        self._padlen = None"
                   ""
                   "    def datagram_received(self, data, addr):"
                   "        before = CHALLENGE in self._quic._local_challenges"
                   "        super().datagram_received(data, addr)"
                   "        if self._watch and before and CHALLENGE not in self._quic._local_challenges:"
                   "            self._padlen = len(data)"
                   ""
                   "    def quic_event_received(self, event):"
                   "        if isinstance(event, ConnectionTerminated):"
                   "            self._terminated = event.error_code"
                   ""
                   "def arm(quic):"
                   "    quic._local_challenges[CHALLENGE] = quic._network_paths[0]"
                   "    quic._response_count = 0"
                   "    handlers = quic._QuicConnection__frame_handlers"
                   "    handle, epochs = handlers[0x1B]"
                   "    def count_response(context, frame_type, buf):"
                   "        quic._response_count += 1"
                   "        handle(context, frame_type, buf)"
                   "    handlers[0x1B] = (count_response, epochs)"
                   "    original = quic._write_application"
                   "    state = {'sent': False}"
                   "    def wrapped(builder, network_path, now):"
                   "        real = builder.start_packet"
                   "        def start_packet(packet_type, crypto):"
                   "            real(packet_type, crypto)"
                   "            if state['sent'] or packet_type is not QuicPacketType.ONE_RTT:"
                   "                return"
                   "            buf = builder.start_frame(QuicFrameType.PATH_CHALLENGE, capacity=9)"
                   "            buf.push_bytes(CHALLENGE)"
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
                   "            sentlen = {}"
                   "            real_sendto = client._transport.sendto"
                   "            def sendto(data, addr):"
                   "                if state['sent'] and 'n' not in sentlen:"
                   "                    sentlen['n'] = len(data)"
                   "                return real_sendto(data, addr)"
                   "            client._transport.sendto = sendto"
                   "            client._watch = True"
                   "            client._quic.send_ping(1)"
                   "            client.transmit()"
                   "            for _ in range(20):"
                   "                if CHALLENGE not in client._quic._local_challenges or client._terminated is not None:"
                   "                    break"
                   "                await asyncio.sleep(0.1)"
                   "            print('SENT %s' % state['sent'])"
                   "            print('ANSWERED %s' % (CHALLENGE not in client._quic._local_challenges))"
                   "            print('RESPONSES %s' % client._quic._response_count)"
                   "            print('CLOSED %s' % client._terminated)"
                   "            print('PADLEN %s' % client._padlen)"
                   "            print('PADDED %s' % (client._padlen is not None and client._padlen >= 1200))"
                   "            print('SMALL %s' % sentlen.get('n'))"
                   "    except Exception as exc:"
                   "        print('ERR %r' % exc)"
                   ""
                   "asyncio.run(main())"))
    script))

