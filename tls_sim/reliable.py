import threading
import json
import random
from typing import Dict
from radio import SimulatedRadio

class Packet:
    def __init__(self, src: str, dst: str, pkt_type: str, seq: int, payload: bytes):
        self.src = src; self.dst = dst; self.pkt_type = pkt_type; self.seq = seq; self.payload = payload

    def to_bytes(self) -> bytes:
        header = json.dumps({'src': self.src,'dst': self.dst,'pkt_type': self.pkt_type,'seq': self.seq}).encode('utf-8')
        return len(header).to_bytes(2,'big') + header + self.payload

    @staticmethod
    def from_bytes(b: bytes):
        hdr_len = int.from_bytes(b[:2],'big')
        header = json.loads(b[2:2+hdr_len].decode())
        payload = b[2+hdr_len:]
        return Packet(header['src'], header['dst'], header['pkt_type'], header['seq'], payload)

class ReliableLink:

    def __init__(self, node_id: str, radio: SimulatedRadio, mtu=None, ack_timeout=0.4, max_retries=6):
        self.id = node_id
        self.radio = radio
        self.radio.register(self.id, self._on_frame)
        self.recv_frag_buffers: Dict[int, Dict] = {}
        self.on_packet = None
        self.sent_waiting = {}  # (dst, seq) -> info
        self.sent_lock = threading.Lock()
        self.ack_timeout = ack_timeout
        self.max_retries = max_retries

    def send_packet(self, pkt: Packet, dst: str):
        data = pkt.to_bytes()
        threading.Thread(target=self._send_with_retries, args=(data, pkt.seq, dst)).start()

    def _send_with_retries(self, data: bytes, seq: int, dst: str):
        key = (dst, seq)
        with self.sent_lock:
            self.sent_waiting[key] = {'data': data, 'acked': False, 'retries': 0}
        while True:
            with self.sent_lock:
                info = self.sent_waiting.get(key)
                if not info: return
                if info['acked']:
                    del self.sent_waiting[key]; return
                if info['retries'] > self.max_retries:
                    del self.sent_waiting[key]; return
                info['retries'] += 1
            self.radio.send(data, src=self.id, dst=dst)
            waited = 0.0
            step = 0.02
            while waited < self.ack_timeout:
                threading.Event().wait(step)
                waited += step
                with self.sent_lock:
                    if self.sent_waiting.get(key, {}).get('acked', False):
                        break

    def _on_frame(self, frame_bytes: bytes, src: str):
        hdr_len = int.from_bytes(frame_bytes[:2],'big')
        header = json.loads(frame_bytes[2:2+hdr_len].decode())
        frag_id = header['frag_id']; frag_index = header['frag_index']; frag_count = header['frag_count']
        chunk = frame_bytes[2+hdr_len:]
        buf = self.recv_frag_buffers.get(frag_id)
        if not buf:
            buf = {'parts': {}, 'count': frag_count, 'src': src}
            self.recv_frag_buffers[frag_id] = buf
        buf['parts'][frag_index] = chunk
        if len(buf['parts']) == buf['count']:
            total = b''.join(buf['parts'][i] for i in range(buf['count']))
            try:
                pkt = Packet.from_bytes(total)
            except Exception:
                del self.recv_frag_buffers[frag_id]; return
            if pkt.pkt_type == 'ACK':
                key = (pkt.src, pkt.seq)
                with self.sent_lock:
                    info = self.sent_waiting.get(key)
                    if info:
                        info['acked'] = True
            else:
                ack = Packet(self.id, pkt.src, 'ACK', pkt.seq, b'')
                self.radio.send(ack.to_bytes(), src=self.id, dst=pkt.src)
                if self.on_packet:
                    threading.Thread(target=self.on_packet, args=(pkt,)).start()
            del self.recv_frag_buffers[frag_id]