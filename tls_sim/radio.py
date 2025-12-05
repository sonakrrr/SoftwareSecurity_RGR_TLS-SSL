import threading
import time
import random
import json
import math

class SimulatedRadio:

    def __init__(self, mtu=64, loss_prob=0.15, rtt=0.12):
        self.nodes = {}
        self.mtu = mtu
        self.loss_prob = loss_prob
        self.rtt = rtt
        self.lock = threading.Lock()

    def register(self, node_id: str, recv_callback):
        with self.lock:
            self.nodes[node_id] = recv_callback

    def send(self, pkt_bytes: bytes, src: str, dst: str):
        frames = []
        total = len(pkt_bytes)
        pos = 0
        frag_id = random.randint(0, 1<<30)
        frag_count = math.ceil(total / self.mtu)
        while pos < total:
            chunk = pkt_bytes[pos:pos+self.mtu]
            header = json.dumps({'frag_id': frag_id, 'frag_index': len(frames), 'frag_count': frag_count}).encode('utf-8')
            frame = len(header).to_bytes(2, 'big') + header + chunk
            frames.append(frame)
            pos += self.mtu
        for frame in frames:
            threading.Thread(target=self._deliver_frame, args=(frame, src, dst)).start()

    def _deliver_frame(self, frame: bytes, src: str, dst: str):
        time.sleep(self.rtt * (0.8 + random.random()*0.6))
        if random.random() < self.loss_prob:
            return
        with self.lock:
            cb = self.nodes.get(dst)
        if cb:
            cb(frame, src)
