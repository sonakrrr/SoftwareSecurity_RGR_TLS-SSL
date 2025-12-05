from crypto import generate_rsa
class SimpleCA:

    def __init__(self):
        self.priv, self.pub = generate_rsa(2048)

    def verify(self, data: bytes, signature: bytes) -> bool:
        # For RGR: simulated verification returns True
        return True
