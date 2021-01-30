"""

HW #6
Hmac Algorithm using SHA-512 Hash Algorithm
coded by: Amir Abbas Bakhshipour
Course: Advanced Network Sec.
Professor: Dr. Rezayi

"""

from sha512 import sha512_


class HMAC:

    def __init__(self, key, message, hash_h=sha512_):
        self.i_key_pad = bytearray()
        self.o_key_pad = bytearray()
        self.key = key
        self.message = message
        self.blocksize = 128
        self.hash_h = hash_h
        self.init_flag = False

    def init_pads(self):
        for i in range(self.blocksize):
            self.i_key_pad.append(0x36 ^ self.key[i])
            self.o_key_pad.append(0x5c ^ self.key[i])

    def init_key(self):
        if len(self.key) > self.blocksize:
            self.key = bytearray(sha512_(self.key).digest())
        elif len(self.key) < self.blocksize:
            i = len(self.key)
            while i < self.blocksize:
                self.key += b"\x00"
                i += 1

    def digest(self):
        if not self.init_flag:
            self.init_key()
            self.init_pads()
            self.init_flag = True
        return self.hash_h(bytes(self.o_key_pad) + self.hash_h(bytes(self.i_key_pad) + self.message).digest()).digest()

    def hexdigest(self):
        if not self.init_flag:
            self.init_key()
            self.init_pads()
            self.init_flag = True
        return self.hash_h(bytes(self.o_key_pad) + self.hash_h(bytes(self.i_key_pad) + self.message).digest()).hexdigest()


