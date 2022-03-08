#!/usr/bin/env python3
from Crypto.Util.Padding import pad, unpad
from pwn import *
import logging

from paddingoracle import BadPaddingException, PaddingOracle

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.sock = remote('crypto.challs.pragyanctf.tech', 5001)
        self.sock.recvuntil(b'you:\n')
        self.enc = bytes.fromhex(self.sock.recvline(0).decode())

    def oracle(self, data, **kwargs):
        self.sock.sendline(data.hex().encode())
        response = self.sock.recvline(0)
        self.history.append(response)

        if response == b'idk':
            logging.debug(f'No padding exception raised on {data.hex()}')
            return

        raise BadPaddingException

    def iteractive(self, **kwargs):
        self.sock.interactive()

    def solve(self, data, **kwargs):
        iv, enc = self.enc[:16], self.enc[16:]
        token = pad(data, 16)
        target = pad(data + b'gg', 16)
        assert len(target) == 16

        niv = xor(iv, token, target)
        pload = niv + enc
        self.sock.sendline(pload.hex().encode())
        answer = self.sock.recvline(0)
        print(answer) # secrets[gg]

        target = pad(b'gg', 16)
        niv = xor(iv, token, target)
        pload = niv + enc
        self.sock.sendline(pload.hex().encode())
        print(self.sock.recvline(0)) # welcome gg

        target = pad(answer, 16)
        niv = xor(iv, token, target)
        pload = niv + enc
        self.sock.sendline(pload.hex().encode())
        print(self.sock.recvline(0)) # flag

logging.basicConfig(level=logging.DEBUG)

padbuster = PadBuster()
enc = padbuster.enc

decrypted = padbuster.decrypt(enc)
print(decrypted)

unpadded = unpad(decrypted, 16)
padbuster.solve(unpadded)
