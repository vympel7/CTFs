from cryptils.attacks.block_ciphers.aes.ecb import chosen_prefix
from cryptils.utils import blockify
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from pwn import *
import os, string


def encrypt(r, msg: bytes, block: int = -1):
    r.sendlineafter(b'x) ', msg.hex().encode())
    r.recvuntil(b'n:\n|\n|   ')
    ct = bytes.fromhex(r.recvline().rstrip().decode())
    if 0 <= block < len(ct) // 16:
        return ct[16*block:16*(block + 1)]
    return ct

def dec0(r):
    msg1 = os.urandom(16)
    enc_msg1 = encrypt(r, msg1, 1)
    msg2 = os.urandom(16)
    enc_msg2 = encrypt(r, msg2, 1)
    val = xor(enc_msg2, msg1)

    ct3 = encrypt(r, enc_msg1 + msg1 + msg2, 3)

    d0 = xor(ct3, val)

    assert encrypt(r, d0, 1) == b'\x00'*16

    return d0

def main():
    r = remote('confusion.challs.srdnlen.it', 1338) if args.REMOTE else process('./chall.py') 

    r.recvuntil(b' = ')
    ct_flag = blockify(bytes.fromhex(r.recvline().rstrip().decode()))

    D0 = dec0(r)

    flag = chosen_prefix(lambda b: encrypt(r, b, 1), string.printable, length=16)
    curr, prev = flag, ct_flag[0]

    for i in range(2, len(ct_flag)):
        ct3 = encrypt(r, prev + curr + D0, 3)
        enc_next = xor(ct_flag[i], ct3)

        msg = os.urandom(16)
        enc_msg = encrypt(r, msg, 1)
        enc = encrypt(r, enc_next + D0 + msg, 3)

        prev = curr
        curr = xor(enc, xor(enc_msg, D0))

        flag += curr

    print('flag:', unpad(flag, 16).decode())

    r.close()

if __name__ == '__main__':
    context.log_level = 'error'
    main()
