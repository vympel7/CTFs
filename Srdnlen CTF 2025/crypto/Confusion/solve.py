from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os, string
from pwn import *
from cryptils.attacks.block_ciphers.aes.ecb import chosen_prefix


def blocks(data: bytes, num=-1):
    arr = [data[i:i+16] for i in range(0, len(data), 16)]
    if 0 <= num < len(arr):
        return arr[num]
    return arr

def encrypt(r, msg: bytes):
    r.sendlineafter(b'x) ', msg.hex().encode())
    r.recvuntil(b'n:\n|\n|   ')
    return bytes.fromhex(r.recvline().rstrip().decode())


def dec0(r):
    msg = os.urandom(16)
    enc_msg = encrypt(r, msg)[16:32]
    msg2 = os.urandom(16)
    enc_msg2 = encrypt(r, msg2)[16:32]
    val = xor(enc_msg2, msg)

    ct3 = blocks(encrypt(r, enc_msg + msg + msg2), 3)

    d0 = xor(ct3, val)

    assert encrypt(r, d0)[16:32] == b'\x00'*16

    return d0

def main():
    r = remote('confusion.challs.srdnlen.it', 1338) if args.REMOTE else process('./chall.py') 

    r.recvuntil(b' = ')
    ct_flag = blocks(bytes.fromhex(r.recvline().rstrip().decode()))

    D0 = dec0(r)

    F1 = b'srdnlen{I_h0p3_t'
    Fr = ct_flag[0]

    # E(F2)# {{{
    Ef1 = encrypt(r, F1)[16:32]

    data = blocks(encrypt(r, b'\x00'*32 + Fr + F1))
    Fc1 = xor(data[5], xor(Ef1, F1))

    Ef2 = xor(ct_flag[2], xor(Fc1, F1))
    # }}}
    # F2# {{{
    msg = os.urandom(16)
    enc_msg = encrypt(r, msg)[16:32]
    enc = encrypt(r, Ef2 + D0 + msg)
    ct3 = blocks(enc, 3)
    F2 = xor(ct3, xor(enc_msg, D0))
    # }}}
    F2 = b'h15_Gl4ss_0f_M1r'

    # E(F3)# {{{
    ct3 = blocks(encrypt(r, F1 + F2 + D0), 3)
    Fc2 = xor(ct3, F2)

    Ef3 = xor(ct_flag[3], xor(Fc2, F2))
    # }}}
    # F3# {{{
    msg = os.urandom(16)
    enc_msg = encrypt(r, msg)[16:32]
    enc = encrypt(r, Ef3 + D0 + msg)
    ct3 = blocks(enc, 3)
    F3 = xor(ct3, xor(enc_msg, D0))
    #}}}
    F3 = b't0_w4rm3d_y0u_3n'

    # E(F4)# {{{
    ct3 = blocks(encrypt(r, F2 + F3 + D0), 3)
    Fc3 = xor(ct3, F3)

    Ef4 = xor(ct_flag[4], xor(Fc3, F3))
    # }}}
    # F3# {{{
    msg = os.urandom(16)
    enc_msg = encrypt(r, msg)[16:32]
    enc = encrypt(r, Ef4 + D0 + msg)
    ct3 = blocks(enc, 3)
    F4 = xor(ct3, xor(enc_msg, D0))
    #}}}
    F4 = b'0ugh}'

    print(F1 + F2 + F3 + F4)

    r.close()

def main2():
    r = remote('confusion.challs.srdnlen.it', 1338) if args.REMOTE else process('./chall.py') 

    def encrypt(msg: bytes):
        r.sendlineafter(b'x) ', msg.hex().encode())
        r.recvuntil(b'n:\n|\n|   ')
        return bytes.fromhex(r.recvline().rstrip().decode())[16:32]

    r.recvuntil(b' = ')
    ct_flag = blocks(bytes.fromhex(r.recvline().rstrip().decode()))

    D0 = dec0(r)
    F1 = chosen_prefix(encrypt, string.printable, length=16, print_partial=True)


    r.close()

if __name__ == '__main__':
    context.log_level = 'error'
    main2()
