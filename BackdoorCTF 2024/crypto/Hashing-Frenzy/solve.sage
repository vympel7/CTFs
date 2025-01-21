from Pwn4Sage.pwn import *
from Crypto.Util.number import *
import hashlib, sys

class testhash:
    def __init__(self, data):
        self.data = data

    def digest(self):
        return self.data 

hashes = []
hashes.append(testhash) 
hashes.append(hashlib.md5)
hashes.append(hashlib.sha224)
hashes.append(hashlib.sha256)
hashes.append(hashlib.sha3_224)
hashes.append(hashlib.sha3_256)

def calc(msg, h):
    return bytes_to_long(h(msg).digest())

def solve(factors, val, p):
    scale = 2^256
    idmat = identity_matrix(ZZ, 6).stack(zero_vector(ZZ, 6))
    mat = idmat.augment(vector(ZZ, [0] * 6 + [scale]))
    mat = mat.augment(vector(ZZ, factors + [-val]))
    mat = mat.stack(vector(ZZ, [0] * 7 + [-p]))

    for vec in mat.LLL():
        if vec[-1] == 0:
            return vec

    return None

def main():
    r = remote('34.45.235.239', 8007) if sys.argv[1] == 'REMOTE' else remote('localhost', 5050)

    r.recvuntil(b'[')
    flag_sig = eval('[' + r.recvline().rstrip().decode())


    r.recvuntil(b': '); r.sendline(b'1')
    msg0 = b'a'
    r.recvuntil(b': '); r.sendline(msg0)
    r.recvuntil(b'[')
    sig0 = eval('[' + r.recvline().rstrip().decode())

    r.recvuntil(b': '); r.sendline(b'1')
    msg1 = b'a'
    r.recvuntil(b': '); r.sendline(msg1)
    r.recvuntil(b'[')
    sig1 = eval('[' + r.recvline().rstrip().decode())

    v0 = sig0[-1]
    v1 = sig1[-1]

    val0 = sum(sig0[i] * calc(msg0, hashes[i]) for i in range(6))
    val1 = sum(sig1[i] * calc(msg1, hashes[i]) for i in range(6))

    diff0 = abs(v0 - val0)
    diff1 = abs(v1 - val1)
    p = max(prime_divisors(gcd(diff0, diff1)))

    vec = solve(flag_sig[:-1], flag_sig[-1], p)
    print(long_to_bytes(vec[0]))

    r.close()


if __name__ == '__main__':
    main()
