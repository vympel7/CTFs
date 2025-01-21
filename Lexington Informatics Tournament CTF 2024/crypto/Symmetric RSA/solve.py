from Crypto.Util.number import isPrime as is_prime
from math import gcd
from pwn import *

def enc(r, m):
    r.sendlineafter(b't: ', str(m).encode())
    r.recvuntil(b' = ')
    return int(r.recvline().strip().decode())

def main():
    r = remote('litctf.org', 31783)
    r.recvuntil(b' = ')
    f = int(r.recvline().strip().decode())

    n = enc(r, -1) + 1
    e2 = enc(r, 2)
    p = gcd(n, e2 - 2)
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(p, -1, phi)
    m = pow(f, d, n)
    flag = m.to_bytes(m.bit_length() // 8 + 1)
    print(flag.decode())



if __name__ == '__main__':
    main()
