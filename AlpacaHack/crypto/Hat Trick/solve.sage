from Pwn4Sage.pwn import *
import json, string

def babai(B, target):
    # M = B.LLL()
    M = B
    G = B.gram_schmidt()[0]
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

def _hash(vals, base, p):
    return sum(val*pow(base, i, p) % p for i, val in enumerate(vals)) % p


r = remote('localhost', 9999)

params = json.loads(r.recvline()[8:])
base1, p1 = params[0]['base'], params[0]['p']
base2, p2 = params[1]['base'], params[1]['p']
base3, p3 = params[2]['base'], params[2]['p']
bases = [base1, base2, base3]
mods = [p1, p2, p3]

for _ in range(3):
    targets = eval(r.recvline()[8:].decode())
    target1, target2, target3 = targets

    weight = 1 << 64
    for size in range(45, 55):
        W = block_matrix(ZZ, [
            [identity_matrix(ZZ, size), 0                                ],
            [0                        , diagonal_matrix(ZZ, [weight] * 4)]
        ])

        right = matrix(ZZ, [
            vector(ZZ, [pow(base, i, p) for i in range(size)] + [-target]) for base, p, target in zip(bases, mods, targets)
        ]).T

        mat = block_matrix(ZZ, [
            [diagonal_matrix(ZZ, [1] * size + [1]), right                     ],
            [0                                         , -diagonal_matrix(ZZ, mods)]
        ])

        vecs = (mat * W).LLL() / W
        cv = babai(vecs.change_ring(ZZ), vector(ZZ, [110] * size + [1] + [0] * 3))

        if any(x < ord('a') or x > ord('z') for x in cv[:size]):
            continue

        calcs = [_hash(cv[:size], base, p) for base, p in zip(bases, mods)]

        if calcs == targets:
            string = ''.join(map(chr, cv[:size]))
            r.sendafter(b'> ', string.encode() + b'\n')
            break

flag = r.recvline().rstrip().decode().split(': ')[1]
print('flag:', flag)

r.close()
