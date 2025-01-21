from pwn import *
import random
from secrets import randbelow, randbits
from copy import deepcopy
import multiprocessing as mp

GSIZE = 8209
GNUM = 79

LIM = GSIZE**GNUM


def gen(n):# {{{
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)# }}}

def gexp(g, e):# {{{
    res = tuple(g)
    while e:
        if e & 1: # if odd
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res# }}}

def enc(k, m, G):# {{{
    if not G:
        return m
    mod = GSIZE
    return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod# }}}

def inverse(perm):# {{{
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res# }}}

def decm(k, G, val):# {{{
    m = 0
    for i in range(GNUM):
        x = val % GSIZE
        y = gexp(G[i], k % GSIZE).index(x)
        m += y * GSIZE ** i
        val = (val - x) // GSIZE
        k //= GSIZE
    return m# }}}

def maketable(g):# {{{
    gg = deepcopy(g)
    table = {}
    for i in range(GSIZE):
        table[i] = gg
        gg = tuple(gg[i] for i in gg)
    return table# }}}

def perm(table, e):# {{{
    res = tuple(table[0])
    rbits = reversed(bits(e))
    ones = filter(lambda x: x != -1, [i if v == 1 else -1 for i, v in enumerate(rbits)])
    for index in ones:
        res = tuple(res[j] for j in table[index])
    return res# }}}

def findk(queue, event, table, start, end, index, want):# {{{
    for k in range(start, min(GSIZE, end)):
        if event.is_set():
            return
        if perm(table, k)[index] == want:
            event.set()
            queue.put(k)
            return# }}}

def deck(m, G, val):# {{{
    key = 0
    for i in range(GNUM):
        x = val % GSIZE
        table = maketable(G[i])
        queue = mp.Queue()
        event = mp.Event()
        ps = [mp.Process(target=findk, args=(queue, event, table, start, start + (GSIZE // mp.cpu_count()) + 1, m % GSIZE, x)) for start in range(0, GSIZE, GSIZE // mp.cpu_count())][:mp.cpu_count()]
        for p in ps:
            p.start()

        k = queue.get()
        if k == 0:
            return key

        key += k * GSIZE ** i
        val = (val - x) // GSIZE
        m //= GSIZE
    return key + m * GSIZE ** GNUM# }}}


def conn_set_seed():
    r = remote('sometrick.chals.sekai.team', 1337, ssl=True) if args.REMOTE else process('./sometrick.py')
    s = int(r.recvline().strip().decode().split('.')[-1])
    random.seed(s)
    return r

def main():
    r = conn_set_seed()

    G = [gen(GSIZE) for i in range(GNUM)]

    bob_encr = int(r.recvline().strip().decode().split(' ')[-1])
    alice_encr = int(r.recvline().strip().decode().split(' ')[-1])
    bob_decr = int(r.recvline().strip().decode().split(' ')[-1])
    r.close()

    bob_key = decm(alice_encr, [inverse(i) for i in G], bob_decr)

    key = deck(bob_key, G, bob_encr)

    for i in range(key.bit_length()):
        shifted = key >> i
        for j in range(1, shifted.bit_length()):
            keepmask = (1 << j) - 1
            final = shifted & keepmask
            dec = final.to_bytes(keepmask.bit_length() // 8 + 1)
            if b'SEKAI{' in dec:
                start = dec.index(b'SEKAI')
                end = start + dec[start:].index(b'}') + 1
                print(f'flag: {dec[start:end].decode()}')
                break
        else:
            continue
        break


if __name__ == '__main__':
    main()
