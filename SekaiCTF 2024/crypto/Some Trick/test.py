from secrets import randbelow, randbits

LIM = 8209**79

f = [7101, 2010, 7261, 4828, 1493, 7565, 939, 105, 6524, 504, 2117, 6753, 1640, 2174, 6561, 7166, 4206, 6313, 3843, 4468, 6978, 7627, 2317, 2949, 1722, 7123, 5477, 1053, 1189, 1879, 2743, 1296, 227, 2993, 1766, 1167, 603, 2432, 3653, 5401, 5486, 1887, 6867, 4819, 8073, 4592, 2507, 802, 4117, 5013, 197, 2731, 4285, 7772, 7322, 3513, 707, 7736, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


s = 0
for i, v in enumerate(ff):
    s += v * 8209 ** i

for i in range(s.bit_length()):
    shifted = s >> i
    for j in range(shifted.bit_length()):
        keepmask = (1 << j) - 1
        final = shifted & keepmask
        dec = final.to_bytes(130)
        if b'SEKAI' in dec:
            print(dec)
            break
    else:
        continue
    break
