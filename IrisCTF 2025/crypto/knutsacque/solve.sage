from sage.all import *
import numpy as np
from cryptils.attacks.lattices.linear import shortest_vector as sv

def babai(B, target):
    M = B
    G = M.gram_schmidt()[0]
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

F.<i,j,k> = QuaternionAlgebra(-1, -1)

A = [17182433425281628234 + 14279655808574179137*i + 8531159707880760053*j + 10324521189909330699*k, 10979190813462137563 + 11958433776450130274*i + 10360430094019091456*j + 11669398524919455091*k, 3230073756301653559 + 4778309388978960703*i + 7991444794442975980*j + 11596790291939515343*k, 11946083696500480600 + 18097491527846518653*i + 5640046632870036155*j + 2308502738741771335*k, 12639949829592355838 + 12578487825594881151*i + 5989294895593982847*j + 9055819202108394307*k, 15962426286361116943 + 6558955524158439283*i + 2284893063407554440*j + 14331331998172190719*k, 14588723113888416852 + 432503514368407804*i + 11024468666631962695*j + 10056344423714511721*k, 2058233428417594677 + 7708470259314925062*i + 7418836888786246673*j + 14461629396829662899*k, 4259431518253064343 + 9872607911298470259*i + 16758451559955816076*j + 16552476455431860146*k]
s = -17021892191322790357078 + 19986226329660045481112*i + 15643261273292061217693*j + 21139791497063095405696*k


coeffs = []
for a in A:
    b = a.coefficient_tuple()
    c0 = [b[0], -b[1], -b[2], -b[3]]
    ci = [b[1], b[0], b[3], -b[2]]
    cj = [b[2], -b[3], b[0], b[1]]
    ck = [b[3], b[2], -b[1], b[0]]
    coeffs.extend(c[0] for c in (c0, ci, cj, ck))
    coeffs.extend(c[1] for c in (c0, ci, cj, ck))
    coeffs.extend(c[2] for c in (c0, ci, cj, ck))
    coeffs.extend(c[3] for c in (c0, ci, cj, ck))


coeffs = np.array(coeffs).reshape(4*len(A), 4)

targets = s.coefficient_tuple()

xs = sv(2^64, coeffs, targets, return_matrix=True)

close = [ord(c) for c in 'irisctf{'] + [110] * (xs[0].degree() - len('irisctf{}') - 4) + [ord('}')] + [0] * 4

B = babai(xs, vector(ZZ, close))
print(''.join(chr(c) for c in B[:-4]))
