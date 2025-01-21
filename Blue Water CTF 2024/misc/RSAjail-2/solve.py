from pwn import *
from solve_pow import solve_challenge
from tqdm import tqdm


gadgets = {
'q':
'''(N
//
p)
_,'''
,
'eh':
'''(
(4
**
8+
1)
,
(p
-1
)*
(
_[
0]
-1
))
(e
:=
_[
0]
,h
:=
_[
1]
)'''
,
'anbc':
'''(a
:=
e,
n
:=
h,
b
:=
1,
C
:=
0)'''
,
'first_egcd':
'''(Q
:=
a
//
n,
r
:=
a%
n)
(t
:=
b,
a
:=
n,
b
:=
C,
C
:=
t-
Q*
C,
n
:=
r)'''
,
'egcd':
'''(Q
:=
a
//
n,
r
:=
a%
n)
(t
:=
b,
a
:=
n,
b
:=
[C
,b
][
a
==
0]
,C
:=
t-
Q*
C,
n
:=
r)'''
,
'init_dec':
'''(s
:=
1,
d
:=
b
,
b
:=
c)
(d
:=
d
%N
)''',
'dec':
'''(s
:=
((
s*
b)
*(
d&
1)
+(
s*
(1
-(
d&
1)
))
)%
N
,b
:=
[b
,(
b
**
2)
%N
][
d>
1]
,d
:=
d
>>
1)'''
,
'end':
'''X(
s
%N
)'''
}

p = remote('rsajail2.chal.perfect.blue', 1337) if args.REMOTE else process('./chall.py')

if args.REMOTE:
    p.recvline(); p.recvline(); p.recvline()
    work = ''.join(p.recvline().decode().split(' ')[9:])
    solved = solve_challenge(work)
    p.sendlineafter(b'? ', solved.encode())
    assert 'Correct' == p.recvline().rstrip().decode()
else:
    p.recvline()

batch = '\n'.join(gadgets['q'].split('\n')).encode() + b'\n' \
        + '\n'.join(gadgets['eh'].split('\n')).encode() + b'\n' \
        + '\n'.join(gadgets['anbc'].split('\n')).encode() + b'\n' \
        + '\n'.join(gadgets['first_egcd'].split('\n')).encode() + b'\n'

p.recvuntil(b'>>> ')
p.send(batch)
for i in range(15):
    p.send('\n'.join(gadgets['egcd'].split('\n')).encode() + b'\n')

p.send('\n'.join(gadgets['init_dec'].split('\n')).encode() + b'\n')

for i in tqdm(range(2050)):
    if i % 100 > 70:
        p.send('\n'.join(gadgets['dec'].split('\n')).encode() + b'\n')
    else:
        for line in gadgets['dec'].split('\n'):
            p.sendafter(b'>>> ', line.encode() + b'\n')

p.sendafter(b'>>> ', '\n'.join(gadgets['end'].split('\n')).encode() + b'\n')

p.sendline()
while (rec := p.recvn(4)) == b'>>> ':
    continue
print(rec.decode() + p.recvline().decode())
p.close()
