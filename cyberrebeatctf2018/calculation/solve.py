from netcat.netcat import Netcat

nc = Netcat('59.106.212.75', 8080)

while True:
    q = nc.read_until('\n')
    print(q)
    ans = str(eval(q.strip('\ufeff').strip('\n')))
    print(ans)
    nc.write(str(ans + '\n').encode('utf-8'))
