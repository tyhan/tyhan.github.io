ns = []
cs = []
with open("rsa3.txt","r") as f:
    file = f.readlines()
    for i in range(len(file)/3):
        n = file[3*i].strip()
        ns += [int(n.split("=")[1])]
        c = file[3*i+1].strip()
        cs += [int(c.split("=")[1])]
c = cs[0]
cs = cs[1:]
n = ns[0]
ns = ns[1:]

p = 1
while len(ns) != 0:
    c1 = crt(c, cs[1], n, ns[1])
    p += 1
    n *= ns[1]
    ns = ns[1:]
    cs = cs[1:]
    if c == c1:
        break
    c = c1

length = int(log(c,2))

for j in range(p - 5, p+10000):
    m = 0
    for i in range(length/(j - 3), -1, -1):
        m97 = pow((m+(2^i)),j)
        if m97 <= c:
            m = m + (2^i)
    m97 = pow(m,j)
    if m97 == c:
        print hex(m).decode("hex")
        break