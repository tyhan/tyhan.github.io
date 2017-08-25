import matplotlib.pyplot as plt

data = []
with open("data.txt", "r") as f:
    data = f.read().split(",")
    data = map(float, data)

def plot(data):
    plt.plot(data)
    plt.ylabel('some numbers')
    plt.show()

diff_ilist = []
for i in range(len(data) - 1):
    base = 225.0
    if (data[i] > base) and (base > data[i+1]):
        diff_ilist += [i]

ilist = []
for i in range(1, len(diff_ilist)):
    diff = diff_ilist[i] - diff_ilist[i-1]
    ilist += [diff]

key = "1"
for i in range(len(ilist)):
    if ilist[i] == 150:
        key = "1" + key
    elif ilist[i] == 100:
        key = "0" + key
    else:
        None

print hex(int(key, 2))
d = int(key,2)

from Crypto.PublicKey import RSA
pem = open("publickey.pem").read()
rsa = RSA.importKey(pem)

c = 0x014b05e1a09668c83e13fda8be28d148568a2342aed833e0ad646bd45461da2decf9d538c2d3ab245b272873beb112586bb7b17dc4b30f0c5408d8b03cfbc8388b2bd579fb419a1cac38798da1c3da75dc9a74a90d98c8f986fd8ab8b2dc539768beb339cadc13383c62b5223a50e050cb9c6b759072962c2b2cf21b4421ca73394d9e12cfbc958fc5f6b596da368923121e55a3c6a7b12fdca127ecc0e8470463f6e04f27cd4bb3de30555b6c701f524c8c032fa51d719901e7c75cc72764ac00976ac6427a1f483779f61cee455ed319ee9071abefae4473e7c637760b4b3131f25e5eb9950dd9d37666e129640c82a4b01b8bdc1a78b007f8ec71e7bad48046
m = pow(c, d, rsa.n)

print hex(m)[2:-1].decode("hex")