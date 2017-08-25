---
layout: post
title:  "hack in the card I"
date:   2017-08-25 00:00:00 +0900
categories: CTF CRYPTO RSA
---

문제
------
HITB GSEC CTF 2017
hack in the card I
 
 Welcome to work for C.I.A. Our agent 47 has successfully penetrated to an evil company and sent this secret smart card to us. Intelligence department said the crypto chip on this card is doing RSA operation and the public key we got is here(attachments -> publickey.pem). Your mission is to extract the private key embedded in this smart card and decrypt the following hex-encoded ciphertext. 

014b05e1a09668c83e13fda8be28d148568a2342aed833e0ad646bd45461da2decf9d538c2d3ab245b272873beb112586bb7b17dc4b30f0c5408d8b03cfbc8388b2bd579fb419a1cac38798da1c3da75dc9a74a90d98c8f986fd8ab8b2dc539768beb339cadc13383c62b5223a50e050cb9c6b759072962c2b2cf21b4421ca73394d9e12cfbc958fc5f6b596da368923121e55a3c6a7b12fdca127ecc0e8470463f6e04f27cd4bb3de30555b6c701f524c8c032fa51d719901e7c75cc72764ac00976ac6427a1f483779f61cee455ed319ee9071abefae4473e7c637760b4b3131f25e5eb9950dd9d37666e129640c82a4b01b8bdc1a78b007f8ec71e7bad48046

The progress of hacking was going well untill it got stuck, what we did so far is that as you can see the smartcard, an oscilloscope, a computer (act as the card reader) and a resistor are plugged into a circuit board. The circuit diagram is given as follows. 

![circuitdiagram.png]({{ site.url }}/downloads/2017/hitb/HackInTheCardI/circuitdiagram.png)


 We finally managed to decrypt a crafted message and captured voltage variation(http://47.74.147.53:20015/index.html) of the resistor during the whole process. Now we are counting on you to do the rest... 

[0b8ff93a-d959-4fe4-bd32-56b8c041fcea.gz]({{ site.url }}/downloads/2017/hitb/HackInTheCardI/0b8ff93a-d959-4fe4-bd32-56b8c041fcea.gz)

[index.html]({{ site.url }}/downloads/2017/hitb/HackInTheCardI/index.html)


풀이
------

> Simple side channel attack

simple side channel attack를 공부한다면 가장 먼저 배우는 내용

> RSA에서 지수승을 할 때엔는 여러 가지 방법이 있다.

[Exponentiation by squaring](https://en.wikipedia.org/wiki/Exponentiation_by_squaring#Basic_method)
가장 기본적으로 square-and-multiply 방법을 사용한다.

지수를 bit로 보았을때 1일 경우 base를 곱하고 0일 경우 아무 일도 안하다. 지수의 자리를 한자리 옮길때마다 square를 한다.

> 곱하기 연산이 1일 경우(squre and multiply)와 0일 경우(squre)의 연산량이 다르기 때문에 전력 소비 패턴이 다르다

![index.html]({{ site.url }}/downloads/2017/hitb/HackInTheCardI/mult.png)

전력 소모량을 보았을 때 위에가 긴것(squre and multiply)이 1 짧은것(squre)이 0이 된다.
스샷을 보았을때는 11001101... or ...10110011 (right to left, left to right).

> index.html에 데이터를 가지고 전력량이 225.0를 위에서 아래로 내려 갈때를 확인하였으며, 그 index의 차이를 계산하였다.

index.html의 172 line의 var data를 data.txt로 따로 만들었다.
[data.txt]({{ site.url }}/downloads/2017/hitb/HackInTheCardI/data.txt)

{% highlight python %}
diff_ilist = []
for i in range(len(data) - 1):
    base = 225.0
    if (data[i] > base) and (base > data[i+1]):
        diff_ilist += [i]

ilist = []
for i in range(1, len(diff_ilist)):
    diff = diff_ilist[i] - diff_ilist[i-1]
    ilist += [diff]
{% endhighlight %}

> 그 index 차이의 길이를 보았을 때 임의로 생성하여 몇가지 경우밖에 나오지 않았다. (150, 100, ...)

{% highlight python %}
key = "1"
for i in range(len(ilist)):
    if ilist[i] == 150:
        key = "1" + key
    elif ilist[i] == 100:
        key = "0" + key
    else:
        None
{% endhighlight %}

> 이렇게 만든 string을 key로 하여 복호화 하였다.

{% highlight python %}

print hex(int(key, 2))
d = int(key,2)

from Crypto.PublicKey import RSA
pem = open("publickey.pem").read()
rsa = RSA.importKey(pem)

c = 0x014b05e1a09668c83e13fda8be28d148568a2342aed833e0ad646bd45461da2decf9d538c2d3ab245b272873beb112586bb7b17dc4b30f0c5408d8b03cfbc8388b2bd579fb419a1cac38798da1c3da75dc9a74a90d98c8f986fd8ab8b2dc539768beb339cadc13383c62b5223a50e050cb9c6b759072962c2b2cf21b4421ca73394d9e12cfbc958fc5f6b596da368923121e55a3c6a7b12fdca127ecc0e8470463f6e04f27cd4bb3de30555b6c701f524c8c032fa51d719901e7c75cc72764ac00976ac6427a1f483779f61cee455ed319ee9071abefae4473e7c637760b4b3131f25e5eb9950dd9d37666e129640c82a4b01b8bdc1a78b007f8ec71e7bad48046
m = pow(c, d, rsa.n)

print hex(m)[2:-1].decode("hex")
{% endhighlight %}

[solve.py]({{ site.url }}/downloads/2017/hitb/HackInTheCardI/solve.py)

HITB{My name is Alice, and this is my story, the end of my story}