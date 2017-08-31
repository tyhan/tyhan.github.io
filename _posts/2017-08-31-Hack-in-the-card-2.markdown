---
layout: post
title:  "hack in the card 2"
date:   2017-08-31 00:00:00 +0900
categories: CTF CRYPTO RSA
---

문제
------
HITB GSEC CTF 2017

hack in the card II
 
 The second smart card sent to us has been added some countermeasures by that evil company. They also changed the public key(attachments -> publickey.pem). However it seems that they missed something...... Can you decrypt the following hex-encoded ciphertext this time?  
 
016d1d26a470fad51d52e5f3e90075ab77df69d2fb39905fe634ded81d10a5fd10c35e1277035a9efabb66e4d52fd2d1eaa845a93a4e0f1c4a4b70a0509342053728e89e977cfb9920d5150393fe9dcbf86bc63914166546d5ae04d83631594703db59a628de3b945f566bdc5f0ca7bdfa819a0a3d7248286154a6cc5199b99708423d0749d4e67801dff2378561dd3b0f10c8269dbef2630819236e9b0b3d3d8910f7f7afbbed29788e965a732efc05aef3194cd1f1cff97381107f2950c935980e8954f91ed2a653c91015abea2447ee2a3488a49cc9181a3b1d44f198ff9f0141badcae6a9ae45c6c75816836fb5f331c7f2eb784129a142f88b4dc22a0a977


[publickey.pem]({{ site.url }}/downloads/2017/hitb/HackInTheCard2/publickey.pem)


풀이
------

> 롸업을 보고 알았다. N의 값이 같다는것을 1번 문제와 ..

[writeup](https://tradahacking.vn/hitb-gsec-singapore-2017-ctf-write-ups-crypto-category-803d6c770103)

[hack in the card 1]({{ site.url }}/ctf/crypto/rsa/2017/08/25/Hack-in-the-card-I.html)

> 문제의 키워드는 N과 e, d를 알고 있으면 factoring이 가능하다는 것이다.

1번 문제의 e,d를 가지고 N을 인수분해하여 p, q를 구한다.

[이것](https://www.di-mgt.com.au/rsa_factorize_n.html)을 간한히 구현하였다.

{% highlight python %}

for g in range(3,1000):
    k = d1 * e1 - 1
    t = k
    x = 1
    while pow(t, 1, 2) != 1 :
        t = t / 2
        x = pow(g,t,n)
        if x == 1:
            continue
        if gcd(x-1, n) != 1:
            p = gcd(x-1, n)
            q = n / p
    if p != 0:
        break
{% endhighlight %}

> 오랜 시간이 걸리지 않아 바로 구해진다. 구해진 p, q를 가지고 새로운 e의 키를 찾아 복호화 한다.

[solve.py]({{site.url}}/downloads/2017/hitb/HackInTheCard2/solve.py)

HITB{they say that history is written by the victors}