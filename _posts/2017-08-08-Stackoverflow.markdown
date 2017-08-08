---
layout: post
title:  "Stack Over Flow"
date:   2017-08-08 00:00:00 +0900
categories: CTF CRYPTO AES
---

문제
------

{% highlight python %}
import os, sys
from Crypto.Cipher import AES

fn = sys.argv[1]
data = open(fn,'rb').read()

# Secure CTR mode encryption using random key and random IV, taken from
# http://stackoverflow.com/questions/3154998/pycrypto-problem-using-aesctr
secret = os.urandom(16)
crypto = AES.new(os.urandom(32), AES.MODE_CTR, counter=lambda: secret) 

encrypted = crypto.encrypt(data)
open(fn+'.enc','wb').write(encrypted)
{% endhighlight %}

[flag.pdf.enc]({{ site.url }}/downloads/2017/shactf/stackoverflow/flag.pdf.enc)

풀이
------

>  pycrypto의 문제점을 이용한 문제

stackoverflow의 말에 따르면 AES CTR을 이용할때 아래와 같은 카운터를 사용한다면 계속 같은 값이 들어간다고 한다.
~~~
counter=lambda: os.urandom(16)
~~~

* 계속 같은 값이 들어간다는 말은 매번 xor되는 블럭이 같다는 이야기임

> 문제에 주어진 pdf를 복호화 하는 문제임

일반적인 pdf에 뒤부분에 0000 (0x30303030)이 많은 것을 볼수 있었다. 이부분을 중심으로 맞추면 될것같아 찾아 보았다.

인터넷에서 받은 임의의 pdf파일의 뒷부분
~~~
00004e80: 3030 3030 3030 3030 3030 2036 3535 3335  0000000000 65535
00004e90: 2066 0d0a 3030 3030 3030 3030 3030 2036   f..0000000000 6
00004ea0: 3535 3335 2066 0d0a 3030 3030 3030 3030  5535 f..00000000
00004eb0: 3030 2036 3535 3335 2066 0d0a 3030 3030  00 65535 f..0000
00004ec0: 3030 3030 3030 2036 3535 3335 2066 0d0a  000000 65535 f..
00004ed0: 3030 3030 3030 3030 3030 2036 3535 3335  0000000000 65535
00004ee0: 2066 0d0a 3030 3030 3030 3030 3030 2036   f..0000000000 6
00004ef0: 3535 3335 2066 0d0a 3030 3030 3030 3030  5535 f..00000000
00004f00: 3030 2036 3535 3335 2066 0d0a 3030 3030  00 65535 f..0000
00004f10: 3030 3030 3030 2036 3535 3335 2066 0d0a  000000 65535 f..
00004f20: 3030 3030 3030 3030 3030 2036 3535 3335  0000000000 65535
00004f30: 2066 0d0a 3030 3030 3030 3030 3030 2036   f..0000000000 6
00004f40: 3535 3335 2066 0d0a 3030 3030 3030 3030  5535 f..00000000
00004f50: 3030 2036 3535 3335 2066 0d0a 3030 3030  00 65535 f..0000
00004f60: 3030 3030 3030 2036 3535 3335 2066 0d0a  000000 65535 f..
00004f70: 3030 3030 3030 3030 3030 2036 3535 3335  0000000000 65535
00004f80: 2066 0d0a 3030 3030 3030 3030 3030 2036   f..0000000000 6
00004f90: 3535 3335 2066 0d0a 3030 3030 3030 3030  5535 f..00000000
00004fa0: 3030 2036 3535 3335 2066 0d0a 3030 3030  00 65535 f..0000
00004fb0: 3030 3030 3030 2036 3535 3335 2066 0d0a  000000 65535 f..
00004fc0: 3030 3030 3030 3030 3030 2036 3535 3335  0000000000 65535
00004fd0: 2066 0d0a 3030 3030 3030 3030 3030 2036   f..0000000000 6
00004fe0: 3535 3335 2066 0d0a 3030 3030 3030 3030  5535 f..00000000
00004ff0: 3030 2036 3535 3335 2066 0d0a 3030 3030  00 65535 f..0000
00005000: 3030 3030 3030 2036 3535 3335 2066 0d0a  000000 65535 f..
00005010: 3030 3030 3030 3030 3030 2036 3535 3335  0000000000 65535
00005020: 2066 0d0a 3030 3030 3030 3030 3030 2036   f..0000000000 6
00005030: 3535 3335 2066 0d0a 7472 6169 6c65 720d  5535 f..trailer.
00005040: 0a3c 3c2f 5369 7a65 2033 372f 456e 6372  .<</Size 37/Encr
00005050: 7970 7420 3338 2030 2052 3e3e 0d0a 7374  ypt 38 0 R>>..st
00005060: 6172 7478 7265 660d 0a31 3136 0d0a 2525  artxref..116..%%
00005070: 454f 460d 0a                             EOF..
~~~

주어진 암호화된 pdf의 문서의 뒷부분

~~~
0001ab30: c38a cd03 2d18 749c 1512 fe87 ee3c 5f89  ....-.t......<_.
0001ab40: d3d4 dd39 2d18 7498 1510 ee83 ea3c 4f89  ...9-.t......<O.
0001ab50: c38a cd03 3d46 64a2 1510 ee87 ee3c 5f8d  ....=Fd......<_.
0001ab60: c58b dd03 2d18 7498 054e febd ee3c 5f89  ....-.t..N...<_.
0001ab70: c28a c903 2d1c 6498 1510 ee87 fe62 4fb3  ....-.d......bO.
0001ab80: c38a cd03 2c18 7098 1716 fe87 ee3c 5f89  ....,.p......<_.
0001ab90: d3d4 dd39 2d18 7498 1410 ea87 eb3f 4f89  ...9-.t......?O.
0001aba0: c38a cd03 3d46 64a2 1510 ee87 ef3c 5780  ....=Fd......<W.
0001abb0: c78e dd03 2d18 7498 054e febd ee3c 5f89  ....-.t..N...<_.
0001abc0: c28a c50a 2b1d 6498 1510 ee87 fe62 4fb3  ....+.d......bO.
0001abd0: c38a cd03 2c18 7c91 1d17 fe87 ee3c 5f89  ....,.|......<_.
0001abe0: d3d4 dd39 2d18 7498 1410 e787 ee34 4f89  ...9-.t......4O.
0001abf0: c38a cd03 3d46 64a2 1510 ee87 ef3c 5689  ....=Fd......<V.
0001ac00: c08a dd03 2d18 7498 054e febd ee3c 5f89  ....-.t..N...<_.
0001ac10: c28a c403 2819 6498 1510 ee87 fe62 4fb3  ....(.d......bO.
0001ac20: 87c8 9c5a 714d 36a2 191c d498 8d65 15dc  ...ZqM6......e..
0001ac30: d38b c539 3261 2ace 4a00 ef80 fe3c 4feb  ...92a*.J....<O.
0001ac40: f995 af5c 725c 6499 0510 fee5 d423 26fd  ...\r\d......#&.
0001ac50: d3e1 c155 2b18 2191 1213 ba81 e839 0a8a  ...U+.!......9..
0001ac60: c38d cb04 2b4a 21c9 1145 e78f e73d 5689  ....+J!..E...=V.
0001ac70: 908a 9957 281b 2090 1713 ea82 b83c 5989  ...W(. ......<Y.
0001ac80: c3de c902 2819 229e 1213 bcd4 eb6d 5fdc  ....(."......m_.
0001ac90: 90db 980d 3d14 229e 1545 e780 ed68 598f  ....=."..E...hY.
0001aca0: c6df ce03 2a1e 739e 4745 bf83 bb35 5780  ....*.s.GE...5W.
0001acb0: c283 cd50 2d4c 209d 1644 e685 ed38 5adf  ...P-L ..D...8Z.
0001acc0: c38c cd03 791c 759d 1446 e880 ed6e 0c8c  ....y.u..F...n..
0001acd0: 928a 9850 7c4d 7af5 2f1e e0bd ad78 0ecb  ...P|Mz./....x..
0001ace0: 87c2 8f56 7b22 7598 1c12 ed87 d429 4afc  ...V{"u......)J.
0001acf0: bcfc f7                                  ...
~~~

친절하게도 AES는 16바이트로 되어 있어서 정렬이 잘 되어 있었다.
어느 한부분은 3030이라는 가정하에 xor값 aa를 손수 찾았다.
예를들어 첫 2바이트는 c38a가 많이 나와 선택하였다.
원문에는 3030이 많이 나오므로 많이 겹치는 값을 중심으로 발췌하여 b값을 채워 넣었다.

~~~
def sxor(s1,s2):    
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

f2 = open("flag.pdf.enc", "rb")
s2 = f2.read(16)
f3 = open("flag.pdf", "wb")

a = "30303030303030303030303030303030"
b = "c38acd032d1874981510ee87ee3c5f89"
aa = sxor(a.decode("hex"), b.decode("hex"))


while s2 != "":
    f3.write(sxor(aa,s2))
    s2 = f2.read(16)
~~~

[flag.pdf]({{ site.url }}/downloads/2017/shactf/stackoverflow/flag.pdf)