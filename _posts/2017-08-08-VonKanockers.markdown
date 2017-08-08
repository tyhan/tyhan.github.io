---
layout: post
title:  "Von Kanockers"
date:   2017-08-08 01:00:00 +0900
categories: CTF NETWORK PORTKNOCKING
---

문제
------
주어진 사이트에 가보로가고 나왔고 거기 접속하여 소스를 보았다.

{% highlight html %}
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>The name is Kanockers. Vod Kanockers</title>
  </head>
  <body>
    <!-- *Knock Knock* 88 156 983 1287 8743 5622 9123 -->
    <img src="vod.jpg" />
  </body>
</html>
{% endhighlight %}

풀이
------

> 주어진 사이트를 가서 소스를 문제에 적어 놓았다.

주석이 수상하다.
nc로 하나 하나 접속해 보았더니 마지막 포트가 열리지 않는다.
수열을 맞춰서 열어야 하는것 같아 packet 캡쳐를 해보았다.
data는 오지 않는다.

계속 nc 34.249.81.124 port 를 입력하는게 구찮아서 한번에 입력하게 만들고 패킷을 캡쳐하려하였지만,
플래그가 나와버렸다.

아마도 순서대로 빠르게 접속을 하면 플래그를 주는 형식이였던 것 같다.

![screen shot]({{ site.url }}/downloads/2017/shactf/VodKanockers/vonKanockers.png)