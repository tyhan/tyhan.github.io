---
layout: post
title:  "Secure Login"
date:   2017-08-07 00:00:00 +0900
categories: CTF CRYPTO RSA
---

문제
------

{% highlight python %}
import SocketServer,threading

n = 25504352309535290475248970674346405639150033303276037621954645287836414954584485104061261800020387562499019659311665606506084209652278825297538342995446093360707480284955051977871508969158833725741319229528482243960926606982225623875037437446029764584076579733157399563314682454896733000474399703682370015847387660034753890964070709371374885394037462378877025773834640334396506494513394772275132449199231593014288079343099475952658539203870198753180108893634430428519877349292223234156296946657199158953622932685066947832834071847602426570899103186305452954512045960946081356967938725965154991111592790767330692701669
e = 65537

f = open('secret.txt')
d = int(f.readline().strip())
flag = f.readline().strip()

# Translate a number to a string (byte array), for example 5678 = 0x162e = \x16\x2e
def num2str(n):
    d = ('%x' % n)
    if len(d) % 2 == 1:
        d = '0' + d
    return d.decode('hex')

# Translate byte array back to number \x16\x2e = 0x162e = 5678
def str2num(s):
    return int(s.encode('hex'),16)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class MyTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        while True:
            self.request.sendall("\nWelcome to the secure login server, make your choice from the following options:\n1. Register yourself as a user.\n2. Collect flag\n3. Sign a message\n4. Exit\nChoice: ")
            inp = self.request.recv(1024).strip()
            if inp == '1':
                self.request.sendall("Pick a username: ")
                uname = self.request.recv(1024).strip()
                self.request.sendall("Enter your full name: ")
                full = self.request.recv(1024).strip()
                ticket = 'ticket:user|%s|%s' % (uname,full)
                ticket = pow(str2num(ticket),d,n)
                ticket = num2str(ticket)
                self.request.sendall("Your ticket:\n")
                self.request.sendall(ticket.encode('hex') + "\n")
            elif inp == '2':
                self.request.sendall("Enter your ticket: ")
                ticket = self.request.recv(1024).strip()
                try:
                    ticket = int(ticket,16)
                except:
                    ticket = 0
                ticket = pow(ticket,e,n)
                ticket = num2str(ticket)
                if ticket.startswith('ticket:'):
                    if ticket.startswith('ticket:admin|root|'):
                        self.request.sendall("Here you go!\n")
                        self.request.sendall(flag + "\n")
                        break
                    else:
                        self.request.sendall("Sorry that function is only available to admin user root\n")
                else:
                    self.request.sendall("That doesn't seem to be a valid ticket\n")
            elif inp == '3':
                self.request.sendall("Enter your message, hex encoded (i.e. 4142 for AB): ")
                msg = self.request.recv(1024).strip()
                try:
                    msg = msg.decode('hex')
                except:
                    self.request.sendall("That's not a valid message\n!")
                    continue
                msg = '\xff' + msg # Add some padding at the start so users can't use this to sign a ticket
                if str2num(msg) >= n:
                    self.request.sendall("That's not a valid message\n!")
                    continue
                signed = pow(str2num(msg),d,n)
                signed = num2str(signed)
                self.request.sendall("Your signature:\n")
                self.request.sendall(signed.encode('hex') + "\n")
            elif inp == '4':
                self.request.sendall("Bye!\n")
                break
            else:
                self.request.sendall("Invalid choice!\n")

SocketServer.TCPServer.allow_reuse_address = True
server = ThreadedTCPServer(("0.0.0.0", 12345), MyTCPHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()
server.serve_forever()

{% endhighlight %}

풀이
------

> 패딩이 없어 취약점이 존재하는 RSA 

* $$m = m_1 * m_2 $$
* $$m^d = m_1 + m_2 ^ d = m_1 ^ d * m_2 ^ d
$$

> 접속을 하면 아래와 같은 메뉴가 나옵니다. 
{% highlight bash %}
Welcome to the secure login server, make your choice from the following options:
1. Register yourself as a user.
2. Collect flag
3. Sign a message
4. Exit
Choice: 
{% endhighlight %}

* 1 ticket 발행

아래 모양의 티켓을 발행하여 $$ticket ^ d$$를 해줍니다.
~~~
'ticket:user|%s|%s' % (uname,full)
~~~

* 2 login

받은 티켓에 $$ticket ^ e$$를 하여 아래 포멧인지 확인합니다.
~~~
'ticket:admin|root|'
~~~

* 3 메시지 서명

메시지를 받아 패딩을 붙인 후 $$m^d$$를 해줍니다.
~~~
msg = '\xff' + msg
~~~


> 우리가 원하는 메시지는 'ticket:admin|root|' 입니다.
사용하는 메시지를 아래와 같이 정의 합니다. 
~~~
root = 'ticket:admin|root|'
user = 'ticket:user|tyhan|%s' % alpha
msg = '\xff' + msg
~~~
root는 우리가 만들어야 하는 문자열
user는 입력 가능한 포멧의 문자열 (alpha 가변)
msg는 readable하지 않은 메시지의 서명

아래 조건을 만족하는 alpha를 만들어 냅니다.
~~~
root / user = msg
~~~

alpha를 변형하며 msg쪽의 \xff가 되는 것을 찾습니다.

제가 찾은 메시지는 아래와 같습니다.

~~~
user = ticket:user|tyhan|abrJC
msg = ff452829fdb490a35102ed25b5052f29893e61e34d96edf72843aeb1c362cbebe4fb120cca8f985478ad44e483219ec1c65e85e65d672cd29c68b53bfc7ac9a6a5dddf51d9b88ceee29aa0e9d37ce1b5a5d8129634bcf43a4d9e55a9ae4750840f71834f3430acb38bc33d31677c160d22f8c71c5d481940ae3277a908e93778b7bd0d9db6051fb6ee41ccdd4c63cec3b595c75e30d7002c65454a1f738b4aab2966ec579084797b7e791ecee0d894a4fc01b49c2407c6c3a6cd9b13d7c156b17f6facaf6269888a36b666aecedbb119aa42984ef10bbc912e4013b65b59d4a1092a369aa93928a86ddcae06b8a778a3ad67e2ec4ccb6ca5040066b6e73626
~~~

> 입력하여 $$root^d$$값을 찾습니다

* $$user^d$$는 1번 메뉴
~~~
Choice: 1
Pick a username: tyhan
Enter your full name: abrJC
Your ticket:
7b7a9c274362234b92e330824c9335a0aa3262113b1657e9ca40205105a06c783de3c8612c256d7bed1c686374ee9df4d27cc20886f5bc7bd0eaa2d3a5dfb9e07f728a0d26cab68050bebb4adff952c430c4cd860c022672ff35719ec327c6591ef704f7ab2408d16b933842a56ba46f807a59cb7a443aadd082d58a15fd46188c94042a0a8efee2463de4ab4cdcf19ddd5eaa77adc6bf08714303ae05fa1b7dcd01b2276ac48d718b4c50bb7a359a1c39aae965c27c427101252d7742c44358b638d6d2905a390188ea8c36281a0aef91b603d650e860a75d8f8e4ffc511cafe9ec7818b05d70148a3d287c4c2ac33780affed4f00bb13e90a1788b3934788e
~~~

* $$msg^d$$은 3번메뉴

~~~
Choice: 3
Enter your message, hex encoded (i.e. 4142 for AB): 452829fdb490a35102ed25b5052f29893e61e34d96edf72843aeb1c362cbebe4fb120cca8f985478ad44e483219ec1c65e85e65d672cd29c68b53bfc7ac9a6a5dddf51d9b88ceee29aa0e9d37ce1b5a5d8129634bcf43a4d9e55a9ae4750840f71834f3430acb38bc33d31677c160d22f8c71c5d481940ae3277a908e93778b7bd0d9db6051fb6ee41ccdd4c63cec3b595c75e30d7002c65454a1f738b4aab2966ec579084797b7e791ecee0d894a4fc01b49c2407c6c3a6cd9b13d7c156b17f6facaf6269888a36b666aecedbb119aa42984ef10bbc912e4013b65b59d4a1092a369aa93928a86ddcae06b8a778a3ad67e2ec4ccb6ca5040066b6e73626
Your signature:
5395ebe595044451c275055e3c2ce4e0a567dc96f39571e4d774bd4e0fad9016b37daf4ed6d13806a0b60e22e93f2757c24f6b93dd032dc5265c68110f8215e5b3584c37940f061d9d616d76fa634b5e9049612e66309376f8b45ec16db2c7f28e5e67c23b8517eb9636cc280357bcd3256645f4a27d41bf600179718b809a920ddc2b51f7c83e641150f3549dc13a4f7961f2fbe20914274cd971c512c87f9c11f506a858e75ddb38e09633b7350a62e001c3ff6e397f9d1f1fbea7b4d6900b239e9a5194df830fd7f518b9fba7a0a86c513772b73615e21592e85d79ec1521b83d05187730ce1e1c539f285b7b4e16c7f0a83bacaf1a2a0bb19be24a37eb4d
~~~

* $$root^d$$은 $$user^d$$과 $$msg^d$$을 곱합니다


$$root^d = user*msg^d = user^d * msg^d$$


> $$root^d$$을 입력하여 flag를 얻습니다.

~~~
Choice: 2
Enter your ticket: 5a364210ffafab17baf18c75b4d67ec5272e0de06be6f4e952da7d80fbf037150c132f59fa49e090b9e399b7615b34937753064f2101c02d1df2ac97b324e72522cafa82084b96ae2b455343dac828fba66650a770a729a4ef91466573db590852e95bdf9902ceaeaa3fff64e37d832d575930b1d153e950fbd9cd8480594ddff16b96b7949364e46e9d17183ce153f04e185901bb2a5b26519b0264fde1c162df3940f5cf2ff6bfd687a12e12df7359597572c1ce4ffca1451dc3181ed738d2f678669063936291e343caac4955fada311be164f740f2a318ae76553fd80bf6bafdb94ecaf966e432709bdb94fc4054c4bdc1f7d9a2ec0575381706cb775a9f
Here you go!
flag{8f898e19de410591acbcdbfae798d603}
~~~