---
title: BoardLight-wp
date: '2024-09-18 00:00:00'
permalink: /post/boardlightwp-zetjxi.html
tagline: >-
  本文介绍了对BoardLight靶机的渗透测试过程。首先通过nmap扫描发现开放22和80端口，并识别出域名board.htb。接着在Dolibarr
  17.0.0后台使用弱口令admin:admin登录，利用CVE-2023-30253漏洞进行认证后的PHP代码注入，成功获取shell权限。最后枚举了/etc/passwd文件中的用户信息。
tags:
  - 信息收集
  - 漏洞利用
  - 权限提升
  - web渗透
  - linux
categories:
  - 渗透测试
layout: post
published: true
---



# BoardLight-wp

# BoardLight

## enum

### nmap

```
nmap boardlight.htb -p22,80 -sC -sV -o details  
Starting Nmap 7.94 ( https://nmap.org ) at 2024-09-17 21:03 EDT
Nmap scan report for boardlight.htb (10.10.11.11)
Host is up (0.15s latency).
rDNS record for 10.10.11.11: BoardLight.htb

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.12 seconds
```

### 子域名

![image-20240920160030264](/assets/images/image-20240920160030264-20250705113328-xm9mgxc.png)

这里域名应该是board.htb，一开始用的boardlight.htb，子域名根本枚举不出来，我属于是思维固化了，默认域名是靶机名.htb

![image-20240920155949974](/assets/images/image-20240920155949974-20250705113328-lhmq2je.png)

## web

![image-20240920160245737](/assets/images/image-20240920160245737-20250705113328-4o72vt7.png)

dolibarr 17.0.0

![image-20240920160405933](/assets/images/image-20240920160405933-20250705113328-uxgy6li.png)

弱口令admin:admin可以进入后台，但是没有分配权限

![image-20240920160520935](/assets/images/image-20240920160520935-20250705113328-lckp6e5.png)

试了一下，可以在后台创建网站，估计存在代码注入。但是试了半天没成功，先找一下nday

https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253

### CVE-2023-30253

找到个认证后php代码注入，刚好利用我们刚刚找到的弱口令

![image-20240920162113085](/assets/images/image-20240920162113085-20250705113328-ghia43d.png)

成功获取shell

![image-20240920162124999](/assets/images/image-20240920162124999-20250705113328-190xok5.png)

## foothold

### enum

/etc/passwd

```
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:126:131:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:127:134:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:128:135:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:129:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

端口情况

![image-20240920163225859](/assets/images/image-20240920163225859-20250705113328-nqnqdot.png)

3306开了个mysql

源码拖下来找一下数据库的账号密码

![image-20240920163615982](/assets/images/image-20240920163615982-20250705113328-duk2le9.png)

dolibarrowner:serverfun2$2023!!

口令复用成功登录了larissa的账户

### user flag

![image-20240920163901583](/assets/images/image-20240920163901583-20250705113328-9jqz49g.png)

## root

### enum

#### group

用户存在组adm，枚举一下组下的文件

![image-20240920164104186](/assets/images/image-20240920164104186-20250705113328-k6dgyuf.png)

#### mysql

![image-20240920164345085](/assets/images/image-20240920164345085-20250705113328-c9pw622.png)

权限不高，只能访问网站的数据库

#### linux exploit suggester

```bash
Available information:

Kernel version: 5.15.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 20.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

81 kernel space exploits
49 user space exploits

Possible Exploits:

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
```

#### suid

```
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
```

这个enlightment就很耐人寻味

### CVE-2022-37706

https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh

![image-20240920171404861](/assets/images/image-20240920171404861-20250705113328-el3oe6d.png)

## hash

```
root:$6$h9/xKUsFWX90kjQc$qcBeHXPiRHqbF0NgNxhPiZzYS1DiH4UnQc2kcshKtYEDPbjDe3E5qihEbapIJk8fAxRaj
larissa:$6$zNTCKunWYdACDiCg$m1Ci3x/AkPAUZM/YzNIXd7Ou89u/hMPPRAboFhbbevXu30s2PNtXcUvO3K1IwKIyxh.UKsonvBxKzDkedo7cw0:19860:0:99999:7:::
```
