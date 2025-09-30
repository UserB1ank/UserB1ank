---
title: nibbles-wp
date: '2023-12-08 00:00:00'
permalink: /post/nibbleswp-25aq8m.html
layout: post
published: true
---



# nibbles-wp

# Nibbles

## user

### Nmap

```shell
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-08 13:58 CST
Nmap scan report for nibbles.htb (10.129.39.47)
Host is up (0.47s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.56 seconds
```

### 前端信息泄漏

![image-20231208141915922](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208141915922.png)

### ENUM

![image-20231208142052112](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208142052112.png)

![image-20231208142133899](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208142133899.png)

### brute force

admin.php需要帐号密码，爆破一下

![image-20231208142425955](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208142425955.png)

但是存在黑名单，进去了被屏蔽了

> 后来发现这里其实密码不对，1870是他被waf墙了，真实的密码应该是nibbles

### 解析配置错误

`/content`路径下的解析文件配置的不对，直接把目录暴露了出来，其中user.xml里面提示了用户名是`admin`，但是我们已经猜到了。其中对我们有用的信息是这个`notification.xml`，时间戳转换一下可以发现`session_fail`的都是我们最近的请求，猜测是对ip进行了校验。

![image-20231208143710778](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208143710778.png)

![image-20231208143855712](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208143855712.png)

### msf

![image-20231208151400564](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208151400564.png)

## root

### sudo

![image-20231208152202982](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208152202982.png)

![image-20231208152302508](https://gitee.com/UserB1ank/picgo_bed/raw/master/img/image-20231208152302508.png)
