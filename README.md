# Утилита для сканирования безопасности сети Nmap
<p>
    # Подготовка ОС.<br>
    # Настройка Iptables.<br>
    # Настройка Vsftpd-сервера.<br>
    # Настройка Nginx-сервера.<br>
    # Настройка Proxy-сервера.<br>
    # Сканирование сети Nmap.<br>
    # Перехват трафиков в Tcpdump.<br>
    # Блокировка подозрительных IP-адресов.<br>
    # Безопасность сервера.<br>
    <strong>Task:</strong><br>
    Подготовка ОС. Подключение внешнего диска к WSl<br>
    <strong>Decision:</strong><br>
    &gt; wmic diskdrive list brief<br>
    Caption&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; DeviceID&nbsp;&nbsp; Model&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Partitions Size&nbsp;&nbsp;<br>
    ST1000LM 035-1RK172 SCSI Disk Device \\.\PHYSICALDRIVE2 ST1000LM 035-1RK172 SCSI Disk Device 1&nbsp;&nbsp; 1000202273280<br>
    ...<br>
    &gt; wsl --mount \\.\PHYSICALDRIVE2 --partition 1<br>
    Диск успешно подключен как "/mnt/wsl/PHYSICALDRIVE2p1".<br>
    ...<br>
    &gt; wsl<br>
    # ls /mnt/wsl/PHYSICALDRIVE2p1/<br>
    Centos_9.img Ubuntu_2204.qcow2 Windows12.qcow2 ubuntu-22.04.3-desktop-amd64.iso<br>
    Kali.qcow2 Windows.qcow2 lost+found<br>
    # lsblk<br>
    NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS<br>
    ...<br>
    sdc 8:32 0 931.5G 0 disk<br>
    └─sdc1 8:33 0 931.5G 0 part /mnt/wsl/PHYSICALDRIVE2p1<br>
    ...<br>
    # mount /dev/sdc1 /var/lib/libvirt/images/<br>
    # ls /var/lib/libvirt/images/<br>
    Centos_9.img Ubuntu_2204.qcow2 Windows12.qcow2 ubuntu-22.04.3-desktop-amd64.iso<br>
    Kali.qcow2 Windows.qcow2 lost+found<br>
    &gt; wsl.exe --unmount \\.\PHYSICALDRIVE2<br>
    <strong>Source:</strong><br>
    # https://habr.com/ru/news/518806/ - Microsoft добавила в подсистему Windows для Linux 2 (WSL2) возможность монтирования дисков<br>
    # https://qna.habr.com/q/861519 - Где находится домашняя директория WSL?&nbsp;<br>
    <strong>Task:</strong><br>
    Настройка iptables. Выводим список текущих правил iptables и проанализируем какие порты открыты в сервере Centos.&nbsp;<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo yum install iptables-services<br>
    [tuser@kvmcentos ~]$ sudo iptables --version<br>
    [tuser@kvmcentos ~]$ sudo iptables -L -v<br>
    Chain INPUT (policy ACCEPT 0 packets, 0 bytes)<br>
    pkts bytes target prot opt in out source destination&nbsp;<br>
    Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)<br>
    pkts bytes target prot opt in out source destination&nbsp;<br>
    Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)<br>
    pkts bytes target prot opt in out source destination&nbsp;<br>
    [tuser@kvmcentos ~]$ sudo systemctl start iptables<br>
    [tuser@kvmcentos ~]$ sudo systemctl enable iptables<br>
    [tuser@kvmcentos ~]$ sudo service iptables status<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap tipcentos<br>
    Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-17 08:33 CDT<br>
    Nmap scan report for centos (tipcentos)<br>
    Host is up (0.00089s latency).<br>
    Not shown: 999 filtered ports<br>
    PORT STATE SERVICE<br>
    22/tcp open ssh<br>
    MAC Address: 52:54:00:7e:05:15 (QEMU virtual NIC)<br>
    Nmap done: 1 IP address (1 host up) scanned in 5.30 seconds<br>
    <strong>Task:</strong><br>
    Настройка iptables. В сервере Centos Напишем набор правил iptables, в котором мы разрешаем все исходящие соединения и строго ограничиваем входящие.&nbsp;<br>
    Доступ будет возможен по портам TCP: 21, 22, 25, 53, 80, 143, 443, по портам UDP: 20, 21, 53, также мы пропускаем пакеты для уже установленных соединений.<br>
    С удаленной машины просканируем порты на нашем сервере.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo vim firewall.sh<br>
    [tuser@kvmcentos ~]$ sudo cat firewall.sh<br>
    #!/bin/bash<br>
    IPT="/sbin/iptables"<br>
    # Очищаем правила и удаляем цепочки.<br>
    $IPT -F<br>
    $IPT -X<br>
    # По умолчанию доступ запрещен.<br>
    $IPT -P INPUT DROP<br>
    $IPT -P FORWARD DROP<br>
    $IPT -P OUTPUT DROP<br>
    # Список разрешенных TCP и UDP портов.<br>
    TCP_PORTS="21,22,25,53,80,143,443"<br>
    UDP_PORTS="53,21,20"<br>
    # Разрешаем пакеты для интерфейса обратной петли.<br>
    $IPT -A INPUT -i lo -j ACCEPT<br>
    $IPT -A OUTPUT -o lo -j ACCEPT<br>
    # Разрешаем пакеты для установленных соединений.<br>
    $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT<br>
    # Разрешаем исходящие соединения.<br>
    $IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT<br>
    # Разрешаем доступ к портам, описанным в переменных TCP_PORTS и UDP_PORTS.<br>
    $IPT -A INPUT -p tcp -m multiport --dport $TCP_PORTS -j ACCEPT<br>
    $IPT -A INPUT -p udp -m multiport --dport $UDP_PORTS -j ACCEPT<br>
    # Разрешаем исходящий ping.<br>
    $IPT -A INPUT -p icmp -m icmp --icmp-type echo-reply -j ACCEPT<br>
    [tuser@kvmcentos ~]$ sudo chmod +x firewall.sh<br>
    [tuser@kvmcentos ~]$ sudo ./firewall.sh<br>
    [tuser@kvmcentos ~]$ sudo iptables -L -v<br>
    Chain INPUT (policy DROP 1986 packets, 87384 bytes)<br>
    pkts bytes target prot opt in out source destination&nbsp;<br>
    0 0 ACCEPT all -- lo any anywhere anywhere&nbsp;<br>
    79 5604 ACCEPT all -- any any anywhere anywhere state RELATED,ESTABLISHED<br>
    9 396 ACCEPT tcp -- any any anywhere anywhere multiport dports ftp,ssh,smtp,domain,http,imap,https<br>
    0 0 ACCEPT udp -- any any anywhere anywhere multiport dports domain,ftp,ftp-data<br>
    0 0 ACCEPT icmp -- any any anywhere anywhere icmp echo-reply<br>
    Chain FORWARD (policy DROP 0 packets, 0 bytes)<br>
    pkts bytes target prot opt in out source destination&nbsp;<br>
    Chain OUTPUT (policy DROP 0 packets, 0 bytes)<br>
    pkts bytes target prot opt in out source destination&nbsp;<br>
    0 0 ACCEPT all -- any lo anywhere anywhere&nbsp;<br>
    60 7920 ACCEPT all -- any any anywhere anywhere state NEW,RELATED,ESTABLISHED<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap tipcentos<br>
    ...<br>
    PORT STATE SERVICE<br>
    21/tcp closed ftp<br>
    22/tcp open ssh<br>
    25/tcp closed smtp<br>
    53/tcp closed domain<br>
    80/tcp closed http<br>
    143/tcp closed imap<br>
    443/tcp closed https<br>
    ...<br>
    <strong>Source:</strong><br>
    # https://blog.sedicomm.com/2016/12/16/iptables-ustanovka-i-nastrojka/?ysclid=ln3wplng53988958006#1<br>
    <strong>Task:</strong><br>
    Настройка Vsftpd-сервера. Install and configure an FTP server. Securing the connection to the FTP server.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo dnf update -y<br>
    [tuser@kvmcentos ~]$ sudo dnf install vsftpd -y<br>
    [tuser@kvmcentos ~]$ sudo systemctl enable vsftpd --now<br>
    [tuser@kvmcentos ~]$ sudo systemctl status vsftpd<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap tipcentos<br>
    ...<br>
    PORT STATE SERVICE<br>
    21/tcp open ftp<br>
    22/tcp open ssh<br>
    25/tcp closed smtp<br>
    53/tcp closed domain<br>
    80/tcp closed http<br>
    143/tcp closed imap<br>
    443/tcp closed https<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo useradd -m -d "/home/tuser2" tuser2<br>
    [tuser@kvmcentos ~]$ sudo passwd tuser2<br>
    [tuser@kvmcentos ~]$ sudo mkdir -p /home/tuser2/shared<br>
    [tuser@kvmcentos ~]$ sudo chmod -R 750 /home/tuser2/shared<br>
    [tuser@kvmcentos ~]$ sudo chown tuser2: /home/tuser2/shared<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/vsftpd/user_list<br>
    [tuser@kvmcentos ~]$ sudo cat /etc/vsftpd/user_list | grep ftp<br>
    tuser2<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/vsftpd/vsftpd.conf<br>
    [tuser@kvmcentos ~]$ sudo cat /etc/vsftpd/vsftpd.conf<br>
    ...<br>
    anonymous_enable=NO<br>
    ...<br>
    local_enable=YES<br>
    ...<br>
    write_enable=YES<br>
    ...<br>
    chroot_local_user=YES<br>
    ...<br>
    allow_writeable_chroot=YES<br>
    pasv_min_port=31500<br>
    pasv_max_port=32500<br>
    userlist_file=/etc/vsftpd/user_list<br>
    userlist_deny=NO<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart vsftpd<br>
    [tuser@kvmcentos ~]$ sudo openssl req -x509 -nodes -days 3650 \<br>
    -newkey rsa:2048 -keyout /etc/vsftpd.pem \<br>
    -out /etc/vsftpd/vsftpd.pem<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/vsftpd/vsftpd.conf<br>
    [tuser@kvmcentos ~]$ sudo cat /etc/vsftpd/vsftpd.conf<br>
    ...<br>
    #rsa_cert_file=/etc/vsftpd/vsftpd.pem<br>
    #rsa_private_key_file=/etc/vsftpd.pem<br>
    #ssl_enable=YES<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart vsftpd<br>
    [tuser@kvmcentos ~]$ sudo cat /etc/sysconfig/iptables<br>
    # Generated by iptables-save v1.8.8 (nf_tables) on Sun Oct 22 12:10:33 2023<br>
    *mangle<br>
    :PREROUTING ACCEPT [45:3316]<br>
    :INPUT ACCEPT [45:3316]<br>
    :FORWARD ACCEPT [0:0]<br>
    :OUTPUT ACCEPT [34:5048]<br>
    :POSTROUTING ACCEPT [34:5048]<br>
    COMMIT<br>
    # Completed on Sun Oct 22 12:10:33 2023<br>
    # Generated by iptables-save v1.8.8 (nf_tables) on Sun Oct 22 12:10:33 2023<br>
    *raw<br>
    :PREROUTING ACCEPT [45:3316]<br>
    :OUTPUT ACCEPT [34:5048]<br>
    COMMIT<br>
    # Completed on Sun Oct 22 12:10:33 2023<br>
    # Generated by iptables-save v1.8.8 (nf_tables) on Sun Oct 22 12:10:33 2023<br>
    *filter<br>
    :INPUT DROP [0:0]<br>
    :FORWARD DROP [0:0]<br>
    :OUTPUT DROP [0:0]<br>
    -A INPUT -i lo -j ACCEPT<br>
    -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT<br>
    -A INPUT -p tcp -m multiport --dports 21,22,25,53,80,143,443 -j ACCEPT<br>
    -A INPUT -p udp -m multiport --dports 53,21,20 -j ACCEPT<br>
    -A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT<br>
    -A OUTPUT -o lo -j ACCEPT<br>
    -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT<br>
    COMMIT<br>
    # Completed on Sun Oct 22 12:10:33 2023<br>
    # Generated by iptables-save v1.8.8 (nf_tables) on Sun Oct 22 12:10:33 2023<br>
    *nat<br>
    :PREROUTING ACCEPT [0:0]<br>
    :INPUT ACCEPT [0:0]<br>
    :OUTPUT ACCEPT [0:0]<br>
    :POSTROUTING ACCEPT [0:0]<br>
    COMMIT<br>
    # Completed on Sun Oct 22 12:10:33 2023<br>
    [tuser@kvmcentos ~]$ sudo iptables -t filter -A INPUT -p tcp --dport 20:21 -j ACCEPT<br>
    [tuser@kvmcentos ~]$ sudo iptables -t filter -A INPUT -p tcp --dport 31500:32500 -j ACCEPT<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ telnet tipcentos 21<br>
    Trying tipcentos...<br>
    Connected to tipcentos.<br>
    Escape character is '^]'.<br>
    220 (vsFTPd 3.0.5)<br>
    USER tuser2<br>
    331 Please specify the password.<br>
    PASS tpassword<br>
    230 Login successful.<br>
    PWD<br>
    257 "/" is the current directory<br>
    PASV<br>
    227 Entering Passive Mode (I,P,126,61).<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ 126*256+61<br>
    32317<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ telnet tipcentos 32317<br>
    Trying tipcentos...<br>
    Connected to tipcentos.<br>
    Escape character is '^]'.<br>
    LIST<br>
    150 Here comes the directory listing.<br>
    226 Directory send OK.<br>
    drwxr-x--- 2 1001 1001 6 Oct 21 03:06 shared<br>
    QUIT<br>
    221 Goodbye.<br>
    <strong>Task:</strong><br>
    Настройка Vsftpd-сервера. Запрещаем доступ к фтп всем пользователям, кроме пользователя с MAC-адресом 52:54:00:19:98:c5.<br>
    <strong>Decision:</strong><br>
    tuser@kvmubuntu:~$ ifconfig | grep 52:54:00:19:98:c5<br>
    ether 52:54:00:19:98:c5 txqueuelen 1000 (Ethernet)<br>
    [tuser@kvmcentos ~]$ sudo iptables -I INPUT -p tcp --dport 21 -m mac ! --mac-source 52:54:00:19:98:c5 -j REJECT<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables<br>
    tuser@kvmubuntu:~$ ftp tipcentos<br>
    Connected to tipcentos.<br>
    220 (vsFTPd 3.0.5)<br>
    Name (tipcentos:user): tuser2<br>
    331 Please specify the password.<br>
    Password:&nbsp;<br>
    230 Login successful.<br>
    Remote system type is UNIX.<br>
    Using binary mode to transfer files.<br>
    ftp&gt; ls<br>
    229 Entering Extended Passive Mode (|||31695|)<br>
    150 Here comes the directory listing.<br>
    drwxr-x--- 2 1001 1001 6 Oct 21 03:06 shared<br>
    226 Directory send OK.<br>
    ftp&gt; exit<br>
    221 Goodbye.<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ ftp tipcentos<br>
    ftp: Can't connect to `tipcentos:21': Connection refused<br>
    ftp: Can't connect to `tipcentos:ftp'<br>
    ftp&gt; exit<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ telnet tipcentos 21&nbsp;<br>
    Trying tipcentos...<br>
    telnet: Unable to connect to remote host: Connection refused<br>
    <strong>Source:</strong><br>
    # https://unixcop.com/how-to-install-and-configure-an-ftp-server-on-centos-9-stream/<br>
    # https://losst.pro/kak-otkryt-port-iptables?ysclid=lnvrpgxwj8175390861<br>
    # https://techviewleo.com/configure-vsftpd-ftp-server-on-ubuntu-linux/<br>
    # https://stackoverflow.com/questions/38523250/vsftpd-login-is-not-successful<br>
    <strong>Task:</strong><br>
    Настройка Nginx-сервера. Install Nginx.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo dnf update -y<br>
    [tuser@kvmcentos ~]$ sudo dnf install nginx<br>
    [tuser@kvmcentos ~]$ sudo systemctl start nginx<br>
    [tuser@kvmcentos ~]$ sudo systemctl enable nginx<br>
    [tuser@kvmcentos ~]$ nginx -v<br>
    [tuser@kvmcentos ~]$ firefox http://tipcentos:80/<br>
    <strong>Source:</strong><br>
    # https://devcoops.com/install-nginx-on-centos-9-stream/<br>
    <strong>Task:</strong><br>
    Настройка Proxy-сервера. Configure Squid Proxy Kali.<br>
    <strong>Decision:</strong><br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo apt update<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo apt install squid<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo systemctl start squid<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo systemctl enable squid<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ grep -Eiv '(^#|^$)' /etc/squid/squid.conf<br>
    acl localnet src 0.0.0.1-0.255.255.255 # RFC 1122 "this" network (LAN)<br>
    acl localnet src 10.0.0.0/8 # RFC 1918 local private network (LAN)<br>
    acl localnet src 100.64.0.0/10 # RFC 6598 shared address space (CGN)<br>
    acl localnet src 169.254.0.0/16 # RFC 3927 link-local (directly plugged) machines<br>
    acl localnet src 172.16.0.0/12 # RFC 1918 local private network (LAN)<br>
    acl localnet src 192.168.0.0/16 # RFC 1918 local private network (LAN)<br>
    acl localnet src fc00::/7 # RFC 4193 local private network range<br>
    acl localnet src fe80::/10 # RFC 4291 link-local (directly plugged) machines<br>
    acl SSL_ports port 443<br>
    acl Safe_ports port 80 # http<br>
    acl Safe_ports port 21 # ftp<br>
    acl Safe_ports port 443 # https<br>
    acl Safe_ports port 70 # gopher<br>
    acl Safe_ports port 210 # wais<br>
    acl Safe_ports port 1025-65535 # unregistered ports<br>
    acl Safe_ports port 280 # http-mgmt<br>
    acl Safe_ports port 488 # gss-http<br>
    acl Safe_ports port 591 # filemaker<br>
    acl Safe_ports port 777 # multiling http<br>
    http_access deny !Safe_ports<br>
    http_access deny CONNECT !SSL_ports<br>
    http_access allow localhost manager<br>
    http_access deny manager<br>
    http_access allow localhost<br>
    http_access deny to_localhost<br>
    http_access deny to_linklocal<br>
    include /etc/squid/conf.d/*.conf<br>
    http_access deny all<br>
    http_port 3128<br>
    coredump_dir /var/spool/squid<br>
    refresh_pattern ^ftp: 1440 20% 10080<br>
    refresh_pattern -i (/cgi-bin/|\?) 0 0% 0<br>
    refresh_pattern . 0 20% 4320<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo mv /etc/squid/squid.conf /etc/squid/squid.conf.bac<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo vim /etc/squid/squid.conf<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo cat /etc/squid/squid.conf&nbsp;<br>
    acl localnet src tipkali<br>
    http_access allow localnet<br>
    http_port 3128<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo systemctl restart squid&nbsp;<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ cat /var/log/squid/access.log<br>
    1698153952.395 1 tipkali NONE_NONE/400 3816 - / - HIER_NONE/- text/html<br>
    1698153953.958 7 tipkali TCP_DENIED/403 4185 GET http://kali:3128/squid-internal-static/icons/SN.png - HIER_NONE/- text/html<br>
    ...<br>
    1698154905.087 2 tipkali TCP_MISS/400 3889 GET http://tipkali:3128/ - HIER_DIRECT/tipkali text/html<br>
    1698154906.698 149 tipkali TCP_TUNNEL/200 39 CONNECT static.vk.com:443 - HIER_DIRECT/87.240.137.164 -<br>
    1698154906.796 0 tipkali NONE_NONE/400 3838 - /favicon.ico - HIER_NONE/- text/html<br>
    1698154906.797 2 tipkali TCP_MISS/400 3911 GET http://tipkali:3128/favicon.ico - HIER_DIRECT/tipkali text/html<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo apt install apache2-utils&nbsp;<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo htpasswd -c /etc/squid/passwd user<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo vim /etc/squid/squid.conf&nbsp;<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ cat /etc/squid/squid.conf<br>
    #acl localnet src tipkali<br>
    #http_access allow localnet<br>
    http_port 3128<br>
    via off<br>
    auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd<br>
    auth_param basic children 5<br>
    auth_param basic credentialsttl 2 hours<br>
    auth_param basic casesensitive on<br>
    auth_param basic realm Squid proxy for kali<br>
    acl auth_users proxy_auth REQUIRED<br>
    http_access allow auth_users<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo systemctl restart squid<br>
    <strong>Task:</strong><br>
    Настройка Proxy-сервера. Configure Squid Proxy Centos.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo dnf install squid<br>
    [tuser@kvmcentos ~]$ sudo systemctl enable --now squid<br>
    [tuser@kvmcentos ~]$ grep -Eiv '(^#|^$)' /etc/squid/squid.conf<br>
    acl localnet src 0.0.0.1-0.255.255.255 # RFC 1122 "this" network (LAN)<br>
    acl localnet src 10.0.0.0/8 # RFC 1918 local private network (LAN)<br>
    acl localnet src 100.64.0.0/10 # RFC 6598 shared address space (CGN)<br>
    acl localnet src 169.254.0.0/16 # RFC 3927 link-local (directly plugged) machines<br>
    acl localnet src 172.16.0.0/12 # RFC 1918 local private network (LAN)<br>
    acl localnet src 192.168.0.0/16 # RFC 1918 local private network (LAN)<br>
    acl localnet src fc00::/7 # RFC 4193 local private network range<br>
    acl localnet src fe80::/10 # RFC 4291 link-local (directly plugged) machines<br>
    acl SSL_ports port 443<br>
    acl Safe_ports port 80 # http<br>
    acl Safe_ports port 21 # ftp<br>
    acl Safe_ports port 443 # https<br>
    acl Safe_ports port 70 # gopher<br>
    acl Safe_ports port 210 # wais<br>
    acl Safe_ports port 1025-65535 # unregistered ports<br>
    acl Safe_ports port 280 # http-mgmt<br>
    acl Safe_ports port 488 # gss-http<br>
    acl Safe_ports port 591 # filemaker<br>
    acl Safe_ports port 777 # multiling http<br>
    http_access deny !Safe_ports<br>
    http_access deny CONNECT !SSL_ports<br>
    http_access allow localhost manager<br>
    http_access deny manager<br>
    http_access allow localnet<br>
    http_access allow localhost<br>
    http_access deny all<br>
    http_port 3128<br>
    coredump_dir /var/spool/squid<br>
    refresh_pattern ^ftp: 1440 20% 10080<br>
    refresh_pattern ^gopher: 1440 0% 1440<br>
    refresh_pattern -i (/cgi-bin/|\?) 0 0% 0<br>
    refresh_pattern . 0 20% 4320<br>
    [tuser@kvmcentos ~]$ sudo mv /etc/squid/squid.conf /etc/squid/squid.conf.bac<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/squid/squid.conf<br>
    [tuser@kvmcentos ~]$ cat /etc/squid/squid.conf<br>
    acl localnet src tipcentos<br>
    acl localnet src tip.0/32<br>
    acl Safe_ports port 80<br>
    acl Safe_ports port 443<br>
    cache_dir ufs /var/spool/squid 1000 16 256<br>
    http_access allow localnet<br>
    http_port 3128&nbsp;<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart squid<br>
    [tuser@kvmcentos ~]$ sudo iptables -t filter -A INPUT -p tcp --dport 3128 -j ACCEPT<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables.service<br>
    [tuser@kvmcentos ~]$ sudo curl -O -L "https://www.redhat.com/index.html" -x "tipcentos:3128"<br>
    % Total % Received % Xferd Average Speed Time Time Time Current<br>
    &nbsp;&nbsp;&nbsp;&nbsp; Dload Upload Total Spent Left Speed<br>
    0 0 0 0 0 0 0 0 --:--:-- --:--:-- --:--:-- 0<br>
    100 156k 0 156k 0 0 147k 0 --:--:-- 0:00:01 --:--:-- 795k<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap tipcentos<br>
    ...<br>
    PORT STATE SERVICE<br>
    20/tcp closed ftp-data<br>
    21/tcp open ftp<br>
    22/tcp open ssh<br>
    25/tcp closed smtp<br>
    53/tcp closed domain<br>
    80/tcp open http<br>
    143/tcp closed imap<br>
    443/tcp closed https<br>
    3128/tcp open squid-http<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo dnf install httpd-tools<br>
    [tuser@kvmcentos ~]$ sudo touch /etc/squid/passwd<br>
    [tuser@kvmcentos ~]$ sudo chown squid /etc/squid/passwd<br>
    [tuser@kvmcentos ~]$ sudo htpasswd /etc/squid/passwd proxyuser<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/squid/squid.conf<br>
    [tuser@kvmcentos ~]$ cat /etc/squid/squid.conf<br>
    #acl localnet src tipcentos<br>
    #acl localnet src tip.0/32<br>
    #acl Safe_ports port 80<br>
    #acl Safe_ports port 443<br>
    #cache_dir ufs /var/spool/squid 1000 16 256<br>
    #http_access allow localnet<br>
    http_port 3128&nbsp;<br>
    auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd<br>
    auth_param basic children 5<br>
    auth_param basic realm Squid Basic Authentication<br>
    auth_param basic credentialsttl 2 hours<br>
    acl auth_users proxy_auth REQUIRED<br>
    http_access allow auth_users<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart squid<br>
    [tuser@kvmcentos ~]$ sudo curl -O -L "https://www.redhat.com/index.html" -x "proxyuser:tpassword@tipcentos:3128"<br>
    % Total % Received % Xferd Average Speed Time Time Time Current<br>
    &nbsp;&nbsp;&nbsp;&nbsp; Dload Upload Total Spent Left Speed<br>
    0 0 0 0 0 0 0 0 --:--:-- --:--:-- --:--:-- 0<br>
    100 156k 0 156k 0 0 124k 0 --:--:-- 0:00:01 --:--:-- 562k<br>
    <strong>Source:</strong><br>
    # https://support.mozilla.org/ru/kb/parametry-soedineniya-v-firefox<br>
    # https://techviewleo.com/configure-squid-proxy-on-centos-almalinux-rhel/<br>
    <strong>Task:</strong><br>
    Настройка Proxy-сервера. Перенаправление пакетов, идущих на 80-й порт, на стандартный порт прокси-сервера.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo iptables -t nat -A PREROUTING -s tip.0 -p tcp --dport 80 -j REDIRECT --to-port 3128<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables.service<br>
    <strong>Task:</strong><br>
    Настройка Proxy-сервера. Предоставляем доступ из Интернет к веб-серверу, который расположен в локальной сети (проброс порта). Вместо tipubuntu укажите IP-адрес вашего веб-сервера.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination tipubuntu:80<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables.service<br>
    <strong>Task:</strong><br>
    Настройка Proxy-сервера. Включаем маскарадинг для доступа в Интернет пользователей локальной сети.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo iptables -t nat -A POSTROUTING -o enp1s0 -s tip.0/32 -j MASQUERADE<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables.service<br>
    <strong>Task:</strong><br>
    Сканирование сети Nmap. Обнаружим активные устройства в сети.<br>
    <strong>Decision:</strong><br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo apt install nmap<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap -sL tipcentos/24<br>
    ...<br>
    Nmap scan report for KvmKali (tipkali)<br>
    ...<br>
    Nmap scan report for kvmcentos (tipcentos)<br>
    ...<br>
    Nmap scan report for kvmubuntu (tipubuntu)<br>
    ...<br>
    <strong>Task:</strong><br>
    Сканирование сети Nmap. Просканируем хост и проанализируем порт ftp. В некоторых случаях можно вытащить логин и пароль. Такое происходит, когда используются параметры входа по умолчанию.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo nmap -sV tipcentos<br>
    ...<br>
    PORT STATE SERVICE VERSION<br>
    21/tcp open ftp vsftpd 3.0.5<br>
    22/tcp open ssh OpenSSH 8.7 (protocol 2.0)<br>
    80/tcp open http nginx 1.22.1<br>
    3128/tcp open http-proxy Squid http proxy 5.5<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo nmap -sC tipcentos -p 21<br>
    ...<br>
    PORT STATE SERVICE<br>
    21/tcp open ftp<br>
    ...<br>
    $ find /usr/share/nmap/scripts/ -name '*.nse' | grep ftp<br>
    ...<br>
    /usr/share/nmap/scripts/ftp-brute.nse<br>
    ...<br>
    $ sudo nmap --script-help ftp-brute.nse<br>
    ...<br>
    Performs brute force password auditing against FTP servers.<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo nmap --script ftp-brute.nse tipcentos -p 21<br>
    ...<br>
    PORT STATE SERVICE<br>
    21/tcp open ftp<br>
    | ftp-brute:&nbsp;<br>
    | Accounts: No valid accounts found<br>
    | Statistics: Performed 324 guesses in 642 seconds, average tps: 7.5<br>
    |_ ERROR: The service seems to have failed or is heavily firewalled...<br>
    ...<br>
    <strong>Task:</strong><br>
    Сканируем диапазон портов<br>
    <strong>Decision:</strong><br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap -sT -p 21-80 tipcentos<br>
    ...<br>
    PORT STATE SERVICE<br>
    21/tcp open ftp<br>
    22/tcp open ssh<br>
    25/tcp closed smtp<br>
    53/tcp closed domain<br>
    ...<br>
    <strong>Task:</strong><br>
    Сканирование сети Nmap. Просканируем удаленный хост (агрессивный режим).<br>
    <strong>Decision:</strong><br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap -A -T4 tipcentos<br>
    ...<br>
    PORT STATE SERVICE VERSION<br>
    20/tcp closed ftp-data<br>
    21/tcp open ftp vsftpd 3.0.5<br>
    22/tcp open ssh OpenSSH 8.7 (protocol 2.0)<br>
    25/tcp closed smtp<br>
    53/tcp closed domain<br>
    143/tcp closed imap<br>
    443/tcp closed https<br>
    3128/tcp open http-proxy Squid http proxy 5.5<br>
    |_http-server-header: squid/5.5<br>
    |_http-title: ERROR: The requested URL could not be retrieved<br>
    MAC Address: 52:54:00:7e:05:15 (QEMU virtual NIC)<br>
    Aggressive OS guesses: Linux 2.6.32 - 3.13 (94%), Linux 2.6.22 - 2.6.36 (92%), Linux 3.10 (92%), Linux 3.10 - 4.11 (92%), Linux 2.6.39 (92%), Linux 2.6.32 (91%), Linux 3.2 - 4.9 (91%), Linux 2.6.32 - 3.10 (91%), Linux 2.6.18 (90%), Linux 3.16 - 4.6 (90%)<br>
    No exact OS matches for host (test conditions non-ideal).<br>
    Network Distance: 1 hop<br>
    Service Info: OS: Unix<br>
    TRACEROUTE<br>
    HOP RTT ADDRESS<br>
    1 0.83 ms tipcentos<br>
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .<br>
    Nmap done: 1 IP address (1 host up) scanned in 24.18 seconds<br>
    <strong>Source:</strong><br>
    # https://losst.ru/kak-polzovatsya-nmap-dlya-skanirovaniya-seti<br>
    <strong>Task:</strong><br>
    Перехват трафиков в Tcpdump. Перехватываем DNS-трафик между сервером и каким-нибудь узлом в сети.<br>
    <strong>Decision:</strong><br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ sudo nmap tipwindows12<br>
    ...<br>
    PORT STATE SERVICE<br>
    53/tcp open domain<br>
    80/tcp open http<br>
    443/tcp open https<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -i enp1s0 -n -nn -ttt 'host tipwindows12 and port 53'<br>
    <strong>Task:</strong><br>
    Перехват трафиков в Tcpdump. Перехватываем весь трафик для MAC-адреса 52:54:00:7e:05:15 на сетевом интерфейсе enp1s0.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ ifconfig<br>
    enp1s0: flags=4163&lt;UP,BROADCAST,RUNNING,MULTICAST&gt; mtu 1500<br>
    ...<br>
    ether 52:54:00:7e:05:15 txqueuelen 1000 (Ethernet)<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -n -i enp1s0 "ether host 52:54:00:7e:05:15"<br>
    ...<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ ssh tuser@tipcentos<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -n -i enp1s0 "ether host 52:54:00:7e:05:15"<br>
    ...<br>
    00:11:12.536934 IP tipcentos.58598 &gt; tipubuntu.22: Flags [.], ack 3730, win 501, options [nop,nop,TS val 3107339434 ecr 2462889902], length 0<br>
    00:11:12.586762 IP tipubuntu.22 &gt; tipcentos.58598: Flags [P.], seq 3730:3782, ack 2242, win 501, options [nop,nop,TS val 2462889993 ecr 3107339434], length 52<br>
    00:11:12.586838 IP tipubuntu.22 &gt; tipcentos.58598: Flags [P.], seq 3782:3898, ack 2242, win 501, options [nop,nop,TS val 2462889993 ecr 3107339434], length 116<br>
    00:11:12.588205 IP tipcentos.58598 &gt; tipubuntu.22: Flags [.], ack 3782, win 501, options [nop,nop,TS val 3107339485 ecr 2462889993], length 0<br>
    00:11:12.588207 IP tipcentos.58598 &gt; tipubuntu.22: Flags [.], ack 3898, win 501, options [nop,nop,TS val 3107339486 ecr 2462889993], length 0<br>
    <strong>Task:</strong><br>
    Перехват трафиков в Tcpdump. Перехватываем только ICMP-пакеты<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo tcpdump -i enp1s0 -n -nn -ttt 'ip proto \icmp'<br>
    ...<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ ping tipcentos<br>
    ...<br>
    64 bytes from tipcentos: icmp_seq=1 ttl=64 time=0.692 ms<br>
    64 bytes from tipcentos: icmp_seq=2 ttl=64 time=0.764 ms<br>
    64 bytes from tipcentos: icmp_seq=3 ttl=64 time=0.868 ms<br>
    64 bytes from tipcentos: icmp_seq=4 ttl=64 time=1.01 ms<br>
    64 bytes from tipcentos: icmp_seq=5 ttl=64 time=1.13 ms<br>
    ^C<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -i enp1s0 -n -nn -ttt 'ip proto \icmp'<br>
    ...<br>
    00:00:00.000000 IP tipcentos &gt; tipubuntu: ICMP echo request, id 4, seq 1, length 64<br>
    00:00:00.000171 IP tipubuntu &gt; tipcentos: ICMP echo reply, id 4, seq 1, length 64<br>
    00:00:01.001145 IP tipcentos &gt; tipubuntu: ICMP echo request, id 4, seq 2, length 64<br>
    00:00:00.000077 IP tipubuntu &gt; tipcentos: ICMP echo reply, id 4, seq 2, length 64<br>
    00:00:01.001365 IP tipcentos &gt; tipubuntu: ICMP echo request, id 4, seq 3, length 64<br>
    00:00:00.000077 IP tipubuntu &gt; tipcentos: ICMP echo reply, id 4, seq 3, length 64<br>
    00:00:01.001375 IP tipcentos &gt; tipubuntu: ICMP echo request, id 4, seq 4, length 64<br>
    00:00:00.000077 IP tipubuntu &gt; tipcentos: ICMP echo reply, id 4, seq 4, length 64<br>
    00:00:01.001573 IP tipcentos &gt; tipubuntu: ICMP echo request, id 4, seq 5, length 64<br>
    00:00:00.000125 IP tipubuntu &gt; tipcentos: ICMP echo reply, id 4, seq 5, length 64<br>
    <strong>Task:</strong><br>
    Перехват трафиков в Tcpdump. Перехватываем входящий трафик на порт 80. сохраняем статистику в файл my.log для первых 500 пакетов. Будет создан бинарный файл my.log, который можно отпарсить с помощью команды<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo tcpdump -v -i enp1s0 dst port 80<br>
    ...<br>
    ┌──(tuser㉿KvmKali)-[~]<br>
    └─$ firefox tipcentos:80<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -v -i enp1s0 dst port 80<br>
    ...<br>
    14:07:24.835633 IP (tos 0x0, ttl 64, id 15549, offset 0, flags [DF], proto TCP (6), length 60)<br>
    kvmcentos.45022 &gt; kvmubuntu.http: Flags [S], cksum 0x76d1 (incorrect -&gt; 0x9a90), seq 1076682845, win 64240, options [mss 1460,sackOK,TS val 3110711737 ecr 0,nop,wscale 7], length 0<br>
    14:07:24.836511 IP (tos 0x0, ttl 64, id 15550, offset 0, flags [DF], proto TCP (6), length 52)<br>
    kvmcentos.45022 &gt; kvmubuntu.http: Flags [.], cksum 0x76c9 (incorrect -&gt; 0x51b3), ack 2952605173, win 502, options [nop,nop,TS val 3110711738 ecr 3247231251], length 0<br>
    14:07:24.836838 IP (tos 0x0, ttl 64, id 15551, offset 0, flags [DF], proto TCP (6), length 412)<br>
    kvmcentos.45022 &gt; kvmubuntu.http: Flags [P.], cksum 0x7831 (incorrect -&gt; 0xb0a2), seq 0:360, ack 1, win 502, options [nop,nop,TS val 3110711739 ecr 3247231251], length 360: HTTP, length: 360<br>
    GET / HTTP/1.1<br>
    Host: tipubuntu<br>
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0<br>
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8<br>
    Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3<br>
    Accept-Encoding: gzip, deflate<br>
    Connection: keep-alive<br>
    Upgrade-Insecure-Requests: 1<br>
    14:07:24.844920 IP (tos 0x0, ttl 64, id 15552, offset 0, flags [DF], proto TCP (6), length 52)<br>
    kvmcentos.45022 &gt; kvmubuntu.http: Flags [.], cksum 0x76c9 (incorrect -&gt; 0x4285), ack 3522, win 489, options [nop,nop,TS val 3110711747 ecr 3247231260], length 0<br>
    14:07:29.846014 IP (tos 0x0, ttl 64, id 15553, offset 0, flags [DF], proto TCP (6), length 52)<br>
    kvmcentos.45022 &gt; kvmubuntu.http: Flags [F.], cksum 0x76c9 (incorrect -&gt; 0x2eef), seq 360, ack 3522, win 501, options [nop,nop,TS val 3110716748 ecr 3247231260], length 0<br>
    14:07:29.846795 IP (tos 0x0, ttl 64, id 15554, offset 0, flags [DF], proto TCP (6), length 52)<br>
    kvmcentos.45022 &gt; kvmubuntu.http: Flags [.], cksum 0x76c9 (incorrect -&gt; 0x1b63), ack 3523, win 501, options [nop,nop,TS val 3110716749 ecr 3247236262], length 0<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -v -n -w my.log dst port 80 -c 500<br>
    ...<br>
    [tuser@kvmcentos ~]$ ls my.log<br>
    my.log<br>
    [tuser@kvmcentos ~]$ sudo tcpdump -nr my.log | awk '{print $3}' | grep -oE '[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}' | sort | uniq -c | sort -rn<br>
    reading from file my.log, link-type EN10MB (Ethernet), snapshot length 262144<br>
    dropped privs to tcpdump<br>
    6 tipkali<br>
    <strong>Task:</strong><br>
    Блокировка подозрительных IP-адресов. IP-адреса, которые вызывают подозрение, можно заблокировать в iptables с помощью команды, указанной ниже.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo iptables -A INPUT -s tipkali -j DROP<br>
    [tuser@kvmcentos ~]$ sudo service iptables save<br>
    [tuser@kvmcentos ~]$ sudo systemctl restart iptables.service<br>
    <strong>Task:</strong><br>
    Безопасность сервера. Установка и настройка tripwire.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo dnf -y install epel-releasey<br>
    [tuser@kvmcentos ~]$ sudo dnf -y install tripwire<br>
    [tuser@kvmcentos ~]$ sudo tripwire-setup-keyfiles<br>
    [tuser@kvmcentos ~]$ sudo tripwire --init<br>
    ...<br>
    ### Warning: File system error.<br>
    ### Filename: /proc/pci<br>
    ### Нет такого файла или каталога<br>
    ### Continuing...<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo cat /etc/tripwire/twpol.txt<br>
    ...<br>
    /proc/pci&nbsp;&nbsp; -&gt; $(Device) ;<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/tripwire/twpol.txt<br>
    [tuser@kvmcentos ~]$ sudo cat /etc/tripwire/twpol.txt<br>
    ...<br>
    #/proc/pci&nbsp;&nbsp; -&gt; $(Device) ;<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo tripwire --update-policy --secure-mode low /etc/tripwire/twpol.txt<br>
    [tuser@kvmcentos ~]$ sudo tripwire --check —interactive<br>
    <strong>Task:</strong><br>
    Безопасность сервера. Создаем конфигурацию, Создаем базу данных.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ ls /etc/tripwire/<br>
    centos-local.key site.key tw.cfg twcfg.txt tw.pol tw.pol.bak twpol.txt<br>
    [tuser@kvmcentos ~]$ sudo twadmin -m F -c /etc/tripwire/tw.cfg -S /etc/tripwire/site.key /etc/tripwire/twcfg.txt<br>
    [tuser@kvmcentos ~]$ sudo vim /etc/tripwire/twpolmake.pl<br>
    [tuser@kvmcentos ~]$ cat /etc/tripwire/twpolmake.pl<br>
    #!/usr/bin/perl<br>
    # Tripwire Policy File customize tool<br>
    # ----------------------------------------------------------------<br>
    # Copyright (C) 2003 Hiroaki Izumi<br>
    # This program is free software; you can redistribute it and/or<br>
    # modify it under the terms of the GNU General Public License<br>
    # as published by the Free Software Foundation; either version 2<br>
    # of the License, or (at your option) any later version.<br>
    # This program is distributed in the hope that it will be useful,<br>
    # but WITHOUT ANY WARRANTY; without even the implied warranty of<br>
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the<br>
    # GNU General Public License for more details.<br>
    # You should have received a copy of the GNU General Public License<br>
    # along with this program; if not, write to the Free Software<br>
    # Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.<br>
    # ----------------------------------------------------------------<br>
    # Usage:<br>
    # perl twpolmake.pl {Pol file}<br>
    # ----------------------------------------------------------------<br>
    #<br>
    $POLFILE=$ARGV[0];<br>
    open(POL,"$POLFILE") or die "open error: $POLFILE" ;<br>
    my($myhost,$thost) ;<br>
    my($sharp,$tpath,$cond) ;<br>
    my($INRULE) = 0 ;<br>
    while (&lt;POL&gt;) {<br>
    chomp;<br>
    if (($thost) = /^HOSTNAME\s*=\s*(.*)\s*;/) {<br>
    $myhost = `hostname` ; chomp($myhost) ;<br>
    if ($thost ne $myhost) {<br>
    $_="HOSTNAME=\"$myhost\";" ;<br>
    }<br>
    }<br>
    elsif ( /^{/ ) {<br>
    $INRULE=1 ;<br>
    }<br>
    elsif ( /^}/ ) {<br>
    $INRULE=0 ;<br>
    }<br>
    elsif ($INRULE == 1 and ($sharp,$tpath,$cond) = /^(\s*\#?\s*)(\/\S+)\b(\s+-&gt;\s+.+)$/) {<br>
    $ret = ($sharp =~ s/\#//g) ;<br>
    if ($tpath eq '/sbin/e2fsadm' ) {<br>
    $cond =~ s/;\s+(tune2fs.*)$/; \#$1/ ;<br>
    }<br>
    if (! -s $tpath) {<br>
    $_ = "$sharp#$tpath$cond" if ($ret == 0) ;<br>
    }<br>
    else {<br>
    $_ = "$sharp$tpath$cond" ;<br>
    }<br>
    }<br>
    print "$_\n" ;<br>
    }<br>
    close(POL) ;<br>
    [tuser@kvmcentos ~]$ sudo perl /etc/tripwire/twpolmake.pl /etc/tripwire/twpol.txt &gt; /etc/tripwire/twpol.txt.new&nbsp;<br>
    [tuser@kvmcentos ~]$ sudo twadmin -m P -c /etc/tripwire/tw.cfg -p /etc/tripwire/tw.pol -S /etc/tripwire/site.key /etc/tripwire/twpol.txt.new<br>
    [tuser@kvmcentos ~]$ sudo tripwire -m i -s -c /etc/tripwire/tw.cfg<br>
    [tuser@kvmcentos ~]$ sudo tripwire -m c -s -c /etc/tripwire/tw.cfg<br>
    Open Source Tripwire(R) 2.4.3.7 Integrity Check Report<br>
    Report generated by: root<br>
    Report created on: Вс 29 окт 2023 14:26:04<br>
    Database last updated on: Never<br>
    ...<br>
    ===============================================================================<br>
    Object Summary:&nbsp;<br>
    ===============================================================================<br>
    -------------------------------------------------------------------------------<br>
    # Section: Unix File System<br>
    -------------------------------------------------------------------------------<br>
    No violations.<br>
    ===============================================================================<br>
    Error Report:&nbsp;<br>
    ===============================================================================<br>
    ...<br>
    [tuser@kvmcentos ~]$ sudo ls /var/lib/tripwire/report<br>
    итого 28<br>
    -rw-r--r--. 1 root root 350 окт 29 13:55 centos-20231029-135511.twr<br>
    -rw-r--r--. 1 root root 350 окт 29 13:57 centos-20231029-135712.twr<br>
    -rw-r--r--. 1 root root 350 окт 29 14:00 centos-20231029-140029.twr<br>
    -rw-r--r--. 1 root root 350 окт 29 14:08 centos-20231029-140853.twr<br>
    -rw-r--r--. 1 root root 350 окт 29 14:09 centos-20231029-140919.twr<br>
    -rw-r--r--. 1 root root 6446 окт 29 14:27 centos-20231029-142604.twr<br>
    <strong>Task:</strong><br>
    Безопасность сервера. Проверим на работоспособность утилиты Tripwire. Создав файл в системе, утилита должна показать, что добавлен был файл.<br>
    <strong>Decision:</strong><br>
    [tuser@kvmcentos ~]$ sudo touch /var/lib/tripwire/tfile3.txt<br>
    [tuser@kvmcentos ~]$ sudo tripwire -m c -s -c /etc/tripwire/tw.cfg<br>
    Open Source Tripwire(R) 2.4.3.7 Integrity Check Report<br>
    ...<br>
    -------------------------------------------------------------------------------<br>
    Rule Name: Tripwire Data Files (/var/lib/tripwire)<br>
    Severity Level: 100<br>
    -------------------------------------------------------------------------------<br>
    Added:<br>
    "/var/lib/tripwire/tfile3.txt"<br>
    ===============================================================================<br>
    Error Report:&nbsp;<br>
    ===============================================================================<br>
    ...<br>
    <strong>Source:</strong><br>
    # https://linux-notes.org/ustanovka-i-nastrojka-tripwire-v-centos-redhat-fedora/?ysclid=loazeq8vjc96566460&nbsp;<br>
    # https://www.server-world.info/en/note?os=CentOS_7&amp;p=tripwire<br>
    # https://www.lisenet.com/2017/configure-tripwire-on-centos-7/
</p>