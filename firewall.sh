#!/bin/bash
IPT="/sbin/iptables"
# Очищаем правила и удаляем цепочки.
$IPT -F
$IPT -X
# По умолчанию доступ запрещен.
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT DROP
# Список разрешенных TCP и UDP портов.
TCP_PORTS="21,22,25,53,80,143,443"
UDP_PORTS="53,21,20"
# Разрешаем пакеты для интерфейса обратной петли.
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
# Разрешаем пакеты для установленных соединений.
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Разрешаем исходящие соединения.
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
# Разрешаем доступ к портам, описанным в переменных TCP_PORTS и UDP_PORTS.
$IPT -A INPUT -p tcp -m multiport --dport $TCP_PORTS -j ACCEPT
$IPT -A INPUT -p udp -m multiport --dport $UDP_PORTS -j ACCEPT
# Разрешаем исходящий ping.
$IPT -A INPUT -p icmp -m icmp --icmp-type echo-reply -j ACCEPT
