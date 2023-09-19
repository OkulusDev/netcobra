#!/usr/bin/python3
# -*- coding:utf-8 -*-
import socket
from time import time
from threading import Thread
import sys

opened_ports = []


def scan_port(target_hostname: str, port: int):
	global opened_ports

	ports = {
		20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
		25: "SMTP", 43: "WHOIS", 53: "DNS", 80: "http",
		115: "SFTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
		179: "BGP", 443: "HTTPS", 445: "MICROSOFT-DS",
		514: "SYSLOG", 515: "PRINTER", 993: "IMAPS",
		995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
		1433: "SQL Server", 1723: "PPTP", 3128: "HTTP",
		3268: "LDAP", 3306: "MySQL", 3389: "RDP",
		5432: "PostgreSQL", 5900: "VNC", 8080: "Tomcat", 10000: "Webmin"}

	try:
		sock = socket.socket()
		sock.connect((target_hostname, port))
	except:
		print(f'[{target_hostname}] {port} закрыт')
	else:
		try:
			opened_ports.append(f'{port}/{ports[port]}')
		except:
			opened_ports.append(port)

	return


def scan_ports(target_hostname: str, port_count: int=2 ** 16) -> dict:
	ip_addr = socket.gethostbyname(target_hostname)

	start = time()

	threads: list[Thread] = []

	for port in range(1, port_count + 1):
		threads.insert(0, Thread(target=scan_port, args=(ip_addr, port,)))
		threads[0].start()

	end = time()

	return {'opened_ports': opened_ports, 'total': f'{end - start}s'}
