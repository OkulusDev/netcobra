#!/usr/bin/python3
# -*- coding:utf-8 -*-
import socket
from datetime import datetime
import sys


def scan_ports(target_hostname: str) -> dict:
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

	ip_addr = socket.gethostbyname(target_hostname)

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(1)

	start = datetime.now()

	opened_ports = []
	port = -1

	while port < 65537:
		port += 1

		try:
			sock.connect((ip_addr, port))
		except:
			print(f'[{ip_addr}] Порт {port} закрыт')
		else:
			try:
				print(f'[{ip_addr}] Порт {port}/{ports[port]} открыт')
				opened_ports.append(f'{port}')
			except KeyError:
				print(f'[{ip_addr}] Порт {port} открыт')
				opened_ports.append(port)
		finally:
			sock.close()

	ends = datetime.now()
	
	return {'opened_ports': opened_ports, 'time': ends - start}
