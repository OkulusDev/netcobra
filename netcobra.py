#!/usr/bin/python3
# -*- coding:utf -*-
"""Сетевая кобра - это программа для сканирования сетей, IP, работой с сетью и серверами
Copyright (C) 2023  Okulus Dev
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>."""
import argparse
import socket
import shlex
import subprocess
import time
import sys
import textwrap
import threading
import re
import ssl
from datetime import datetime
from ipaddress import IPv4Address, AddressValueError, ip_network, ip_address
import dns
from dns import resolver
from requests import get, exceptions
import ipwhois
import whois


def ip_in_range(ip, addr):
	if ip_address(ip) in ip_network(addr):
		return True
	return False


def cloudfare_detect(ip):
	list_addr = ["104.16.0.0/12"]

	url = 'https://www.cloudflare.com/ips-v4'
	req = get(url=url)

	for adr in req.text.split("\n"):
		list_addr.append(adr)

	for addr in list_addr:
		detect = ip_in_range(ip, addr)
		if detect:
			return True
	return False


def public_ip():
	try:
		return get('https://api.ipify.org/').text
	except exceptions.ConnectionError:
		return '127.0.0.1'


def dns_bl_check(ip):
	print('\n- Проверка черных списков\n')
	bad_dict = dict()
	req = get('https://raw.githubusercontent.com/evgenycc/DNSBL-list/main/DNSBL')
	read = req.text.splitlines()
	
	for serv in read:
		req = f"{'.'.join(reversed(ip.split('.')))}.{serv.strip()}"
		try:
			resolv = dns.resolver.Resolver()
			resolv.timeout = 5
			resolv.lifetime = 5
			resp = resolv.resolve(req, 'A')
			resp_txt = resolv.resolve(req, 'TXT')
			print(f'{serv.strip():30}: [BAD]')
			pattern = '(?:https?:\/\/)?(?:[\w\.]+)\.(?:[a-z]{2,6}\.?)(?:\/[\w\.]*)*\/?'
			find = re.findall(pattern, str(resp_txt[0]))
			if len(find) == 0:
				find = ['No address']
			bad_dict.update({serv.strip(): f'{resp[0]} {find[0]}'})
		except dns.resolver.NXDOMAIN:
			print(f'{serv.strip():30}: [OK]')
		except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer):
			continue
	if len(bad_dict) > 0:
		len_str = len(f'IP-АДРЕС: "{ip.upper()}" ОБНАРУЖЕН В ЧЕРНЫХ СПИСКАХ')
		print(f'\nIP-АДРЕС: {ip.upper()} ОБНАРУЖЕН В ЧЕРНЫХ СПИСКАХ\n{"*"*len_str}')
		for bad in bad_dict:
			print(f' - {bad:30} : {bad_dict[bad]}')
	else:
		print('\n[+] IP-адрес в черных списках не обнаружен')


def check_ip_in_black_list(addr_input):
	print(f'\n- Ваш внешний IP-адрес: {public_ip()}')
	#addr_input = input('- Введите IP-адрес или домен для проверки\n  Для выхода введите "x"\n  >>> ')
	if addr_input.lower() == "x":
		exit(0)
	ip = ''
	try:
		ip = socket.gethostbyname(addr_input)
	except socket.gaierror:
		print('\n - Не удалось получить IP-адрес')
		exit(0)

	if cloudfare_detect(ip):
		print(f'\n[!] ВНИМАНИЕ! Обнаружен адрес Cloudflare: {ip}')
	
	dns_bl_check(ip)


def execute(cmd: str) -> str:
	"""Выполнение команды в терминале

	Параметры:
	 + cmd: str - команда

	Возвращает:
	 + str - строка с выводом команды
	"""
	cmd = cmd.strip()

	if not cmd:
		return 'None'

	output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)    # Чтение и возрват (1)
	
	return str(output.decode()).replace('\n', '')


class NetCobra:
	"""Класс NetCobra"""
	def __init__(self, args, buffer=None):
		"""Инициализация класса NetCobra

		 + args - аргументы
		 + buffer - буфер"""
		self.args = args 					# Наши будующие аргументы
		self.buffer = buffer    			# Буфер с данными
		
		# Подключение к серверу
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Обработка запроса и протоколов
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	def run(self):
		"""Запуск NetCobra
		Если аргумент равен listen, то мы слушаем подключения
		Если же был передан любой другой, то мы запускаем функцию send"""
		if self.args.listen:
			print('[+] Слушаем...')
			self.listen()
		else:
			print('[+] Отправляем...')
			self.send()

	def send(self):
		"""Отправка данных
		Коннектимся к хосту, если буфер не пуст, то отправляем его. 
		Потом читаем данные, максимальный размер пакета - 4096 байтов"""
		self.socket.connect((self.args.target, self.args.port))			# Установка соединения с сервером
		
		print('[+] Отправляем данные...')

		if self.buffer:
			print('[/] Отправляем данные из буфера')
			self.socket.send(self.buffer)								# Проверка буфера на наличие данных

		try:
			while True:
				print('[+] Отправка данных на сервер')
				recv_len = 1								# Задаем длину запроса
				response = ''
				
				while recv_len:
					data = self.socket.recv(4096)			# Размер буфера в битах
					recv_len = len(data)					# Проверяем длину
					response += data.decode()				# Декодируем запрос
				
				# Если длина запроса больше 100
				if recv_len > 4096:							# Сверяем данные
					print("[/] Сообщение слишком длинное. Максимальное количество байтов в пакете - 4096")
					break
			
			if response:
				print('[/] Отправка данных и заполнение буфера')
				print(response)								# Выводим его на экран
				buffer = input('NetCobra > $ ')						# Задаем приглашение для ввода
				buffer += '\n'								# Добавляем перевод на новую строку
				self.socket.send(buffer.encode())			# Отправляем информацию с ее энкодированием
		except KeyboardInterrupt:
			# Нажат Ctrl+C, клавиатурное прерывание
			print('[Abort] Сервер прервал свою работу клавиатурным прерыванием')
			self.socket.close()
			sys.exit()

	def listen(self):
		try:
			self.socket.bind((self.args.target, self.args.port))
		except OSError as oserr:
			print(f'[!] Операция была прервана с ошибкой: {oserr}')
			self.socket.close()
			sys.exit()
		else:
			print(f'[/] Слушаем подключение к {self.args.target}:{self.args.port}')

		self.socket.listen(5)
		print('[+] Слушаем подключения...')

		try:
			while True:
				client_socket, addr = self.socket.accept()
				print(f'[{addr}] присоединился')
				client_thread = threading.Thread(target=self.handle, args=(client_socket,))
				client_thread.start()
		except KeyboardInterrupt:
			print('[Abort] Сервер прервал свою работу клавиатурным прерыванием')
			self.socket.close()
			sys.exit()


	def handle(self, client_socket):
		data = client_socket.recv(4096).decode('utf-8')
		print(data)
		if self.args.execute:
			output = execute(self.args.execute)				# Обращаемся к командной строке
			client_socket.send(output.encode())
			print(f'[exec] {output}')
		elif self.args.upload:
			file_buffer = b''								# Задаем буфер обмена
			
			while True:
				data = client_socket.recv(4096)				# Размер буфера в битах
				if data:
					print(f'[Данные] {data}')
					file_buffer += f'{data}\n'				# Помещаем файл в наш запрос
				else:
					break
			
			with open(self.args.upload, 'wb') as f:
				print(f'[+] Записываем данные в файл {self.args.upload}')
				f.write(file_buffer)						# Открываем и читаем файл в бинарном виде
			
			message = f'Файл сохранен в {self.args.upload}'	# Выгружаем и отправляем на сервер
			client_socket.send(message.encode())
			self.socket.close()
			sys.exit()
		elif self.args.command:
			cmd_buffer = b''								# Снова задаем буфер
			while True:
				try:
					client_socket.send(b'Unknown: #> ')		# Приглашение для ввода команды
					
					while '\n' not in cmd_buffer.decode():
						cmd_buffer += client_socket.recv(64)
					
					response = execute(cmd_buffer.decode())	# Декодирование команды в читаемый для пк вид
					
					if response:
						client_socket.send(response.encode())	# Отправка ответа
					
					cmd_buffer = b''						# Очистка буфера
				except Exception as e:						# В случаи ошибки говорим что сервер умер от потери питания
					print(f'[!] Сервер был отключен: {e}')
					self.socket.close()
					sys.exit()
		else:
			while True:
				data = client_socket.recv(4096).decode('utf-8')
				if data:
					print(f'[Данные] {data}')
				else:
					break


def ipwhois_info(ip):
	results = ipwhois.IPWhois(ip).lookup_whois()
	print(results)
	print("\n")


def whois_info(ip):
	results = whois.whois(ip)
	print(results)


def ianna(ip):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("whois.iana.org", 43))
	s.send((ip + "\r\n").encode())
	response = b""
	while True:
		data = s.recv(4096)
		response += data
		if not data:
			break
	s.close()
	whois = ''
	for resp in response.decode().splitlines():
		if resp.startswith('%') or not resp.strip():
			continue
		elif resp.startswith('whois'):
			whois = resp.split(":")[1].strip()
			break
	return whois if whois else False


def get_whois(ip, whois):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((whois, 43))
	s.send((ip + "\r\n").encode())
	response = b""
	while True:
		data = s.recv(4096)
		response += data
		if not data:
			break
	s.close()
	whois_ip = dict()
	num = 0
	for ln in response.decode().splitlines():
		if ln.strip().startswith("%") or not ln.strip():
			continue
		else:
			if ln.strip().split(": ")[0].strip() in ['created', 'last-modified']:
				dt = datetime.fromisoformat(ln.strip().split(": ")[1].strip()).strftime("%Y-%m-%d %H:%M:%S")
				whois_ip.update({f'{ln.strip().split(": ")[0].strip()}_{num}': dt})
				num += 1
			else:
				whois_ip.update({ln.strip().split(": ")[0].strip(): ln.strip().split(": ")[1].strip()})
	return whois_ip if whois_ip else False


def validate_request(ip):
	try:
		IPv4Address(ip)
		if whois := ianna(ip):
			time.sleep(1)
			if info := get_whois(ip, whois):
				print(info)
			else:
				print("Не была получена информация")
		else:
			if info := get_whois(ip, 'whois.ripe.net'):
				print(info)
			else:
				print("Не была получена информация")
	except AddressValueError:
		print("IP адрес не валидный")
	except ConnectionResetError as ex:
		print(ex)


class TLSServer:
	def __init__(self, hostname: str, port: int, server_key: str, client_cert: str, server_cert: str):
		self.hostname = hostname
		self.server_cert = server_cert
		self.server_key = server_key
		self.client_cert = client_cert
		self.port = port

	def create_ssl_context(self):
		context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		context.verify_mode = ssl.CERT_REQUIRED
		context.verify_mode = ssl.CERT_REQUIRED
		context.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)
		context.options |= ssl.OP_SINGLE_ECDH_USE
		context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2

	def run(self):
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
			sock.bind(('', port))
			sock.listen(1)
			
			with context.wrap_socket(sock, server_side=True) as socks:
				conn, addr = socks.accept()
				print(f'[{addr}] Connected')
				message = conn.recv(1024).decode()
				capitalizedMessage = message.upper()
				conn.send(capitalizedMessage.encode())


class TLSClient:
	def __init__(self, hostname, port, client_key, client_cert, server_cert):
		self.hostname = hostname
		self.port = port
		self.client_key = client_key
		self.client_cert = client_cert
		self.server_cert = server_cert

	def create_ssl_context(self):
		context = ssl.SSLContext(ssl.PROTOCOL_TLS, cafile=server_cert)
		context.load_cert_chain(certfile=client_cert, keyfile=client_key)
		context.load_verify_locations(cafile=server_cert)
		context.verify_mode = ssl.CERT_REQUIRED
		context.options |= ssl.OP_SINGLE_ECDH_USE
		context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2

	def run(self):
		with socket.create_connection((hostname, port)) as sock:
			with context.wrap_socket(sock, server_side=False, server_hostname=hostname) as socks:
				print(socks.version())
				message = input("Введите ваше сообщение > ")
				socks.send(message.encode())
				receives = socks.recv(1024)
				print(receives)


def main():
	client_key = 'client.key'
	client_cert = 'client.crt'
	server_cert = 'server.crt'
	server_key = 'server.key'
	
	parser = argparse.ArgumentParser(description='NetCobra', formatter_class=argparse.RawDescriptionHelpFormatter, 
								epilog=textwrap.dedent('''
Примеры использования:

// Командная оболочка
netcobra -t 127.0.0.1 -p 4444 -l -c

// Загружаем в файл
netcobra -t 127.0.0.1 -p 4444 -l -u=mytest.txt

// Выполняем команду
netcobra -t 127.0.0.1 -p 4444 -l -e=\"cat /etc/passwd\"

// Шлем текст на порт сервера 1234
echo 'ABC' | ./netcobra -t 127.0.0.1 -p 1234

// Соединяемся с сервером
netcobra -t 127.0.0.1 -p 4444

// Узнаем информацию о домене по IP адресу
netcobra -t 127.0.0.1 -w

// Узнаем, есть ли IP в черных списках DNS
netcobra -t 127.0.0.1 -b

// Запуск TLS-соединения (сервер)
netcobra -t 127.0.0.1 -p 4444 -ts

// Запуск TLS-соединения (клиент)
netcobra -t 127.0.0.1 -p 4444 -tc
	'''))

	parser.add_argument('-c', '--command', action='store_true',
						help='командная строка')
	parser.add_argument('-e', '--execute', help='выполнение специфичной команды')
	parser.add_argument('-l', '--listen', action='store_true', help='слушание подключений')
	parser.add_argument('-p', '--port', type=int, default=5555,
						help='специфичный порт')
	parser.add_argument('-t', '--target', default='192.168.1.203',
						help='специфичный IP адрес')
	parser.add_argument('-u', '--upload', help='загрузка файла')
	parser.add_argument('-w', '--whois', help='информация о домене по IP адресу', action='store_true')
	parser.add_argument('-b', '--blacklist', help='проверить IP в черных списках DNS', action='store_true')
	parser.add_argument('-ts', '--tls-server', help='запуск tls-сервера', action='store_true')
	parser.add_argument('-tc', '--tls-client', help='запуск tls-клиента', action='store_true')
	args = parser.parse_args()

	if args:
		if args.whois:
			ipwhois_info(args.target)
			whois_info(args.target)
			print('\n')
			validate_request(args.target)
		elif args.blacklist:
			check_ip_in_black_list(args.target)
		elif args.ts:
			tls_serv = TLSServer(args.target, args.port, server_key, client_cert, server_cert)
			tls_serv.create_ssl_context()
			print(f'[{args.target}:{args.port}] Запуск TLS соединения (серверная часть)')
			tls.run()
		elif args.tc:
			tls_client = TLSClient(args.target, args.port, client_key, client_cert, server_cert)
			tls_client.create_ssl_context()
			print(f'[{args.target}:{args.port}] Подключение TLS соединения (клиентская часть)')
			tls_client.run()
		else:
			print(f'[/] Попытка соединения с сервером...')
			if args.listen:
				buffer = ''
			else:
				print('Введите сообщение для буфера:')
				buffer = sys.stdin.read()
			
			nc = NetCobra(args, buffer.encode())
			nc.run()


if __name__ == '__main__':
	main()
