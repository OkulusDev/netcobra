#!/usr/bin/python3
# -*- coding:utf -*-
"""netcobra - альтернатива утилиты NetCat на python3
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
from datetime import datetime
from ipaddress import IPv4Address, AddressValueError
import ipwhois
import whois


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
	print("\n\n")


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


def main():
	parser = argparse.ArgumentParser(description='NetCobra', formatter_class=argparse.RawDescriptionHelpFormatter, 
								epilog=textwrap.dedent('''
Примеры использования:

// Командная оболочка
netcobra.py -t 127.0.0.1 -p 4444 -l -c

// Загружаем в файл
netcobra.py -t 127.0.0.1 -p 4444 -l -u=mytest.txt

// Выполняем команду
netcobra.py -t 127.0.0.1 -p 4444 -l -e=\"cat /etc/passwd\"

// Шлем текст на порт сервера 1234
echo 'ABC' | ./netcobra.py -t 127.0.0.1 -p 1234

// Соединяемся с сервером
netcobra.py -t 127.0.0.1 -p 4444

// Узнаем информацию о домене по IP адресу
netcobra.py -t 127.0.0.1 -w
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
	args = parser.parse_args()

	if args:
		if args.whois:
			ipwhois_info(args.target)
			whois_info(args.target)
			print('\n\n')
			validate_request(args.target)
		else:
			if args.listen:
				buffer = ''
			else:
				print('> ')
				buffer = sys.stdin.read()
			
			nc = NetCobra(args, buffer.encode())
			nc.run()


if __name__ == '__main__':
	main()
