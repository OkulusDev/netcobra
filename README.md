# netcobra
Сетевая кобра - это программа для сканирования сетей, IP, работой с сетью и серверами

## Установка NetCobra

0. Установка программ и зависимостей

 + Debian/Ubuntu

 	```bash
sudo apt install -y openssl make python3 python3-pip
 	```

 + Arch/Manjaro

 	```bash
sudo pacman -Sy openssl make python3 python-pip
 	```

1. Клонирование репозитория

```git clone https://github.com/OkulusDev/netcobra.git```

2. Переход в репозиторий

```cd netcobra```

3. Создание виртуального окружения

```python3 -m venv venv```

4. Вход в виртуальное окружение

```source venv/bin/activate```

5. Установка

```make install```

6. Создание бинарного файла

```make build```

## Документация

### Запуск

 + Запуск скрипта (показ справки)

 ```python3 netcobra.py --help```

 + Запуск бинарного файла (показ справки)

 ```./netcobra --help```

### Установка бинарного файла

Скопируйте бинарный файл ```netcobra``` в /usr/bin/

```sudo cp netcobra -r /usr/bin/```

### Примеры использования

 + Командная оболочка

```netcobra -t 127.0.0.1 -p 4444 -l -c```

 + Загружаем в файл

```netcobra -t 127.0.0.1 -p 4444 -l -u=mytest.txt```

 + Выполняем команду

```netcobra -t 127.0.0.1 -p 4444 -l -e=\"cat /etc/passwd\"```

 + Шлем текст на порт сервера 1234

```echo 'ABC' | ./netcobra -t 127.0.0.1 -p 1234```

 + Соединяемся с сервером

```netcobra -t 127.0.0.1 -p 4444```

 + Узнаем информацию о домене по IP адресу

```netcobra -t 127.0.0.1 -w```

 + Узнаем, есть ли IP в черных списках DNS

```netcobra -t 127.0.0.1 -b```

 + Запуск TLS-соединения (сервер)

```netcobra -t 127.0.0.1 -p 4444 -ts```

 + Запуск TLS-соединения (клиент)

```netcobra -t 127.0.0.1 -p 4444 -tc```

 + Справка

```netcobra --help```
