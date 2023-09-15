# netcobra
Сетевая кобра - это программа для сканирования сетей, IP, работой с сетью и серверами

## Установка

```bash
git clone https://github.com/OkulusDev/netcobra.git
cd netcobra
python3 -m venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Примеры использования:

 + Командная оболочка

```netcobra.py -t 127.0.0.1 -p 4444 -l -c```

 + Загружаем в файл

```netcobra.py -t 127.0.0.1 -p 4444 -l -u=mytest.txt```

 + Выполняем команду

```netcobra.py -t 127.0.0.1 -p 4444 -l -e=\"cat /etc/passwd\"```

 + Шлем текст на порт сервера 1234

```echo 'ABC' | ./netcobra.py -t 127.0.0.1 -p 1234```

 + Соединяемся с сервером

```netcobra.py -t 127.0.0.1 -p 4444```

 + Узнаем информацию о домене по IP адресу

```netcobra.py -t 127.0.0.1 -w```

 + Узнаем, есть ли IP в черных списках DNS

```netcobra.py -t 127.0.0.1 -b```

 + Справка

```netcobra.py --help```
