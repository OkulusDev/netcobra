# netcobra
Сетевая кобра - это программа для сканирования сетей, IP, работой с сетью и серверами.

## Информация о NetCobra

NetCobra имеет множество функций, которые постоянно дополняются. TLS соединения, информация об IP, сканирование сети - все это малая часть того, что может делать сетевая кобра.

NetCobra написана на Python, и благодаря этому легкому и простому языку программирования, пользователь может сам дописать или переделать функционал.

NetCobra не имеет тяжеловесный графический интерфейс, она имеет только легкий режим аргументов командной строки. Но возможно, что в скором времени появится форк с графическим интерфейсом

NetCobra изначально была реализацией NetCat, но после я решил добавить больше функционала. Теперь сетевая кобра является более продвинутым инструментом

## Установка NetCobra

0. Установка программ и зависимостей

 + Debian/Ubuntu

```sudo apt install -y openssl make python3 python3-pip clang```

 + Arch/Manjaro

```sudo pacman -Sy openssl make python3 python-pip clang```

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

6. Создание бинарного файла (только Linux, но вы можете попробовать создать его под Windows и Mac OS по инструкции в разделе *Документация*)

---

## Документация

### Создание бинарного файла

 + Создание бинарного файла для Linux

```make build```

 + Создание бинарного файла для Windows

```make build_win```

 + Создание бинарного файла для Mac OS

 ```make build_mac```

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

## ToDo

 + Сделать форк с графическим интерфейсом
 + Задействовать ScaPy
 + Сделать сканер сетей
 + Создать функции для ARP-спуфинга и его обнаружения

## Описание коммитов

| Название | Описание                                                        |
|----------|-----------------------------------------------------------------|
| build	   | Сборка проекта или изменения внешних зависимостей               |
| ci       | Настройка CI и работа со скриптами                              |
| docs	   | Обновление документации                                         |
| feat	   | Добавление нового функционала                                   |
| fix	   | Исправление ошибок                                              |
| perf	   | Изменения направленные на улучшение производительности          |
| refactor | Правки кода без исправления ошибок или добавления новых функций |
| revert   | Откат на предыдущие коммиты                                     |
| style	   | Правки по кодстайлу (табы, отступы, точки, запятые и т.д.)      |
| test	   | Добавление тестов                                               |
