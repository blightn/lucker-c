# Lucker

Lucker - программа для демонстрации уязвимости некоторых криптовалют к методу подбора закрытых ключей. Также можно использовать для восстановления доступа к кошельку, если доступ к нему был утерян. Написано на C с использованием MSVS 2019 и WinAPI. Для операций с эллиптической кривой secp256k1 используется одноимённая библиотека secp256k1 из ядра Bitcoin. В качестве реализации алгоритма SHA-256 и RIPEMD-160 используется бибилотека OpenSSL 1.1.1m (от 14 Дек 2021), а для KECCAK-256 - SHA3IUF.

На данный момент поддерживаются следующие криптовалюты:
- BTC (только P2PKH - адреса, которые начинаются с "1");
- ETH;
- LTC (только P2PKH - адреса, которые начинаются с "L").

Открытые ключи бывают двух типов:
1. Несжатые: 65 байтов, 04 + x + y.
2. Сжатые: 33 байта, 02 или 03 + x.

При одном и том же закрытом ключе, но при разных типах открытых ключей, итоговые адреса будут различаться. Причём нет способа определить по адресу тип открытого ключа, по которому он был получен. Поэтому есть смысл указать оба типа для сравнения, если заранее неизвестно, из какого типа открытого ключа был получен адрес. Также стоит учитывать, что из одного закрытого ключа можно получить оба типа открытых ключей, а из них уже несжатый и сжатый адреса.

Скорость перебора измеряется в циклах в секунду (cycles/s). За 1 цикл считается: генерация закрытого ключа, получение из него открытых ключей (один из типов или оба), хеширование в зависимости от алгоритма и сравнение со всеми загруженными адресами.

В случае успеха, найденный закрытый ключ и соответствующие ему адреса сохраняются в файл "Result.txt" в папке Data.

Репозиторий содержит:
- решение MSVS 2019 (Lucker.sln);
- исходники (Lucker);
- скрипты для очистки (clean.bat удаляет увесистую папку ipch в .vs\Lucker\v16\ и бинарники, clean_all.bat удаляет то же + всю папку .vs);
- используемые библиотеки (Libs);
- папка с файлами со случайно сгенерированными адресами для тестирования (Data).

Решение состоит из 1-го проекта Lucker с динамической/статической конфигурациями для x86 и x64. Протестировано на Windows Vista и выше.

## Библиотеки

- [secp256k1](https://github.com/bitcoin-core/secp256k1/);
- OpenSSL 1.1.1 можно скачать и собрать автоматически с использованием пакетного менеджера [Vcpkg](https://github.com/microsoft/vcpkg/) (с OpenSSL версии 3.0 ещё не проверено, но, вероятно, будет работать);
- [SHA3IUF](https://github.com/brainhub/SHA3IUF/).

## Сборка

Для сборки решения использовалась Microsoft Visual Studio 2019.

После успешной сборки все бинарники будут находиться в папке Bins\:

- x64\
  - Debug\
  - Debug (static)\
  - Release\
  - Release (static)\
- x86\
	- Debug\
	- Debug (static)\
	- Release\
	- Release (static)\

## Использование

### Папка Data

В этой папке должны находиться текстовые файлы с адресами, закрытые ключи к которым необходимо подобрать. Имена файлов должны начинаться с тикера поддерживаемых криптовалют. Кодировка может быть ANSI или UTF-8. Строки внутри файлов должны разделяться с помощью "\r\n". В конце файла должна быть пустая строка, иначе последний адрес не загрузится. В папке Data есть готовые примеры файлов со случайно сгенерированными адресами.

### Флаги

На данный момент можно указать 4 флага:

    -h      - Вывести подсказку.
    -w <n>  - Количество воркеров. Должно быть в диапазоне [1 <= n <= количество_ядер]. 0 - выбрать автоматически. По умолчанию: 0.
    -c <n>  - Указать тип открытых ключей для сравнения:
            0 - использовать сжатые и несжатые;
            1 - только несжатые;
            2 - только сжатые.
             По умолчанию: 0.
    -bw     - Привязать воркеры к ядрам. Результат можно увидеть в Диспетчере задач на вкладке Производительность. По умолчанию: выключено.

____

Lucker is a program for demonstrating the vulnerability (Proof of Concept) of some cryptocurrencies to the method of enumerating private keys. It can also be used to restore access to the wallet if access to it has been lost. Written in C using MSVS 2019 and WinAPI. For secp256k1 elliptic curve operations the secp256k1 library from the Bitcoin core is used. As an implementation of the SHA-256 and RIPEMD-160 algorithm the OpenSSL 1.1.1m library (from 14 Dec 2021) is used, and for KECCAK-256 - SHA3IUF.

The following cryptocurrencies are currently supported:
- BTC (only P2PKH - addresses that start with "1");
- ETH;
- LTC (only P2PKH - addresses that start with "L").

Public keys are of two types:
1. Uncompressed: 65 bytes, 04 + x + y.
2. Compressed: 33 bytes, 02 or 03 + x.

With the same private key but with different types of public keys, the final addresses will differ. Moreover, there is no way to determine the type of public key by which it was received from the address. Therefore, it makes sense to specify both types for comparison if you don't know from which type of public key the address was obtained. Thus, both types of public keys can be obtained from the same private key and then both uncompressed and compressed addresses can be obtained from them.

The speed of enumeration is measured in cycles per second (cycles/s). For 1 cycle it is considered: generating a private key, obtaining public keys from it (one of the types or both), hashing depending on the algorithm and comparing with all loaded addresses.

If successful, the found private key and its corresponding addresses are saved to the "Result.txt" file in the Data folder.

The repository contains:
- MSVS 2019 solution (Lucker.sln);
- source code (Lucker);
- scripts for clean up (clean.bat removes the weighty ipch folder in .vs\Lucker\v16\ and also removes binaries, clean_all.bat removes the same as the previous one plus the entire .vs folder);
- libraries used (Libs);
- folder with randomly generated addresses for testing (Data).

The solution consists of one Lucker project with dynamic/static configurations for both x86 and x64 architectures. Tested on Windows Vista and above.

## Libraries

- [secp256k1](https://github.com/bitcoin-core/secp256k1/);
- OpenSSL 1.1.1 can be obtained via the [Vcpkg](https://github.com/microsoft/vcpkg/) package manager (with OpenSSL 3.0 hasn't been tested yet, but will probably work);
- [SHA3IUF](https://github.com/brainhub/SHA3IUF/).

## Building

Microsoft Visual Studio 2019 is used to build the solution.

Once built, you can find the binaries in the Bins\ folder:

- x64\
  - Debug\
  - Debug (static)\
  - Release\
  - Release (static)\
- x86\
	- Debug\
	- Debug (static)\
	- Release\
	- Release (static)\

## Usage

### Data folder

This folder should contain text files with addresses to compare against randomly generated private keys. Filenames must begin with the ticker of the supported cryptocurrencies. Encoding can be ANSI or UTF-8. Lines within files must be separated by "\r\n". At the end of the file must be an empty line otherwise the last address won't be loaded. There are some example files in the Data folder with randomly generated addresses.

### Flags

There are four flags:

    -h      - Print help.
    -w <n>  - Number of workers. Must be in the range [1 <= n <= cores]. 0 - select automatically. Default: 0.
    -c <n>  - Specify the type of public keys to be compared:
            0 - use both compressed and uncompressed;
            1 - uncompressed only;
            2 - compressed only.
             Default: 0.
    -bw     - Bind workers to cores. You can see the result in the Program manager under the Performance tab. Default: off.

____

## Screenshot

On my laptop with Windows 10 20H2 x64, Intel(R) i7-8750H (2.2GHz, 6 cores), 6000 BTC addresses:

![Performance](https://user-images.githubusercontent.com/4202176/154676782-d089b684-78cc-4cd2-bd1a-c91640db28f2.png)

## Authors

```
blightn <blightan@gmail.com>
```
## License

This project is licensed under the MIT License. See LICENSE in the project's root directory.

____

Если Вам всё-таки улыбнулась удача и/или Вы хотите отблагодарить за софт, вклад в свободное ПО или что-нибудь ещё, я буду очень признателен / If you are still lucky and/or you want to thank for the software, contribution to free software or something else, I will be very grateful:

```
BTC: 1JUqdnZtRDE3sAxytkCfP6WSLDuBn3fo6W
ETH: 0x08d2828d0a99ecbdb1feddd1d2e02ebbe50c8eba
```
