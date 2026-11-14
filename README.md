# NativeBox

Сборка под Windows x64, на C++20 и Qt 6.8.3. Само приложение — x64, runtime собирается сразу для x64 и x86.

## Что установить

- [Git for Windows](https://git-scm.com/install/windows).
- [Python 3.12 или новее](https://www.python.org/downloads/windows/). Команда `python` должна быть доступна в терминале.
- [Visual Studio или Build Tools](https://visualstudio.microsoft.com/downloads/) с набором **«Разработка классических приложений на C++»**. Нужны MSVC для x64/x86, Windows SDK и компонент **C++ CMake tools for Windows**. В нём идут CMake и Ninja, которые использует скрипт. Минимальная версия CMake — 3.25.

Команды ниже выполняются в обычном PowerShell. Окружение MSVC скрипт подключает сам.

## Зависимости

| Компонент | Версия | Для чего нужен |
| --- | --- | --- |
| Qt, комплект MSVC 2022 x64 | 6.8.3 | Интерфейс, QML, сеть и Qt SQL |
| Microsoft Detours | 4.0.1 | Runtime с перенаправлением вызовов |
| SQLite | 3.54.1 | База данных; драйвер `qsqlite` пересобирается с этой версией |
| Microsoft Offline Registry Library | 10.0.26100.6584 | Создание приватных файлов реестра |
| 7zr | 26.06 | Распаковка архивов Qt при загрузке зависимостей |
| WiX Toolset | 5.0.2 | Только сборка установщика |

Qt, Detours, SQLite и 7zr скачиваются скриптами с официальных серверов. WiX загружается из NuGet при сборке установщика. Ссылки на конкретные архивы и их хеши лежат в [dependencies.lock.json](dependencies.lock.json).

`offreg.dll` уже есть в `third_party/offreg/x64`. Отдельно искать DLL, ставить Qt через Qt Installer или устанавливать пакеты через pip не нужно.

## Сборка

```powershell
git clone https://github.com/pnwjdw/NativeBox.git
cd NativeBox
python -I -B scripts/build-driverless.py --configuration Release
```

При первом запуске нужен интернет. Зависимости сохраняются в `.deps`, результат сборки — в `out/release`.

Подготовить отдельную папку для запуска:

```powershell
python -I -B scripts/deploy-driverless.py --build out/release --destination out/stage
.\out\stage\nativebox.exe
```

Папки `out/stage` перед этой командой быть не должно. Для повторной подготовки можно указать другое имя, например `out/stage-2`.

Переносить на другой компьютер нужно всю папку `out/stage`, а не один EXE. В ней лежат Qt, плагины и runtime. На другом компьютере также нужен [Visual C++ v14 Redistributable x64](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist). Установщик приложения включает этот пакет.

При подготовке папки скрипт добавит исходные архивы библиотек в `out/stage/licenses/corresponding-source`. Если их ещё нет в кеше, скачает дополнительно. Это материалы для распространения вместе с приложением; лицензии находятся в [licenses](licenses).

## Установщик

Для этого шага дополнительно нужен [.NET SDK](https://dotnet.microsoft.com/en-us/download) версии 6.0 или новее. WiX вручную устанавливать не надо.

У текущего скрипта упаковки закреплён конкретный Visual C++ Redistributable: **14.51.36247.0**. Он ищется внутри установленной Visual Studio по пути `VC/Redist/MSVC/14.51.36231/vc_redist.x64.exe` и проверяется по хешу и подписи Microsoft. Просто установить свежий Redistributable в Windows недостаточно: для упаковки нужен сам этот файл. Путь и хеш указаны в `dependencies.lock.json`; для другого пакета их придётся обновить после проверки файла. Сборке самого приложения этот EXE не нужен.

После сборки и подготовки `out/stage`:

```powershell
python -I -B scripts/package-driverless.py --deployment out/stage-deployment.json --output out/installer --build-only
```

`out/installer` тоже должна быть новой папкой. На выходе получатся `out/installer/1.exe` и `out/installer/NativeBox.msi`.

`--build-only` собирает установщик без отчётов испытаний. Проверки хешей и состава файлов при этом остаются.

Готовый установщик лежит в [Releases](https://github.com/pnwjdw/NativeBox/releases).
