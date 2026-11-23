# Редактор настроек CMOS — ASRock X670E Taichi Carrara

GUI-редактор образа настроек `4.43-5400f` для AMI Aptio V / AMI TSE. Прошивка
`X67ETCC4.43.ROM` (BIOS 4.43) используется как источник описаний, вариантов значений и заводских
дефолтов. Редактор изменяет только dump, а не ROM.

## Запуск

```
python editor/app.py
```

По умолчанию открываются `4.43-5400f`, `X67ETCC4.43.ROM` и `out/settings_map.json` из корня проекта.
Можно указать другие файлы:

```
python editor/app.py [dump] [firmware.ROM] [settings_map.json]
```

Нужен Python 3.10+ с Tkinter. Внешних Python-зависимостей у приложения нет.

## Возможности

- 3 708 уникальных пунктов, реально присутствующих в этом dump: основной Setup, AMD CBS для
  RPL/PHX/STXKRK, AMD PBS и AMD Overclocking;
- поиск по названию и пути меню, фильтр отличий от заводских значений;
- выпадающие списки для `one_of`/`checkbox`, проверка диапазона и шага чисел, signed-значения;
- заводской сброс отдельного пункта из NVAR или из IFR `DEFAULT`;
- подсказки из строкового пула прошивки, адрес varstore и Question ID;
- hex-дамп и запись произвольных байтов на вкладке **Raw varstores**;
- экспорт текущих значений в `settings.csv`;
- резервная копия `*.bak` при перезаписи файла и режим **Save As**.

Пароли разблокированы как точные 40-байтные поля: вводятся 80 hex-символов, пустая строка очищает
пароль. Это не предполагает конкретное кодирование AMI (plain/XOR). Динамические списки также
разблокированы и принимают числовое значение с проверкой диапазона; их подписи прошивка формирует
во время работы. Дата и время остаются только для чтения.

## Формат dump-файла

```
0x00  "A86\0"   подпись контейнера
0x20  " 4.10"   версия раскладки setup, 16 байт с NUL
0x38  u16       поле формата (= 2)
0x3A  u16       длина области записей (= 0x2026 для этого dump)
0x55  records   поток: u32 little-endian длина + содержимое
tail            нулевое выравнивание до фиксированного размера
```

Каждая запись содержит значение EFI-переменной (`Setup`, `AMITSESetup`, `AmdSetupRPL`,
`AodSetupRpl`, `AMD_PBS_SETUP` и т. д.). Имён внутри контейнера нет. Записи идентифицируются по
заводским NVAR-значениям и размеру. `AodSetupRpl` дополнительно подтверждается размером `0x320` и
парным присутствием `AmdSetupRPL`.

Контрольной суммы у контейнера нет. При сохранении пересчитывается только 16-битная длина области
записей в `0x3A`; размеры записей и хвост файла сохраняются. Парсер теперь отклоняет повреждённые
длины вместо молчаливого чтения хвоста.

В dump 14 записей, из них 11 непустых и три нулевых. Отличия исходного `4.43-5400f` от заводских
значений: `Setup` — 72 байта, `AmdSetupRPL` — 21, `AMD_PBS_SETUP` — 3, `AMITSESetup` — 1.

## Откуда берётся карта настроек

В большом LZMA-модуле `out/payload/0x1118730_guid-section.bin` находятся девять независимых баз
форм. Старая версия проекта декодировала только основную AMI TSE и поэтому не показывала AMD CBS,
PBS и Overclocking.

| База | Смещение IFR | Varstore | Вопросов |
|---|---:|---|---:|
| AMD CBS | `0x2ea21b` | `AmdSetupRPL` | 913 |
| AMD CBS | `0x331b7b` | `AmdSetupPHX` | 976 |
| AMD CBS | `0x37d2de` | `AmdSetupSTXKRK` | 979 |
| AMD PBS | `0x3c2db1` | `AMD_PBS_SETUP` | 138 |
| RAID Configuration | `0x622907` | `MyRC*` | 672 |
| AMI TSE Setup | `0x690e22` | 68 varstores | 635 |
| AMD Overclocking | `0x2624d47` | `AodSetupStx` | 223 |
| AMD Overclocking | `0x2631407` | `AodSetupRpl` | 257 |
| AMD Overclocking | `0x265a677` | `AodSetupPhx` | 150 |

Всего декодируются 4 943 вопроса и 78 varstores. В GUI попадают только хранилища из dump;
служебные вопросы без названия и повторные ссылки на один и тот же пункт удаляются. Для оставшихся
3 708 пунктов все смещения находятся внутри соответствующих varstores, а заводские IFR/NVAR-
дефолты совпадают там, где доступны оба источника.

Основная AMI TSE-база содержит таблицу varstore по `0x690489`, поток IFR по `0x690e22` и строковый
пул `en-US` по `0x69b044`. Побайтовое описание — в `out/TSE_NOTES.md`.

Заводские значения остальных переменных читаются из `StdDefaults` → `NVAR` по смещению `0x1BC0000`
(17 переменных). Для `AodSetup*`, которого нет в NVAR, используется стандартный IFR `DEFAULT`.

## Инструменты

| Файл | Назначение |
|---|---|
| `editor/app.py` | Tkinter GUI |
| `editor/model.py` | значения, типы, дефолты, фильтрация и сохранение |
| `tools/uefi/setupimg.py` | строгий reader/writer контейнера A86 |
| `tools/uefi/nvarstore.py` | NVAR и заводские значения |
| `tools/uefi/decompress.py` | LZMA-alone / Brotli |
| `tools/carve.py` | извлечение LZMA payload из ROM |
| `tools/inspect_image.py` | сводка записей и отличий от завода |
| `tools/tse/setupdb.py` | декодер всех девяти HII/TSE-баз |
| `out/settings_map.json` | готовая объединённая карта |
| `out/TSE_NOTES.md` | byte-level заметки по основной базе |

Перегенерировать карту:

```
python tools/carve.py X67ETCC4.43.ROM out/payload
python tools/tse/setupdb.py out/payload/0x1118730_guid-section.bin --rom X67ETCC4.43.ROM \
        -o out/settings_map.json --validate 12
```

`--main-only` оставляет старое поведение и декодирует только наибольшую базу.

Проверить dump без GUI:

```
python tools/inspect_image.py 4.43-5400f X67ETCC4.43.ROM
```

## PCIe: первый слот x16 и второй слот

В `AMD PBS Option → AMD Common Platform Module → PCIe/GFX Lanes Configuration` найден параметр
`AMD_PBS_SETUP+0x18`. Для текущего Board ID=2 активен список `x16 / x8x8 / x8x4x4 / x4x4x4x4`;
в исходном dump выбрано `x16` (значение 0).

Руководство ASRock подтверждает наличие **PCIe Switch + Redriver**: PCIE1 обозначен `x16/x8`, а
PCIE2 — `x0/x8`. Следовательно, режим `x16` отдаёт все CPU-линии первому слоту, а второй получает
`x0` (фактически отключён). Режим `x8x8` даёт обеим картам по восемь линий. Это аппаратный
мультиплексор, управляемый настройкой BIOS, а не необратимая аппаратная схема x8/x8. Оставить вторую
карту активной и одновременно получить x16 на первой в этой конфигурации нельзя.

У ASUS используется аналогичный подход: в руководствах встречается `PCIe Bandwidth Bifurcation
Configuration` с `Auto = full PCIe X16` и `X8/X8`. Конкретное поведение и отключаемый при x16 слот
или M.2 зависят от модели платы.

## Внешние источники

- [ASRock X670E Taichi Carrara — BIOS](https://www.asrock.com/mb/AMD/X670E%20Taichi%20Carrara/bios.html)
- [ASRock X670E Taichi Carrara — User Manual](https://download.asrock.com/Manual/X670E%20Taichi%20Carrara.pdf)
- [ASRock Software/BIOS Setup Guide](https://download.asrock.com/Manual/Software/AMD%20X670/Software_BIOS%20Setup%20Guide_English.pdf)
- [ASUS ProArt X670E-CREATOR WIFI — Tech Specs](https://www.asus.com/us/motherboards-components/motherboards/proart/proart-x670e-creator-wifi/techspec/)
- [Пример ASUS BIOS: PCIe Bandwidth Bifurcation Configuration](https://www.manualowl.com/m/Asus/PRIME-B560M-A-AC/Manual/653746?page=40)
- [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) — устройство UEFI PI-контейнеров;
  редактор не зависит от UEFITool, поскольку нужный AMI/HII-парсер включён в проект.
- [UEFI Specification — Human Interface Infrastructure](https://uefi.org/specs/UEFI/2.10/33_Human_Interface_Infrastructure.html)

## Ограничения и безопасность

- Это редактор dump, а не утилита прошивки. Способ загрузки изменённого dump в плату зависит от
  программы, которой он был получен. Сохраните оригинал и проверьте возможность аппаратного сброса
  CMOS; скрытые параметры могут сделать систему незагружаемой.
- `Auto` — конкретное число в varstore, а не отсутствие значения.
- Условия `suppress-if`/`gray-out-if` показаны как справочные правила и не ограничивают редактирование.
  Это позволяет менять скрытые настройки, но ответственность за совместимость значений несёт пользователь.
- В dump присутствуют три CBS-варианта. Прошивка использует подходящий процессору вариант; не следует
  без необходимости менять одинаковые параметры сразу во всех трёх.
- Подстановки `%d`/`%s` в некоторых именах оставлены как в прошивке. Порядок загрузки и другие
  динамические списки нельзя безопасно редактировать как обычные enum-настройки.
