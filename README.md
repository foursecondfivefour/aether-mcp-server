# AETHER_01 — Full-Spectrum Windows Management MCP Server

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**10 инструментов. 99% охвата Windows. 0 компромиссов в безопасности.**

AETHER_01 — это [MCP (Model Context Protocol)](https://modelcontextprotocol.io) сервер на Rust, предоставляющий AI-ассистентам полный контроль над Windows 10/11 через стандартный ввод/вывод. От управления процессами до GUI-автоматизации, от реестра до WMI-запросов.

---

## Возможности

| # | Инструмент | Действия |
|---|-----------|----------|
| 1 | `process_control` | список, убить, создать, приоритет, потоки, affinity, модули, инъекция DLL* |
| 2 | `file_system` | чтение/запись/удаление, ACL, симлинки, ADS-потоки, EFS, тома, сетевые шары |
| 3 | `registry_editor` | чтение/запись/удаление, все кусты, security, мониторинг, офлайн-монтирование* |
| 4 | `service_manager` | список, старт/стоп/рестарт, конфигурация, триггеры, драйверы |
| 5 | `gui_automation` | мышь, клавиатура, окна, скриншоты, буфер обмена, дисплей, аудио |
| 6 | `system_info` | CPU, память, диски, ОС, питание, устройства, BIOS, NTP, ПО, обновления, BCD* |
| 7 | `network_manager` | адаптеры, соединения, DNS, фаервол, прокси, маршрутизация, WiFi, VPN, Bluetooth |
| 8 | `user_management` | пользователи, группы, сессии, политики, сертификаты, credentials, токены* |
| 9 | `security_audit` | аудит, UAC, Defender, AppLocker, BitLocker, TPM, Secure Boot, exploit protection |
| 10 | `system_automation` | Event Log, Scheduled Tasks, **WMI-запросы** |

`*` = отключено по умолчанию, включается через `.env` feature gates.

## Быстрый старт

### Требования

- **Windows 10/11** (x86-64, MSVC toolchain)
- **Rust** 1.85+ (`rustup default stable-x86_64-pc-windows-msvc`)
- **Администратор** (для большинства операций)

### Сборка

```powershell
git clone https://github.com/YOUR_USER/aether-mcp-server
cd aether-mcp-server

# Создать .env (все feature gates выключены по умолчанию)
Copy-Item .env.example .env

# Сборка (релизная — с максимальной оптимизацией и hardening)
cargo build --release
```

### Подключение к Cursor

Добавить в `%USERPROFILE%\.cursor\mcp.json`:

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "d:\\path\\to\\target\\release\\aether-mcp-server.exe",
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

Перезапустить Cursor. В интерфейсе MCP появится 10 инструментов AETHER_01.

## Feature Gates (.env)

Опасные операции отключены по умолчанию и включаются администратором:

```env
AETHER_BCD_EDIT=0          # Изменение конфигурации загрузки Windows
AETHER_HAL_CONFIG=0        # Настройка HAL и дампа памяти
AETHER_OFFLINE_REGISTRY=0  # Монтирование офлайн-кустов реестра
AETHER_DLL_INJECT=0        # Инъекция DLL в процессы
AETHER_TOKEN_MANIPULATION=0 # Манипуляция токенами доступа
AETHER_LSA_SECRETS=0       # Чтение LSA-секретов
```

## Безопасность

- **Подтверждение опасных действий**: параметр `force: true` обязателен для kill, delete, stop, write в системные области
- **Feature Gates**: наиболее опасные операции отключены по умолчанию
- **Компилятор**: Control Flow Guard, ASLR, DEP/NX, high-entropy ASLR, статический CRT
- **Валидация**: каждый параметр проверяется до вызова Win32 API
- **Без shell-инъекций**: никаких вызовов `cmd.exe` или `powershell.exe` для системных операций — только прямые Win32 API вызовы
- **WMI защита**: только SELECT-запросы, таймаут 30 секунд, лимит 1000 строк

## Производительность

- `opt-level = 3` (все оптимизации LLVM)
- `lto = true` (fat LTO через все крейты)
- `codegen-units = 1` (полное удаление мёртвого кода)
- `panic = "abort"` (нет unwind-таблиц)
- `strip = "symbols"` (минимальный бинарник)
- `target-cpu = native` (AVX2, BMI2, FMA, POPCNT)

## Структура проекта

```
src/
├── main.rs              # tokio::main, stdio транспорт
├── server.rs            # AetherServer + tool_router
├── config.rs            # FeatureGates из .env
├── error.rs             # AetherError + FormatMessageW (русские сообщения)
├── audit.rs             # Структурированный аудит
└── tools/
    ├── process.rs       # process_control
    ├── filesystem.rs    # file_system
    ├── registry.rs      # registry_editor
    ├── service.rs       # service_manager
    ├── gui.rs           # gui_automation
    ├── sysinfo.rs       # system_info
    ├── network.rs       # network_manager
    ├── user.rs          # user_management
    ├── security.rs      # security_audit
    └── automation.rs    # system_automation
```

## Лицензия

MIT
