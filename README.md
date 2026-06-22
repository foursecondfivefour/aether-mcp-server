# AETHER_01 — Full-Spectrum Windows Management MCP Server

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<p align="center">
  <a href="cursor://anysphere.cursor-deeplink/mcp/install?name=aether-01&config=eyJhcmdzIjpbIi1FeGVjdXRpb25Qb2xpY3kiLCJCeXBhc3MiLCItTm9Qcm9maWxlIiwiLUNvbW1hbmQiLCJpcm0gaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2ZvdXJzZWNvbmRmaXZlZm91ci9hZXRoZXItbWNwLXNlcnZlci9tYWluL2luc3RhbGwucHMxIHwgaWV4Il0sImNvbW1hbmQiOiJwb3dlcnNoZWxsIn0=">
    <img src="https://img.shields.io/badge/Add%20to-Cursor-3ecf8e?logo=cursor&logoColor=white&style=for-the-badge" alt="Add to Cursor" />
  </a>
  <a href="vscode://mcp/install?%7B%22args%22%3A%5B%22-ExecutionPolicy%22%2C%22Bypass%22%2C%22-NoProfile%22%2C%22-Command%22%2C%22irm+https%3A%2F%2Fraw.githubusercontent.com%2Ffoursecondfivefour%2Faether-mcp-server%2Fmain%2Finstall.ps1+%7C+iex%22%5D%2C%22command%22%3A%22powershell%22%7D">
    <img src="https://img.shields.io/badge/Add%20to-VSCode-007acc?logo=visualstudiocode&logoColor=white&style=for-the-badge" alt="Add to VS Code" />
  </a>
  <a href="vscode-insiders://mcp/install?%7B%22args%22%3A%5B%22-ExecutionPolicy%22%2C%22Bypass%22%2C%22-NoProfile%22%2C%22-Command%22%2C%22irm+https%3A%2F%2Fraw.githubusercontent.com%2Ffoursecondfivefour%2Faether-mcp-server%2Fmain%2Finstall.ps1+%7C+iex%22%5D%2C%22command%22%3A%22powershell%22%7D">
    <img src="https://img.shields.io/badge/Add%20to-VSCode%20Insiders-007acc?logo=visualstudio&logoColor=white&style=for-the-badge" alt="Add to VS Code Insiders" />
  </a>
</p>

<p align="center">
  <a href="https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1"><img src="https://img.shields.io/badge/PowerShell-Install%20Script-5391FE?logo=powershell&logoColor=white&style=for-the-badge" alt="Install via PowerShell" /></a>
</p>

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

### Один клик — автоустановка

Скопируйте и вставьте в **PowerShell (администратор)**:

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

Скрипт автоматически:
1. Найдёт или скачает последний бинарник AETHER_01
2. Создаст `.env` с безопасными настройками по умолчанию
3. Добавит сервер в **все найденные** агентные среды: Cursor, Claude Desktop, Windsurf, VS Code

### Выборочная установка

```powershell
# Только Cursor
.\install.ps1 -Targets cursor

# Claude Desktop + Windsurf
.\install.ps1 -Targets claude,windsurf

# С указанием пути к своему бинарнику
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe

# Скачать конкретный релиз
.\install.ps1 -ReleaseTag v1.0.0
```

### Сборка из исходников

```powershell
git clone https://github.com/foursecondfivefour/aether-mcp-server
cd aether-mcp-server
Copy-Item .env.example .env
cargo build --release
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe
```

### Ручная настройка (без скрипта)

Добавьте в конфигурационный файл вашей агентной среды:

<details>
<summary><b>Cursor</b> — <code>%USERPROFILE%\.cursor\mcp.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "d:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

<details>
<summary><b>Claude Desktop</b> — <code>%APPDATA%\Claude\claude_desktop_config.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "d:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

<details>
<summary><b>Windsurf</b> — <code>%USERPROFILE%\.codeium\windsurf\mcp_config.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "d:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

<details>
<summary><b>VS Code (Claude MCP)</b> — <code>%APPDATA%\Code\User\globalStorage\anthropic.claude-mcp\mcp.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "d:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

> **После настройки** перезапустите приложение. В интерфейсе MCP появится 10 инструментов AETHER_01.

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
