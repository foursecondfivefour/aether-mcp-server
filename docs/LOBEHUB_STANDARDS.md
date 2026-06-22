# Стандарты и практики AETHER_01 — основано на LobeHub

## Источник

[LobeHub](https://github.com/lobehub/lobe-chat) (~79,000 звёзд на GitHub) — крупнейший open-source AI-агентный фреймворк. Использует pnpm-монорепо из 50+ пакетов, Next.js 16 + React 19, TypeScript. Лучшие практики этого проекта адаптированы для Rust-проекта AETHER_01.

---

## 1. Архитектура: корни vs. фичи (Roots vs. Features)

### Принцип (из LobeHub)

```
src/routes/   — ТОЛЬКО тонкие страничные сегменты. Никакой бизнес-логики. Импортируют из features.
src/features/ — Бизнес-компоненты по доменам. Вся логика, хуки, UI здесь.
src/spa/      — Точки входа + конфигурация роутера.
```

### Адаптация для AETHER_01 (Rust)

```text
src/
├── main.rs              # Точка входа — «route» в терминах LobeHub.
│                         # Только инициализация, загрузка .env, stdio-transport.
│                         # Никакой бизнес-логики.
│
├── server.rs            # «SPA entry + router» — регистрация 10 тулов.
│                         # Тонкий: только dispatch к tools/*.
│                         # Метаданные: ServerHandler, возможности, инструкции.
│
└── tools/               # «features» — бизнес-логика по доменам.
    ├── process.rs       #   Домен: процессы и потоки
    ├── filesystem.rs    #   Домен: файловая система
    ├── registry.rs      #   Домен: реестр Windows
    ├── service.rs       #   Домен: службы и драйверы
    ├── gui.rs           #   Домен: GUI-автоматизация
    ├── sysinfo.rs       #   Домен: системная информация
    ├── network.rs       #   Домен: сеть
    ├── user.rs          #   Домен: пользователи и безопасность
    ├── security.rs      #   Домен: аудит безопасности
    └── automation.rs    #   Домен: автоматизация (EventLog, WMI, задачи)
```

### Правило (из LobeHub AGENTS.md)

> **«В src/routes/ добавляйте только файлы сегментов маршрута, которые делегируют в features. Реализуйте контент в src/features/ и экспортируйте оттуда. Не создавайте папки features/ внутри src/routes/.»**

Адаптация для AETHER_01:

> **«В server.rs регистрируйте только точки входа инструментов (атрибут #[tool]) и делегируйте в tools/. Реализуйте бизнес-логику в tools/ и экспортируйте через pub fn. Не создавайте папки tools/ внутри других модулей.»**

---

## 2. Монорепо-архитектура

### Принцип LobeHub

| Уровень | LobeHub | AETHER_01 |
|---------|---------|-----------|
| **Приложение** | `src/` — Next.js веб-приложение | `src/` — MCP-сервер |
| **Платформа** | `apps/desktop/` — Electron | `target/` — Windows .exe |
| **Пакеты** | `packages/` — `@lobechat/*` | `Cargo.toml` зависимости |
| **БД** | `@lobechat/database` (Drizzle ORM) | `windows-registry` (реестр Windows) |
| **Рантайм** | `@lobechat/agent-runtime` | `src/tools/` (Win32 API) |
| **Тесты** | `e2e/` (Playwright + Cucumber) | `cargo test` |

### Структура пакетов LobeHub

| Категория | Шаблон пакета | Примеры |
|-----------|--------------|---------|
| AI Runtime | `@lobechat/*-runtime` | `agent-runtime`, `model-runtime` |
| Встроенные инструменты | `@lobechat/builtin-tool-*` | `builtin-tool-lobe-agent`, `python-interpreter` |
| Бизнес-логика | `@lobechat/business-*` | `business-model-runtime` |
| База данных | `@lobechat/database` | `database` |
| Desktop/Electron | `@lobechat/*-ipc` | `electron-server-ipc` |
| Утилиты | `@lobechat/utils`, `@lobechat/*-safe-*` | `utils`, `ssrf-safe-fetch` |
| Память | `@lobechat/memory-*` | `memory-user-memory` |

### Эквивалент в AETHER_01

Хотя AETHER_01 не монорепо, модульная структура повторяет тот же принцип:

- **Core runtime** = `src/tools/` — каждый файл = один инструмент (аналог `@lobechat/builtin-tool-*`)
- **Database layer** = `windows-registry` crate (аналог `@lobechat/database`)
- **Agent runtime** = `rmcp` crate (аналог `@lobechat/agent-runtime`)
- **Model runtime** = Windows API через `windows` crate (аналог `@lobechat/model-runtime`)

---

## 3. Git-воркфлоу

### Ветки (LobeHub)

| Ветка | Назначение | Адаптация для AETHER |
|-------|-----------|---------------------|
| `canary` | Разработка (облачный продакшен) | `main` — у нас один стабильный бранч |
| `main` | Релизный бранч (cherry-pick из canary) | — |
| `feat/имя-фичи` | Новые возможности от `canary` | `feat/имя-фичи` от `main` |
| `fix/описание` | Исправления от `canary` | `fix/описание` от `main` |

### Коммиты

**LobeHub использует gitmoji:**

```
✨ feat: add user avatar upload
🐛 fix: resolve race condition in chat store
🎨 style: reformat agent panel layout
♻️ refactor: extract file service to shared package
📝 docs: update API documentation
✅ test: add E2E tests for onboarding flow
🔒 security: fix XSS in markdown renderer
⬆️ deps: upgrade next.js to 16.0.0
```

**AETHER_01 использует Conventional Commits (более стандартно для Rust-экосистемы):**

```
feat: add BCD editor to system_info tool
fix: handle null pointer in registry offline mount
refactor: extract win32_description to error module
docs: add AGENTS.md with build instructions
perf: cache SCM handle in service_manager
test: add integration test for process_control
chore: fix all 68 compiler warnings
security: add FormatMessageW to error translation
```

### Формат веток

**LobeHub:** `username/feat/feature-name` или `feat/feature-name`

**AETHER_01:** `feat/feature-name` или `fix/bug-description`

### Pull Request'ы

LobeHub использует `.github/PULL_REQUEST_TEMPLATE.md`. AETHER_01 уже следует этому стандарту.

---

## 4. AI-ассистированная разработка

### Система навыков (Skills)

LobeHub помещает инструкции для AI-ассистентов в `.agents/skills/`:

```
.agents/skills/
├── spa-routes/SKILL.md        # Правила маршрутизации SPA
├── review-checklist/SKILL.md  # Чек-лист код-ревью
├── ux/SKILL.md                # UX-дизайн и состояния
├── version-release/SKILL.md   # Релизный процесс
├── cli/SKILL.md               # CLI-разработка
└── ...
```

AETHER_01 уже имеет:

```
.agents/skills/aether-windows-mcp/SKILL.md  # System prompt + quick reference
.cursor/rules/aether-mcp.mdc                 # Cursor-правила
CLAUDE.md                                     # Claude Code инструкции
.github/copilot-instructions.md              # GitHub Copilot инструкции
.windsurfrules                                # Windsurf правила
```

### AGENTS.md

LobeHub использует `AGENTS.md` в корне репозитория как точку входа для всех AI-ассистентов. В нём описаны:

- Технологический стек
- Структура проекта
- Правила роутинга и features
- Git-воркфлоу
- Пакетный менеджмент
- Тестирование
- i18n
- Стиль кода

AETHER_01 уже имеет `AGENTS.md` с полным соответствием этому формату.

---

## 5. Технологический стек

### LobeHub

| Слой | Технология |
|------|-----------|
| Фреймворк | Next.js 16 + React 19 |
| Язык | TypeScript |
| UI | Ant Design + @lobehub/ui + antd-style (CSS-in-JS) |
| Состояние | Zustand + SWR |
| Бэкенд | tRPC + Drizzle ORM + PostgreSQL |
| Тесты | Vitest (юнит) + Playwright (E2E) |
| Пакеты | pnpm (монорепо) |
| Линтинг | ESLint + Stylelint + Prettier |
| CI/CD | GitHub Actions + semantic-release |
| Деплой | Vercel / Docker |

### AETHER_01 (эквивалент)

| Слой | Технология |
|------|-----------|
| Рантайм | Rust (edition 2021) |
| MCP SDK | `rmcp` 0.5 |
| Системные вызовы | `windows` 0.58 (50+ features) |
| Реестр | `windows-registry` 0.3 |
| Асинхронность | `tokio` |
| Сериализация | `serde` / `serde_json` |
| Валидация схем | `schemars` 0.8 |
| Логирование | `tracing` |
| Ошибки | `thiserror` 2 |
| Линтинг | `clippy -- -D clippy::all -D clippy::pedantic` |
| Форматирование | `rustfmt` (max_width = 120) |
| Сборка | `cargo build --release` |

---

## 6. Компонентная иерархия и приоритеты

### LobeHub: приоритет компонентов

> **1. `@lobehub/ui/base-ui` (headless-примитивы)**
> **2. `@lobehub/ui` (корневой пакет)**
> **3. `antd` (только в крайнем случае)**

Когда компонент существует в base-ui, используй его — никогда не бери корневой или antd-аналог.

### AETHER_01: приоритет API-вызовов

> **1. Прямые Win32 API через `windows` crate (максимальная производительность, минимальная поверхность атаки)**
> **2. `windows-registry` crate (для безопасных операций с реестром)**
> **3. `std::process::Command` с фиксированными аргументами (только для утилит без Win32 API-эквивалента: `bcdedit`, `wevtutil`)**
> **4. PowerShell (только для операций без прямого Win32 API: `Get-MpComputerStatus`, `Get-BitLockerVolume`)**

Никогда не используй `cmd.exe` для системных операций. Никакого shell-инжекта. Всегда валидируй параметры перед передачей в Win32 API.

---

## 7. Состояние и управление данными

### LobeHub: Zustand + SWR

- **Zustand** для клиентского состояния (слайсы: actions, selectors, initialState)
- **SWR** для серверных данных (кеширование, ревалидация)
- **Chat Store**: сообщения, топики, AI-генерация
- **File Store**: загрузки, документы, UploadDock

### AETHER_01: FeatureGates + AuditLogger

- **FeatureGates** (аналог Zustand store) — глобальное состояние, загружается из `.env` при старте
- **AuditLogger** (аналог SWR кеша) — структурированное логирование каждлго вызова инструмента
- **ToolRouter** — диспетчеризация вызовов к 10 инструментам
- **ErrorContext** — контекст ошибки, передаваемый через все слои

---

## 8. Стиль кода и размер файлов

### LobeHub: правило 800 строк

> **«Когда файл превышает ~800 строк, разделите его на несколько файлов (извлеките субкомпоненты, хуки, хелперы, типы). Маленькие сфокусированные файлы дружественны и людям, и AI-агентам.»**

### AETHER_01: текущее состояние

| Файл | Строк | Статус | Рекомендация |
|------|-------|--------|--------------|
| `error.rs` | 476 | Ок | |
| `audit.rs` | 46 | Ок | |
| `config.rs` | 75 | Ок | |
| `main.rs` | 58 | Ок | |
| `server.rs` | 158 | Ок | |
| `process.rs` | ~1150 | Превышает | Разделить на: `process_list.rs`, `process_control.rs`, `process_inject.rs` |
| `filesystem.rs` | ~996 | Превышает | Разделить на: `fs_basic.rs`, `fs_acl.rs`, `fs_streams.rs`, `fs_volumes.rs` |
| `registry.rs` | ~840 | На грани | Разделить на: `registry_crud.rs`, `registry_security.rs`, `registry_offline.rs` |
| `service.rs` | ~930 | Превышает | Разделить на: `service_lifecycle.rs`, `service_drivers.rs` |
| `gui.rs` | ~1320 | Превышает | Разделить на: `gui_mouse.rs`, `gui_keyboard.rs`, `gui_window.rs`, `gui_clipboard.rs`, `gui_screenshot.rs` |
| `sysinfo.rs` | ~2017 | Значительно | Разделить на: `sys_cpu.rs`, `sys_power.rs`, `sys_devices.rs`, `sys_software.rs`, `sys_bcd.rs` |
| `network.rs` | ~1260 | Превышает | Разделить на: `net_adapters.rs`, `net_firewall.rs`, `net_wireless.rs` |
| `user.rs` | ~2040 | Значительно | Разделить на: `user_accounts.rs`, `user_certs.rs`, `user_credentials.rs`, `user_lsa.rs` |
| `security.rs` | ~700 | Ок | |
| `automation.rs` | ~600 | Ок | |

Следуя стандарту LobeHub, файлы `sysinfo.rs` (2017 строк) и `user.rs` (2040 строк) должны быть разделены в первую очередь. Это улучшит читаемость, упростит код-ревью и ускорит работу AI-ассистентов с проектом.

---

## 9. i18n и локализация

### LobeHub

- Ключи в `src/locales/default/` (en-US и zh-CN вручную)
- Остальные локали заполняет CI-воркфлоу `auto-i18n.yml`
- `react-i18next` для фронтенда

### AETHER_01

- Все сообщения об ошибках на русском языке с переводом Win32-кодов через `FormatMessageW`
- `Win32_description()` использует `LANG_SYSTEM_DEFAULT` — автоматически подстраивается под язык ОС
- Конструкторы ошибок (`AetherError::invalid_param`, `permission_denied`, etc.) генерируют сообщения на русском

**Рекомендация (из LobeHub):** при добавлении новых сообщений об ошибках, всегда пиши русскую версию. Английскую можно добавить через feature-флаг `cfg(feature = "i18n")`.

---

## 10. Тестирование

### LobeHub

```bash
# Запуск конкретного теста (НИКОГДА `bun run test` — ~10 минут)
bunx vitest run --silent='passed-only' '[file-path]'

# Пакет базы данных
cd packages/database && bunx vitest run --silent='passed-only' '[file]'
```

- Предпочитать `vi.spyOn` вместо `vi.mock`
- E2E: Playwright + Cucumber (BDD)

### AETHER_01

```bash
# Проверка компиляции
cargo check

# Ручное тестирование через MCP-клиент
cargo run

# Линтинг
cargo clippy -- -D clippy::all -D clippy::pedantic
```

**Рекомендация (из LobeHub):** никогда не запускай `cargo test` глобально — тестируй конкретные модули:

```bash
cargo test tools::process
cargo test tools::filesystem
```

---

## 11. Код-ревью

### LobeHub: чек-лист ревью

Перед ревью PR'а читай файл `.agents/skills/review-checklist/SKILL.md` — там перечислены повторяющиеся ошибки, специфичные для кодовой базы.

### AETHER_01: чек-лист ревью

- [ ] `force: true` проверяется для опасных операций
- [ ] Feature gates проверяются для gated-операций
- [ ] Пути каноникализируются перед файловыми операциями
- [ ] Все Win32 API-вызовы имеют `.map_err(|e| AetherError::win32(ctx.clone(), ...))?`
- [ ] `ErrorContext` передаётся во все конструкторы ошибок
- [ ] Нет `use windows::core::*` (затеняет `std::result::Result`)
- [ ] Нет выводов в stdout (только stderr через `tracing`)
- [ ] `// SAFETY:` комментарий на каждом `unsafe` блоке
- [ ] Аудит-логирование добавлено для всех новых действий
- [ ] Никакого `cmd.exe` или `powershell.exe` для системных операций

---

## 12. UX и дизайн ошибок

### LobeHub: UX-ценности

> **Естественность (自然), осмысленность (意义感), определённость (确定性)**

При проектировании пользовательских потоков (пустые состояния, загрузка, ошибки, подтверждения, асинхронная обратная связь):

1. **Естественность** — интерфейс ведёт себя так, как пользователь ожидает
2. **Осмысленность** — каждое действие имеет понятную цель
3. **Определённость** — пользователь всегда знает, в каком состоянии система

### AETHER_01: UX ошибок (RFC 9457 + Elastic UI)

Трёхчастная структура ошибки (Elastic UI Framework):

```
══════════════════════════════════════════════════════
  Инструмент:  process_control
  Действие:    kill
  Цель:        notepad.exe (PID 1234)
  Тип ошибки:  Доступ запрещён
══════════════════════════════════════════════════════

Проблема:                               ← Естественность
  Система отклонила операцию «kill».

Причина:                                ← Осмысленность
  Процесс защищён на уровне ядра или требует
  прав администратора.

Система сообщает:
  Отказано в доступе. (0x80070005)

Рекомендация:                           ← Определённость
  1. Передайте параметр "force": true в запросе
  2. Запустите среду от имени Администратора

Пример корректного вызова:
  {"action":"kill","params":{"pid":1234,"force":true}}
```

---

## 13. Процесс релиза

### LobeHub

- PR-заголовки с `🚀 release: v{x.y.z}` запускают релиз автоматически
- `semantic-release` управляет версионированием
- CI/CD: GitHub Actions → Vercel/Docker

### AETHER_01

- Ручной процесс: `git tag -a v1.0.0 -m "..." && git push origin v1.0.0`
- `gh release create v1.0.0 --title "..." --notes-file release_notes.md`
- Бинарник: `cargo build --release`
- Все инструменты командной строки: `gh`, `git`, `cargo`

---

## Сводка: что AETHER_01 уже реализовал по стандартам LobeHub

| Стандарт | Статус |
|----------|--------|
| Roots vs. Features (`server.rs` тонкий, `tools/` по доменам) | Реализован |
| AGENTS.md с полным стеком и инструкциями | Реализован |
| Skills для AI-ассистентов (`.agents/skills/`, `.cursor/rules/`, `CLAUDE.md`) | Реализован |
| PR Template (`.github/PULL_REQUEST_TEMPLATE.md`) | Реализован |
| SECURITY.md с threat model и CVE-анализом | Реализован |
| Формальный стиль ошибок (RFC 9457 + Elastic UI) | Реализован |
| Чек-лист код-ревью | Определён (см. раздел 11) |
| Git-воркфлоу (conventional commits, feature branches) | Реализован |

## Что ещё можно улучшить

| Улучшение | Приоритет |
|-----------|-----------|
| Разделить большие файлы (>800 строк) на субмодули | Средний |
| Добавить `.agents/skills/review-checklist/SKILL.md` с чек-листом ревью | Высокий |
| Добавить `.agents/skills/testing/SKILL.md` с инструкциями по тестированию | Средний |
| Автоматизировать релизы через GitHub Actions | Низкий |
| Добавить английскую локализацию ошибок через feature-флаг `i18n` | Низкий |
