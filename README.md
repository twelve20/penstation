# PENSTATION

**Autonomous Network Security Station for Raspberry Pi**

PENSTATION — автономная станция мониторинга и анализа уязвимостей локальной сети. Работает на Raspberry Pi 3B+, сканирует сеть 24/7, находит хосты, открытые порты, сервисы и уязвимости (CVE). Веб-интерфейс в стиле hacker terminal доступен из любой точки мира.

---

## Возможности

- Автоматическое обнаружение хостов в локальной сети (nmap)
- Сканирование портов с определением сервисов и ОС
- Поиск уязвимостей через Nuclei (9000+ шаблонов CVE)
- Обогащение CVE данными из NVD API
- Автообновление баз уязвимостей каждую ночь
- Real-time логи сканирования через WebSocket
- Алерты при обнаружении критических уязвимостей
- Сетевая карта (интерактивная топология)
- Risk Score (0-100) для каждого хоста
- Heatmap уязвимостей за 30 дней
- **WiFi менеджер** — переключение сетей прямо из веб-интерфейса
- Удалённый доступ через Tailscale

---

## Установка на Raspberry Pi

### Требования

- **Raspberry Pi 3B+** или новее (ARM)
- **Raspbian / Raspberry Pi OS** (Debian Bookworm)
- Подключение к сети (Ethernet или WiFi)
- SSH доступ к Pi

### Быстрая установка

```bash
# 1. Подключись к Pi по SSH
ssh pi@<IP_RASPBERRY_PI>

# 2. Клонируй репозиторий
git clone https://github.com/twelve20/penstation.git ~/penstation

# 3. Запусти установщик
cd ~/penstation
sudo bash install.sh
```

Установщик автоматически:
- Обновит систему
- Установит nmap, masscan, Nuclei, Python, Nginx, SQLite
- Скачает правильный ARM-бинарник Nuclei с GitHub
- Создаст Python venv и установит зависимости
- Инициализирует базу данных
- Настроит Nginx (reverse proxy порт 80 → 8080)
- Создаст systemd сервис с автозапуском
- Настроит logrotate
- Опционально установит Tailscale

### После установки

```bash
# Сервис уже запущен! Открой в браузере:
http://<IP_RASPBERRY_PI>

# Или напрямую:
http://<IP_RASPBERRY_PI>:8080
```

Первое сканирование начнётся автоматически в течение 60 секунд.

---

## WiFi

WiFi управляется через веб-интерфейс — кнопка **WiFi** в хедере дашборда.

- Сканирование доступных сетей
- Подключение/отключение одним кликом
- Отображение силы сигнала
- Управление сохранёнными сетями

Для первоначальной настройки подключи Pi по Ethernet, открой дашборд и настрой WiFi через интерфейс.

---

## Управление сервисом

```bash
# Запуск
sudo systemctl start penstation

# Остановка
sudo systemctl stop penstation

# Перезапуск
sudo systemctl restart penstation

# Логи (live)
journalctl -u penstation -f

# Статус
sudo systemctl status penstation
```

---

## Обновление

```bash
cd ~/penstation
git pull
sudo systemctl restart penstation
```

---

## Удалённый доступ (Tailscale)

Если при установке выбрал Tailscale:

```bash
sudo tailscale up
```

После авторизации Pi будет доступен по Tailscale IP из любой точки мира.

---

## Конфигурация

Файл `~/penstation/.env` — основные настройки:

```env
SUBNET=auto                 # "auto" или конкретная подсеть (192.168.1.0/24)
SCAN_INTERVAL_HOURS=1       # Интервал полного сканирования
NMAP_TIMING=T3              # T1(тихий) - T5(агрессивный)
NUCLEI_RATE_LIMIT=50        # Ограничение запросов nuclei
ALERT_ON_CRITICAL=true      # Алерты при критических уязвимостях
ALERT_ON_NEW_HOST=true      # Алерты при новых хостах в сети
```

---

## Архитектура

```
Backend:   Python 3.11+ / FastAPI / SQLAlchemy async / APScheduler
Scanner:   nmap + Nuclei
Database:  SQLite (aiosqlite)
Frontend:  Vanilla HTML/CSS/JS + WebSocket + Canvas
Proxy:     Nginx
Service:   systemd
```

---

## API

```
GET  /api/stats           — статистика
GET  /api/hosts           — список хостов
GET  /api/host/{ip}       — детали хоста
GET  /api/vulns           — все уязвимости
GET  /api/network/map     — данные сетевой карты
GET  /api/wifi/status     — статус WiFi
GET  /api/wifi/scan       — доступные сети
POST /api/wifi/connect    — подключиться к сети
POST /api/scan/trigger    — ручной запуск скана
WS   /ws/logs             — real-time логи
WS   /ws/alerts           — push-алерты
```

---

## Лицензия

Только для мониторинга **собственной домашней сети**. Используйте ответственно.
