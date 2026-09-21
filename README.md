# CLI-VPN-Client

`sbx` — консольный VPN-клиент для Linux поверх [sing-box](https://sing-box.sagernet.org).
Без графической оболочки: подписки, выбор сервера, проверка задержек, TUN или прокси,
автозапуск через systemd.

> ⚠️ **Полноценные тесты пока не проводились.**
> Проверялись только разбор реальной подписки и запуск в режиме `sbx probe`
> (TUN без перехвата трафика, рядом с другим работающим VPN). Полный TUN-режим
> (`sbx up`) с перехватом всего трафика системы, автозапуск и таймер обновления
> подписок в работе не проверены. Используйте на свой риск и держите под рукой
> способ откатиться (`sbx down`, `sbx disable`).

## Возможности

- **Подписки, а не только серверы.** Формат определяется сам:
  - sing-box JSON (полный конфиг или список outbound'ов);
  - Clash / mihomo YAML (секция `proxies`);
  - base64 или просто список URI: `vless`, `vmess`, `trojan`, `ss`, `hysteria2`/`hy2`, `tuic`, `socks`.
- Из подписки берутся только серверы. DNS, TUN и маршрутизацию sbx собирает сам:
  панели часто отдают конфиг в устаревшем формате, который свежий sing-box не принимает.
- **HWID для панелей вроде Remnawave.** Без него они вместо серверов отдают заглушки.
  sbx отправляет `x-hwid` = `sha256(/etc/machine-id)[:16]`, а также `x-device-os`,
  `x-ver-os` и `x-device-model`. Отключается флагом `--no-hwid`.
- Трафик и срок подписки берутся из заголовка `subscription-userinfo`.
- Группа `auto` (urltest) и ручной выбор сервера. Сервер переключается на лету через
  clash API, без перезапуска.
- `sbx test` — задержка до всех серверов. Если VPN не запущен, поднимается временный
  sing-box без TUN.
- Режимы: `tun` (весь трафик системы плюс mixed SOCKS5/HTTP на `127.0.0.1:2080`)
  или `proxy` (только mixed-прокси).
- Маршруты: `ru` (российские домены и IP напрямую, rule-set'ы geoip-ru и
  geosite-category-ru) или `global` (всё через VPN).
- Частные сети (LAN, 10.0.0.0/8, docker) в туннель не идут. Ответы локальных серверов
  по заданным портам (по умолчанию WireGuard `udp:51820` и `tcp:443`) уходят мимо TUN
  через `ip rule`, чтобы удалённый доступ к машине не отвалился.
- Автозапуск: `sbx.service` плюс `sbx-update.timer` (обновление подписок раз в 6 часов).

## Требования

- Linux с systemd;
- `sing-box` 1.12+ со сборочным тегом `with_gvisor` (на Arch — `pacman -S sing-box`);
- Python 3.9+, `python-yaml` (только для Clash-подписок);
- `sudo` — для установки юнитов и старта/остановки сервиса.

## Установка

```bash
git clone https://github.com/EGORIUMAS/CLI-VPN-Client
install -Dm755 CLI-VPN-Client/sbx.py ~/.local/bin/sbx
```

## Использование

```bash
sbx sub add myvpn 'https://sub.example/xyz'   # добавить подписку и скачать
sbx sub ls                                    # подписки: трафик, срок
sbx update                                    # обновить все подписки
sbx ls                                        # серверы (● выбран, › активный в auto)
sbx test                                      # задержки
sbx use 5 | sbx use германия | sbx use auto   # выбрать сервер
sbx probe [-a]                                # проверка без перехвата трафика
sbx up | down | restart | status | log -f
sbx ip                                        # внешний IP через VPN
sbx enable [--now] | disable                  # автозапуск
sbx mode tun|proxy
sbx route ru|global
sbx add 'vless://…'                           # сервер без подписки
sbx set [ключ [значение]]                     # настройки
```

### Проверка без риска: `sbx probe`

Поднимает временный sing-box с TUN-интерфейсом `sbx-probe`, но без `auto_route`:
ни маршрутов, ни `ip rule` он не добавляет. Через туннель идёт только тестовый `curl`,
привязанный к интерфейсу. Команда проверяет ядро, серверы подписки, mixed-прокси
и сам TUN, затем всё останавливает. Её можно запускать рядом с другим VPN-клиентом.

### Настройки (`sbx set`)

| Ключ | По умолчанию | |
|---|---|---|
| `mixed_port` | `2080` | SOCKS5/HTTP на 127.0.0.1 |
| `api_port` | `9097` | clash API на 127.0.0.1 |
| `exclude` | частные сети | что не пускать в TUN (через запятую, `default` — сброс) |
| `bypass_sports` | `udp:51820,tcp:443` | ответы с этих локальных портов идут мимо TUN |
| `auto_exclude` | — | regex серверов, которые не попадут в `auto` |
| `dns_remote` | `https://1.1.1.1/dns-query` | DNS через VPN |
| `dns_direct` | `77.88.8.8` | DNS для прямых доменов и адресов серверов |
| `ua` | `SFA/1.13 (sbx; sing-box)` | User-Agent: от него зависит формат ответа панели |

## Где что лежит

- `~/.config/sbx/`: `state.json`, `subs/`, `rulesets/`, `config.json` (права 600, внутри ключи);
- `~/.local/state/sbx/`: рабочий каталог sing-box;
- `/etc/systemd/system/sbx.service`, `sbx-update.{service,timer}`.

Сервис работает от имени пользователя с `CAP_NET_ADMIN`/`CAP_NET_RAW`, а не от root.

## Известные особенности

- TUN-стек — **gvisor**. Стек `system`/`mixed` принимает TCP через input-цепочку ядра
  с TUN-интерфейса, и фаервол с `policy drop` на input (nftables/iptables) такие пакеты
  отбрасывает: TCP молча не работает.
- Не запускайте `sbx up` одновременно с другим VPN-клиентом в TUN-режиме: маршруты
  конфликтуют. `sbx up` проверяет это и отказывается стартовать без `--force`.
- Транспорты xhttp/splithttp/kcp sing-box не поддерживает, такие серверы пропускаются
  с предупреждением.
