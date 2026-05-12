=== Доступ ===
ssh root@62.238.28.107
sudo -u morok -i              # перейти на morok користувача

=== Робоча папка ===
cd /home/morok/morok-relay
source .venv/bin/activate     # активувати venv

=== Сервіси ===
systemctl status morok-relay         # стан
systemctl restart morok-relay        # перезапуск після оновлення коду
journalctl -u morok-relay -f         # дивитись логи у реальному часі
journalctl -u morok-relay -n 100     # останні 100 рядків

=== Оновлення коду ===
cd /home/morok/morok-relay
git pull
source .venv/bin/activate
pip install -r requirements.txt      # якщо змінились залежності
deactivate
systemctl restart morok-relay        # від root
systemctl status morok-relay

=== Перевірка ===
curl https://relay1.morok.app/health

=== БД ===
PGPASSWORD="<пароль_з_.env>" psql -h localhost -U morok -d morok_relay

=== Redis ===
redis-cli                            # консоль
redis-cli ping                       # перевірка

=== nginx ===
nginx -t                             # перевірка конфігу
systemctl reload nginx               # м'який перезапуск
tail -f /var/log/nginx/morok-relay-access.log
tail -f /var/log/nginx/morok-relay-error.log

=== Сертифікат ===
certbot certificates                 # подивитись
# Автоматичне оновлення вже налаштоване через systemd timer
systemctl list-timers | grep certbot