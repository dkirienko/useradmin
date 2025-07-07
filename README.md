# UserAdmin - Приложение для управления пользователями

Приложение для управления пользователями в системе Роса Linux с поддержкой LDAP, Kerberos, NFS и квот.

## Возможности

- Добавление пользователей в LDAP с созданием персональных групп (без паролей)
- Создание паролей только в Kerberos
- Создание домашних каталогов с копированием файлов из /etc/skel
- Установка дисковых квот для пользователей
- Удаление пользователей из системы
- Просмотр списка пользователей

## Требования

- Python 3.6+
- Роса Linux
- Настроенный LDAP сервер
- Настроенный Kerberos
- Права root для выполнения операций

## Установка зависимостей

```bash
# Установка Python модулей
pip3 install ldap3

# Или через пакетный менеджер
sudo dnf install python3-ldap3
```

## Требования к системе

Приложение использует модуль ldap3 для работы с LDAP и системные утилиты:

- `kadmin` - для работы с Kerberos  
- `setquota` - для установки квот (ext4)
- `xfs_quota` - для установки квот (XFS)
- `useradd`, `groupadd` - для создания пользователей в системе (опционально)

Убедитесь, что эти утилиты установлены в системе.

## Конфигурация

1. Отредактируйте файл `useradmin.conf`:

```ini
[LDAP]
server = ldap://localhost:389
bind_dn = cn=admin,dc=yourdomain,dc=com
bind_password = your_ldap_password
base_dn = dc=yourdomain,dc=com
user_ou = ou=users
group_ou = ou=groups

[KERBEROS]
realm = YOURDOMAIN.COM
kadmin_principal = admin/admin@YOURDOMAIN.COM
kadmin_password = your_kadmin_password

[NFS]
home_base = /home
skel_dir = /etc/skel

[QUOTAS]
default_soft_limit = 100M
default_hard_limit = 200M
default_inode_soft_limit = 1000
default_inode_hard_limit = 2000
quota_type = user
filesystem_type = xfs

[LOGGING]
level = INFO
file = /var/log/useradmin.log
```

## Использование

### Добавление пользователей из файла

Создайте файл с пользователями в формате:
```
UID Группы Логин Фамилия Имя Пароль
```

Пример файла `users.txt`:
```
24201 students s24v_avdeev Авдеев Дмитрий PassWord1
24202 students s24v_belenkii Беленький Владимир PassWord2
```

Запустите:
```bash
sudo python3 useradmin.py add-file users.txt
```

### Добавление одного пользователя

```bash
sudo python3 useradmin.py add-user 24201 "students" s24v_avdeev "Авдеев" "Дмитрий" "PassWord1"
```

### Просмотр списка пользователей

```bash
sudo python3 useradmin.py list-users
```

### Удаление пользователя

```bash
sudo python3 useradmin.py delete-user s24v_avdeev
```

## Структура LDAP

Приложение создает следующую структуру в LDAP:

### Пользователи (ou=users)
```
uid=username
uidNumber=1001
gidNumber=1001
cn=Фамилия Имя
sn=Фамилия
givenName=Имя
homeDirectory=/home/username
loginShell=/bin/bash
```
*Примечание: Пароли не хранятся в LDAP, только в Kerberos

### Группы (ou=groups)
```
cn=username (персональная группа)
gidNumber=1001
memberUid=username

cn=students (дополнительная группа)
memberUid=username
```

## Безопасность

- Приложение должно запускаться с правами root
- Пароли LDAP и Kerberos можно не указывать в конфиге - они будут запрошены интерактивно
- Все операции логируются в `/var/log/useradmin.log`

## Логирование

Логи записываются в файл, указанный в конфигурации. Уровень логирования можно изменить:
- DEBUG - подробная отладочная информация
- INFO - основная информация о операциях
- WARNING - предупреждения
- ERROR - ошибки

## Примеры использования

### Массовое добавление студентов

1. Создайте файл `students.txt`:
```
24201 students s24v_avdeev Авдеев Дмитрий PassWord1
24202 students s24v_belenkii Беленький Владимир PassWord2
24203 students s24v_biriukov Бирюков Иван PassWord3
```

2. Запустите:
```bash
sudo python3 useradmin.py add-file students.txt
```

### Проверка результатов

```bash
# Список пользователей
sudo python3 useradmin.py list-users

# Проверка квот
sudo repquota -a

# Проверка Kerberos
klist -kt /etc/krb5.keytab
```

## Поддержка файловых систем

### XFS
- Использует команду `xfs_quota` для управления квотами
- Поддерживает квоты на блоки и inode
- Требует включения квот командой `xfs_quota -x -c 'enable' /путь/к/разделу`

### ext4
- Использует команду `setquota` для управления квотами
- Поддерживает квоты на блоки и inode
- Требует опции `usrquota` в /etc/fstab

## Устранение неполадок

### Ошибка подключения к LDAP
- Проверьте настройки сервера и учетные данные в конфиге
- Убедитесь, что LDAP сервер запущен

### Ошибка Kerberos
- Проверьте realm и учетные данные kadmin
- Убедитесь, что Kerberos настроен правильно

### Ошибка квот
- Убедитесь, что файловая система поддерживает квоты
- Проверьте, что quota установлен в системе
- **Для XFS**: 
  - Включите квоты командой `xfs_quota -x -c 'enable' /home`
  - Убедитесь, что раздел смонтирован с опцией `usrquota` в /etc/fstab
- **Для ext4**: 
  - Добавьте опцию `usrquota` в /etc/fstab и перемонтируйте раздел
  - Включите квоты командой `quotaon -a`

### Ошибка прав доступа
- Приложение должно запускаться с правами root
- Проверьте права на домашние каталоги

## Поддержка

При возникновении проблем проверьте логи в `/var/log/useradmin.log` и убедитесь, что все сервисы (LDAP, Kerberos) работают корректно. 