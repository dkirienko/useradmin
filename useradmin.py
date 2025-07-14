#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UserAdmin - Приложение для управления пользователями в системе Роса Linux
Поддерживает работу с LDAP, Kerberos, NFS и квотами
"""

import os
import sys
import subprocess
import configparser
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Optional
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
import shutil
import pwd
import grp
import getpass
import base64


class UserAdmin:
    def __init__(self, config_file: Optional[str] = None):
        """Инициализация приложения с загрузкой конфигурации"""
        if config_file is None:
            # Ищем конфиг в домашнем каталоге пользователя, затем в текущей директории
            home_config = os.path.expanduser("~/.useradmin.conf")
            current_config = "useradmin.conf"
            
            if os.path.exists(home_config):
                config_file = home_config
            elif os.path.exists(current_config):
                config_file = current_config
            else:
                # Если ни один файл не найден, создаем в домашнем каталоге
                config_file = home_config
        
        self.config = self._load_config(config_file)
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Загрузка конфигурационного файла"""
        config = configparser.ConfigParser()
        
        if not os.path.exists(config_file):
            self._create_default_config(config_file)
            
        config.read(config_file)
        return config
    
    def _create_default_config(self, config_file: str):
        """Создание конфигурационного файла по умолчанию"""
        config = configparser.ConfigParser()
        
        config['LDAP'] = {
            'server': 'ldap://localhost:389',
            'bind_dn': 'cn=admin,dc=sch179,dc=local',
            'bind_password': '',
            'base_dn': 'dc=sch179,dc=local',
            'user_ou': 'ou=people',
            'group_ou': 'ou=groups'
        }
        
        config['KERBEROS'] = {
            'realm': 'SCH179.LOCAL',
            'kadmin_principal': 'admin/admin@SCH179.LOCAL',
            'kadmin_password': '',
            'check_method': 'kadmin'
        }
        
        config['NFS'] = {
            'home_base': '/home',
            'skel_dir': '/etc/skel',
            'home_permissions': '750' # Добавляем настройку прав
        }
        
        config['QUOTAS'] = {
            'default_soft_limit': '100M',
            'default_hard_limit': '200M',
            'default_inode_soft_limit': '1000',
            'default_inode_hard_limit': '2000',
            'quota_type': 'user'  # user или group
        }
        
        config['LOGGING'] = {
            'level': 'INFO',
            'file': './useradmin.log'
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            config.write(f)
            
        print(f"Создан конфигурационный файл {config_file}")
        print("Пожалуйста, отредактируйте его перед использованием")
        sys.exit(1)
    
    def _setup_logging(self):
        """Настройка логирования"""
        log_level = getattr(logging, self.config.get('LOGGING', 'level', fallback='INFO'))
        log_file = self.config.get('LOGGING', 'file', fallback='./useradmin.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def _get_ldap_connection(self) -> Connection:
        """Создание подключения к LDAP"""
        server = Server(self.config.get('LDAP', 'server'), get_info=ALL)
        
        # Запрашиваем пароль если не указан в конфиге
        bind_password = self.config.get('LDAP', 'bind_password')
        if not bind_password:
            bind_password = getpass.getpass("Введите пароль для LDAP: ")
        
        conn = Connection(
            server,
            user=self.config.get('LDAP', 'bind_dn'),
            password=bind_password,
            auto_bind=True
        )
        
        if not conn.bound:
            raise Exception("Не удалось подключиться к LDAP")
            
        return conn
    
    def _get_kadmin_password(self) -> str:
        """Получение пароля для kadmin"""
        password = self.config.get('KERBEROS', 'kadmin_password')
        if not password:
            password = getpass.getpass("Введите пароль для kadmin: ")
        return password
    

    
    def add_user_to_ldap(self, uid: int, username: str, surname: str, firstname: str, 
                         groups: List[str]) -> bool:
        """Добавление пользователя в LDAP"""
        try:
            conn = self._get_ldap_connection()
            
            # Создаем DN для пользователя
            user_dn = f"uid={username},{self.config.get('LDAP', 'user_ou')},{self.config.get('LDAP', 'base_dn')}"
            
            # Проверяем, существует ли пользователь
            if conn.search(user_dn, '(objectClass=*)', search_scope=ldap3.BASE):
                self.logger.warning(f"Пользователь {username} уже существует в LDAP")
                return False
            
            # Создаем primary group для пользователя
            primary_group = username
            group_dn = f"cn={primary_group},{self.config.get('LDAP', 'group_ou')},{self.config.get('LDAP', 'base_dn')}"
            
            # Создаем группу если не существует
            if not conn.search(group_dn, '(objectClass=*)', search_scope=ldap3.BASE):
                group_attrs = {
                    'objectClass': ['top', 'posixGroup'],
                    'cn': primary_group,
                    'gidNumber': str(uid),
                    'memberUid': username,
                    'description': f'Primary group for user {username}'
                }
                conn.add(group_dn, attributes=group_attrs)
                self.logger.info(f"Создана группа {primary_group}")
            
            # Создаем пользователя
            full_name = f"{firstname} {surname}"
            user_attrs = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount', 'shadowAccount'],
                'uid': username,
                'uidNumber': str(uid),
                'gidNumber': str(uid),
                'cn': full_name,
                'sn': surname,
                'givenName': firstname,
                'homeDirectory': f"{self.config.get('NFS', 'home_base')}/{username}",
                'loginShell': '/bin/bash',
                'description': f'User {username} ({full_name})'
            }
            
            conn.add(user_dn, attributes=user_attrs)
            self.logger.info(f"Пользователь {username} добавлен в LDAP")
            
            # Добавляем пользователя в дополнительные группы
            for group_name in groups:
                if group_name != primary_group:
                    group_dn = f"cn={group_name},{self.config.get('LDAP', 'group_ou')},{self.config.get('LDAP', 'base_dn')}"
                    if conn.search(group_dn, '(objectClass=*)', search_scope=ldap3.BASE):
                        conn.modify(group_dn, {'memberUid': [(ldap3.MODIFY_ADD, [username])]})
                        self.logger.info(f"Пользователь {username} добавлен в группу {group_name}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка при добавлении пользователя в LDAP: {e}")
            return False
    
    def add_user_to_kerberos(self, username: str, password: str) -> bool:
        """Добавление пользователя в Kerberos"""
        try:
            kadmin_password = self._get_kadmin_password()
            realm = self.config.get('KERBEROS', 'realm')
            principal = f"{username}@{realm}"
            
            # Команда для добавления пользователя в Kerberos
            cmd = [
                'kadmin', '-p', self.config.get('KERBEROS', 'kadmin_principal'),
                '-w', kadmin_password,
                '-q', f'addprinc -pw "{password}" {principal}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Пользователь {username} добавлен в Kerberos")
                return True
            else:
                self.logger.error(f"Ошибка при добавлении в Kerberos: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Ошибка при добавлении пользователя в Kerberos: {e}")
            return False
    
    def create_home_directory(self, username: str) -> bool:
        """Создание домашнего каталога пользователя"""
        try:
            home_base = self.config.get('NFS', 'home_base')
            skel_dir = self.config.get('NFS', 'skel_dir')
            home_dir = Path(home_base) / username
            # Получаем права из конфига (по умолчанию 750)
            permissions_str = self.config.get('NFS', 'home_permissions', fallback='750')
            permissions = int(permissions_str, 8)
            # Создаем домашний каталог
            home_dir.mkdir(parents=True, exist_ok=True)
            # Устанавливаем права доступа
            os.chmod(home_dir, permissions)
            
            # Копируем файлы из /etc/skel
            if os.path.exists(skel_dir):
                for item in os.listdir(skel_dir):
                    src = os.path.join(skel_dir, item)
                    dst = os.path.join(home_dir, item)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
            
            # Устанавливаем правильные права доступа
            try:
                uid = pwd.getpwnam(username).pw_uid
                gid = pwd.getpwnam(username).pw_gid
                
                os.chown(home_dir, uid, gid)
                for root, dirs, files in os.walk(home_dir):
                    os.chown(root, uid, gid)
                    for file in files:
                        os.chown(os.path.join(root, file), uid, gid)
            except KeyError:
                # Пользователь еще не существует в системе, используем UID из LDAP
                self.logger.warning(f"Пользователь {username} не найден в системе, пропускаем установку прав")
            
            self.logger.info(f"Создан домашний каталог для {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании домашнего каталога: {e}")
            return False
    
    def set_user_quota(self, username: str) -> bool:
        """Установка дисковой квоты для пользователя"""
        try:
            home_base = self.config.get('NFS', 'home_base')
            # Автоматически определяем тип файловой системы, если не указан в конфиге
            config_fs_type = self.config.get('QUOTAS', 'filesystem_type', fallback=None)
            if config_fs_type:
                filesystem_type = config_fs_type
            else:
                filesystem_type = self.get_filesystem_type(home_base)
            
            # Получаем лимиты квот
            soft_limit = self.config.get('QUOTAS', 'default_soft_limit')
            hard_limit = self.config.get('QUOTAS', 'default_hard_limit')
            inode_soft_limit = self.config.get('QUOTAS', 'default_inode_soft_limit')
            inode_hard_limit = self.config.get('QUOTAS', 'default_inode_hard_limit')
            
            if filesystem_type.lower() == 'xfs':
                # Для XFS используем xfs_quota
                cmd = [
                    'xfs_quota', '-x', '-c',
                    f'limit bsoft={soft_limit} bhard={hard_limit} isoft={inode_soft_limit} ihard={inode_hard_limit} {username}',
                    home_base
                ]
            else:
                # Для ext4 и других используем setquota
                cmd = [
                    'setquota', '-u', username,
                    soft_limit, hard_limit, inode_soft_limit, inode_hard_limit,
                    home_base
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Установлена квота для пользователя {username} на {filesystem_type}")
                return True
            else:
                self.logger.error(f"Ошибка при установке квоты: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Ошибка при установке квоты: {e}")
            return False
    
    def add_user(self, uid: int, groups: str, username: str, surname: str, 
                 firstname: str, password: str, steps: Optional[List[str]] = None) -> bool:
        """Добавление пользователя в систему"""
        if steps is None:
            steps = ['ldap', 'kerberos', 'home', 'quota']
        
        self.logger.info(f"Начинаем добавление пользователя {username}")
        
        # Парсим группы
        group_list = [g.strip() for g in groups.split(',')]
        
        results = {}
        
        # 1. Добавляем в LDAP
        if 'ldap' in steps:
            results['ldap'] = self.add_user_to_ldap(uid, username, surname, firstname, group_list)
            if not results['ldap']:
                self.logger.error("Не удалось добавить пользователя в LDAP")
        
        # 2. Добавляем в Kerberos
        if 'kerberos' in steps:
            results['kerberos'] = self.add_user_to_kerberos(username, password)
            if not results['kerberos']:
                self.logger.error("Не удалось добавить пользователя в Kerberos")
        
        # 3. Создаем домашний каталог
        if 'home' in steps:
            results['home'] = self.create_home_directory(username)
            if not results['home']:
                self.logger.error("Не удалось создать домашний каталог")
        
        # 4. Устанавливаем квоту
        if 'quota' in steps:
            results['quota'] = self.set_user_quota(username)
            if not results['quota']:
                self.logger.error("Не удалось установить квоту")
        
        # Проверяем результаты
        failed_steps = [step for step, success in results.items() if not success]
        if failed_steps:
            self.logger.error(f"Ошибки в шагах: {', '.join(failed_steps)}")
            return False
        
        self.logger.info(f"Пользователь {username} успешно добавлен в систему")
        return True
    
    def process_user_file(self, filename: str, steps: Optional[List[str]] = None) -> Dict[str, bool]:
        """Обработка файла с пользователями"""
        results = {}
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        parts = line.split()
                        if len(parts) != 6:
                            self.logger.warning(f"Строка {line_num}: неверный формат")
                            continue
                        
                        uid, groups, username, surname, firstname, password = parts
                        
                        success = self.add_user(
                            int(uid), groups, username, surname, firstname, password, steps
                        )
                        results[username] = success
                        
                    except ValueError as e:
                        self.logger.error(f"Строка {line_num}: ошибка парсинга - {e}")
                        continue
                        
        except FileNotFoundError:
            self.logger.error(f"Файл {filename} не найден")
        except Exception as e:
            self.logger.error(f"Ошибка при обработке файла: {e}")
        
        return results
    
    def check_kerberos_principal(self, username: str) -> bool:
        """Проверка существования билета Kerberos для пользователя"""
        try:
            realm = self.config.get('KERBEROS', 'realm')
            principal = f"{username}@{realm}"
            check_method = self.config.get('KERBEROS', 'check_method', fallback='kadmin')

            if check_method == 'kadmin.local' and os.geteuid() == 0:
                cmd = [
                    'kadmin.local', '-q', f'getprinc {principal}'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    self.logger.debug(f"kadmin.local для {principal} вернул код {result.returncode}")
                    self.logger.debug(f"stderr: {result.stderr}")
                return result.returncode == 0 and f'Principal: {principal}' in result.stdout
            else:
                kadmin_principal = self.config.get('KERBEROS', 'kadmin_principal')
                kadmin_password = self._get_kadmin_password()
                cmd = [
                    'kadmin',
                    '-p', kadmin_principal,
                    '-w', kadmin_password,
                    '-q', f'getprinc {principal}'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    self.logger.debug(f"kadmin для {principal} вернул код {result.returncode}")
                    self.logger.debug(f"stderr: {result.stderr}")
                return result.returncode == 0 and f'Principal: {principal}' in result.stdout
        except Exception as e:
            self.logger.debug(f"Ошибка при проверке Kerberos для {username}: {e}")
            return False
    
    def check_home_directory(self, username: str) -> bool:
        """Проверка существования домашнего каталога"""
        try:
            home_base = self.config.get('NFS', 'home_base')
            home_dir = Path(home_base) / username
            return home_dir.exists() and home_dir.is_dir()
        except Exception as e:
            self.logger.debug(f"Ошибка при проверке домашнего каталога для {username}: {e}")
            return False
    
    def get_filesystem_type(self, path: str) -> str:
        """Автоматическое определение типа файловой системы"""
        try:
            # Получаем информацию о файловой системе
            result = subprocess.run(['df', '-T', path], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:  # Пропускаем заголовок
                    parts = lines[1].split()
                    if len(parts) >= 2:
                        fs_type = parts[1].lower()
                        # Поддерживаемые типы
                        if fs_type in ['xfs', 'ext4', 'ext3', 'ext2']:
                            self.logger.debug(f"Определен тип файловой системы: {fs_type} для пути {path}")
                            return fs_type
                        else:
                            self.logger.debug(f"Неподдерживаемый тип файловой системы: {fs_type}")
        except Exception as e:
            self.logger.debug(f"Ошибка при определении типа файловой системы: {e}")
        
        # Возвращаем значение по умолчанию
        self.logger.debug(f"Используется тип файловой системы по умолчанию: ext4")
        return 'ext4'

    def get_all_quotas(self) -> Dict[str, Dict]:
        """Получить квоты для всех пользователей за один вызов xfs_quota"""
        quotas = {}
        try:
            home_base = self.config.get('NFS', 'home_base')
            config_fs_type = self.config.get('QUOTAS', 'filesystem_type', fallback=None)
            if config_fs_type:
                filesystem_type = config_fs_type
            else:
                filesystem_type = self.get_filesystem_type(home_base)
            
            if filesystem_type.lower() == 'xfs':
                # Получаем квоты по блокам для всех пользователей
                cmd_blocks = ['xfs_quota', '-x', '-c', 'report -h', home_base]
                result_blocks = subprocess.run(cmd_blocks, capture_output=True, text=True)
                
                # Получаем квоты по inodes для всех пользователей
                cmd_inodes = ['xfs_quota', '-x', '-c', 'report -h -i', home_base]
                result_inodes = subprocess.run(cmd_inodes, capture_output=True, text=True)
                
                # Парсим блоки
                if result_blocks.returncode == 0:
                    lines = result_blocks.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5 and parts[0] not in ['User', 'User ID', '----------', 'root']:
                            username = parts[0]
                            if username not in quotas:
                                quotas[username] = {}
                            quotas[username]['blocks'] = f"{parts[1]}/{parts[2]}/{parts[3]}"
                
                # Парсим inodes
                if result_inodes.returncode == 0:
                    lines = result_inodes.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5 and parts[0] not in ['User', 'User ID', '----------', 'root']:
                            username = parts[0]
                            if username not in quotas:
                                quotas[username] = {}
                            quotas[username]['inodes'] = f"{parts[1]}/{parts[2]}/{parts[3]}"
                
                # Формируем итоговые строки
                for username in quotas:
                    blocks_info = quotas[username].get('blocks', '-')
                    inodes_info = quotas[username].get('inodes', '-')
                    quotas[username]['quota_str'] = f"blocks: {blocks_info}; inodes: {inodes_info}"
            else:
                # Для ext4 и других файловых систем
                cmd = ['quota', '-a']
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 6 and parts[0] not in ['Filesystem', 'root']:
                            username = parts[0]
                            quotas[username] = {
                                'quota_str': f"blocks: {parts[1]}/{parts[2]}; inodes: {parts[4]}/{parts[5]}"
                            }
        except Exception as e:
            self.logger.debug(f"Ошибка при получении квот: {e}")
        
        return quotas

    def get_user_quota(self, username: str) -> Optional[str]:
        """Получение информации о квоте пользователя (для обратной совместимости)"""
        try:
            home_base = self.config.get('NFS', 'home_base')
            config_fs_type = self.config.get('QUOTAS', 'filesystem_type', fallback=None)
            if config_fs_type:
                filesystem_type = config_fs_type
            else:
                filesystem_type = self.get_filesystem_type(home_base)
            if filesystem_type.lower() == 'xfs':
                # Получаем квоту по блокам для всех пользователей
                cmd_blocks = ['xfs_quota', '-x', '-c', 'report -h', home_base]
                result_blocks = subprocess.run(cmd_blocks, capture_output=True, text=True)
                self.logger.debug(f"xfs_quota blocks stdout for {username}:\n{result_blocks.stdout}")
                blocks_info = None
                if result_blocks.returncode == 0:
                    lines = result_blocks.stdout.strip().split('\n')
                    for line in lines:
                        self.logger.debug(f"blocks line: {line}")
                        if line.strip().startswith(username):
                            parts = line.split()
                            self.logger.debug(f"blocks parts: {parts}")
                            if len(parts) >= 5:
                                blocks_info = f"{parts[1]}/{parts[2]}/{parts[3]}"
                # Получаем квоту по inodes для всех пользователей
                cmd_inodes = ['xfs_quota', '-x', '-c', 'report -h -i', home_base]
                result_inodes = subprocess.run(cmd_inodes, capture_output=True, text=True)
                self.logger.debug(f"xfs_quota inodes stdout for {username}:\n{result_inodes.stdout}")
                inodes_info = None
                if result_inodes.returncode == 0:
                    lines = result_inodes.stdout.strip().split('\n')
                    for line in lines:
                        self.logger.debug(f"inodes line: {line}")
                        if line.strip().startswith(username):
                            parts = line.split()
                            self.logger.debug(f"inodes parts: {parts}")
                            if len(parts) >= 5:
                                inodes_info = f"{parts[1]}/{parts[2]}/{parts[3]}"
                result_str = None
                if blocks_info or inodes_info:
                    result_str = f"blocks: {blocks_info if blocks_info else '-'}; inodes: {inodes_info if inodes_info else '-'}"
                else:
                    result_str = "Не установлена"
                self.logger.debug(f"get_user_quota result for {username}: {result_str}")
                return result_str
            else:
                # Для ext4 и других используем quota
                cmd = ['quota', '-u', username]
                result = subprocess.run(cmd, capture_output=True, text=True)
                self.logger.debug(f"quota stdout for {username}:\n{result.stdout}")
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) >= 3:
                        quota_line = lines[2]
                        self.logger.debug(f"quota line: {quota_line}")
                        parts = quota_line.split()
                        self.logger.debug(f"quota parts: {parts}")
                        if len(parts) >= 6:
                            block_usage = f"{parts[1]}/{parts[2]}"
                            inode_usage = f"{parts[4]}/{parts[5]}"
                            result_str = f"blocks: {block_usage}; inodes: {inode_usage}"
                            self.logger.debug(f"get_user_quota result for {username}: {result_str}")
                            return result_str
                        elif len(parts) >= 4:
                            result_str = f"blocks: {parts[1]}/{parts[2]}"
                            self.logger.debug(f"get_user_quota result for {username}: {result_str}")
                            return result_str
                self.logger.debug(f"get_user_quota result for {username}: Не установлена")
                return "Не установлена"
        except Exception as e:
            self.logger.debug(f"Ошибка при получении квоты для {username}: {e}")
            return "Ошибка"
    
    def list_users(self, detailed: bool = False) -> List[Dict]:
        """Список пользователей в LDAP"""
        try:
            conn = self._get_ldap_connection()
            base_dn = f"{self.config.get('LDAP', 'user_ou')},{self.config.get('LDAP', 'base_dn')}"
            
            self.logger.info(f"Поиск пользователей в: {base_dn}")
            
            conn.search(
                base_dn,
                '(objectClass=posixAccount)',
                attributes=['uid', 'uidNumber', 'cn', 'homeDirectory']
            )
            
            self.logger.info(f"Найдено записей: {len(conn.entries)}")
            
            # Получаем квоты для всех пользователей за один вызов
            all_quotas = {}
            if detailed:
                all_quotas = self.get_all_quotas()
            
            users = []
            for entry in conn.entries:
                user_info = {
                    'uid': entry.uid.value,
                    'uidNumber': entry.uidNumber.value,
                    'cn': entry.cn.value,
                    'homeDirectory': entry.homeDirectory.value
                }
                
                if detailed:
                    user_info['kerberos'] = self.check_kerberos_principal(entry.uid.value)
                    user_info['home_dir'] = self.check_home_directory(entry.uid.value)
                    # Используем кэшированные квоты
                    user_info['quota'] = all_quotas.get(entry.uid.value, {}).get('quota_str', 'Не установлена')
                
                users.append(user_info)
            
            return users
            
        except Exception as e:
            self.logger.error(f"Ошибка при получении списка пользователей: {e}")
            return []
    
    def delete_user(self, username: str) -> bool:
        """Удаление пользователя из системы"""
        self.logger.info(f"Начинаем удаление пользователя {username}")
        
        try:
            conn = self._get_ldap_connection()
            
            # Удаляем из LDAP
            user_dn = f"uid={username},{self.config.get('LDAP', 'user_ou')},{self.config.get('LDAP', 'base_dn')}"
            if conn.search(user_dn, '(objectClass=*)', search_scope=ldap3.BASE):
                conn.delete(user_dn)
                self.logger.info(f"Пользователь {username} удален из LDAP")
            
            # Удаляем группу пользователя
            group_dn = f"cn={username},{self.config.get('LDAP', 'group_ou')},{self.config.get('LDAP', 'base_dn')}"
            if conn.search(group_dn, '(objectClass=*)', search_scope=ldap3.BASE):
                conn.delete(group_dn)
                self.logger.info(f"Группа {username} удалена из LDAP")
            
            # Удаляем из Kerberos
            kadmin_password = self._get_kadmin_password()
            realm = self.config.get('KERBEROS', 'realm')
            principal = f"{username}@{realm}"
            
            cmd = [
                'kadmin', '-p', self.config.get('KERBEROS', 'kadmin_principal'),
                '-w', kadmin_password,
                '-q', f'delprinc {principal}'
            ]
            
            subprocess.run(cmd, capture_output=True, text=True)
            self.logger.info(f"Пользователь {username} удален из Kerberos")
            
            # Удаляем домашний каталог
            home_dir = Path(self.config.get('NFS', 'home_base')) / username
            if home_dir.exists():
                shutil.rmtree(home_dir)
                self.logger.info(f"Домашний каталог {username} удален")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка при удалении пользователя: {e}")
            return False


def main():
    """Основная функция приложения"""
    parser = argparse.ArgumentParser(
        description='UserAdmin - Управление пользователями в системе Роса Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  useradmin.py add-file users.txt --all                    # Выполнить все шаги
  useradmin.py add-file users.txt --ldap --kerberos        # Только LDAP и Kerberos
  useradmin.py add-file users.txt --steps ldap home        # Только LDAP и домашний каталог
  useradmin.py add-user 1001 students user1 "Иванов" "Иван" "password123" --all
  useradmin.py add-user 1001 students user1 "Иванов" "Иван" "password123" --ldap --home
  useradmin.py list-users                                  # Список пользователей
  useradmin.py list-users --detailed                      # Детальная информация
  useradmin.py delete-user user1                           # Удалить пользователя

Ключи для add-file и add-user:
  --all         Выполнить все шаги (LDAP, Kerberos, домашний каталог, квота)
  --ldap        Только добавить в LDAP
  --kerberos    Только создать билет в Kerberos
  --home        Только создать домашний каталог
  --quota       Только задать квоту
  --steps ...   Выполнить только указанные шаги (можно несколько: ldap, kerberos, home, quota)

Ключи для list-users:
  --detailed    Показать Kerberos, домашний каталог, квоты

Конфигурационный файл:
  По умолчанию ищется в ~/.useradmin.conf, затем в ./useradmin.conf.
  Если не найден — будет создан ~/.useradmin.conf автоматически.
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')
    
    # Общие параметры для команд добавления
    def add_step_arguments(subparser):
        step_group = subparser.add_mutually_exclusive_group()
        step_group.add_argument('--all', action='store_true', 
                               help='Выполнить все шаги (LDAP, Kerberos, домашний каталог, квота)')
        step_group.add_argument('--ldap', action='store_true', 
                               help='Добавить пользователя в LDAP')
        step_group.add_argument('--kerberos', action='store_true', 
                               help='Создать билет в Kerberos')
        step_group.add_argument('--home', action='store_true', 
                               help='Создать домашний каталог')
        step_group.add_argument('--quota', action='store_true', 
                               help='Задать квоту')
        subparser.add_argument('--steps', nargs='+', 
                              choices=['ldap', 'kerberos', 'home', 'quota'],
                              help='Выполнить указанные шаги (можно указать несколько)')
    
    # Команда добавления из файла
    add_file_parser = subparsers.add_parser('add-file', help='Добавить пользователей из файла')
    add_file_parser.add_argument('filename', help='Путь к файлу с пользователями')
    add_step_arguments(add_file_parser)
    
    # Команда добавления одного пользователя
    add_user_parser = subparsers.add_parser('add-user', help='Добавить одного пользователя')
    add_user_parser.add_argument('uid', type=int, help='UID пользователя')
    add_user_parser.add_argument('groups', help='Группы (через запятую)')
    add_user_parser.add_argument('username', help='Имя пользователя')
    add_user_parser.add_argument('surname', help='Фамилия')
    add_user_parser.add_argument('firstname', help='Имя')
    add_user_parser.add_argument('password', help='Пароль')
    add_step_arguments(add_user_parser)
    
    # Команда списка пользователей
    list_parser = subparsers.add_parser('list-users', help='Список пользователей')
    list_parser.add_argument('--detailed', action='store_true', 
                            help='Показать детальную информацию (Kerberos, домашний каталог, квоты)')
    
    # Команда удаления пользователя
    delete_parser = subparsers.add_parser('delete-user', help='Удалить пользователя')
    delete_parser.add_argument('username', help='Имя пользователя для удаления')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Проверяем права root только для команд, которые их требуют
    if args.command in ['delete-user'] and os.geteuid() != 0:
        print("Ошибка: приложение должно запускаться с правами root для этой команды")
        sys.exit(1)
    
    try:
        admin = UserAdmin()
        
        # Определяем шаги для выполнения
        def get_steps(args):
            if args.all:
                return ['ldap', 'kerberos', 'home', 'quota']
            elif args.ldap:
                return ['ldap']
            elif args.kerberos:
                return ['kerberos']
            elif args.home:
                return ['home']
            elif args.quota:
                return ['quota']
            elif args.steps:
                return args.steps
            else:
                return ['ldap', 'kerberos', 'home', 'quota']  # По умолчанию все шаги
        
        if args.command == 'add-file':
            steps = get_steps(args)
            print(f"Выполняем шаги: {', '.join(steps)}")
            results = admin.process_user_file(args.filename, steps)
            print(f"\nРезультаты обработки файла {args.filename}:")
            for username, success in results.items():
                status = "УСПЕХ" if success else "ОШИБКА"
                print(f"  {username}: {status}")
        
        elif args.command == 'add-user':
            steps = get_steps(args)
            print(f"Выполняем шаги: {', '.join(steps)}")
            success = admin.add_user(
                args.uid, args.groups, args.username, 
                args.surname, args.firstname, args.password, steps
            )
            if success:
                print(f"Пользователь {args.username} успешно добавлен")
            else:
                print(f"Ошибка при добавлении пользователя {args.username}")
                sys.exit(1)
        
        elif args.command == 'list-users':
            users = admin.list_users(detailed=args.detailed)
            if users:
                if args.detailed:
                    print("Список пользователей (детальная информация):")
                    print(f"{'UID':<15} {'UID Number':<12} {'Имя':<25} {'Kerberos':<10} {'Домашний каталог':<12} {'Квота':<20}")
                    print("-" * 100)
                    for user in users:
                        kerberos_status = "✓" if user.get('kerberos', False) else "✗"
                        home_status = "✓" if user.get('home_dir', False) else "✗"
                        quota_info = user.get('quota', 'Ошибка')
                        print(f"{user.get('uid', ''):<15} {user.get('uidNumber', ''):<12} {user.get('cn', ''):<25} {kerberos_status:<10} {home_status:<12} {quota_info:<20}")
                else:
                    print("Список пользователей:")
                    print(f"{'UID':<15} {'UID Number':<12} {'Имя':<30} {'Домашний каталог'}")
                    print("-" * 80)
                    for user in users:
                        print(f"{user.get('uid', ''):<15} {user.get('uidNumber', ''):<12} {user.get('cn', ''):<30} {user.get('homeDirectory', '')}")
            else:
                print("Пользователи не найдены")
        
        elif args.command == 'delete-user':
            success = admin.delete_user(args.username)
            if success:
                print(f"Пользователь {args.username} успешно удален")
            else:
                print(f"Ошибка при удалении пользователя {args.username}")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nОперация прервана пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 