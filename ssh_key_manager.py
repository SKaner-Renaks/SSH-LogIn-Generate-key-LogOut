import os
import stat
import datetime
import getpass
import paramiko
import sys
import ctypes
import json
import uuid
from paramiko.ssh_exception import AuthenticationException, SSHException

"""
Скрипт для автоматизированного управления SSH-ключами на нескольких серверах.
Использует JSON-конфигурацию и UUID для идентификации экземпляров ключей.
"""

# --- БЛОК ГЛОБАЛЬНЫХ КОНСТАНТ ---

# Таймаут подключения к SSH в секундах
SSH_TIMEOUT = 10

# Размер генерируемого RSA-ключа в битах по умолчанию (рекомендовано 3072)
KEY_SIZE = 3072

# ANSI Color Codes (Цветовые коды для вывода в консоль)
CLR_RESET = "\033[0m"
CLR_TIMESTAMP = "\033[1;97m"
CLR_OK = "\033[92m"
CLR_X = "\033[91m"
CLR_I = "\033[96m"
CLR_WARN = "\033[93m"
CLR_PROCESS = "\033[94m"
CLR_GRAY = "\033[90m"
CLR_CMD = "\033[1;92m"

# Соответствие префиксов логов их цветам
PREFIX_COLORS = {
    "[OK]": CLR_OK,
    "[X]": CLR_X,
    "[i]": CLR_I,
    "[!]": CLR_WARN,
    "[...]": CLR_PROCESS,
    ">>>": CLR_I,
    "---": CLR_GRAY,
    "***": CLR_WARN,
    "...": CLR_PROCESS,
    "===": CLR_TIMESTAMP,
    " ": CLR_GRAY
}

def enable_windows_ansi(use_colors):
    """
    Включает обработку ANSI-последовательностей в консоли Windows 10/11.
    """
    if not use_colors:
        return False

    if sys.platform != "win32":
        return use_colors

    try:
        kernel32 = ctypes.windll.kernel32
        stdout_handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode)):
            return False
        new_mode = mode.value | 0x0004
        if not kernel32.SetConsoleMode(stdout_handle, new_mode):
            return False
        return True
    except Exception:
        return False

# Определяем, нужно ли использовать цвета
USE_COLORS = sys.stdout.isatty()
USE_COLORS = enable_windows_ansi(USE_COLORS)

def log(prefix, message, msg_color=None):
    """
    Выводит форматированное сообщение в консоль с меткой времени.
    """
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if USE_COLORS:
        ts_str = f"{CLR_TIMESTAMP}[{timestamp}]{CLR_RESET}"
        pfx_color = PREFIX_COLORS.get(prefix, "")
        pfx_str = f"{pfx_color}{prefix}{CLR_RESET}"

        m_color = msg_color if msg_color else ""
        m_reset = CLR_RESET if msg_color else ""
        print(f"{ts_str} {pfx_str} {m_color}{message}{m_reset}")
    else:
        print(f"[{timestamp}] {prefix} {message}")

def execute_remote_command(ssh, command, description=None):
    """
    Выполняет команду на удаленном сервере и возвращает результат.
    """
    if description:
        log("[...]", description)

    if USE_COLORS:
        log("[...]", f"Выполнение команды: {CLR_CMD}{command}{CLR_RESET}")
    else:
        log("[...]", f"Выполнение команды: {command}")

    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    return exit_status, stdout, stderr

def connect_and_setup_ssh(host, username, password, local_key_dir, remote_home_dir, instance_id, server_name=None, key_size=KEY_SIZE):
    """
    Основной алгоритм настройки SSH доступа с использованием UUID.
    """
    log(">>>", f"Инициализация подключения к серверу {host}...")

    # Формируем имя для файлов и комментариев
    if server_name:
        clean_name = server_name
    else:
        clean_name = host.replace(".", "_")

    key_filename = f"id_rsa_{clean_name}"
    private_key_path = os.path.join(local_key_dir, key_filename)
    public_key_path = private_key_path + ".pub"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    key_exists = os.path.exists(private_key_path)
    session_established = False

    # 1. Попытка аутентификации по ключу
    if key_exists:
        log("[i]", f"Найден локальный ключ {CLR_CMD}{key_filename}{CLR_RESET}. Попытка аутентификации...")
        try:
            ssh.connect(host, username=username, key_filename=private_key_path, timeout=SSH_TIMEOUT)
            log("[OK]", "Аутентификация по ключу прошла успешно.")
            return ssh
        except AuthenticationException:
            log("[!]", "Аутентификация по ключу отклонена.")
        except (SSHException, Exception) as e:
            log("[X]", f"Ошибка сети или подключения: {e}")
            raise e
    else:
        log("[!]", "Локальный ключ не найден.")

    # 2. Аутентификация по паролю
    log("***", "Требуется парольная аутентификация ***")

    if password:
        log("[...]", "Попытка входа с паролем из конфигурации.")
        try:
            ssh.connect(host, username=username, password=password, timeout=SSH_TIMEOUT)
            session_established = True
        except AuthenticationException:
            log("[!]", "Пароль из конфигурации отклонен.")
        except (SSHException, Exception) as e:
            log("[X]", f"Ошибка сети или подключения: {e}")
            raise e

    if not session_established:
        log("[!]", "Требуется интерактивный ввод пароля.")
        log("[i]", f"Пользователь: {username}")
        password_input = getpass.getpass(f"Введите пароль для {username}@{host}: ")
        log("[...]", "Выполняется вход...")
        try:
            ssh.connect(host, username=username, password=password_input, timeout=SSH_TIMEOUT)
            session_established = True
        except AuthenticationException:
            log("[X]", "Ошибка: Неверный логин или пароль.")
            raise Exception("Authentication failed")
        except (SSHException, Exception) as e:
            log("[X]", f"Ошибка сети или подключения: {e}")
            raise e

    # 3. Генерация и сохранение ключей
    if key_exists:
        log("[!]", "Внимание: старый локальный ключ будет заменён новым.")

    log("[...]", f"Генерация новой пары RSA-ключей ({key_size} бит)...")
    new_key = paramiko.RSAKey.generate(key_size)
    log("[OK]", "Ключи сгенерированы.")

    if not os.path.exists(local_key_dir):
        log("[...]", f"Создание директории для ключей: {local_key_dir}")
        os.makedirs(local_key_dir, mode=0o700, exist_ok=True)

    new_key.write_private_key_file(private_key_path)
    os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR)

    # Формируем строку публичного ключа с UUID
    public_key_str = f"{new_key.get_name()} {new_key.get_base64()} {username}@{host}:{clean_name}:{instance_id}"
    with open(public_key_path, "w") as pub_file:
        pub_file.write(public_key_str)

    log("[OK]", f"Локальные ключи сохранены: {CLR_CMD}{key_filename}{CLR_RESET}")

    # 4. Развертывание ключа на сервере
    log("[...]", f"Развертывание публичного ключа на сервере {host}...")

    ssh_dir = f"{remote_home_dir}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"

    # Проверка .ssh
    exit_status, stdout, stderr = execute_remote_command(ssh, f"test -d {ssh_dir} && echo 'EXISTS' || echo 'NOT_EXISTS'")
    dir_check = stdout.read().decode().strip()

    if dir_check == "NOT_EXISTS":
        execute_remote_command(ssh, f"mkdir -p {ssh_dir}", f"Создание директории {ssh_dir}")
        execute_remote_command(ssh, f"chmod 700 {ssh_dir}")
    else:
        log("[i]", f"Директория {ssh_dir} уже существует.")

    # Проверка authorized_keys
    exit_status, stdout, stderr = execute_remote_command(ssh, f"test -f {auth_keys} && echo 'EXISTS' || echo 'NOT_EXISTS'")
    file_check = stdout.read().decode().strip()

    if file_check == "NOT_EXISTS":
        execute_remote_command(ssh, f"touch {auth_keys}", f"Создание файла {auth_keys}")
        execute_remote_command(ssh, f"chmod 600 {auth_keys}")
    else:
        log("[i]", f"Файл {auth_keys} уже существует.")

    # Очистка старых ключей по UUID и добавление нового
    log("[...]", "Анализ ключей в authorized_keys...")
    exit_status, stdout, stderr = execute_remote_command(ssh, f"cat {auth_keys}")

    existing_lines = stdout.read().decode().splitlines()
    search_pattern = f"{username}@{host}:{clean_name}:"

    new_lines = []
    old_keys_found = []
    current_key_present = False
    target_key_stripped = public_key_str.strip()

    for line in existing_lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue

        if search_pattern in stripped_line:
            if instance_id in stripped_line:
                if stripped_line == target_key_stripped:
                    # Точное совпадение — ключ уже на сервере
                    current_key_present = True
                    new_lines.append(stripped_line)
                else:
                    # UUID совпадает, но контент ключа другой — это старый ключ
                    old_keys_found.append(stripped_line)
            else:
                # UUID отличается — это старый ключ другого экземпляра/времени
                old_keys_found.append(stripped_line)
        else:
            # Чужой ключ, не имеющий нашего паттерна в комментарии
            new_lines.append(stripped_line)

    if old_keys_found:
        log("[!]", f"На сервере найдены старые ключи ({len(old_keys_found)}) для {clean_name}.")
        # Используем sys.stdout.write и sys.stdin.readline для интерактивности
        prompt = f"{CLR_WARN}[?] Удалить их? (y/n): {CLR_RESET}"
        if USE_COLORS:
            print(prompt, end="", flush=True)
        else:
            print(f"[?] Удалить их? (y/n): ", end="", flush=True)

        choice = sys.stdin.readline().strip().lower()
        if choice == 'y':
            log("[...]", "Старые ключи удалены из списка записи.")
        else:
            log("[i]", "Старые ключи оставлены в файле.")
            new_lines.extend(old_keys_found)

    if not current_key_present:
        new_lines.append(target_key_stripped)
        log("[...]", "Добавление актуального ключа в список.")
    else:
        log("[i]", "Актуальный ключ уже присутствует в списке.")

    # Бэкап перед записью
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    bak_file = f"{auth_keys}.bak.{timestamp}"
    execute_remote_command(ssh, f"cp {auth_keys} {bak_file}", f"Создание резервной копии: {bak_file}")

    # Полная перезапись через cat >
    log("[...]", "Запись обновленного файла authorized_keys...")
    full_content = "\n".join(new_lines) + "\n"
    stdin, stdout, stderr = ssh.exec_command(f"cat > {auth_keys}")
    stdin.write(full_content)
    stdin.channel.shutdown_write()
    stdout.channel.recv_exit_status()

    log("[OK]", "Публичный ключ успешно развернут.")
    return ssh

def test_connection(ssh_session):
    """
    Выполняет тестовую команду для проверки работоспособности сессии.
    """
    test_cmd = "ls -la /"
    log(">>>", f"Выполнение тестовой команды \"{CLR_CMD}{test_cmd}{CLR_RESET}\" на сервере...")

    stdin, stdout, stderr = ssh_session.exec_command(test_cmd)
    exit_status = stdout.channel.recv_exit_status()

    if exit_status == 0:
        log("---", "Содержимое корневой директории: ---")
        for line in stdout:
            log(" ", line.strip(), msg_color=CLR_GRAY if USE_COLORS else None)
        log("---", "Конец вывода ---")
        log("[OK]", "Тестовая команда выполнена успешно.")
    else:
        err = stderr.read().decode().strip()
        raise Exception(f"Ошибка выполнения тестовой команды: {err}")

def disconnect_ssh(ssh_session):
    """
    Безопасно закрывает SSH-соединение.
    """
    log("...", "Завершение SSH сессии.")
    ssh_session.close()
    log("[OK]", "Отключение от сервера выполнено.")

def main():
    """
    Загрузка конфигурации и основной цикл обработки.
    """
    log("===", "Запуск скрипта управления SSH-подключениями ===")

    try:
        script_full_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_full_path)
        script_name = os.path.splitext(os.path.basename(script_full_path))[0]
    except NameError:
        script_dir = os.getcwd()
        script_name = "ssh_key_manager"

    config_path = os.path.join(script_dir, f"{script_name}.cfg")

    # Проверка существования конфигурации
    if not os.path.exists(config_path):
        template = {
            "_comment": "Конфигурация скрипта управления SSH-ключами. UUID заполняется автоматически.",
            "uuid": str(uuid.uuid4()),
            "local_key_dir": None,
            "servers": [
                {
                    "name": "Server1",
                    "host": "127.0.0.1",
                    "enabled": True,
                    "_comment_enabled": "true — сервер обрабатывается, false — сервер временно отключён и пропускается",
                    "username": "root",
                    "password": None,
                    "remote_home": "/root",
                    "key_size": 3072,
                    "_comment_key_size": "2048 (слабо), 3072 (стандарт, рекомендовано), 4096 (сверхнадёжно)"
                }
            ]
        }
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(template, f, indent=4, ensure_ascii=False)
            log("[i]", f"Создан файл конфигурации: {config_path}")
            log("[!]", "Заполните список серверов и запустите скрипт снова.")
        except Exception as e:
            log("[X]", f"Не удалось создать файл конфигурации: {e}")
            sys.exit(1)
        sys.exit(0)

    # Чтение конфигурации
    config = None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        log("[X]", f"Ошибка чтения конфигурации: {e}")
        sys.exit(1)

    if config is None:
        log("[X]", "Ошибка чтения конфигурации: пустой файл.")
        sys.exit(1)

    # Проверка UUID
    instance_id = config.get("uuid")
    if instance_id is None:
        instance_id = str(uuid.uuid4())
        config["uuid"] = instance_id
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            log("[i]", f"Сгенерирован новый UUID для этого экземпляра: {instance_id}")
        except Exception as e:
            log("[X]", f"Не удалось обновить файл конфигурации с UUID: {e}")
            sys.exit(1)

    # Настройка директории ключей
    l_key_dir = config.get("local_key_dir")
    if l_key_dir is None:
        local_key_dir = os.path.join(script_dir, "ssh_keys")
    else:
        local_key_dir = l_key_dir

    servers = config.get("servers", [])
    if not servers:
        log("[!]", "Список серверов пуст.")
        sys.exit(0)

    # Проверка режима --show
    if "--show" in sys.argv:
        log("===", "Режим проверки доступности (--show) ===")
        for server in servers:
            if not server.get("enabled", True):
                continue

            host = server.get("host")
            if not host: continue

            name = server.get("name")
            display_name = name or host
            user = server.get("username", "root")

            clean_name = name if name else host.replace(".", "_")
            key_filename = f"id_rsa_{clean_name}"
            private_key_path = os.path.join(local_key_dir, key_filename)

            if not os.path.exists(private_key_path):
                log("[!]", f"{display_name} ({host}) — ключ не найден")
                continue

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(host, username=user, key_filename=private_key_path, timeout=SSH_TIMEOUT)
                log("[OK]", f"{display_name} ({host}) — доступен по ключу")
            except AuthenticationException:
                log("[!]", f"{display_name} ({host}) — аутентификация отклонена")
            except Exception as e:
                log("[X]", f"{display_name} ({host}) — ошибка подключения: {e}")
            finally:
                ssh.close()

        log("===", "Проверка завершена ===")
        sys.exit(0)

    failed_servers = []

    for server in servers:
        if not server.get("enabled", True):
            display_name = server.get("name") or server.get("host", "неизвестный")
            log("[i]", f"Сервер {display_name} отключён (enabled: false), пропуск.")
            continue

        host = server.get("host")
        if not host:
            log("[!]", "Пропуск сервера без указания host.")
            continue

        name = server.get("name")
        display_name = name or host
        user = server.get("username", "root")
        pwd = server.get("password")
        home = server.get("remote_home", "/root")
        k_size = server.get("key_size", KEY_SIZE)

        log("===", f"Обработка сервера: {display_name} ({host})")

        ssh_session = None
        try:
            ssh_session = connect_and_setup_ssh(
                host=host,
                username=user,
                password=pwd,
                local_key_dir=local_key_dir,
                remote_home_dir=home,
                instance_id=instance_id,
                server_name=name,
                key_size=k_size
            )

            test_connection(ssh_session)
            log("[OK]", f"Сервер {display_name} ({host}) обработан успешно.")

        except Exception as e:
            log("[X]", f"Ошибка при работе с сервером {display_name} ({host}): {e}")
            failed_servers.append((display_name, host, str(e)))

        finally:
            if ssh_session:
                disconnect_ssh(ssh_session)

    # Итоговая сводка
    log("===", "Итоговая сводка выполнения")
    if failed_servers:
        log("[X]", "Следующие серверы обработаны с ошибками:", msg_color=CLR_X)
        for name, host, error in failed_servers:
            log("-", f"{name} ({host}): {error}", msg_color=CLR_X)
        sys.exit(1)
    else:
        log("[OK]", "Все серверы обработаны успешно!")
        sys.exit(0)

if __name__ == "__main__":
    main()
