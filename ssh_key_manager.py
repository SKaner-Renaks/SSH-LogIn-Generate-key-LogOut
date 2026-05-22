import os
import stat
import datetime
import getpass
import paramiko
import sys
import ctypes
from paramiko.ssh_exception import AuthenticationException, SSHException

"""
Скрипт для автоматизированного управления SSH-ключами на нескольких серверах.
Позволяет генерировать ключи, развертывать их на удаленных серверах и проверять подключение.
"""

# --- БЛОК ГЛОБАЛЬНЫХ КОНСТАНТ ---

# Список серверов для обработки
# name: уникальное имя сервера (используется для именования файлов ключей)
# host: IP-адрес или доменное имя сервера
# username: имя пользователя для SSH-подключения
# password: пароль (если None, будет запрошен интерактивно)
# remote_home: домашняя директория пользователя на сервере
SERVERS = [
    {
        "name": "proxmox1",
        "host": "127.0.0.1",
        "username": "root",
        "password": None,
        "remote_home": "/root",
    }
]

# Путь к директории для хранения ключей.
# Если None — создается папка 'ssh_keys' в директории со скриптом.
LOCAL_KEY_DIR = None

# Таймаут подключения к SSH в секундах
SSH_TIMEOUT = 10

# Размер генерируемого RSA-ключа в битах
KEY_SIZE = 4096

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
    Это позволяет отображать цвета в CMD и PowerShell.

    :param use_colors: Текущий флаг использования цветов
    :return: Обновленный флаг использования цветов
    """
    if not use_colors:
        return False

    if sys.platform != "win32":
        return use_colors

    try:
        # Получаем дескриптор стандартного вывода (-11 = STD_OUTPUT_HANDLE)
        kernel32 = ctypes.windll.kernel32
        stdout_handle = kernel32.GetStdHandle(-11)

        # Получаем текущий режим консоли
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode)):
            return False

        # Включаем флаг ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
        new_mode = mode.value | 0x0004
        if not kernel32.SetConsoleMode(stdout_handle, new_mode):
            return False

        return True
    except Exception:
        return False

# Определяем, нужно ли использовать цвета (только если вывод идет в терминал)
USE_COLORS = sys.stdout.isatty()
USE_COLORS = enable_windows_ansi(USE_COLORS)

def log(prefix, message, msg_color=None):
    """
    Выводит форматированное сообщение в консоль с меткой времени.

    :param prefix: Префикс сообщения (например, [OK], [X])
    :param message: Текст сообщения
    :param msg_color: Опциональный цвет для самого сообщения
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

def connect_and_setup_ssh(host, username, password, local_key_dir, remote_home_dir, server_name=None):
    """
    Основной алгоритм настройки SSH доступа:
    1. Проверка наличия локального ключа.
    2. Попытка входа по ключу.
    3. При неуспехе — попытка входа по паролю (из конфига или интерактивно).
    4. Генерация новой пары ключей (если нужно).
    5. Развертывание публичного ключа на сервере.

    :param host: Адрес сервера
    :param username: Имя пользователя
    :param password: Пароль (может быть None)
    :param local_key_dir: Директория для хранения ключей
    :param remote_home_dir: Домашняя папка на сервере
    :param server_name: Имя сервера для названия файла ключа
    """
    log(">>>", f"Инициализация подключения к серверу {host}...")

    # Формируем имя файла ключа
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

    # Пробуем пароль из конфигурации
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

    # Интерактивный ввод пароля
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

    log("[...]", f"Генерация новой пары RSA-ключей ({KEY_SIZE} бит)...")
    new_key = paramiko.RSAKey.generate(KEY_SIZE)
    log("[OK]", "Ключи сгенерированы.")

    if not os.path.exists(local_key_dir):
        log("[...]", f"Создание директории для ключей: {local_key_dir}")
        os.makedirs(local_key_dir, mode=0o700, exist_ok=True)

    # Сохраняем приватный ключ в формате OpenSSH
    new_key.write_private_key_file(private_key_path)
    os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR) # 600

    # Формируем строку публичного ключа
    public_key_str = f"{new_key.get_name()} {new_key.get_base64()} {username}@{host}"
    with open(public_key_path, "w") as pub_file:
        pub_file.write(public_key_str)

    log("[OK]", f"Локальные ключи сохранены: {CLR_CMD}{key_filename}{CLR_RESET}")

    # 4. Развертывание ключа на сервере
    log("[...]", f"Развертывание публичного ключа на сервере {host}...")

    ssh_dir = f"{remote_home_dir}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"

    # Проверка и создание .ssh
    exit_status, stdout, stderr = execute_remote_command(ssh, f"test -d {ssh_dir} && echo 'EXISTS' || echo 'NOT_EXISTS'")
    dir_check = stdout.read().decode().strip()

    if dir_check == "NOT_EXISTS":
        execute_remote_command(ssh, f"mkdir -p {ssh_dir}", f"Создание директории {ssh_dir}")
        execute_remote_command(ssh, f"chmod 700 {ssh_dir}")
    else:
        log("[i]", f"Директория {ssh_dir} уже существует.")

    # Проверка и создание authorized_keys
    exit_status, stdout, stderr = execute_remote_command(ssh, f"test -f {auth_keys} && echo 'EXISTS' || echo 'NOT_EXISTS'")
    file_check = stdout.read().decode().strip()

    if file_check == "NOT_EXISTS":
        execute_remote_command(ssh, f"touch {auth_keys}", f"Создание файла {auth_keys}")
        execute_remote_command(ssh, f"chmod 600 {auth_keys}")
    else:
        log("[i]", f"Файл {auth_keys} уже существует.")

    # Проверка на дубликаты
    log("[...]", "Проверка ключа в authorized_keys...")
    exit_status, stdout, stderr = execute_remote_command(ssh, f"cat {auth_keys}")

    existing_keys = stdout.read().decode().splitlines()
    key_already_exists = False
    target_key_stripped = public_key_str.strip()

    for line in existing_keys:
        if line.strip() == target_key_stripped:
            key_already_exists = True
            break

    if key_already_exists:
        log("[i]", "Ключ уже присутствует на сервере.")
    else:
        log("[...]", "Добавление ключа...")
        stdin, stdout, stderr = ssh.exec_command(f"cat >> {auth_keys}")
        stdin.write(f"\n{public_key_str}\n")
        stdin.channel.shutdown_write()
        stdout.channel.recv_exit_status()
        log("[OK]", "Ключ успешно добавлен.")

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
    Основной цикл обработки серверов.
    """
    log("===", "Запуск скрипта управления SSH-подключениями ===")

    # Определение рабочей директории для ключей
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        script_dir = os.getcwd()

    if LOCAL_KEY_DIR is None:
        local_key_dir = os.path.join(script_dir, "ssh_keys")
    else:
        local_key_dir = LOCAL_KEY_DIR

    failed_servers = []

    for server in SERVERS:
        host = server.get("host")
        name = server.get("name")
        display_name = name or host
        user = server.get("username")
        pwd = server.get("password")
        home = server.get("remote_home", "/root")

        log("===", f"Обработка сервера: {display_name} ({host})")

        ssh_session = None
        try:
            ssh_session = connect_and_setup_ssh(
                host=host,
                username=user,
                password=pwd,
                local_key_dir=local_key_dir,
                remote_home_dir=home,
                server_name=name
            )

            test_connection(ssh_session)
            log("[OK]", f"Сервер {name} ({host}) обработан успешно.")

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
