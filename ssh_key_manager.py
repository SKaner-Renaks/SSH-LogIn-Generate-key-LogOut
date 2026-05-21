import os
import stat
import datetime
import getpass
import paramiko
import sys
import ctypes
from paramiko.ssh_exception import AuthenticationException, SSHException

# ANSI Color Codes
CLR_RESET = "\033[0m"
CLR_TIMESTAMP = "\033[1;97m"
CLR_OK = "\033[92m"
CLR_X = "\033[91m"
CLR_I = "\033[96m"
CLR_WARN = "\033[93m"
CLR_PROCESS = "\033[94m"
CLR_GRAY = "\033[90m"
CLR_CMD = "\033[1;92m"

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
    Enables ANSI escape sequence processing on Windows consoles.
    Returns the updated use_colors flag.
    """
    if not use_colors:
        return False

    if sys.platform != "win32":
        return use_colors

    try:
        # Get standard output handle
        # -11 is STD_OUTPUT_HANDLE
        kernel32 = ctypes.windll.kernel32
        stdout_handle = kernel32.GetStdHandle(-11)

        # Get current console mode
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode)):
            return False

        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | 0x0004
        if not kernel32.SetConsoleMode(stdout_handle, new_mode):
            return False

        return True
    except Exception:
        return False

# Determine if we should use colors
USE_COLORS = sys.stdout.isatty()
USE_COLORS = enable_windows_ansi(USE_COLORS)

def log(prefix, message, msg_color=None):
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
    if description:
        log("[...]", description)

    if USE_COLORS:
        log("[...]", f"Выполнение команды: {CLR_CMD}{command}{CLR_RESET}")
    else:
        log("[...]", f"Выполнение команды: {command}")

    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    return exit_status, stdout, stderr

def connect_and_setup_ssh(host, username, password, local_key_dir, remote_home_dir):
    log(">>>", f"Инициализация подключения к серверу {host}...")

    key_filename = "id_rsa_proxmox"
    private_key_path = os.path.join(local_key_dir, key_filename)
    public_key_path = private_key_path + ".pub"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    key_exists = os.path.exists(private_key_path)
    session_established = False

    if key_exists:
        log("[i]", "Найден локальный ключ. Попытка аутентификации по ключу...")
        try:
            ssh.connect(host, username=username, key_filename=private_key_path, timeout=10)
            log("[OK]", "Аутентификация по ключу прошла успешно.")
            return ssh
        except AuthenticationException:
            log("[!]", "Аутентификация по ключу отклонена. Возможно, ключ устарел или не зарегистрирован на сервере.")
        except (SSHException, Exception) as e:
            log("[X]", f"Ошибка сети или подключения: {e}")
            raise e
    else:
        log("[!]", "Локальный ключ не найден. Запуск процедуры интерактивной настройки.")

    # Password authentication block
    log("***", "Требуется парольная аутентификация ***")

    if password:
        log("[...]", "Попытка входа с паролем из конфигурации.")
        try:
            ssh.connect(host, username=username, password=password, timeout=10)
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
        log("[...]", "Выполняется вход по логину и паролю...")
        try:
            ssh.connect(host, username=username, password=password_input, timeout=10)
            session_established = True
        except AuthenticationException:
            log("[X]", "Ошибка: Неверный логин или пароль.")
            raise Exception("Authentication failed")
        except (SSHException, Exception) as e:
            log("[X]", f"Ошибка сети или подключения: {e}")
            raise e

    # If we reached here, we are connected via password.
    # Now generate and deploy keys.

    if key_exists:
        log("[!]", "Внимание: старый локальный ключ будет заменён новым. Доступ со старого ключа на другие серверы будет утерян.")

    log("[...]", "Генерация новой пары RSA-ключей (4096 бит)...")
    new_key = paramiko.RSAKey.generate(4096)
    log("[OK]", "Ключи сгенерированы.")

    # Save locally
    if not os.path.exists(local_key_dir):
        log("[...]", f"Создание локальной директории для ключей: {local_key_dir}")
        os.makedirs(local_key_dir, mode=0o700, exist_ok=True)

    # Save in PEM format (-----BEGIN RSA PRIVATE KEY-----) using binary write
    # to avoid line ending issues on different platforms.
    with open(private_key_path, "wb") as priv_file:
        new_key.write_private_key(priv_file)
    os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR) # 600

    public_key_str = f"{new_key.get_name()} {new_key.get_base64()} {username}@{host}"
    with open(public_key_path, "w") as pub_file:
        pub_file.write(public_key_str)

    log("[OK]", f"Локальные ключи сохранены в {local_key_dir}")

    # Deploy to server
    log("[...]", f"Развертывание публичного ключа на сервере {host}...")

    ssh_dir = f"{remote_home_dir}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"

    execute_remote_command(ssh, f"mkdir -p {ssh_dir}", f"Проверка и создание (если нужно) директории {ssh_dir}")
    execute_remote_command(ssh, f"chmod 700 {ssh_dir}")
    execute_remote_command(ssh, f"touch {auth_keys}", f"Обеспечение наличия файла {auth_keys}")

    # Check for duplicate
    log("[...]", "Проверка наличия ключа на сервере...")
    grep_cmd = f"grep -qF - {auth_keys}"
    if USE_COLORS:
        log("[...]", f"Выполнение команды: {CLR_CMD}{grep_cmd}{CLR_RESET}")
    else:
        log("[...]", f"Выполнение команды: {grep_cmd}")

    stdin, stdout, stderr = ssh.exec_command(grep_cmd)
    stdin.write(public_key_str)
    stdin.channel.shutdown_write()
    exit_status = stdout.channel.recv_exit_status()

    if exit_status == 0:
        log("[i]", "Ключ уже присутствует на сервере, пропускаем добавление.")
    else:
        log("[...]", "Добавление публичного ключа в authorized_keys")
        cat_cmd = f"cat >> {auth_keys}"
        if USE_COLORS:
            log("[...]", f"Выполнение команды: {CLR_CMD}{cat_cmd}{CLR_RESET}")
        else:
            log("[...]", f"Выполнение команды: {cat_cmd}")

        stdin, stdout, stderr = ssh.exec_command(cat_cmd)
        stdin.write(f"\n{public_key_str}\n")
        stdin.channel.shutdown_write()
        stdout.channel.recv_exit_status()

    execute_remote_command(ssh, f"chmod 700 {ssh_dir}", "Установка строгих прав доступа (700 на .ssh, 600 на authorized_keys)")
    execute_remote_command(ssh, f"chmod 600 {auth_keys}")

    log("[OK]", "Публичный ключ успешно установлен на сервер.")

    return ssh

def test_connection(ssh_session):
    test_cmd = "ls -la /"
    if USE_COLORS:
        log(">>>", f"Выполнение тестовой команды \"{CLR_CMD}{test_cmd}{CLR_RESET}\" на сервере...")
    else:
        log(">>>", f"Выполнение тестовой команды \"{test_cmd}\" на сервере...")

    stdin, stdout, stderr = ssh_session.exec_command(test_cmd)
    exit_status = stdout.channel.recv_exit_status()

    if exit_status == 0:
        log("---", "Содержимое корневой директории (подтверждение подключения) ---")
        for line in stdout:
            log(" ", line.strip(), msg_color=CLR_GRAY if USE_COLORS else None)
        log("---", "Конец вывода ---")
        log("[OK]", "Тестовая команда выполнена успешно.")
    else:
        err = stderr.read().decode().strip()
        log("[X]", f"Ошибка выполнения тестовой команды: {err}")

def disconnect_ssh(ssh_session):
    log("...", "Завершение SSH сессии.")
    ssh_session.close()
    log("[OK]", "Отключение от сервера выполнено.")

def main():
    # --- БЛОК КОНФИГУРАЦИИ ---
    TARGET_HOST = "127.0.0.1" # Измените на адрес вашего сервера
    TARGET_USER = "root"      # Измените при необходимости
    PASSWORD = None           # Можно указать пароль здесь для автоматизации
    LOCAL_KEY_DIR = os.path.join(os.getcwd(), "ssh_keys")
    REMOTE_HOME = "/root"     # При смене пользователя изменить путь
    # -------------------------

    log("===", "Запуск скрипта управления SSH-подключением ===")

    ssh_session = None
    try:
        ssh_session = connect_and_setup_ssh(
            TARGET_HOST,
            TARGET_USER,
            PASSWORD,
            LOCAL_KEY_DIR,
            REMOTE_HOME
        )
    except Exception as e:
        log("[X]", f"Критическая ошибка на этапе подключения: {e}")
        log("[X]", "Критическая ошибка на этапе подключения. Работа скрипта остановлена.")
        exit(1)

    try:
        test_connection(ssh_session)
    finally:
        if ssh_session:
            disconnect_ssh(ssh_session)

    log("===", "Скрипт успешно завершил работу ===")
    exit(0)

if __name__ == "__main__":
    main()
