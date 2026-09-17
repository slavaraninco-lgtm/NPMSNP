"""
CLI tool to generate and configure encrypted administrator password for MSNP Server.
Stores password encrypted (AES-128-CBC + HMAC-SHA256 via Fernet) in config.py or environment.
"""
import argparse
import getpass
import os
import re
import sys

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
from db.security import encrypt_password, decrypt_password, is_encrypted


def update_config_file(config_path: str, encrypted_password: str) -> bool:
    """Updates ADMIN_PASSWORD assignment in config.py with the new encrypted token."""
    if not os.path.exists(config_path):
        print(f"[ERROR] Файл конфигурации {config_path} не найден!")
        return False

    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Pattern for ADMIN_PASSWORD = ...
    pattern = r'(ADMIN_PASSWORD\s*=\s*os\.getenv\(\s*["\']MSNP_ADMIN_PASSWORD["\']\s*,\s*["\'])([^"\']+)(["\']\s*\))'
    replacement = rf'\g<1>{encrypted_password}\g<3>'

    if re.search(pattern, content):
        new_content = re.sub(pattern, replacement, content)
    else:
        # If simple assignment or not found, try simple regex
        simple_pattern = r'(ADMIN_PASSWORD\s*=\s*["\'])([^"\']+)(["\'])'
        if re.search(simple_pattern, content):
            new_content = re.sub(simple_pattern, rf'\g<1>{encrypted_password}\g<3>', content)
        else:
            # Append to config.py
            new_content = content.rstrip() + f'\n\n# Administrator Password (Encrypted)\nADMIN_PASSWORD = os.getenv("MSNP_ADMIN_PASSWORD", "{encrypted_password}")\n'

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Генератор зашифрованного пароля администратора для панели управления MSNP Server"
    )
    parser.add_argument(
        "password",
        nargs="?",
        default=None,
        help="Пароль администратора в открытом виде (если не передан, будет запрошен интерактивно)"
    )
    parser.add_argument(
        "--update-config",
        action="store_true",
        help="Автоматически обновить переменную ADMIN_PASSWORD в config.py"
    )
    parser.add_argument(
        "--secret-key",
        default=None,
        help="Мастер-ключ шифрования (по умолчанию берется из config.DB_SECRET_KEY)"
    )

    args = parser.parse_args()

    secret_key = args.secret_key or getattr(config, "DB_SECRET_KEY", "msnp_server_default_master_salt_key_2026")
    raw_password = args.password

    if not raw_password:
        try:
            raw_password = getpass.getpass("Введите новый пароль администратора: ")
            if not raw_password:
                print("[ERROR] Пароль не может быть пустым!")
                sys.exit(1)
            confirm = getpass.getpass("Подтвердите новый пароль администратора: ")
            if raw_password != confirm:
                print("[ERROR] Введенные пароли не совпадают!")
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\nОтменено.")
            sys.exit(1)

    # Encrypt password
    encrypted_token = encrypt_password(raw_password, secret_key)

    # Verify roundtrip
    decrypted_check = decrypt_password(encrypted_token, secret_key)
    if decrypted_check != raw_password:
        print("[CRITICAL] Ошибка верификации шифрования пароля!")
        sys.exit(1)

    print("=" * 70)
    print("  ГЕНЕРАТОР ЗАШИФРОВАННОГО ПАРОЛЯ АДМИНИСТРАТОРА MSNP")
    print("=" * 70)
    print(f"Открытый пароль      : {'*' * len(raw_password)} ({len(raw_password)} симв.)")
    print(f"Зашифрованный токен  : {encrypted_token}")
    print("=" * 70)
    print("\nДля установки этого пароля в config.py используйте:")
    print(f'ADMIN_PASSWORD = os.getenv("MSNP_ADMIN_PASSWORD", "{encrypted_token}")\n')
    print("Либо через переменную окружения системы:")
    print(f'set MSNP_ADMIN_PASSWORD={encrypted_token}\n')

    config_file_path = os.path.join(BASE_DIR, "config.py")

    should_update = args.update_config
    if not should_update and sys.stdin.isatty():
        try:
            choice = input(f"Хотите автоматически обновить {config_file_path}? [Y/n]: ").strip().lower()
            if choice in ("", "y", "yes", "д", "да"):
                should_update = True
        except (KeyboardInterrupt, EOFError):
            pass

    if should_update:
        if update_config_file(config_file_path, encrypted_token):
            print(f"[OK] Файл {config_file_path} успешно обновлен новым зашифрованным паролем!")
        else:
            print(f"[ERROR] Не удалось обновить {config_file_path}")


if __name__ == "__main__":
    main()
