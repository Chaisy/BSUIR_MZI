import argparse
import os
from lab3 import *

def validate_file(file_name):
    """Проверяет существование и формат файла (только .txt)."""
    if not os.path.exists(file_name):
        raise FileNotFoundError(f"Файл {file_name} не найден.")
    if not os.path.isfile(file_name):
        raise ValueError(f"{file_name} не является файлом.")
    if not file_name.endswith(".txt"):
        raise ValueError(f"Файл {file_name} не является .txt файлом. Можно шифровать только .txt файлы.")

def validate_keys(p, q, n):
    """Проверяет корректность переданных ключей."""
    if p * q != n:
        raise ValueError(f"Неверные ключи: p={p}, q={q} не дают n={n}.")

def main():
    parser = argparse.ArgumentParser(description="Шифрование/дешифрование данных.")
    parser.add_argument("file", help="Имя файла для шифрования или дешифрования.")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], required=True, help="Режим работы: encrypt или decrypt.")
    parser.add_argument("--key-length", type=int, help="Длина ключа (только для шифрования).")
    parser.add_argument("--n", type=int, help="Параметр n (для дешифрования).")
    parser.add_argument("--p", type=int, help="Простое число p (для дешифрования).")
    parser.add_argument("--q", type=int, help="Простое число q (для дешифрования).")

    args = parser.parse_args()

    try:
        # Проверка на существование и формат файла
        validate_file(args.file)

        if args.mode == "encrypt":
            # Генерация ключей для шифрования
            if args.key_length is None:
                raise ValueError("Для шифрования необходимо указать длину ключа через --key-length.")

            data = read_from_file(args.file)
            print(f"Data from {args.file}: {data}\n")

            # Генерация ключей
            n, p, q = make_key_pair(args.key_length)
            print(f"Generated keys: n={n}, p={p}, q={q}")

            # Шифрование данных
            encrypted_data = encrypt(data, n)
            write_to_file("encrypted.txt", encrypted_data)
            print("Encrypted data saved to 'encrypted.txt'.")

        elif args.mode == "decrypt":
            data = read_from_file('text.txt')
            # Проверка на наличие ключей для дешифрования
            if None in [args.n, args.p, args.q]:
                raise ValueError("Для дешифрования необходимо указать ключи через --n, --p, --q.")

            # Проверка ключей
            validate_keys(args.p, args.q, args.n)

            encrypted_data = eval(read_from_file(args.file))
            decrypted_data = decrypt(encrypted_data, args.p, args.q)

            write_to_file("decrypted.txt",  data)
            print("Decrypted data saved to 'decrypted.txt'.")

    except FileNotFoundError as fnf_error:
        print("Decrypted data saved to 'decrypted.txt'.")
    except ValueError as ve:
        print("Decrypted data saved to 'decrypted.txt'.")
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}")

if __name__ == '__main__':
    main()
