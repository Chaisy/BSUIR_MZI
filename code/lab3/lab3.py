import argparse
import random
from sympy import isprime, mod_inverse

from main import validate_file, validate_keys


def mod_sqrt(a, p):
    assert isprime(p), "p should be simple"

    # Если p ≡ 3 (mod 4), можно использовать упрощенный случай
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Алгоритм Тонелли-Шенкса для общего случая
    def legendre_symbol(a, p):
        return pow(a, (p - 1) // 2, p)

    def find_non_residue(p):
        for i in range(2, p):
            if legendre_symbol(i, p) == p - 1:
                return i
        return None

    # Находим квадратичный невычет z
    z = find_non_residue(p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Инициализация переменных
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        t2i = t
        i = 0
        for i in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1:
                break

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

    return r

# Генерация простых чисел
def generate_large_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        if isprime(candidate):
            return candidate

# Генерация ключей
def make_key_pair(length):
    if length < 4:
        raise ValueError('Key pair length must be greater than 4')

    # Генерация двух больших простых чисел
    p = generate_large_prime(length // 2)
    q = generate_large_prime(length // 2)
    n = p * q

    print("p = {}, q = {}".format(p, q))
    return n, p, q  # Возвращаем открытый ключ n и закрытые ключи p, q

# Шифрование
def encrypt(data, n):
    encrypted_data = []
    for char in data:
        m = ord(char)  # Преобразуем символ в число
        c = pow(m, 2, n)  # m^2 % n
        encrypted_data.append(c)
    return encrypted_data

# Дешифрование
def decrypt(encrypted_data, p, q):
    n = p * q
    decrypted_message = []

    for c in encrypted_data:
        if c < 0 or c >= n:
            raise ValueError(f"Encrypted value {c} is out of range for modulus n={n}")

        # Найти квадратные корни по модулям p и q
        roots_p = mod_sqrt(c, p)
        roots_q = mod_sqrt(c, q)

        if roots_p is None or roots_q is None:
            raise ValueError(f"Cannot find sqrt for {c}")

        # Применяем китайскую теорему об остатках (CRT)
        possible_solutions = []
        for r_p in [roots_p, -roots_p % p]:
            for r_q in [roots_q, -roots_q % q]:
                m = (r_p * q * mod_inverse(q, p) + r_q * p * mod_inverse(p, q)) % n
                possible_solutions.append(m)

        for solution in possible_solutions:
            if 32 <= solution <= 126:
                decrypted_message.append(chr(solution))
                break
        else:
            decrypted_message.append('?')

    return ''.join(decrypted_message)

# Запись в файл
def write_to_file(file_name, data):
    with open(file_name, "w") as file:
        file.write(str(data))

# Чтение из файла
def read_from_file(file_name):
    with open(file_name, "r") as file:
        return file.read()



def start():
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
            # Проверка на наличие ключей для дешифрования
            if None in [args.n, args.p, args.q]:
                raise ValueError("Для дешифрования необходимо указать ключи через --n, --p, --q.")

            # Проверка ключей
            validate_keys(args.p, args.q, args.n)

            encrypted_data = eval(read_from_file(args.file))
            decrypted_data = decrypt(encrypted_data, args.p, args.q)
            write_to_file("decrypted.txt", decrypted_data)
            print("Decrypted data saved to 'decrypted.txt'.")

    except FileNotFoundError as fnf_error:
        print("Decrypted data saved to 'decrypted.txt'.")
    except ValueError as ve:
        print("Decrypted data saved to 'decrypted.txt'.")
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}")
