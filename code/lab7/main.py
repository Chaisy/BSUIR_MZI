from el_gamal import Gamal
import random

PRIVATE_KEY = 100
prime_number = 4093
SENDER_RANDOM = random.choice(range(1, prime_number))
CURVE_A = 1
CURVE_B = 6
ENCODING_RANDOM_K = 5

gamal = Gamal(
    CURVE_A,
    CURVE_B,
    prime_number,
    ENCODING_RANDOM_K,
    SENDER_RANDOM,
    PRIVATE_KEY
)


def get_points():
    with open('encrypt.txt', 'r', encoding="utf-8") as file:
        plain_message = file.read()

    cipherpoints = gamal.encrypt(plain_message)
    return cipherpoints


def main():
    cipherpoints = get_points()
    with open('decrypt.txt', 'w', encoding="utf-8") as file:
        file.write(str([str(pair[1]) for pair in cipherpoints]))

        file.close()

    plaintext = gamal.decrypt(cipherpoints)
    with open('result.txt', 'w', encoding="utf-8") as file:
        file.write(plaintext)


if __name__ == '__main__':
    main()