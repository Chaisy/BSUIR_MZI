import sys
from constants import *
from lab2 import STB

def main():
    try:

        with open("sample.txt", "r") as file:
            data = file.read()

        print("Data: %r\n" % data)

        key = int.from_bytes('dashadashadashadasha'.encode(), 'big')
        synchro = 312312412412

        s = STB(key)
        encrypted_text = s.encrypt(data)

        with open("encrypt.txt", "wb") as file:
            file.write(encrypted_text)

        print("Encrypted: %r" % encrypted_text)

        with open("encrypt.txt", "rb") as file:
            encrypted_data = file.read()
        decrypted_text = s.decrypt(encrypted_data)

        with open("decrypt.txt", "w") as file:
            file.write(decrypted_text)


    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
