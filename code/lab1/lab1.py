import os


# Определяем размер файла
def filesize(filename):
    return os.path.getsize(filename)


# Добавление padding (PKCS7) для заполнения до 8 байт
def add_padding(data):
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len] * pad_len)


# Удаление padding (PKCS7) после расшифрования
def remove_padding(data):
    pad_len = data[-1]
    if 0 < pad_len <= 8:
        return data[:-pad_len]
    return data  # Если что-то пошло не так, возвращаем данные как есть


# Функция, реализующая работу ГОСТ 28147-89 в режиме простой замены
def rpz(rezh, opener, saver):
    # Таблица замен (8x16)
    Tab_Z = [
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF]
    ]

    # Ключ
    key = [
        0x0123,
        0x4567,
        0x89AB,
        0xCDEF,
        0x0123,
        0x4567,
        0x89AB,
        0xCDEF
    ]

    N = bytearray(4)  # 32-разрядный накопитель
    n1 = n2 = SUM232 = 0  # Накопители N1, N2, и сумматор

    with open(opener, "rb") as f_begin, open(saver, "wb") as f_end:
        data = f_begin.read()

        # Добавляем padding при шифровании
        if rezh == 1:
            data = add_padding(data)

        block_count = (len(data) * 8 + 63) // 64  # Определим количество блоков

        sh = min(len(data), 4)
        sh1 = 0
        flag = 0

        # Чтение и преобразование блоков
        for i in range(block_count):
            N[:] = bytearray(4)  # Записываем в накопитель N1
            if (sh1 + sh) < len(data):
                N[:] = data[sh1:sh1 + sh]
                sh1 += sh
            else:
                sh = len(data) - sh1
                N[:] = data[sh1:sh1 + sh]
                flag = 1

            n1 = int.from_bytes(N, 'little')

            N[:] = bytearray(4)  # Записываем в накопитель N2
            if (sh1 + sh) < len(data):
                N[:] = data[sh1:sh1 + sh]
                sh1 += sh
            else:
                if not flag:
                    sh = len(data) - sh1
                    N[:] = data[sh1:sh1 + sh]

            n2 = int.from_bytes(N, 'little')

            # 32 цикла простой замены
            c = 0
            for k in range(32):
                if rezh == 1 and k == 24:
                    c = 7
                elif rezh == 2 and k == 8:
                    c = 7

                # Суммируем в сумматоре СМ1
                SUM232 = (key[c] + n1) & 0xFFFFFFFF

                # Заменяем по таблице замен
                for q in range(4):
                    zam_symbol = (SUM232 >> (q * 8)) & 0xFF
                    first_byte = (zam_symbol & 0xF0) >> 4
                    second_byte = zam_symbol & 0x0F
                    first_byte = Tab_Z[2 * q][first_byte]
                    second_byte = Tab_Z[2 * q + 1][second_byte]
                    zam_symbol = (first_byte << 4) | second_byte
                    SUM232 = (SUM232 & ~(0xFF << (q * 8))) | (zam_symbol << (q * 8))

                SUM232 = ((SUM232 << 11) & 0xFFFFFFFF) | (SUM232 >> 21)  # Циклический сдвиг на 11
                SUM232 ^= n2  # Складываем в сумматоре СМ2

                if k < 31:
                    n2 = n1
                    n1 = SUM232

                if rezh == 1:
                    if k < 24:
                        c = (c + 1) % 8
                    else:
                        c = (c - 1) % 8
                else:
                    if k < 8:
                        c = (c + 1) % 8
                    else:
                        c = (c - 1) % 8

            n2 = SUM232

            # Вывод результата в файл
            f_end.write(n1.to_bytes(4, 'little'))
            f_end.write(n2.to_bytes(4, 'little'))

    # Удаляем padding при дешифровании
    if rezh == 2:
        with open(saver, "rb") as f_end:
            decrypted_data = f_end.read()
        decrypted_data = remove_padding(decrypted_data)
        with open(saver, "wb") as f_end:
            f_end.write(decrypted_data)


# Основная программа
def main():
    # Шифруем файл text.txt в encryp.bin
    rpz(1, 'text.txt', 'encryp.bin')

    # Дешифруем файл encryp.bin в descryp.txt
    rpz(2, 'encryp.bin', 'descryp.txt')


if __name__ == "__main__":
    main()
