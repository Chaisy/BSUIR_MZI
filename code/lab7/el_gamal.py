from ellipticcurve import EllipticCurve, Point
import random
import math


class Gamal:


    def __init__(self, curve_a, curve_b, prime, random_k, sender_random, private_key, encoding='ascii'):
        self.private_key = private_key
        self.prime_number = prime
        self.sender_random_value = sender_random
        self.elliptic_curve = EllipticCurve(curve_a, curve_b, prime)
        self.random_k = random_k
        self.encoding = encoding

        self.__generateBase()


        self.public_key = self.elliptic_curve.multiplication(self.base_point, private_key)

    def encrypt(self, plaintext):

        ciphertext_points = []

        encoded_points = self.__encode_plaintext(plaintext)
        for point in encoded_points:
            ciphertext_points.append(self.__encrypt_point(point))

        return ciphertext_points

    def decrypt(self, cipherpoints):
        plaintext_points = []
        for point_pair in cipherpoints:
            plaintext_points.append(self.__decrypt_point_pair(point_pair))

        return self.__decode_points(plaintext_points)

    def __generateBase(self):

        found = False
        while not found:
            x = random.choice(range(1, self.prime_number))
            y_list = self.elliptic_curve.generatePoints(x)
            if len(y_list) > 0:
                found = True
                self.base_point = Point(x, random.choice(y_list))

    def __encode_plaintext(self, plaintext):

        byte_array = bytearray(plaintext, "1251")
        chunks_list = []
        for byte in byte_array:

            for j in range(self.random_k):
                # решаем для y
                x = byte * self.random_k + j
                list_of_y = self.elliptic_curve.generatePoints(x)
                if len(list_of_y) > 0:
                    y = random.choice(list_of_y)
                    chunks_list.append(Point(x, y))
                    break

        return chunks_list

    def __decode_points(self, plaintext_points):

        proto = ""
        for point in plaintext_points:
            dec_representation = int(math.floor(point.x / self.random_k))
            hex_representation = hex(dec_representation)[2:]
            if len(hex_representation) == 1:
                hex_representation = "0" + hex_representation
            proto += bytes.fromhex(hex_representation).decode("cp1251")

        return proto

    def __encrypt_point(self, point):

        first_cipher = self.elliptic_curve.multiplication(self.base_point, self.sender_random_value)
        second_cipher = self.elliptic_curve.addition(point, self.elliptic_curve.multiplication(self.public_key,
                                                                                               self.sender_random_value))

        return [first_cipher, second_cipher]

    def __decrypt_point_pair(self, point_pair):

        first_block = self.elliptic_curve.multiplication(point_pair[0], self.private_key)
        first_block_inv = Point(first_block.x, (-first_block.y) % self.prime_number)

        return self.elliptic_curve.addition(point_pair[1], first_block_inv)