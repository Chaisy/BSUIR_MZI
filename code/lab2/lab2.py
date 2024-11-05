from constants import *

class STB:
    def __init__(self, key):
        count = self.get_key_chunks_counts(key)
        self.tmp_keys = []

        for i in range(count):
            self.tmp_keys.append(key & 0xFFFF)
            key >>= 32

        if count == 4:
            self.tmp_keys.extend(self.tmp_keys[:])
        elif count == 6:
            self.tmp_keys.extend([
                self.tmp_keys[0] ^ self.tmp_keys[1] ^ self.tmp_keys[2],
                self.tmp_keys[3] ^ self.tmp_keys[4] ^ self.tmp_keys[5]
            ])

        self.K = []
        for _ in range(8):
            self.K.extend(self.tmp_keys[:])

    def get_key_chunks_counts(self, key):
        l = len(bin(key)[2:])
        l &= (1 << 256) - 1
        if 256 >= l > 192:
            return 8
        elif 192 >= l > 128:
            return 6
        elif l <= 128:
            return 4

    def rot_hi(self, u):
        if u < 1 << 31:
            return (2 * u) % (1 << 32)
        else:
            return (2 * u + 1) % (1 << 32)

    def rot_hi_r(self, u, r):
        result = u
        for _ in range(r):
            result = self.rot_hi(result)
        return result

    def square_plus(self, u, v):
        return (u + v) % (1 << 32)

    def square_minus(self, u, v):
        return (u - v) % (1 << 32)

    def G(self, r, word):
        mask = (1 << 8) - 1
        final = 0
        for i in range(4):
            part = word & mask
            word >>= 8
            r = part & 0x0F
            l = (part & 0xF0) >> 4
            result = H[l][r]
            result <<= 8 * i
            final += result
        return self.rot_hi_r(final, r)

    def encrypt_block(self, X):
        if self.get_key_chunks_counts(X) != 4:
            raise ValueError()
        d = X & 0xFFFFFFFF
        X >>= 32
        c = X & 0xFFFFFFFF
        X >>= 32
        b = X & 0xFFFFFFFF
        X >>= 32
        a = X

        for i in range(1, 9):
            b = b ^ self.G(5, self.square_plus(a, self.K[7*i - 7]))
            c = c ^ self.G(21, self.square_plus(d, self.K[7*i - 6]))
            a = self.square_minus(a, self.G(13, self.square_plus(b, self.K[7*i - 5])))
            e = self.G(21, self.square_plus(self.square_plus(b, c), self.K[7*i - 4])) ^ (i % (2 ** 32))
            b = self.square_plus(b, e)
            c = self.square_minus(c, e)
            d = self.square_plus(d, self.G(13, self.square_plus(c, self.K[7*i - 3])))
            b = b ^ self.G(21, self.square_plus(a, self.K[7*i - 2]))
            c = c ^ self.G(5, self.square_plus(d, self.K[7*i - 1]))
            a, b = b, a
            c, d = d, c
            b, c = c, b

        return (b << 96) + (d << 64) + (a << 32) + c

    def decrypt_block(self, X):
        if self.get_key_chunks_counts(X) != 4:
            raise ValueError()
        d = X & 0xFFFFFFFF
        X >>= 32
        c = X & 0xFFFFFFFF
        X >>= 32
        b = X & 0xFFFFFFFF
        X >>= 32
        a = X

        for i in range(8, 0, -1):
            b = b ^ self.G(5, self.square_plus(a, self.K[7*i - 1]))
            c = c ^ self.G(21, self.square_plus(d, self.K[7*i - 2]))
            a = self.square_minus(a, self.G(13, self.square_plus(b, self.K[7*i - 3])))
            e = self.G(21, self.square_plus(self.square_plus(b, c), self.K[7*i - 4])) ^ (i % (2 ** 32))
            b = self.square_plus(b, e)
            c = self.square_minus(c, e)
            d = self.square_plus(d, self.G(13, self.square_plus(c, self.K[7*i - 5])))
            b = b ^ self.G(21, self.square_plus(a, self.K[7*i - 6]))
            c = c ^ self.G(5, self.square_plus(d, self.K[7*i - 7]))
            a, b = b, a
            c, d = d, c
            a, d = d, a

        return (c << 96) + (a << 64) + (d << 32) + b

    def split_message(self, message):
        chunks = []
        while message:
            chunk = message & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            chunks.append(chunk)
            message >>= 128
        return chunks

    def join_message(self, chunks):
        answer = 0
        for chunk in chunks:
            answer <<= 128
            answer += chunk
        return answer

    def encrypt(self, message: str):
        plain_msg = int.from_bytes(message.encode(), 'big')
        chunks = self.split_message(plain_msg)
        results = self.encrypt_block_plain(chunks)
        answer = self.join_message(results)
        return answer.to_bytes((answer.bit_length() + 7) // 8, 'big')

    def decrypt(self, message: bytes):
        plain_msg = int.from_bytes(message, 'big')
        chunks = reversed(self.split_message(plain_msg))
        results = self.decrypt_block_plain(chunks)
        answer = self.join_message(reversed(results))
        return answer.to_bytes((answer.bit_length() + 7) // 8, 'big').decode()

    def encrypt_block_plain(self, chunks):
        results = []
        for X in chunks:
            Y = self.encrypt_block(X)
            results.append(Y)
        return results

    def decrypt_block_plain(self, chunks):
        results = []
        for X in chunks:
            Y = self.decrypt_block(X)
            results.append(Y)
        return results
