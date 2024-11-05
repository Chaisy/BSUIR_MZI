import numpy as np
import math

class hamming_keygen:
    def __init__(self, kgen):
        self.kgen = kgen
        self.k = 2**self.kgen - self.kgen -1
        self.n = 2**self.kgen -1
        self.G = self.genHammingMatrix()
        self.S = self.genInvertibleMatrix()
        self.P = self.genPermuteMatrix()
        self.Gcarat = np.matmul(np.matmul(self.S, self.G), self.P) % 2

    def genHammingMatrix(self):

        identity = np.identity(self.kgen)
        identityk = np.identity(self.k)
        left = np.zeros((self.kgen, 2**self.kgen - 1 - self.kgen)).T
        rowcount = 0
        for i in range(2**self.kgen):
            if i + 1 != 1:
                if (i + 1) & i != 0:
                    binarystring = np.binary_repr(i+1)
                    column = np.zeros((len(binarystring), 1))
                    for i in range(len(binarystring)):
                        column[-i - 1] = binarystring[i]
                    column = np.pad(column, (0, self.kgen - len(binarystring)), 'constant')
                    left[rowcount] = column.T[0]
                    rowcount += 1
        left = left.T
        self.paritycheck = np.block([left, identity])
        self.generator = np.block([identityk, np.transpose(left)])
        return self.generator

    def genInvertibleMatrix(self):

        S = np.random.randint(0,2,(self.k, self.k), dtype=np.uint)
        while np.linalg.det(S) == 0:
            S = np.random.randint(0,2,(self.k, self.k), dtype=np.uint)
        return S

    def genPermuteMatrix(self):
        P = np.identity(self.n, dtype=np.uint)
        return P[np.random.permutation(self.n)]


class Encoder:
    def __init__(self, m, g_prime, t=1):
        self.g_prime = g_prime
        self.message = m
        (k, n) = g_prime.shape
        self.k = k
        self.n = n
        self.t = t
        self.z = self.generate_errors()
        self.encoded = self.encode()

    def generate_errors(self):
        self.z = np.zeros(self.n)
        idx_list = np.random.choice(self.n, self.t, replace=False)
        for idx in idx_list:
            self.z[idx] = 1
        return self.z

    def encode(self):

        self.c_prime = np.matmul(self.message, self.g_prime) % 2
        c = (self.c_prime + self.z) % 2
        return c

    def get_message(self):
        return self.message

    def get_encrypted(self):
        return self.encoded


class decoder:
    def __init__(self, c, S, P, H, m):
        self.c = c
        self.S = S
        self.P = P
        self.H = H
        self.m = m
        self.decrypted = self.decrypt()
        self.correct = (self.m == self.decrypted)

    def decrypt(self):
        P_inv = np.linalg.inv(self.P)
        S_inv = np.linalg.inv(self.S)
        c_prime = np.matmul(self.c, P_inv)
        m_prime = self.error_correction(c_prime)
        decrypted = np.matmul(m_prime, S_inv) % 2
        return decrypted


    def error_correction(self, c_prime):
        parity = np.matmul(c_prime, np.transpose(self.H)) % 2
        parity_bits = np.ma.size(parity, 0)
        parity_total = 0
        for i in range(parity_bits):
            parity_total += 2**i * parity[i]

        if (int((parity_total - 1)) & int(parity_total)) == 0:
            return c_prime[0:(c_prime.size - parity_bits)]
        else:
            error_message = c_prime
            error_bit = int(parity_total - math.ceil(np.log2(parity_total)) - 1)
            if error_message[error_bit] == 1:
                error_message[error_bit] = 0
                return error_message[0:(c_prime.size - parity_bits)]
            elif error_message[error_bit] == 0:
                 error_message[error_bit] = 1
                 return error_message[0:(c_prime.size - parity_bits)]
            else:
                ...

    def is_correct(self):
        return self.correct8