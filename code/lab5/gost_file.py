CHANGE_TABLE = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
]


def a_func(block):
    x4 = (block >> 192) & 0xFFFFFFFFFFFFFFFF
    x3 = (block >> 128) & 0xFFFFFFFFFFFFFFFF
    x2 = (block >> 64) & 0xFFFFFFFFFFFFFFFF
    x1 = block & 0xFFFFFFFFFFFFFFFF
    fin_block = ((x1 ^ x2) << 192) | (x4 << 128) | (x3 << 64) | x2
    return fin_block


def p_func(block):
    def fi_func(arg):
        i = arg & 0x03
        k = (arg >> 2) + 1
        fi = (i << 3) + k - 1
        return fi

    block_list = []
    for i in range(32):
        byte_value = (block >> (i * 8)) & 0xFF
        block_list.append(byte_value)

    fin_block = 0
    for i in range(31, -1, -1):
        fin_block = (fin_block << 8) | block_list[fi_func(i)]
    return fin_block


def f_func(block, h_in, change_table):
    def mix_func(block, h_in, s_enc):
        delta = block ^ psi_round(12, s_enc)
        beta = h_in ^ psi(delta)
        gamma = psi_round(61, beta)

        return gamma

    cs = [0, 0xff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00, 0]
    keys = []

    u = h_in
    v = block
    w = u ^ v
    keys.append(p_func(w))

    for i in range(2, 5):
        u = a_func(u) ^ cs[i - 2]
        v = a_func(a_func(v))
        w = u ^ v
        keys.append(p_func(w))

    h4 = (h_in >> 192) & 0xFFFFFFFFFFFFFFFF
    h3 = (h_in >> 128) & 0xFFFFFFFFFFFFFFFF
    h2 = (h_in >> 64) & 0xFFFFFFFFFFFFFFFF
    h1 = h_in & 0xFFFFFFFFFFFFFFFF

    s1 = encrypt_cycle(keys[0], h1, change_table)
    s2 = encrypt_cycle(keys[1], h2, change_table)
    s3 = encrypt_cycle(keys[2], h3, change_table)
    s4 = encrypt_cycle(keys[3], h4, change_table)
    s = (s4 << 192) | (s3 << 128) | (s2 << 64) | s1

    proto = mix_func(block, h_in, s)
    return proto


def psi(block):
    block_list = []
    for i in range(16):
        byte_value = (block >> (i * 16)) & 0xFFFF
        block_list.append(byte_value)

    fin_block = block_list[15]

    for i in range(14, -1, -1):
        fin_block = fin_block ^ block_list[i]

    for i in range(15):
        fin_block = (fin_block << 16) | block_list[i]

    return fin_block


def psi_round(amount, block):
    proto = block
    for i in range(amount):
        proto = psi(proto)

    return proto


def hash_gost(blocks, change_table, last_length):
    h = 0
    length = 0
    sum_contr = 0

    for i in range(len(blocks) - 1):
        h = f_func(blocks[i], h, change_table)
        length = (length + 256) % (2 ** 256)
        sum_contr = (sum_contr + blocks[i]) % (2 ** 256)

    length = (length + last_length) % (2 ** 256)
    sum_contr = (sum_contr + blocks[len(blocks) - 1]) % (2 ** 256)
    h = f_func(blocks[len(blocks) - 1], h, change_table)
    h = f_func(length, h, change_table)
    h = f_func(sum_contr, h, change_table)

    return h


def split_string_into_blocks(input_string, block_size_bits):
    blocks = []
    current_block = ""

    for char in input_string:
        char_binary = bin(int(char, 16))[2:].zfill(16)
        current_block += char_binary

        if len(current_block) >= block_size_bits:
            blocks.append(int(current_block, 2))
            current_block = ""

    if current_block:
        blocks.append(int(current_block, 2))

    return blocks, len(current_block)


def basic_crypt_step(part_key, block, change_table):
    module = 4294967296

    lower_32_bits = block & 0xFFFFFFFF
    upper_32_bits = (block >> 32) & 0xFFFFFFFF

    s = (lower_32_bits + part_key) % module

    sn = [(s >> (4 * i)) & 0xF for i in range(8)]

    for i in range(8):
        row = i
        col = sn[i]
        sn[i] = change_table[row][col]

    s = 0

    for i in range(8):
        s = (s << 4) | sn[i]

    s = ((s << 11) | (s >> (32 - 11))) & 0xFFFFFFFF

    s = s ^ upper_32_bits

    upper_32_bits = lower_32_bits
    lower_32_bits = s

    result = (lower_32_bits << 32) | upper_32_bits

    return result


def encrypt_cycle(key, block, change_table):
    keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]

    for i in range(24):
        key_index = i % 8
        block = basic_crypt_step(keys[key_index], block, change_table)

    for i in range(7, -1, -1):
        block = basic_crypt_step(keys[i], block, change_table)

    return block


def decrypt_cycle(key, block, change_table):
    keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]

    for i in range(8):
        block = basic_crypt_step(keys[i], block, change_table)

    for _ in range(3):
        for i in range(7, -1, -1):
            block = basic_crypt_step(keys[i], block, change_table)

    return block


def compute_gost_hash(input_string):
    bin_text = [hex(ord(elem)) for elem in input_string]
    blocks, last_len = split_string_into_blocks(bin_text, 256)
    return hex(hash_gost(blocks, CHANGE_TABLE, last_len))