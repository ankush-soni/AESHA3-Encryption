import time,sys
import numpy as np
from BitVector import BitVector

AES_modulus = BitVector(bitstring='100011011')

# S-Box and Rcon
SBOX = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def gee(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_128(key_bv):
    byte_sub_table = SBOX
    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32: i*32+32]
    for i in range(4, 44):
        if i % 4 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]
    return key_words

def gen_key_schedule_192(key_bv):
    byte_sub_table = SBOX
    key_words = [None for i in range(52)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(6):
        key_words[i] = key_bv[i*32: i*32+32]
    for i in range(6, 52):
        if i % 6 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-6] ^ kwd
        else:
            key_words[i] = key_words[i-6] ^ key_words[i-1]
    return key_words

def gen_key_schedule_256(key_bv):
    byte_sub_table = SBOX
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32: i*32+32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i // 8) * 8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i // 8) * 8) == 4:
            key_words[i] = BitVector(size=0)
            for j in range(4):
                key_words[i] += BitVector(intVal=byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size=8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
    return key_words

# AES Core Functions
def sub_bytes(state, sbox):
    return np.vectorize(lambda x: sbox[x])(state)

def shift_rows(state):
    state[1] = np.roll(state[1], -1)
    state[2] = np.roll(state[2], -2)
    state[3] = np.roll(state[3], -3)
    return state

def mix_columns(state):
    for i in range(4):
        col = state[:, i]
        state[0, i] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3]
        state[1, i] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3]
        state[2, i] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3])
        state[3, i] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3])
    return state

def add_round_key(state, round_key):
    # Convert each 32-bit word in the key_schedule to four 8-bit integers manually
    round_key_bytes = np.array([word[i*8:(i+1)*8].intValue() for word in round_key for i in range(4)], dtype=np.uint8)
    round_key_matrix = round_key_bytes.reshape(4, 4)
    return state ^ round_key_matrix

def gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = (a << 1) ^ 0x1B if a & 0x80 else a << 1
        b >>= 1
    return p & 0xFF

# AES Encryption Function
def aes_encrypt(plain_text, key_schedule, num_rounds):
    state = np.array([plain_text[i:i + 4] for i in range(0, 16, 4)], dtype=np.uint8)
    
    state = add_round_key(state, key_schedule[:4])
    
    for round_num in range(1, num_rounds):
        state = sub_bytes(state, SBOX)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule[round_num*4:(round_num+1)*4])
    
    state = sub_bytes(state, SBOX)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule[num_rounds*4:])
    
    return state

# Generate Data for Performance Testing
def generate_data(size_in_kb):
    return np.random.randint(0, 256, size_in_kb * 1024, dtype=np.uint8)

# Measure the performance of AES
def benchmark_aes(data_size, key_schedule, num_rounds):
    data = generate_data(data_size)
    start_time = time.time()
    
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        aes_encrypt(block, key_schedule, num_rounds)
    
    end_time = time.time()
    return (end_time - start_time) * 1000

# Main function to test the encryption performance
def main_benchmark():
    keysize = int(input("Key Size (128, 192, 256): "))
    passphrase = "The quick brown fox jumped over the lazy dogs."
    key_bv = BitVector(textstring=passphrase)
    
    if keysize == 128:
        key_schedule = gen_key_schedule_128(key_bv[:128])  # Use first 128 bits
        num_rounds = 10
    elif keysize == 192:
        key_schedule = gen_key_schedule_192(key_bv[:192])  # Use first 192 bits
        num_rounds = 12
    elif keysize == 256:
        key_schedule = gen_key_schedule_256(key_bv[:256])  # Use first 256 bits
        num_rounds = 14
    else:
        raise ValueError("Invalid key size")

    data_sizes_kb = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]
    
    for data_size in data_sizes_kb:
        encryption_time = benchmark_aes(data_size, key_schedule, num_rounds)
        print(f"Data Size: {data_size} KB, Encryption Time: {encryption_time:.2f} ms")

# Call the benchmarking function
main_benchmark()