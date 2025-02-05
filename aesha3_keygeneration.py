# key_generation.py
from SHA_3_1600_variableInput_Final import *

def randomize_alt(res, start, length):
    seed = start
    need = ''
    while len(need) != length:
        if seed >= len(res):
            seed = start + 1
        need += res[seed]
        seed += 2
    return need

def generate_keys(keccak, user, aes_version):
    original_hash1 = keccak.get_hash_of(user.encode('utf-8')).decode('utf-8')
    
    if aes_version == 128:
        combined_hash = original_hash1
        needed_bits = 1408
        key_names = ["K" + str(i) for i in range(1, 11 + 1)]
    else:
        original_hash2 = keccak.get_hash_of((user + "salt").encode('utf-8')).decode('utf-8')
        combined_hash = original_hash1 + original_hash2  # 3200 bits
        
        if aes_version == 192:
            needed_bits = 1664
            key_names = ["K" + str(i) for i in range(1, 13 + 1)]
        elif aes_version == 256:
            needed_bits = 1920
            key_names = ["K" + str(i) for i in range(1, 15 + 1)]
        else:
            raise ValueError("Unsupported AES version")

    random_output = randomize_alt(combined_hash, 0, needed_bits)
    
    dict_key = {}
    i = 0
    for k in key_names:
        dict_key[k] = random_output[i:i+32]
        i += 32

    return dict_key

# Unit Tests Combined in the Same File

import unittest

class TestKeyGeneration(unittest.TestCase):

    def setUp(self):
        self.keccak = Keccak_1600_custom(576)
        self.user_passphrase = "test_passphrase"

    def test_aes128_key_generation(self):
        keys = generate_keys(self.keccak, self.user_passphrase, 128)
        self.assertEqual(len(keys), 11)
        for key in keys.values():
            self.assertEqual(len(key), 32)

    def test_aes192_key_generation(self):
        keys = generate_keys(self.keccak, self.user_passphrase, 192)
        self.assertEqual(len(keys), 13)
        for key in keys.values():
            self.assertEqual(len(key), 32)

    def test_aes256_key_generation(self):
        keys = generate_keys(self.keccak, self.user_passphrase, 256)
        self.assertEqual(len(keys), 15)
        for key in keys.values():
            self.assertEqual(len(key), 32)

if __name__ == '__main__':
    unittest.main()
