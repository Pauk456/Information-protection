import os
from struct import pack, unpack

def salsa20_quarter_round(a, b, c, d):
    a ^= (b + d) << 7  | (b + d) >> (32 - 7)
    d ^= (a + c) << 9  | (a + c) >> (32 - 9)
    c ^= (d + b) << 13 | (d + b) >> (32 - 13)
    b ^= (c + a) << 18 | (c + a) >> (32 - 18)
    return a, b, c, d

def salsa20_column_round(state):
    state[4], state[0], state[12], state[8] = salsa20_quarter_round(state[4], state[0], state[12], state[8])
    state[9], state[5], state[1], state[13] = salsa20_quarter_round(state[9], state[5], state[1], state[13])
    state[14], state[10], state[6], state[2] = salsa20_quarter_round(state[14], state[10], state[6], state[2])
    state[3], state[15], state[11], state[7] = salsa20_quarter_round(state[3], state[15], state[11], state[7])

def salsa20_row_round(state):
    state[1], state[5], state[9], state[13] = salsa20_quarter_round(state[1], state[5], state[9], state[13])
    state[2], state[6], state[10], state[14] = salsa20_quarter_round(state[2], state[6], state[10], state[14])
    state[3], state[7], state[11], state[15] = salsa20_quarter_round(state[3], state[7], state[11], state[15])
    state[0], state[4], state[8], state[12] = salsa20_quarter_round(state[0], state[4], state[8], state[12])

def salsa20_core(block, rounds=20):
    x = block[:]
    for _ in range(rounds // 2):
        salsa20_column_round(x)
        salsa20_row_round(x)
    return [(x[i] + block[i]) & 0xffffffff for i in range(16)]

def expand_32byte_key_to_state(key, nonce, counter):
    sigma = b"expand 32-byte k"
    state = [
        unpack('<I', sigma[0:4])[0],
        unpack('<I', key[0:4])[0],
        unpack('<I', key[4:8])[0],
        unpack('<I', key[8:12])[0],
        unpack('<I', key[12:16])[0],
        unpack('<I', sigma[4:8])[0],
        unpack('<I', nonce[0:4])[0],
        unpack('<I', nonce[4:8])[0],
        unpack('<I', counter[0:4])[0],
        unpack('<I', counter[4:8])[0],
        unpack('<I', sigma[8:12])[0],
        unpack('<I', key[16:20])[0],
        unpack('<I', key[20:24])[0],
        unpack('<I', key[24:28])[0],
        unpack('<I', key[28:32])[0],
        unpack('<I', sigma[12:16])[0],
    ]
    return state

def salsa20_keystream_bytes(key, nonce, length):
    keystream = b""
    counter = 0
    while len(keystream) < length:
        counter_bytes = pack('<Q', counter)
        state = expand_32byte_key_to_state(key, nonce, counter_bytes)
        output = salsa20_core(state)
        block = b"".join(pack('<I', w) for w in output)
        keystream += block
        counter += 1
    return keystream[:length]

def salsa20_encrypt(plaintext: str, key: bytes, nonce: bytes) -> bytes:
    plaintext_bytes = plaintext.encode('utf-8')
    ks = salsa20_keystream_bytes(key, nonce, len(plaintext_bytes))
    return bytes(a ^ b for a, b in zip(plaintext_bytes, ks))

def salsa20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> str:
    ks = salsa20_keystream_bytes(key, nonce, len(ciphertext))
    plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, ks))
    return plaintext_bytes.decode('utf-8')

if __name__ == "__main__":
    key = os.urandom(32)
    nonce = os.urandom(8)

    msg = "Какой-то зашифрованыый текст dfguyhdisfakulgiufsadiosdf !21389 789789SAHCfcvbnmoipyhiuophoias fd _-- @4123 "
    ct = salsa20_encrypt(msg, key, nonce)
    pt = salsa20_decrypt(ct, key, nonce)

    print("\nИсходное:", msg)
    print("\nКлюч:", key)
    print("\nЗашифровано:", ct.hex())
    print("\nРасшифровано:", pt)
