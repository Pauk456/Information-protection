from struct import pack, unpack

S = [
    252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250,
    218,  35, 197,   4,  77, 233, 119, 240, 219, 147,  46,
    153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 249,
    24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66,
    139,   1, 142,  79,   5, 132,   2, 174, 227, 106, 143,
    160,   6,  11, 237, 152, 127, 212, 211,  31, 235,  52,
    44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,
    58, 206, 204, 181, 112,  14,  86,   8,  12, 118,  18,
    191, 114,  19,  71, 156, 183,  93, 135,  21, 161, 150,
    41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
    178, 177,  50, 117,  25,  61, 255,  53, 138, 126, 109,
    84, 198, 128, 195, 189,  13,  87, 223, 245,  36, 169,
    62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,
    3, 224,  15, 236, 222, 122, 148, 176, 188, 220, 232,
    40,  80,  78,  51,  10,  74, 167, 151,  96, 115,  30,
    0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
    173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165,
    125, 105, 213, 149,  59,   7,  88, 179,  64, 134, 172,
    29, 247,  48,  55, 107, 228, 136, 217, 231, 137, 225,
    27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144,
    202, 216, 133,  97,  32, 113, 103, 164,  45,  43,   9,
    91, 203, 155,  37, 208, 190, 229, 108,  82,  89, 166,
    116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,
    75,  99, 182
]


MASK128 = (1 << 128) - 1

def rol128(x, n):
    return ((x << n) & MASK128) | (x >> (128 - n))

def L(X):
    X &= MASK128
    return X ^ rol128(X, 1) ^ rol128(X, 8) ^ rol128(X, 2)

def L_inv(X):
    X &= MASK128
    for _ in range(15):
        X = L(X)
    return X

def Pi(X):
    out = 0
    for i in range(16):
        out |= S[(X >> (8 * i)) & 0xFF] << (8 * i)
    return out

def key_schedule(master_key):
    K1 = (master_key >> 128) & MASK128
    K2 = master_key & MASK128

    C = []
    for i in range(10):
        shift = (128 - 8 * i) % 128
        C.append((1 << shift) & MASK128)

    K = [0] * 10
    K[0] = K1
    K[1] = K2
    for i in range(2, 10):
        temp = (K[i-2] ^ C[i-2]) & MASK128
        K[i] = (L(Pi(temp)) ^ K[i-1]) & MASK128
    return K

def encrypt_block(block, master_key):
    K = key_schedule(master_key)
    X = block & MASK128
    for i in range(9):
        X ^= K[i]
        X = Pi(X)
        X = L(X)
    X ^= K[9]
    return X & MASK128

def decrypt_block(block, master_key):
    K = key_schedule(master_key)
    X = block & MASK128
    X ^= K[9]
    for i in range(8, -1, -1):
        X = L_inv(X)
        X = Pi(X)
        X ^= K[i]
    return X & MASK128

def encrypt_file(infile, outfile, key_bytes):
    assert len(key_bytes) == 32, "Ключ должен быть 32 байта (256 бит)"
    key = int.from_bytes(key_bytes, 'big')
    with open(infile, 'rb') as f:
        data = f.read()
    assert len(data) % 16 == 0, "Длина файла должна быть кратна 16 байтам!"
    out = b""
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i+16], 'big')
        enc = encrypt_block(block, key)
        out += enc.to_bytes(16, 'big')
    with open(outfile, 'wb') as f:
        f.write(out)

def decrypt_file(infile, outfile, key_bytes):
    assert len(key_bytes) == 32, "Ключ должен быть 32 байта (256 бит)"
    key = int.from_bytes(key_bytes, 'big')
    with open(infile, 'rb') as f:
        data = f.read()
    assert len(data) % 16 == 0, "Длина файла должна быть кратна 16 байтам!"
    out = b""
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i+16], 'big')
        dec = decrypt_block(block, key)
        out += dec.to_bytes(16, 'big')
    with open(outfile, 'wb') as f:
        f.write(out)

def hash_kuz(message: bytes) -> bytes:
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) % 16 != 0:
        padded.append(0x00)
    
    H = 0
    
    for i in range(0, len(padded), 16):
        block = int.from_bytes(padded[i:i+16], 'big')
        encrypted = encrypt_block(H, block)
        H ^= encrypted
        H &= MASK128
    
    H = encrypt_block(H, H)
    
    return H.to_bytes(16, 'big')

if __name__ == "__main__":
    with open("plaintext.txt", "wb") as f:
        f.write(b"1234567890123456")

    key = b"12345678901234567890123456789012"

    encrypt_file("plaintext.txt", "ciphertext.kuz", key)
    decrypt_file("ciphertext.kuz", "decrypted.txt", key)

