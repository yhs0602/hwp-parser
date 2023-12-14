from Crypto.Cipher import AES
from genkey import genkey

BLOCK_SIZE = 16
pad = (
    lambda s: s
    + (BLOCK_SIZE - len(s) % BLOCK_SIZE)
    * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode()
)
unpad = lambda s: s[: -s[-1]]


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw_padded = pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(raw_padded)

    def decrypt(self, enc):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted = cipher.decrypt(enc)
        return unpad(decrypted)


def gogo(pwd, data, is_encrypt=True):
    final_data = b""
    TMP_IN = bytearray(16)

    for kkk in range(0, len(data), 16):
        REAL_INPUT = bytearray(data[kkk : kkk + 16])

        for i in range(128):
            OUT = AESCipher(pwd).encrypt(TMP_IN)

            OUT = OUT[0]

            ff = i & 7

            if is_encrypt:
                REAL_INPUT[i >> 3] ^= (OUT & 0x80) >> (i & 7)

            tmp = 1
            for j in range(3):
                v14 = TMP_IN[tmp]

                TMP_IN[tmp - 1] = ((2 * TMP_IN[tmp - 1]) & 0xFF) | (TMP_IN[tmp] >> 7)
                v15 = TMP_IN[tmp + 1]
                v16 = ((2 * v14) & 0xFF) | (TMP_IN[tmp + 1] >> 7)

                v17 = TMP_IN[tmp + 2]
                TMP_IN[tmp] = v16
                v18 = ((2 * v15) & 0xFF) | (v17 >> 7)

                v19 = TMP_IN[tmp + 3]
                TMP_IN[tmp + 1] = v18
                v20 = ((2 * v17) & 0xFF) | (v19 >> 7)

                v21 = ((2 * v19) & 0xFF) | (TMP_IN[tmp + 4] >> 7)

                TMP_IN[tmp + 2] = v20
                TMP_IN[tmp + 3] = v21

                tmp += 5

            if is_encrypt:
                TMP_IN[15] = ((2 * TMP_IN[15]) & 0xFF) | (
                    REAL_INPUT[i >> 3] >> (7 - ff)
                )
            else:
                TMP_IN[15] = ((2 * TMP_IN[15]) & 0xFF) | (
                    REAL_INPUT[i >> 3] >> (7 - ff)
                ) & 1

            if not is_encrypt:
                REAL_INPUT[i >> 3] ^= (OUT & 0x80) >> (i & 7)

        if is_encrypt:
            final_data += bytes(TMP_IN)
            print(bytes(REAL_INPUT).hex())
        else:
            final_data += bytes(REAL_INPUT)

    return final_data


if __name__ == "__main__":
    pwd = bytes.fromhex("40fc1ff828306c3ab4efc6df53939455")
    pwd = genkey("asdfasdf")

    user_input = input("input: ").strip().encode()
    enc = gogo(pwd, pad(user_input))
    print("enc: ", enc.hex())

    with open("wowmem", "rb") as file:
        data = file.read()
    plain = gogo(pwd, data, False)
    print("plain: ", plain.hex())
