# https://github.com/junorouse/hwp-password-recover/blob/master/password.py
import hashlib


def genkey(pwd):
    buf = bytearray(160)
    password = bytearray(pwd)

    for i in range(0, len(password)):
        if i:
            v6 = password[i - 1]
        else:
            v6 = 0xEC

        v7 = (2 * v6 | (v6 >> 7)) & 0xFF

        buf[i * 2] = v7
        buf[i * 2 + 1] = password[i]

    sha1 = hashlib.sha1()
    sha1.update(str(buf).replace("\x00", ""))
    h = sha1.hexdigest()

    return h[:32].decode("hex")
