from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwnlib.util.lists import group
from secrets import token_bytes
from string import printable


class Oracle:
    key = token_bytes(AES.block_size)
    unknown = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFu\
               ZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    unknown = b64decode(unknown)

    def encrypt(self, plaintext):
        if len(plaintext) == 0:
            raise ValueError
        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        plaintext = plaintext + self.unknown
        plaintext = pad(plaintext, AES.block_size)
        return aes_ecb.encrypt(plaintext)


def main():
    oracle = Oracle()
    A = 'A'
    block_size = 16
    found = b''

    start = 0
    window = block_size

    k = 0
    while True:
        # 0 - 15 and back
        padding_len = ((block_size - 1) - len(found)) % block_size
        # A * 16 + A * [15-0]
        initial = (A * block_size) + (A * padding_len)
        # 32 -> len(msg)
        end = start + window

        # len = 32
        # read 16:32, 48...
        # initial guess that will break the loop below
        initial_ciphertext = oracle.encrypt(initial.encode())[start:end]

        # check every byte
        matched = False
        for byte in range(0, 256):
            byte = bytes([byte])
            candidate = oracle.encrypt(initial.encode() + found + byte)[start:end]
            if initial_ciphertext == candidate:
                found = found + byte
                matched = True
                break

        if not matched:
            printtext = ''
            for char in found:
                char = chr(char)
                if char in printable:
                    printtext = printtext + char
            print(f'{printtext.rstrip()}')
            break

        # increase the size of window
        # start | window |
        # start |     window     |
        if len(found) > 0 and len(found) % block_size == 0: window = window + block_size


if __name__ == '__main__':
    main()
