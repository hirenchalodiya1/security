import argparse

S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

R_CON = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


class AES:
    # Key length in bytes
    key_length = None

    # Number of column in AES state
    Nb = 4

    # Number of 32 bit word in key
    Nk = None

    # Number of cipher round
    Nr = None

    # List of 32 bit words
    # For 128-bit key - 4 words - 16 bytes
    # For 192-bit key - 6 words - 24 bytes
    # For 256-bit key - 8 words - 32 bytes
    initial_key = []

    # List of 32-bit words
    expanded_key = []

    def __init__(self, key, hex_init=False):
        if not hex_init:
            assert type(key) == str, "Key should be string"
            assert len(key) in [32, 48, 64], "key size should be one of these (128-bit, 192-bit, 256-bit)"

            hex_key = []
            for i in range(0, len(key), 2):
                hex_key.append(int(key[i:i + 2], 16))

            self.init_hex_key(hex_key)
        else:
            self.init_hex_key(key)

    def init_hex_key(self, key):
        assert type(key) == list, "Key should be list of hexadecimal values"

        for i, k in enumerate(key):
            assert type(k) == int and 0 <= k < 256, f"Value at position {i + 1} ({k}) is not valid hexadecimal value"

        if len(key) == 16:
            self.key_length = 16
            self.Nk = 4
            self.Nr = 10

        elif len(key) == 24:
            self.key_length = 24
            self.Nk = 6
            self.Nr = 12

        elif len(key) == 32:
            self.key_length = 32
            self.Nk = 8
            self.Nr = 14

        else:
            raise Exception("Invalid key size")

        # initialize key
        self._init_key(key)

        # expand encrypt key
        self._expand_key()

        print("Expanded key")
        print(self._str_x_4(self.expanded_key, 4))

    @staticmethod
    def _str_x_4(var, words=1):
        string = ""
        for i in zip(*[iter(var)] * words):
            for j in i:
                string += "[" + " ".join(map(lambda x: f"{x:x}".upper().zfill(2), j)) + "] "
            string += "\n"
        return string

    def _init_key(self, key):
        for i in range(self.Nk):
            word = key[i * 4: i * 4 + 4]
            self.initial_key.append(word)

    def _expand_key(self):
        self.expanded_key = self.initial_key

        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            prev_key = self.expanded_key[-1]

            a, b, c, d = prev_key

            if i % self.Nk == 0:
                # Root word
                a, b, c, d = b, c, d, a
                # Sub Word
                a, b, c, d = S_BOX[a], S_BOX[b], S_BOX[c], S_BOX[d]
                # Round word
                a = a ^ R_CON[i // self.Nk]
            if self.key_length == 32 and i % self.Nk == 4:
                a, b, c, d = S_BOX[a], S_BOX[b], S_BOX[c], S_BOX[d]

            direct_key = self.expanded_key[-self.Nk]

            new_key = [a ^ direct_key[0], b ^ direct_key[1], c ^ direct_key[2], d ^ direct_key[3]]

            self.expanded_key.append(new_key)

    def _add_round_key(self, state, round_no):
        for i in range(4):
            key = self.expanded_key[round_no * 4 + i]
            for j in range(4):
                state[i][j] ^= key[j]

    @staticmethod
    def _sub_bytes(state, box):
        for i in range(4):
            for j in range(4):
                state[i][j] = box[state[i][j]]

    @staticmethod
    def _left_shift_rows(state):
        # Rotate second row by 1
        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]

        # Rotate third row by 2
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]

        # Rotate fourth row by 3
        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

    @staticmethod
    def _right_shift_rows(state):
        # Rotate second row by 1
        state[0][1], state[1][1], state[2][1], state[3][1] = state[3][1], state[0][1], state[1][1], state[2][1]

        # Rotate third row by 2
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]

        # Rotate fourth row by 3
        state[0][3], state[1][3], state[2][3], state[3][3] = state[1][3], state[2][3], state[3][3], state[0][3]

    @staticmethod
    def _xtime(x):
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1B)) & 0b11111111

    def _mix_columns(self, state):
        for i in range(4):
            t = state[i][0]
            tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]

            state[i][0] ^= self._xtime(state[i][0] ^ state[i][1]) ^ tmp
            state[i][1] ^= self._xtime(state[i][1] ^ state[i][2]) ^ tmp
            state[i][2] ^= self._xtime(state[i][2] ^ state[i][3]) ^ tmp
            state[i][3] ^= self._xtime(state[i][3] ^ t) ^ tmp

    def _multiply(self, x, y):
        return (((y & 1) * x) ^
                ((y >> 1 & 1) * self._xtime(x)) ^
                ((y >> 2 & 1) * self._xtime(self._xtime(x))) ^
                ((y >> 3 & 1) * self._xtime(self._xtime(self._xtime(x)))))

    def _inverse_mix_column(self, state):
        def mul(x, y):
            return self._multiply(x, y)

        for i in range(4):
            a, b, c, d = state[i]

            state[i][0] = mul(a, 0x0E) ^ mul(b, 0x0B) ^ mul(c, 0x0D) ^ mul(d, 0x09)
            state[i][1] = mul(a, 0x09) ^ mul(b, 0x0E) ^ mul(c, 0x0B) ^ mul(d, 0x0D)
            state[i][2] = mul(a, 0x0D) ^ mul(b, 0x09) ^ mul(c, 0x0E) ^ mul(d, 0x0B)
            state[i][3] = mul(a, 0x0B) ^ mul(b, 0x0D) ^ mul(c, 0x09) ^ mul(d, 0x0E)

    def encrypt_128_hex_string(self, message):
        hex_message = []
        for i in range(0, len(message), 2):
            hex_message.append(int(message[i:i + 2], 16))
        cipher = self.encrypt_hex(hex_message)
        return "".join(map(lambda x: f"{x:x}".upper().zfill(2), cipher))

    def decrypt_128_hex_string(self, cipher):
        hex_cipher = []
        for i in range(0, len(cipher), 2):
            hex_cipher.append(int(cipher[i:i + 2], 16))
        message = self.decrypt_hex(hex_cipher)
        return "".join(map(lambda x: f"{x:x}".upper().zfill(2), message))

    @staticmethod
    def _validate_hex(input_, v_name="Message"):
        assert type(input_) == list, f"{v_name} should be list of hexadecimal values"

        for i, k in enumerate(input_):
            assert type(k) == int and 0 <= k < 256, f"Invalid hex {k} at {i + 1} in {input_}"

        assert len(input_) == 16, f"Block size should be 16 bytes (128-bits) in {v_name}"

    def _print_state(self, message, state):
        print(message)
        print(self._str_x_4(state, 1))

    def encrypt_hex(self, message):
        self._validate_hex(message, v_name="Message")

        state = [message[:4], message[4:8], message[8:12], message[12:]]

        self._print_state("Message", state)

        self._add_round_key(state, 0)

        self._print_state("Round 0", state)

        for i in range(1, self.Nr + 1):
            self._sub_bytes(state, S_BOX)
            self._left_shift_rows(state)

            if i == self.Nr:
                self._add_round_key(state, self.Nr)
                break

            self._mix_columns(state)
            self._add_round_key(state, i)

            self._print_state(f"Round {i}", state)

        self._print_state(f"Round {self.Nr}", state)

        cipher = []
        for i in state:
            cipher.extend(i)
        return cipher

    def decrypt_hex(self, cipher):
        self._validate_hex(cipher, v_name="Cipher")

        state = [cipher[:4], cipher[4:8], cipher[8:12], cipher[12:]]

        self._print_state("Cipher", state)

        self._add_round_key(state, self.Nr)

        self._print_state(f"Round {self.Nr}", state)

        for i in range(self.Nr - 1, -1, -1):
            self._right_shift_rows(state)
            self._sub_bytes(state, INV_S_BOX)
            self._add_round_key(state, i)

            if i == 0:
                break

            self._inverse_mix_column(state)

            self._print_state(f"Round {i}", state)

        self._print_state(f"Round 0", state)

        message = []
        for i in state:
            message.extend(i)
        return message


def main():
    parse = argparse.ArgumentParser(description="Advanced Encryption Standard Algorithm")
    parse.add_argument('key', help="Hexadecimal key")
    parse.add_argument('-t', '--type', choices=["enc", "dec", "both"], help="Encryption or description", required=True,
                       default='both')
    parse.add_argument('-m', '--message', help="Message which needs to encode or decode", required=True)
    args = parse.parse_args()

    encryptor = AES(args.key)

    if args.type == "enc":
        encryptor.encrypt_128_hex_string(args.message)

    elif args.type == "dec":
        encryptor.decrypt_128_hex_string(args.message)

    elif args.type == "both":
        cipher = encryptor.encrypt_128_hex_string(args.message)
        derypt = encryptor.decrypt_128_hex_string(cipher)
        if args.message == derypt:
            print("Algorithm works!!")


if __name__ == "__main__":
    main()
