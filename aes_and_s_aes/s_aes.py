import argparse

S_BOX = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]


class AES:
    # For 64-bit key - 2 words - 2 bytes
    initial_key = None

    # expanded key
    e_key = [0] * 6

    def __init__(self, key):
        assert type(key) == int, "Key must be 16-bit int"

        self.initial_key = key

        # expand encrypt key
        self._expand_key()

        print("Expanded key")
        print(self._str_x_2(self.e_key, 2))

    @staticmethod
    def _sub_nibble(state, box):
        return box[state >> 4] + (box[state & 0x0f] << 4)

    @staticmethod
    def _str_x_2(var, words=1):
        string = ""
        for i in zip(*[iter(var)] * words):
            for j in i:
                a, b = j & 0xf0, j & 0x0f
                string += "[" + " ".join(map(lambda x: f"{x:x}".upper().zfill(2), [a, b])) + "]"
            string += "\n"
        return string

    def _expand_key(self):
        rcon1, rcon2 = 0b10000000, 0b00110000

        self.e_key[0] = (self.initial_key & 0xff00) >> 8
        self.e_key[1] = self.initial_key & 0x00ff
        self.e_key[2] = self.e_key[0] ^ rcon1 ^ self._sub_nibble(self.e_key[1], S_BOX)
        self.e_key[3] = self.e_key[1] ^ self.e_key[2]
        self.e_key[4] = self.e_key[2] ^ rcon2 ^ self._sub_nibble(self.e_key[3], S_BOX)
        self.e_key[5] = self.e_key[3] ^ self.e_key[4]

    @staticmethod
    def _left_shift_rows(s):
        return [s[0], s[1], s[3], s[2]]

    @staticmethod
    def _sub_bytes(s, box):
        return [box[i] for i in s]

    @staticmethod
    def _multiply(p1, p2):
        ret = 0
        while p2:
            if p2 & 0b1:
                ret ^= p1
            p1 <<= 1
            if p1 & 0b10000:
                p1 ^= 0b11
            p2 >>= 1
        return ret & 0b1111

    def _mix_columns(self, s):
        return [s[0] ^ self._multiply(4, s[2]), s[1] ^ self._multiply(4, s[3]),
                s[2] ^ self._multiply(4, s[0]), s[3] ^ self._multiply(4, s[1])]

    @staticmethod
    def _add_key(state, key):
        return [i ^ j for i, j in zip(state, key)]

    def encrypt_128_hex_string(self, message):
        hex_message = []
        for i in range(0, len(message), 2):
            hex_message.append(int(message[i:i + 2], 16))

        cipher = ""
        for i in zip(*[iter(hex_message)] * 2):
            cipher += "".join(map(lambda x: f"{x:x}".upper().zfill(2), self.encrypt_hex(i))) + " "
        return cipher

    @staticmethod
    def _validate_hex(input_, v_name="Message"):
        assert type(input_) == tuple, f"{v_name} should be list of hexadecimal values"

        for i, k in enumerate(input_):
            assert type(k) == int and 0 <= k < 256, f"Invalid hex {k} at {i + 1} in {input_}"

        assert len(input_) == 2, f"Block size should be 16 bytes (128-bits) in {v_name}"

    def _print_state(self, message, s):
        print(message)
        string = f"[{s[0]:x} {s[1]:x}]\n[{s[2]:x} {s[3]:x}]"
        print(string)

    @staticmethod
    def _int_to_vec(n):
        return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]

    @staticmethod
    def _vec_to_int(m):
        return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

    def encrypt_hex(self, message):
        self._validate_hex(message, v_name="Message")

        number = message[0] << 8 | message[1]

        state = self._int_to_vec(number)
        print()
        self._print_state("Message", state)

        # Round 0
        number = ((self.e_key[0] << 8) + self.e_key[1]) ^ number
        state = self._int_to_vec(number)

        self._print_state("Round 0", state)

        # Round 1
        state = self._sub_bytes(state, S_BOX)
        state = self._left_shift_rows(state)
        state = self._mix_columns(state)
        state = self._add_key(state, self._int_to_vec((self.e_key[2] << 8) + self.e_key[3]))
        self._print_state("Round 1", state)

        # Round 2

        state = self._sub_bytes(state, S_BOX)
        state = self._left_shift_rows(state)
        state = self._add_key(state, self._int_to_vec((self.e_key[4] << 8) + self.e_key[5]))
        self._print_state("Round 2", state)

        return [state[0] << 4 | state[2], state[1] << 4 | state[3]]


def main():
    parse = argparse.ArgumentParser(description="Simplified AES")
    parse.add_argument('key', help="Binary key")
    parse.add_argument('-m', '--message', help="Message which needs to encode or decode", required=True)
    args = parse.parse_args()

    encryptor = AES(int(args.key, 2))

    enc = encryptor.encrypt_128_hex_string(args.message)
    print(enc)


if __name__ == "__main__":
    main()
