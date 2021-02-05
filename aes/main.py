from aes import AES
import argparse


def main():
    parse = argparse.ArgumentParser(description="Advanced Encryption Standard Algorithm")
    parse.add_argument('key', help="Hexadecimal key")
    parse.add_argument('-t', '--type', choices=["enc", "dec", "both"], help="Encryption or description", required=True)
    parse.add_argument('-m', '--message', help="Message which needs to encode or decode", required=True)
    args = parse.parse_args()

    encryptor = AES(args.key)

    if args.type == "enc":
        encryptor.encrypt_128_hex_string(args.message)

    elif args.type == "dec":
        encryptor.decrypt_128_hex_string(args.message)

    elif args.type == "both":
        cipher = encryptor.encrypt_128_hex_string(args.message)
        encryptor.decrypt_128_hex_string(cipher)


if __name__ == '__main__':
    main()
