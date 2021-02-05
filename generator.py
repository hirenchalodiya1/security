import hashlib
import argparse
import time

SECRET_KEY = "h^m#zf4l0pv^!w!e$jf-=7*!sonz@thaw$f^#6&+dl68-8qf#$"


def main():
    parse = argparse.ArgumentParser(description="Password generator")
    parse.add_argument('password', help="message")
    args = parse.parse_args()

    h = hashlib.sha512()
    addition = str(time.time()) + SECRET_KEY

    raw_password = args.password + addition
    h.update(bytes(raw_password, 'utf-8'))

    print("Hash password:")
    print(h.hexdigest())


if __name__ == "__main__":
    main()
