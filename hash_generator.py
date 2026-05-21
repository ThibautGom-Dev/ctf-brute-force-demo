import hashlib
import argparse
import sys


def generate_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHA-256 Hash Generator for CTF targets")
    parser.add_argument('password', nargs='?', help='Password to hash (prompts if omitted)')
    args = parser.parse_args()

    password = args.password if args.password else input("Enter the password to hash: ")

    hash_result = generate_hash(password)

    print(f"\nSHA-256 for '{password}':")
    print(hash_result)
    print("\n--- Next steps ---")
    print(f"1. Copy into hashes.txt:\n   {hash_result}")
    print(f"\n2. Replace in index.html:\n   xxxx...xxxx  →  {hash_result}")
