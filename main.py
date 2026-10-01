from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import sys
import os
import json
from base64 import urlsafe_b64encode

def main(input_file, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations = 600000
    )
    key = urlsafe_b64encode(kdf.derive(bytes(password, 'UTF-8')))
    with open(input_file, "rb") as f:
        data = f.read()
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(data)
    with open("./timtable_enc.json", "w") as file:
        file.write(json.dumps({
            "salt": salt.hex(),
            "iterations": 600000,
            "key_algorithm": "pbkdf2-sha256",
            "ciphertext": ciphertext.hex(),
            "ciphertext_algorithm": "fernet"
        }))

if __name__ == "__main__":
    main(f'./{sys.argv[1]}.json', str(sys.argv[2]))