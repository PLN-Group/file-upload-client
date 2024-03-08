import sys
import os
import time
import requests
import urllib.parse
import uuid
import hashlib
from requests_toolbelt.multipart.encoder import MultipartEncoder
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher


def read_file(file_path):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    return file_content


def upload_file_data():
    file_uuid = str(uuid.uuid4())
    file_hash = hashlib.md5()


def encode_file(url, file_content):
    public_key = requests.post(url + "get_public_key").json()["public_key"]
    cipher = PKCS1_cipher.new(RSA.import_key(public_key))
    encrypted_file = cipher.encrypt(file_content)

    return encrypted_file


def send_file(url, file, file_path):
    basename = os.path.basename(file_path)
    encoded_basename = urllib.parse.quote_plus(basename)
    print(encoded_basename)

    multipart_data = MultipartEncoder(
        fields={
            'files': (encoded_basename, file, 'application/octet-stream')
        }
    )

    response = requests.post(url + "upload_ppt", data=multipart_data,
                             headers={'Content-Type': multipart_data.content_type})

    print(file_path)
    print(response.text)

    return response.status_code, response.text


def main(url, file_path):
    file_content = read_file(file_path)
    file_content = encode_file(url, file_content)
    send_file(url, file_content, file_path)


if __name__ == "__main__":
    file_path = sys.argv[1]
    print(file_path)
    main("http://127.0.0.1:1463/", file_path)