import sys
import os
import time
import requests
import uuid
import hashlib
import traceback
from requests_toolbelt.multipart.encoder import MultipartEncoder
# Warning: this import code is modified because of the library name changed in Python 3.12
# Please be noticed and modify it if you are running this code in a different environment
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher

class UploadFile(object):
    def __init__(self, url: str, filepath: str) -> None:
        self.url = url

        self.file_path = filepath
        if not os.path.exists(filepath):
            print("File path invalid. Program exiting.")
            sys.exit()

        self.filename = os.path.basename(self.file_path)
        self.filesize = os.path.getsize(self.file_path)
        if self.filesize >= 1024 ** 2 * 256:
            print("Warning: File size larger than 256 MB.")
        with open(filepath, 'rb') as f:
            self.file_content = f.read()
        print("Read file success.")
        self.timestamp = int(time.time())

    def encode_filename(self):
        self.encoded_filename = []
        for char in self.filename:
            self.encoded_filename.append(ord(char) ^ (self.timestamp % 2048))
        print("Encode filename success.")

    def upload_file_data(self):
        self.file_uuid = str(uuid.uuid4())
        file_hash = hashlib.md5(self.file_content).hexdigest()
        print(
            f"Uploading file data:\nFilename: {self.filename}\nEncoded Filename: {self.encoded_filename}\nFile size: {self.filesize} Bytes\nFile hash: {file_hash}\nFile UUID: {self.file_uuid}")
        data = {
            "file_uuid": self.file_uuid,
            "file_hash": file_hash,
            "file_name": self.encoded_filename,
            "timestamp": self.timestamp
        }

        response = requests.post(self.url + "upload_file_data", json=data).json()
        print(f"Response: {response}")
        if response["upload_file"] == False:
            print("Server rejected file. Program exiting.")
            sys.exit(0)

        self.public_key = response["public_key"]
        print(f"Successfully got RSA public key from server: {self.public_key}")


    def encrypt_file(self):
        print("Encrypting file...")
        cipher = PKCS1_cipher.new(RSA.import_key(self.public_key))
        self.encrypted_file_content = cipher.encrypt(self.file_content)
        print("Encryption completed.")

    def send_file(self):
        print("Sending file to server...")
        multipart_data = MultipartEncoder(
            fields={
                'files': (self.file_uuid, self.encrypted_file_content, 'application/octet-stream')
            }
        )

        response = requests.post(self.url + "upload_ppt", data=multipart_data,
                                 headers={'Content-Type': multipart_data.content_type}).json()
        print(response)
        print("Successfully sent.")

    def run(self):
        self.encode_filename()
        self.upload_file_data()
        self.encrypt_file()
        self.send_file()


if __name__ == "__main__":
    try:
        file_path = sys.argv[1]
        print(f"Sys Argv received: {file_path}")
        uf_obj = UploadFile("http://127.0.0.1:1463/", file_path)
        uf_obj.run()
    except Exception as e:
        try:
            print("Exception caught.")
            print(f"{traceback.format_exc()}")
        except:
            sys.exit()
