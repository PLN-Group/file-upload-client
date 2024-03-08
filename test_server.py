

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import os
import uuid
import hashlib
import json

app = Flask(__name__)

# 存储上传的文件和私钥
UPLOAD_FOLDER = 'uploads'
PRIVATE_KEYS_FOLDER = 'private_keys'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PRIVATE_KEYS_FOLDER'] = PRIVATE_KEYS_FOLDER

# 初始化密钥数据库和文件名数据库
private_keys_db = {}
file_names_db = {}


@app.route('/upload_file_data', methods=['POST'])
def upload_file_data():
    data = request.json
    file_uuid = data['file_uuid']
    file_hash = data['file_hash']
    encoded_filename = data['file_name']
    timestamp = data['timestamp']

    # 解码文件名
    decoded_filename = ''.join(chr(char ^ (timestamp % 2048)) for char in encoded_filename)

    # 存储时间戳和原始文件名
    file_names_db[file_uuid] = {
        'timestamp': timestamp,
        'original_filename': decoded_filename
    }


    # 生成RSA密钥对
    private_key = RSA.generate(2048)
    public_key = private_key.publickey().export_key()

    # 保存私钥到密钥数据库
    private_keys_db[file_uuid] = private_key

    # ...之前的代码保持不变...

    return jsonify({
        'upload_file': True,
        'public_key': public_key.decode('utf-8')
    })


@app.route('/upload_ppt', methods=['POST'])
def upload_ppt():
    # 解析上传的文件
    if 'files' not in request.files:
        print("No file part in the request")
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['files']
    if file.filename == '':
        print("No selected file")
        return jsonify({'error': 'No selected file'}), 400

    if file:
        # 打印文件信息
        print(f"Received file: {file.filename}, Size: {file.content_length}")

        # 从文件名中提取UUID
        file_uuid = file.filename.split('.')[0]

        # 检查UUID是否存在于文件名数据库中
        if file_uuid in file_names_db:
            # 获取原始文件名和时间戳
            original_filename = file_names_db[file_uuid]['original_filename']
            timestamp = file_names_db[file_uuid]['timestamp']

            # 解密文件
            private_key = private_keys_db.get(file_uuid)

            if private_key:
                print(f"Decrypting file with UUID: {file_uuid}")
                cipher = PKCS1_cipher.new(private_key)
                decrypted_file_content = cipher.decrypt(file.read(), 2048)

                # 保存解密后的文件
                decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{original_filename}')
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_file_content)

                return jsonify({'success': True, 'file_path': decrypted_file_path})
            else:
                print(f"No private key found for UUID: {file_uuid}")
                return jsonify({'error': 'No private key found for UUID'}), 404
        else:
            print(f"No file name entry found for UUID: {file_uuid}")
            return jsonify({'error': 'No file name entry found for UUID'}), 404

    print("File upload failed")
    return jsonify({'error': 'File upload failed'}), 500



if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    if not os.path.exists(PRIVATE_KEYS_FOLDER):
        os.makedirs(PRIVATE_KEYS_FOLDER)
    app.run(host='127.0.0.1', port=1463, debug=True)