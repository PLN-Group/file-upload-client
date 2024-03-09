from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher, AES
from Crypto.Util.Padding import pad, unpad
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


# def unpad(data, block_size):
#     # 移除填充
#     pad = data[-1]
#     # if pad < 1 or pad > block_size:
#     #     raise ValueError("Invalid padding")
#     return data[:-pad]


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
    if 'aes_key' not in request.files or 'files' not in request.files or 'aes_iv' not in request.files:
        return jsonify({'error': 'Missing aes_key or files part in the request'}), 400

    aes_key_file = request.files['aes_key']
    file = request.files['files']
    aes_iv_file = request.files["aes_iv"]
    if aes_key_file.filename == '' or file.filename == '':
        return jsonify({'error': 'No selected aes_key or file'}), 400

    if aes_key_file and file:
        # 从文件名中提取UUID
        file_uuid = file.filename.split('.')[0]

        # 检查UUID是否存在于文件名数据库中
        if file_uuid in file_names_db:
            # 获取原始文件名和时间戳
            original_filename = file_names_db[file_uuid]['original_filename']
            print(original_filename)
            timestamp = file_names_db[file_uuid]['timestamp']

            # 解密AES密钥
            private_key = private_keys_db.get(file_uuid)
            if private_key:
                cipher = PKCS1_cipher.new(private_key)
                decrypted_aes_key = cipher.decrypt(aes_key_file.read(), 2048)
                decrypted_aes_iv = cipher.decrypt(aes_iv_file.read(), 2048)
                # 使用解密的AES密钥解密文件
                #print(decrypted_aes_iv)
                aes_cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, decrypted_aes_iv)
                decrypted_file_content = aes_cipher.decrypt(file.read())
                # 移除填充
                try:
                    decrypted_file_content = unpad(decrypted_file_content, AES.block_size)
                except Exception as e:
                    return jsonify({'error': 'Invalid padding, cannot decrypt file.'}), 400
                # 保存解密后的文件
                decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{original_filename}')
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_file_content)

                return jsonify({'success': True, 'file_path': decrypted_file_path})
            else:
                return jsonify({'error': 'No private key found for UUID'}), 404
        else:
            return jsonify({'error': 'No file name entry found for UUID'}), 404

    return jsonify({'error': 'File upload failed'}), 500


if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    if not os.path.exists(PRIVATE_KEYS_FOLDER):
        os.makedirs(PRIVATE_KEYS_FOLDER)
    app.run(host='127.0.0.1', port=1463, debug=True)
