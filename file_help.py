import os
import random
def str_to_size(size_str: str) -> int:
    # 定义单位和它们对应的字节数
    units = {
        ' B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4,
        'PB': 1024 ** 5,
        'EB': 1024 ** 6  # 可选：如果你需要处理EB（Exabyte）单位
    }

    # 分割字符串以获取数字和单位
    try:
        number, unit = size_str[:-2], size_str[-2:]
    except ValueError:
        # 如果没有单位，假设它是字节
        number, unit = size_str, 'B'

    # 转换数字为浮点数
    number = float(number)

    # 使用单位找到对应的字节数
    byte_size = number * units[unit]

    return int(byte_size)
mode = input("mode:")
if mode == "fill":
    # 获取用户输入的字节大小
    size = str_to_size(input("Enter size:"))


    # 获取用户输入的文件名
    filename = "test/"+input("Enter the filename: ")

    # 检查文件是否存在，如果存在则删除
    if os.path.exists(filename):
        print("Fail: already exists!")

    # 创建文件并填充随机数据
    with open(filename, 'wb') as file:
        print(f"Creating file {filename} with {size} bytes of random data...")
        file.write(os.urandom(size))  # 使用os.urandom生成随机字节

    print(f"File {filename} has been created with random data.")
elif mode == "cmp":
    def compare_files(file1, file2):
        # 读取两个文件的内容
        with open(file1, 'rb') as f1:
            data1 = f1.read()
        with open(file2, 'rb') as f2:
            data2 = f2.read()

        # 获取文件大小
        size1 = len(data1)
        size2 = len(data2)

        # 比较文件内容
        unequal_bytes = 0
        if size1 != size2 and False:
            print(f"Files are of different sizes: {size1} bytes (file1) and {size2} bytes (file2).")
        else:
            print(f"Files are the same size: {size1} bytes.")
        print("Comparing...")
        unequal_bytes = sum(1 for a, b in zip(data1, data2) if a != b)

        if unequal_bytes == 0:
            print("All bytes are equal.")
        else:
            print(f"{unequal_bytes} bytes are not equal.")

        # 返回比较结果
        return size1, size2, unequal_bytes


    # 用户输入文件名
    f1 = input("Enter the filename for files: ")

    # 比较文件
    size1, size2, unequal_bytes = compare_files(f"test/{f1}", f"uploads/{f1}")
