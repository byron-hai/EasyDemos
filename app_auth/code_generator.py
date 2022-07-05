# -*- coding: utf-8 -*-
# @Time :2022/6/14 16:16
# @Author   :HY
# @File     :code_generator.py
# @Desc

import base64
from pyDes import des, CBC, PAD_PKCS5


class CodeGenerator:
    """
    注册码生成器
    需要单独运行，注意初始化参数Des_Key, Des_IV需要和app_auth里的定义一致
    """
    def __init__(self):
        self.Des_Key = "Broadxt@"  # Key, 个数为8的倍数
        self.Des_IV = "12345678"  # 自定IV向量, 个数为8的倍数

    # 使用DES加base64的形式加密
    def encrypt(self, string):
        k = des(self.Des_Key, CBC, self.Des_IV, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(string)
        return base64.b64encode(encrypt_str)  # 转base64编码返回, Byte类型

    def create_code(self, mac_loc):
        serial_number = str(mac_loc)
        serial_number_key = self.encrypt(serial_number).decode('utf-8')
        print(f"注册码已生成:{serial_number_key}")


if __name__ == '__main__':
    while 1:
        mac_str = input('请输入目标MAC地址(输入’q‘退出): ')
        mac_str = mac_str.strip()
        if not mac_str:
            print(f'无效输入')
        elif mac_str == 'q':
            break
        else:
            generator = CodeGenerator()
            generator.create_code(mac_str)
            break
    exit(0)
