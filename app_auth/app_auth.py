# -*- coding: utf-8 -*-
# @Time :2022/6/11 17:51
# @Author   :HY
# @File     :app_auth.py
# @Desc

import os
import uuid
import base64

import win32api
from pyDes import des, CBC, PAD_PKCS5

REGISTER_FILE = os.path.join(os.getcwd(), 'register_code')


class AppAuth:
    def __init__(self):
        self.Des_Key = "Broadxt@"  # 必须和code_generator内的定义一致
        self.Des_IV = "12345678"  # 自定IV向量, 必须和code_generator内的定义一致

    @staticmethod
    def get_mac_address():
        """ 获取MAC地址 """
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])

    @staticmethod
    def get_disk_serial_number(disk="C:\\"):
        """ 获取硬盘序列号 """
        disk_sn = win32api.GetVolumeInformation(disk)[1]
        return disk_sn or 0

    def get_machine_number(self):
        number = self.get_mac_address()
        return str(number) if number else 0

    def decrypt(self, string):
        """ 解码，解码后返回字节类型，需要解码转为字符串 """
        if not string:
            return ''

        k = des(self.Des_Key, CBC, self.Des_IV, pad=None, padmode=PAD_PKCS5)
        return k.decrypt(string).decode('utf-8')

    def register(self, reg_key, register_file=None):
        """
        注册验证码
        reg_key: 注册码
        register_file: 注册文件存储路径
        """
        if reg_key:
            content = self.get_machine_number()  # number has been changed to str type after use str()
            key_decrypted = self.decrypt(base64.b64decode(reg_key))

            if content != 0 and key_decrypted != 0:
                if content != key_decrypted:
                    return False
                elif content == key_decrypted:
                    # 读写文件要加判断
                    reg_file = register_file or REGISTER_FILE
                    dir_name = os.path.dirname(reg_file)
                    if not os.path.exists(dir_name):
                        os.makedirs(dir_name)

                    with open(reg_file, 'wt', encoding='utf-8') as f:
                        f.write(reg_key)
                        f.close()
                    return True
                else:
                    return False
            else:
                return False
        return False

    def check_authored(self, register_file=None):
        """ 检查是否已经授权 """
        content = self.get_machine_number()
        reg_file = register_file or REGISTER_FILE
        if not os.path.exists(reg_file):
            return False, '未检测到注册文件，请注册'

        try:
            with open(reg_file, 'rt', encoding='utf-8') as fr:
                key = fr.read()

            if not key:
                return False, '注册文件无效, 请重新注册'

            key_decrypted = self.decrypt(base64.b64decode(key))
            if not key_decrypted or key_decrypted != content:
                return False, '校验失败，无效注册码'

            return True, 'Success'
        except (FileNotFoundError, IOError) as err:
            print(err)
            return False, '注册异常，请重新尝试'


if __name__ == '__main__':
    reg = AppAuth()
    is_auth_pass, msg = reg.check_authored()
    if not is_auth_pass:
        print(msg)
        reg_code = input(f'请输入注册码:')
        is_done = reg.register(reg_code)
        if not is_done:
            print('注册失败')
            exit(1)
        print('注册成功')
    print(f'已授权')
