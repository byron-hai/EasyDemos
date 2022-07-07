# -*- coding: utf-8 -*-
# @Time :2022/7/6 15:53
# @Author   :HY
# @File     :rsa_cipher.py
# @Desc

import os
import shutil
import time

import rsa
import base64
from datetime import datetime
from app.common.logger import Logger

logger = Logger('RSACipher').getlog()
DATE_FMT = '%Y-%m-%d'
TIME_FMT = '%Y%m%d-%H:%M:%S'


def get_input_lines():
    lines = ''
    while 1:
        input_str = input()
        if not input_str:
            break
        else:
            lines += f'{input_str}\n'
    return lines


def read_file(file_path):
    try:
        with open(file_path, 'rt', encoding='utf-8') as fr:
            lines = fr.readlines()

        return [line.strip() for line in lines if line]
    except (OSError, UnicodeEncodeError, FileNotFoundError) as err:
        logger.error(err)
        return []


class RSACipher:
    def __init__(self):
        self.output = os.path.join(os.getcwd(), 'rsa_keys')
        self.backup_dir = os.path.join(os.getcwd(), 'backups')
        self.pub_key_file = os.path.join(self.output, 'public_key.pem')
        self.pri_key_file = os.path.join(self.output, 'private_key.pem')
        self.sign_file = os.path.join(self.output, 'signature')

    def gen_keys(self, pub_key_save_path=None, pri_key_save_path=None):
        """ 生成公私钥并保存 """
        pub_key_path = pub_key_save_path or self.pub_key_file
        pri_key_path = pri_key_save_path or self.pri_key_file

        answer = 'y'
        if os.path.exists(pub_key_path) and os.path.exists(pri_key_path):
            answer = input(f"路径{self.output}\n已存在密钥文件，需要重新生成吗？(y/n): ").strip()

        if answer == 'y':
            logger.info(f"生成公私密钥, 输出路径：{self.output}")
            pub, pri = rsa.newkeys(1024)
            pub_key = pub.save_pkcs1('PEM')
            pri_key = pri.save_pkcs1('PEM')
            logger.info(f'生成公钥:\n{pub_key.decode()}\n生成私钥:\n{pri_key.decode()}')
            # Save to local
            self.save_bytes2file(pub_key, pub_key_path)
            self.save_bytes2file(pri_key, pri_key_path)

            # 备份的原因是签名时私钥的路径需要是确定的，所以如果丢了手动将密钥拷贝到output目录
            backup_dir = os.path.join(self.backup_dir, datetime.now().strftime(DATE_FMT))
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)

            shutil.copy(pub_key_path, backup_dir)
            shutil.copy(pri_key_path, backup_dir)
            logger.info(f'密钥已生成, 并已备份到{backup_dir}')

    @staticmethod
    def save_bytes2file(content, file_path, mode='wb'):
        if not file_path:
            logger.error(f'文件路径未指定')
            return False

        dir_name = os.path.dirname(file_path)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)

        if not isinstance(content, bytes):
            content = content.encode('utf-8')

        try:
            with open(file_path, mode) as fw:
                fw.write(content)
            return True
        except (FileNotFoundError, OSError, UnicodeEncodeError) as err:
            logger.error(err)
            return False

    @staticmethod
    def load_key_file(file_path, key_type):
        """ 加载密钥文件 """
        load_map = {'private': rsa.PrivateKey, 'public': rsa.PublicKey}
        if key_type not in load_map:
            return None

        if not file_path or not os.path.exists(file_path):
            logger.error(f'文件{file_path}: 不存在')
            return None

        try:
            with open(file_path, 'rb') as fr:
                return load_map[key_type].load_pkcs1(fr.read())
        except UnicodeEncodeError as err:
            logger.error(err)
            return None

    @staticmethod
    def load_signature(file_path):
        """ 加载签名文件 """
        if not file_path or not os.path.exists(file_path):
            logger.error('签名文件未找到')
            return None

        try:
            with open(file_path, 'rb') as fr:
                sign = fr.read()

            return sign.decode('utf-8') if sign else ''
        except Exception as err:
            logger.error(f'加载签名异常: {err}')
            return ''

    def rsa_private_sign(self, text_str, pri_key_path=None):
        """ 用私钥进行数字签名 """
        pri_key_path = pri_key_path or os.path.join(self.output, self.pri_key_file)
        if not pri_key_path or not os.path.exists(pri_key_path):
            logger.error('私钥文件未找到')
            return ''

        if not text_str:
            logger.error('签名内容未输入')
            return ''

        if not isinstance(text_str, str):
            logger.error('签名内容需是字符串格式')
            return ''

        pri_key = self.load_key_file(pri_key_path, 'private')
        if not isinstance(pri_key, rsa.PrivateKey):
            logger.error(f'无效私钥')
            return ''

        sign_code = rsa.sign(text_str.encode('utf-8'), pri_key,  'SHA-1')
        sign_bytes = base64.encodebytes(sign_code)
        return sign_bytes.decode('utf-8')

    @staticmethod
    def rsa_sign_verify(text_str, sign_text, pub_key):
        """ 签名验证 """
        if not all((text_str, sign_text, pub_key)):
            logger.error(f'验证内容，签名或者公钥未输入')
            return False

        if not isinstance(text_str, str):
            logger.error('签名内容需是字符串格式')
            return False

        if not isinstance(pub_key, rsa.PublicKey):
            logger.error(f'无效公钥')
            return ''

        text_bytes = text_str.encode('utf-8')
        sign_bytes = base64.decodebytes(sign_text.encode('utf-8'))
        return rsa.verify(text_bytes, sign_bytes, pub_key) == 'SHA-1'


def main():
    coder = RSACipher()
    coder.gen_keys()

    while 1:
        ans = input('请输入操作类型:\n'
                    '0: 生成公私钥\n'
                    '1: 数字签名\n'
                    '2: 批量数字签名\n'
                    '3: 签名验证\n'
                    'q: 退出\n:').strip()

        if ans == '0':
            coder.gen_keys()
        elif ans == '1':
            text = input(f'请输入签名内容: ').strip()
            if text:
                signature = coder.rsa_private_sign(text)
                print(f'{text}\n签名:\n{signature}')
                if input(f'保存签名到文件(y/n): ').strip() == 'y':
                    sign_file = os.path.join(coder.sign_file)
                    coder.save_bytes2file(signature, sign_file)
            else:
                logger.info('输入内容为空')
        if ans == '2':
            file_path = input(f'请输入签名内容文件(txt)路径: ').strip()
            if file_path and os.path.exists(file_path):
                text_list = read_file(file_path)
                if not text_list:
                    logger.warning('签名文件内容为空')
                else:
                    sign_file = os.path.join(os.getcwd(), 'signature_output.txt')
                    for item in text_list:
                        signature = coder.rsa_private_sign(item)
                        print(f'内容:{item}, 签名:\n{signature}{"*" * 60}\n')
                        content = f'[{datetime.now().strftime(TIME_FMT)}]: <{item}>, 签名:\n{signature}\n'
                        coder.save_bytes2file(content, sign_file, mode='ab+')
            else:
                logger.info('输入文件不存在')
        elif ans == '3':
            print('签名验证:')
            text = input(f'请输入验证数据: ').strip()
            print('请输入签名内容:')
            sign = get_input_lines()
            pub_key_path = os.path.join(coder.output, coder.pub_key_file)
            pub_key = coder.load_key_file(pub_key_path, 'public')

            if text and sign:
                rtn = coder.rsa_sign_verify(text, sign, pub_key)
                msg = '验证通过\n' if rtn else '验证失败\n'
                print(msg)
            else:
                logger.info('验证数据或签名无效')
        elif ans == 'q':
            print('退出')
            time.sleep(1)
            break


if __name__ == '__main__':
    main()
