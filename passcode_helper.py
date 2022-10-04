#!/usr/bin/env python

import binascii
import base64
import hashlib
import uuid
import pyqrcode

from urllib.parse import urljoin

from Crypto.Cipher import AES
from Crypto import Random


def random_unique_generator():
    """ Generate a unique 32 characters random_code
    """
    return uuid.uuid4().hex


def encrypt(secret_key, random_code):
    """ Encrypt the generated random_code
        :param secret_key: the secret_key to use for encryption
        :param random_code: the random_code to encrypt
    """
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(random_code)

    return base64.b64encode(iv + cipher_text).decode("utf-8")  # str(encoded, 'utf-8')


def decrypt(secret_key, cipher_text):
    """ Decrypt the encrypted passcode using the secret_key
    :param secret_key: the secret_key to use for decryption
    :param cipher_text: the encrypted passcode containint the cipher
    :return: the decrypted passcode
    """
    cipher_text = base64.b64decode(cipher_text.encode("utf-8"))
    iv = cipher_text[:AES.block_size]
    cipher_text = cipher_text[AES.block_size:]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(cipher_text)
    return decrypted.decode("utf-8")


def hash_passcode(passcode, salt):
    """ Hashing passcode for data storage or retrieval
    :param passcode: the passcode to be hashed
    :param salt: salt for hashing
    :return: the hashed_key
    """
    dk = hashlib.pbkdf2_hmac('sha512', passcode.encode("utf-8"), salt, 100000, 16)
    hashed_key = binascii.hexlify(dk)
    return hashed_key


def generate_qr(req, enc_code, qr_path, filetype="svg"):
    """ Generate qr code
        :param req: current request
        :param enc_code: the encrypted random code
        :param qr_path: the path where qrcode files should be temporarilly stored
        :param filetype: the filetype of temporary qrcode file (possible values svg, png)
    """
    qr = pyqrcode.create(enc_code)
    fname = "{}/{}.{}".format(qr_path, uuid.uuid4(), filetype)
    qr_url = urljoin(req.url_root, "{}".format(fname))
    if filetype == "svg":
        qr.svg(fname, scale=8)
    else:
        qr.png(fname, scale=8, module_color=(0, 0, 0, 128))

    # with open(fname, "rb") as fp:
    #     encoded_image = base64.b64encode(fp.read())
    # return encoded_image.decode("utf-8")
    return qr_url

