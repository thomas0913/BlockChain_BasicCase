"""
---操作指南---
    開啟終端機:
        1.運行節點端: Python .\blockchain_server.py 1111
        2.運行使用者端: Python .\blockchain_client.py 1111
        3.創建新地址: 輸入1
        4.查詢餘額: 輸入2
        5.發起交易: 輸入3，輸入發送者公私鑰，輸入接收者公鑰，輸入金額、手續費
"""

# -*- coding: utf-8 -*-
from inspect import signature
import pickle
import socket 
import sys
import threading 
import time

import rsa



#交易定義
class Transaction:
  def __init__(self,sender,receiver,amounts,fee,message): 
    self.sender = sender    #發送者，同時check帳戶餘額是否足夠
    self.receiver = receiver  #接收者，通常直接收款
    self.amounts = amounts   #金額數
    self.fee = fee       #手續費
    self.message = message   #註記，generally for receiver

# 利用RSA加密法隨機產生一對公私鑰，並轉存成pkcs1形式
def generate_address():
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return get_address_from_public(public_key), extract_from_private(private_key)

# 把public_key(pkcs1)原本內容過濾並只剩地址部分
def get_address_from_public(public):
    address = str(public).replace('\\n', '')
    address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    address = address.replace("-----END RSA PUBLIC KEY-----'", '')
    return address
    """
    b'-----BEGIN RSA PUBLIC KEY-----\n
    MEgCQQCC+FnLB6c50HqIU1+xHmVr2ynahARbCc3/eRFLYSDeWKbVfvpMLnrKqm/
    qlmOy3QXjjr15ZNSQMO+Cnn0JvnohAgMBAAE=\n
    -----END RSA PUBLIC KEY-----\n
    """

def extract_from_private(private):
    private_key = str(private).replace('\\n', '')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    return private_key

# 負責把交易明細轉換成字串
def transaction_to_string(transaction):
    transaction_dict = {
        'sender': str(transaction.sender),
        'receiver': str(transaction.receiver),
        'amounts': transaction.amounts,
        'fee': transaction.fee,
        'message': transaction.message
    }
    return str(transaction_dict)

# (在本地端)初始化一筆交易，並且確認帳戶是否餘額足夠
def initialize_transaction(sender, receiver, amount, fee, message):
    #No need to check balance
    new_transaction = Transaction(sender, receiver, amount, fee, message)
    return new_transaction

# (在本地端)簽署數位簽章
def sign_transaction(transaction, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'    
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    transaction_str = transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode(
        'utf-8'), private_key_pkcs, 'SHA-1')  # 簽章
    return signature

def handle_receive():
    while True:
        response = client.recv(4096) #接收的資料為 4 Byte
        if response:
            print(f"[*] Message from node: {response}")

"""
客戶端功能:
    1.產生公私鑰(錢包地址)
    2.向節點詢問帳戶餘額
    3.發起並簽署交易，並傳送到結點端，等待礦工確認與上鏈
"""
if __name__ == "__main__":
    target_host = "192.168.1.105" #本地IP位置
    target_post = int(sys.argv[1]) #本地客戶阜
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_post))

    #開啟一執行緒，隨時接收來自socket的訊息
    receive_handler = threading.Thread(target=handle_receive, args=())
    receive_handler.start()

    command_dict = {
        "1": "generate_address",
        "2": "get_balance",
        "3": "transaction"
    }

    while True:
        print("Command list:")
        print("1. generate_address")
        print("2. get_balance")
        print("3. transaction")
        command = input("Command: ")
        if str(command) not in command_dict.keys():
            print("Unknown command.")
            continue
        message = {
            "request": command_dict[str(command)]
        }
        if command_dict[str(command)] == "generate_address":
            address, private_key = generate_address()
            print(f"Address: {address}")
            print(f"Private key: {private_key}")

        elif command_dict[str(command)] == "get_balance":
            address = input("Address: ")
            message['address'] = address
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "transaction":
            address = input("Address: ")

            private_key = input("Private_key: ")
            receiver = input("Receiver: ")
            amount = input("Amount: ")
            fee = input("Fee: ")

            comment = input("Comment: ")
            new_transaction = initialize_transaction(
                address, receiver, int(amount), int(fee), comment
            )
            signature = sign_transaction(new_transaction, private_key)
            message["data"] = new_transaction
            message["signature"] = signature

            client.send(pickle.dumps(message))

        else:
            print("UNknown command.")
        time.sleep(1)