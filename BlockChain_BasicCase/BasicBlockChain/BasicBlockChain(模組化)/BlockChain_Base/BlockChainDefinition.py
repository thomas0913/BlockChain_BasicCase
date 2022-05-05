import hashlib
import time
import rsa
import BlockChain_Base.__init__

# 區塊鏈定義
class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 10  # 難度調節區塊數，每多少區塊調節一次
        self.difficulty = 1  # 當前難度
        self.block_time = 30  # 出塊時間，理想上多久能夠產出一個區塊
        self.miner_rewards = 10  # 挖礦獎勵，獎勵挖礦者的金額多寡
        self.block_limitation = 32  # 區塊容量，每一區塊能夠容納的交易上限
        self.chain = []  # 區塊鏈，目前鏈中儲存的所有區塊
        self.pending_transactions = []  # 等待中的交易(因區塊鏈能吞吐的交易量有限)

    # 負責把交易明細轉換成字串
    def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_dict)

    # 負責把區塊記錄內的所有交易明細轉換成一個字串
    def get_transactions_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

    # 負責依據這四筆資料產生相對應的雜湊值
    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash  # 前一區塊之雜湊值
                + str(block.timestamp)  # 區塊產生當下的時間戳
                + self.get_transactions_string(block)  # 區塊內所有之交易明細
                + str(nonce)  # 挖掘中的nonce值
            ).encode("utf-8")
        )
        h = s.hexdigest()
        return h

    # 開始部屬區塊鏈所產生之第一個區塊，無任何交易紀錄且為無任何資料的空區塊
    def create_genesis_block(self):
        print("Create genesis block...")

        #定義創世塊 = Block(前一區塊雜湊值,預設難度,礦工姓名,預設挖礦獎勵)
        new_block = BlockChain_Base.__init__.Block('Hello World!', self.difficulty,
                          'lkm543', self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)  # 產生創世塊當前雜湊值
        self.chain.append(new_block)  # 將創世塊加入鏈中

    # 交易明細加入新區塊中
    def add_transaction_to_block(self, block):
        # Get the transaction with highest fee by block_limitation

        # 將等待中的所有交易明細一手續費大小排序，並反序陣列使第一個元素為手續費最高之交易明細
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)

        # 檢查等待中交易明細數量是否超載區塊容量
        if len(self.pending_transactions) > self.block_limitation:
            transaction_accepted = self.pending_transactions[:self.block_limitation]
            # 留下不被接受的交易明細在等待區
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transaction_accepted = self.pending_transactions  # 接受全部等待中的交易明細
            self.pending_transactions = []  # 重至等待區

        # 放入區塊中
        block.transactions = transaction_accepted

    # 利用"POW(工作量證明)"挖掘新區塊
    def mine_block(self, miner):
        start = time.process_time()  # 紀錄挖掘前時間

        # 產生新區塊
        last_block = self.chain[-1]  # 選取鏈中最後一區塊
        new_block = BlockChain_Base.__init__.Block(last_block.hash, self.difficulty,
                          miner, self.miner_rewards)  # 設定新區塊參數
        self.add_transaction_to_block(new_block)  # 加入交易明細至新區塊
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(
            new_block, new_block.nonce)  # 產生加入交易明細後的新雜湊值

        # 透過改變nonce值得到新雜湊值，如符合難度定義"開頭有幾個0"則為合格的雜湊值與nonce值
        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        # 計算並得出區塊挖掘時間花費
        time_consumed = round(time.process_time() - start, 5)
        # 顯示新區塊狀態提示
        print(
            f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")

        # 將所挖掘的新區塊加入鏈中
        self.chain.append(new_block)

    # 難度調節算法，不是最佳解
    def adjust_difficulty(self):
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:  # 調整，如果當前區塊數"到達且超過"上限調節區塊數
            # 計算平均出塊時間
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round(
                (finish - start) / (self.adjust_difficulty_blocks), 2)

            if average_time_consumed > self.block_time:
                print(
                    f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty -= 1
            else:
                print(
                    f"Average block time:{average_time_consumed}s. High up the difficulty")
                self.difficulty += 1

    # 查詢帳戶餘額，遍歷所有交易紀錄之明細
    def get_balance(self, account):
        balance = 0
        for block in self.chain:  # 遍歷所有區塊
            # Check miner rewaard
            miner = False  # 礦工旗標
            if block.miner == account:  # 檢查該帳戶是否為礦工
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:  # 遍歷該區塊的所有交易明細紀錄
                if miner:  # 如為礦工則獲得該明細之手續費
                    balance += transaction.fee
                if transaction.sender == account:  # 如為發送者則從餘額扣除該次轉帳金額與手續費
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:  # 如為接收者直接獲取金額加至帳戶餘額之中
                    balance += transaction.amounts
        return balance

    # 檢驗當前區塊鏈正確性，從第一塊到最後一塊依序計算雜湊值
    def verify_blockchain(self):
        previous_hash = ''

        # 把所有交易紀錄列舉成一單一陣列，並遍歷各個區塊與索引值
        for idx, block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:  # 驗證當前區塊雜湊值
                print("Error:Hash not matched!")
                return False
            elif previous_hash != block.previous_hash and idx:  # 驗證當前區塊位置
                print("Error:Hash not matched to previos_hash")
                return False
            previous_hash = block.hash
        print("Hash correct!")
        return True

    # 利用RSA加密法隨機產生一對公私鑰，並轉存成pkcs1形式
    def generate_address(self):
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()
        private_key = private.save_pkcs1()
        return self.get_address_from_public(public_key), private_key

    # 把public_key(pkcs1)原本內容過濾並只剩地址部分
    def get_address_from_public(self, public):
        address = str(public).replace('\\n', '')
        address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        address = address.replace("-----END RSA PUBLIC KEY-----'", '')
        address = address.replace(' ', '')
        print('Address:', address)
        return address
    """
  b'-----BEGIN RSA PUBLIC KEY-----\n
  MEgCQQCC+FnLB6c50HqIU1+xHmVr2ynahARbCc3/eRFLYSDeWKbVfvpMLnrKqm/
  qlmOy3QXjjr15ZNSQMO+Cnn0JvnohAgMBAAE=\n
  -----END RSA PUBLIC KEY-----\n
  """

    # 利用"數位簽章"接納此筆交易
    def add_transaction(self, transaction, signature):
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        # 如交易金額大於當前帳戶餘額則交易失敗
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            print("Balance not enough!")
            return False
        try:
            # 驗證發送者
            rsa.verify(transaction_str.encode('utf-8'),
                       signature, public_key_pkcs)
            print("Authorized successfully!")
            self.pending_transactions.append(transaction)
            return True
        except Exception:
            print("RSA Verified wrong!")

    # (在本地端)初始化一筆交易，並且確認帳戶是否餘額足夠
    def initialize_transaction(self, sender, receiver, amount, fee, message):
        if self.get_balance(sender) < amount + fee:  # 檢查餘額
            print("Balance not enough!")
            return False
        new_transaction = BlockChain_Base.__init__.Transaction(sender, receiver, amount, fee, message)
        return new_transaction

    # (在本地端)簽署數位簽章
    def sign_transaction(self, transaction, private_key):
        private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key)
        transaction_str = self.transaction_to_string(transaction)
        signature = rsa.sign(transaction_str.encode(
            'utf-8'), private_key_pkcs, 'SHA-1')  # 簽章
        return signature

    def start(self):
        address, private = self.generate_address()
        self.create_genesis_block()
        while(True):
            # Step1: initialize a transaction
            transaction = block.initialize_transaction(
                address, 'test123', 100, 1, 'Test')
            if transaction:
                # Step2: Sign your transaction
                signature = block.sign_transaction(transaction, private)
                # Step3: Send it to blockchain
                block.add_transaction(transaction, signature)
            self.mine_block(address)
            print(self.get_balance(address))
            self.adjust_difficulty()
