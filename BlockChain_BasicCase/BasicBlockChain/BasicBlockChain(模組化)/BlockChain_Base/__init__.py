import time

#交易定義
class Transaction:
  def __init__(self,sender,receiver,amounts,fee,message): 
    self.sender = sender    #發送者，同時check帳戶餘額是否足夠
    self.receiver = receiver  #接收者，通常直接收款
    self.amounts = amounts   #金額數
    self.fee = fee       #手續費
    self.message = message   #註記，generally for receiver

#區塊定義
class Block:
  def __init__(self,previous_hash,difficulty,miner,miner_rewards):
    self.previous_hash = previous_hash  #前一區塊之雜湊值，為了加密
    self.hash = ''            #當前區塊雜湊值，目前區塊計算後之雜湊值
    self.difficulty = difficulty     #當前難度
    self.nonce = 0            #能解開上個區塊鎖的鑰匙
    self.timestamp = int(time.time())   #區塊產生時之時間戳，調整挖礦難度時會用到
    self.transactions = []        #交易紀錄(for all)
    self.miner = miner          #挖掘礦工(誰挖的)
    self.miner_rewards = miner_rewards  #礦工獎勵，區塊產出時分給礦工的獎勵