import BlockChain_Base.BlockChainDefinition
import BlockChain_Base.__init__


if __name__ == '__main__':
  block = BlockChain_Base.BlockChainDefinition.BlockChain() #產生區塊鏈並初始化
  #block.start()
  address,private = block.generate_address()

  block.create_genesis_block() #產生創世塊
  block.mine_block(address) #挖掘新區塊

  #Step1: initialize a transaction
  transaction = block.initialize_transaction(address, 'test123', 100, 1, 'Test')
  if transaction:
    #Step2: Sign your transaction
    signature = block.sign_transaction(transaction, private)
    #Step3: Send it to blockchain
    block.add_transaction(transaction, signature)
  block.mine_block(address)

  block.verify_blockchain() #檢驗hash

  print("Insert fake transaction.")
  fake_transaction = BlockChain_Base.__init__.Transaction('test123', address, 100, 1, 'Test')
  block.chain[1].transactions.append(fake_transaction)
  block.mine_block('lkm543')

  block.verify_blockchain()