class Transaction:
  def __init__(self,sender,receiver,amounts,fee,message):
    self.sender = sender
    self.receiver = receiver
    self.amounts = amounts
    self.fee = fee
    self.message = message