from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

wallet_name="testwallet"
# Node access params
RPC_URL = f"http://alice:password@127.0.0.1:18443/wallet/{wallet_name}"

def send(rpc, addr, data):
    args = [
        {addr: 100},    # recipient address
        None,           # conf target
        None,
        21,             # fee rate in sats/vb
        None            # Empty option object
    ]
    send_result = rpc.send('send', args)
    assert send_result['complete']
    return send_result['txid']

def list_wallet_dir(rpc):
    result = rpc.listwalletdir()
    return [wallet['name'] for wallet in result['wallets']]

def create_wallet(rpc,wallet_name,passphrase):
    """
    Creates a new wallet or loads the wallet if it already exists.

    :param rpc: The RPC connection used to interact with the wallet.
    :param wallet_name: The name of the wallet.
    :param passphrase: The passphrase to encrypt the wallet.
    :return: A string indicating the wallet's status.
    :rtype: str
    """
    try: 
        wallets = list_wallet_dir(rpc)
        if wallet_name in wallets:
            return "Wallet already loaded."
        rpc.loadwallet(wallet_name)
        return "wallet loaded successfully"
    except JSONRPCException as e:
        if "Path does not exist" in str(e):
            result = rpc.createwallet(wallet_name, False, False, passphrase , False , False)
            if result["name"] == wallet_name:
                return "Wallet has been created successfully."
            else:
                return "An issue occurred while creating the wallet."
        else:
            return e

def generate_new_address(rpc, wallet_name):
    """
    Generates a new address for the wallet.

    :param rpc: The RPC connection.
    :param wallet_name: The name of the wallet.
    :return: A new Bitcoin address for receiving payments.
    """
    try:
        return rpc.getnewaddress(wallet_name, "legacy")
    except JSONRPCException as e:
        return e

def mine_blocks(rpc,nblocks,address):
    """
    Mines blocks to generate bitcoins to a specific address.

    :param rpc: The RPC connection.
    :param nblocks: The number of blocks to mine.
    :param address: The address to send the newly generated bitcoin to.
    :return: An array of hashes of the blocks generated
    """
    try:
        return rpc.generatetoaddress(nblocks,address)
    except JSONRPCException as e:
        return e


def create_transaction(rpc, recipient_address, transfer_amount):
    """
    Creates and prepares a Bitcoin transaction.

    :param rpc: The RPC connection.
    :param sender_address: The address to send the transaction from.
    :param recipient_address: The address to send the transaction to.
    :param transfer_amount: Amount of bitcoins to be transferred.
    :param BTC_amount: Amount of bitcoins gathered from the selecting unspent transactions outputs (UTXOs).
    :param txids_and_vouts: A list of dictionaries containing 'txid' and 'vout' of selected UTXOs.
    :return: A raw unsigned transaction ready for signing.
    """
    message = "We are all Satoshi!!"
    hex_message = message.encode().hex()
    outputs = {recipient_address: transfer_amount , "data":hex_message}
    #no need to pass inputs as fundrawtransaction automatically selects inputs from the wallet
    unsigned_tx_hex = rpc.createrawtransaction([],outputs)
    return unsigned_tx_hex


def sign_transaction(rpc, sender_address ,wallet_passphrase, unsigned_tx_hex):
    """
    Unlocks the wallet, funds the transaction, and signs it.

    :param rpc: The RPC connection.
    :param wallet_passphrase: Passphrase to temporarily unlock the wallet.
    :param unsigned_tx_hex: The raw unsigned transaction hex string.
    :return: The signed transaction hex string, ready to be broadcast.
    """
    rpc.walletpassphrase(wallet_passphrase, 60)
    # fundrawtransaction automatically selects inputs to cover the required amount 
    # and allows specifying the address to receive the change.
    funded_tx = rpc.fundrawtransaction(unsigned_tx_hex, {"fee_rate": 21, "change_address":sender_address})
    signed_tx = rpc.signrawtransactionwithwallet(funded_tx["hex"])
    return signed_tx['hex']

def send_transaction(rpc,signed_tx):
    """
    Broadcasts a signed Bitcoin transaction to the network.

    :param rpc: The RPC connection.
    :param signed_tx: The signed transaction hex string to be broadcast.
    :return: The transaction ID (txid) of the successfully broadcast transaction.
    """
    return rpc.sendrawtransaction(signed_tx)
     

def main():
    rpc = AuthServiceProxy(RPC_URL)

    # Check connection
    info = rpc.getblockchaininfo()
    print(info)

    passphrase = "passphrase"
   
    # Create or load the wallet
    print(create_wallet(rpc, wallet_name,passphrase))
    
    # Generate a new address
    sender_address = generate_new_address(rpc, wallet_name)
    print("Successfully generated a sender address: ", sender_address)

    #creation of a recipient address
    recipient_address = "bcrt1qq2yshcmzdlznnpxx258xswqlmqcxjs4dssfxt2"
    print("Successfully generated a recipient address: ", recipient_address)

    # Mine 101 blocks to the new address to activate the wallet with mined coins
    mine_blocks(rpc,103,sender_address)

    # Prepare a transaction to send 100 BTC
    transfer_amount=100
    
    # Step 1: Create a raw unsigned transaction using available UTXOs
    unsigned_tx_hex = create_transaction(rpc , recipient_address, transfer_amount)

    # Step 2: Sign the transaction with the wallet's private key
    signed_tx = sign_transaction(rpc, sender_address ,passphrase, unsigned_tx_hex)
    
    # Send the transaction
    # Step 3: Broadcast the signed transaction to the Bitcoin network
    txid = send_transaction(rpc, signed_tx)

    print("Transaction data showing the transfer amount, fee amount and change ", rpc.gettransaction(txid))
    
    # Write the txid to out.txt
    with open("out.txt","w") as file:
        file.write(txid)

if __name__ == "__main__":
    main()