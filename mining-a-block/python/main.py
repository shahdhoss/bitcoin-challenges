import bitcoinlib.wallets
from bitcoinlib.transactions import Transaction
from bitcoin.core import CTxIn , CTxOut , CMutableTransaction , COutPoint, CTxInWitness , CTxWitness , CScriptWitness
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, CScriptWitness, OP_RETURN 
from bitcoin.core.script import CScript
import hashlib
from pathlib import Path
import json
import time

def create_or_load_wallet(wallet_name):
    """
    Create a wallet using wallet name if it doesn't exist, otherwise just open

    :param wallet_name: The wallet's name to be created or loaded
    :return: A wallet object
    """
    wallet = bitcoinlib.wallets.wallet_create_or_open(wallet_name)
    print(f"Wallet '{wallet_name}' created or opened successfully.")
    return wallet

def generate_or_get_address(wallet):
    """
    Returns an existing address if the wallet has one; otherwise, generates a new address.

    :param wallet: A wallet object 
    :return: The first address in the wallet if available, otherwise a newly generated address.
    """
    if wallet.keys():
        return wallet.keys()[0].address
    else:
        return wallet.get_key().address

def hash256(data):
    """
    Computes the double SHA-256 hash of the given bytes object.

    :param data: A bytes object
    :return: The double SHA-256 hash as a bytes object
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def validate_transaction_signatures(raw_tx_hex):
    """
    Verifies the validity of a transaction by checking all inputs and ensuring that
    signatures match the corresponding public keys.
    This function does not verify whether the UTXOs are valid or already spent.

    :param raw_tx_hex: The raw transaction in hexadecimal format.
    :return: True if the transaction is valid, otherwise False.
    """
    try:
        parsed_tx = Transaction.parse_hex(raw_tx_hex)
        validity = parsed_tx.verify()
        if validity == True:
            return True
        return False
    except Exception as e:
        return False , f"an error occured: {e}"

def calculate_wtxid(tx_hex):
    """
    Computes the witness transaction ID (wtxid) of a given transaction hex.

    :param tx_hex: The raw transaction in hexadecimal format.
    :return: The wtxid as a hexadecimal string.
    """
    return hash256(bytes.fromhex(tx_hex))[::-1].hex()

def generate_merkle_root(txids):
    """
    Computes the Merkle root from a list of transaction IDs (txids).

    :param txids: A list of transaction IDs in hexadecimal format.
    :return: The Merkle root as a bytes object, or None if the input list is empty.
    """
    if not txids:
        return None
    level = [bytes.fromhex(txid)[::-1] for txid in txids]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):  
                pair_hash = hash256(level[i] + level[i])
            else:
                pair_hash = hash256(level[i] + level[i + 1])
            next_level.append(pair_hash)
        level = next_level
    return level[0]

def construct_block_header(version, previous_block, merkle_root, time, bits, target):
    """
    Constructs a valid Bitcoin block header by finding a nonce that satisfies the target difficulty.

    :param version: The block version as an integer.
    :param previous_block: The hash of the previous block in hexadecimal format.
    :param merkle_root: The Merkle root hash as a bytes object.
    :param time: The timestamp as an integer (UNIX time).
    :param bits: The difficulty target in compact format as an integer.
    :param target: The mining target difficulty as a hexadecimal string.
    :return: The valid block header in hexadecimal format.
    """
    nonce = 0x00000000
    target_int = int(target, 16)
    while True:
        block_header = (version.to_bytes(4, byteorder='little') + bytes.fromhex(previous_block)[::-1] + merkle_root + 
            time.to_bytes(4, byteorder='little') + bits.to_bytes(4, byteorder='little') + nonce.to_bytes(4, byteorder='little'))
        first_hash = hashlib.sha256(block_header).digest()
        block_hash = hashlib.sha256(first_hash).digest()
        block_hash_int = int.from_bytes(block_hash[::-1], byteorder='big')
        if block_hash_int < target_int:
            return block_header.hex()
        nonce += 1
    
def calculate_subsidy(block_height):
    """
    Calculates the Bitcoin block reward subsidy based on the block height.

    :param block_height: The block height in integer.
    :return: The block subsidy in satoshis in integer.
    """
    halvings = block_height // 210000
    subsidy = 50* (0.5)** halvings
    return subsidy * 100000000

def calculate_total_fees(files):
    """
    Calculates the total transaction fees from a list of transaction files.

    :param files: A list of transaction files
    :return: The total transaction fee.
    """
    fee = 0 
    for file in files:
        fee += file['fee']
    return fee

def create_coinbase_transaction(block_height, reward, address):
    """
    Creates a coinbase transaction for a newly mined block.

    :param block_height: The block height at which the coinbase transaction is created (integer).
    :param reward: The mining reward for the block in satoshis.
    :param address: The recipient's address for the mining reward in string.
    :return: A tuple containing the coinbase transaction object and its transaction ID in string.
    """
    txid = "0000000000000000000000000000000000000000000000000000000000000000"
    sequence = 0xFFFFFFFF
    block_height_bytes = block_height.to_bytes(4, byteorder='little')
    script_sig = CScript([block_height_bytes + b'\x00']) 
    txin = CTxIn(prevout=COutPoint(bytes.fromhex(txid), 0xFFFFFFFF),scriptSig= script_sig , nSequence= sequence)
    address_hash = hashlib.sha256(address.encode()).digest()[:20] 
    txout = CTxOut(reward, CScript([OP_DUP, OP_HASH160, address_hash, OP_EQUALVERIFY, OP_CHECKSIG]))
    mtx = CMutableTransaction([txin], [txout])
    return mtx , mtx.GetTxid().hex()

def add_witness_commitment(mtx, witness_root_hash):
    """
    Adds a SegWit witness commitment to the transaction.

    :param mtx: The mutable transaction object to which the witness commitment will be added.
    :param witness_root_hash: The root hash of the witness Merkle tree in bytes.
    :return: The serialized transaction in hex format in string.
    """
    witness_reserved_value = '0000000000000000000000000000000000000000000000000000000000000000'
    witness_data = witness_root_hash.hex() + witness_reserved_value
    witness_commitment = hash256(bytes.fromhex(witness_data)).hex()
    op_return_header = '6a24aa21a9ed'
    output1_script = op_return_header + witness_commitment
    witness_commitment_output = CTxOut(0, bytes.fromhex(output1_script))
    mtx.vout.append(witness_commitment_output)
    witness = CTxInWitness(CScriptWitness([bytes.fromhex(witness_reserved_value)]))
    mtx.wit = CTxWitness([witness])
    return mtx.serialize().hex()

def get_valid_transactions(folder_path):
    """
    Get all transaction files from the mempool and returns only the valid transaction files.

    :param folder_path: The folder path to where the transaction files are located
    :return: The valid transaction files
    """
    valid_tx_files=[]
    for file in folder_path.iterdir():
        with open (file , 'r') as data:
            data_file = json.load(data)
            if 'hex' in data_file:
                tx_hex = data_file['hex']
                if validate_transaction_signatures(tx_hex):
                    valid_tx_files.append(data_file)
    return valid_tx_files

def get_wtxids(files):
    """
    Get the witness transaction IDs (wtxid) from the given transaction files.

    :param files: A list of transactio files
    :return: The witness transaction IDs
    """
    wtxids = []
    for file in files:
        wtxids.append(calculate_wtxid(file['hex']))
    return wtxids

def get_txids(files):
    """
    Get the transaction IDs from the given transaction files.
    
    :param files: A list of transaction IDs
    :return: The transaction IDs
    """
    txids = []
    for file in files:
        txids.append(file['txid'])
    return txids

def main():
    #wallet and address creation or loading
    wallet = create_or_load_wallet("mywallet")
    address = generate_or_get_address(wallet)

    #getting the valid transactions
    folder_path = '/home/runner/work/2025-dev-week-3-mining-a-block-shahdhoss/2025-dev-week-3-mining-a-block-shahdhoss/mempool'
    valid_transaction_files = get_valid_transactions(Path(folder_path))

    #creating a coinbase transaction
    txid = b"\x00" * 32
    block_height = 10
    fees = calculate_total_fees(valid_transaction_files)
    subsidy = calculate_subsidy(block_height)
    amount = fees + subsidy
    mtx , coinbase_txid = create_coinbase_transaction(block_height ,amount ,address)

    #constructing the block header
    target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    version = 4
    previous_block = "0000000000000000000000000000000000000000000000000000000000000000"
    unix_time = int(time.time()) + 50 
    bits = 520159231
    txids = get_txids(valid_transaction_files)
    wtxids = get_wtxids(valid_transaction_files)
    txids.insert(0, coinbase_txid)
    wtxids.insert(0, txid.hex())

    merkle_root = generate_merkle_root(txids)
    witness_root_hash = generate_merkle_root(wtxids)
    coinbase_tx = add_witness_commitment(mtx, witness_root_hash)
    block_header = construct_block_header(version, previous_block, merkle_root, unix_time, bits, target)
    
    with open("/home/runner/work/2025-dev-week-3-mining-a-block-shahdhoss/2025-dev-week-3-mining-a-block-shahdhoss/out.txt", 'w') as file:
        file.write(block_header + '\n')
        file.write(coinbase_tx + '\n')
        for txid in txids:
            file.write(txid + '\n')
    print("out.txt file has been written to successfully.")

if __name__ == "__main__":
    main()