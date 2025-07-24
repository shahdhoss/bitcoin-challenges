import hashlib
from bitcoinlib.transactions import Key
import base58
from bitcoin.core import CTxIn, CTxOut, COutPoint,CTxInWitness, CTxWitness,CScriptWitness, CMutableTransaction, x
from bitcoin.core.script import CScript, SignatureHash, SIGHASH_ALL
from ecdsa import SigningKey, SECP256k1, util
from bitcoin.core.script import OP_HASH160, OP_EQUAL, OP_2, OP_CHECKMULTISIG

def generate_witness_script_hash(private_key_1, private_key_2):
    """
    Generates a witness script and its corresponding SHA-256 hash.
    This function takes two private keys, derives their public keys, and constructs
    a 2-of-2 multisig witness script. The script is then hashed using SHA-256 to
    generate the witness script hash.

    :param private_key_1: First private key (hex or bytes)
    :param private_key_2: Second private key (hex or bytes)
    :return: Tuple containing the witness script and its SHA-256 hash
    """
    private_key_1 = Key(private_key_1)
    private_key_2 = Key(private_key_2)
    public_keys = [private_key_2.public(), private_key_1.public()]
    witness_script = CScript([OP_2 ,private_key_2.public().as_bytes() ,private_key_1.public().as_bytes() , OP_2 , OP_CHECKMULTISIG])
    print("witness script: ", witness_script)
    witness_script_bytes = bytes(witness_script)
    witness_script_hash = hashlib.sha256(witness_script_bytes).digest()
    return witness_script, witness_script_hash

def generate_redeem_script(witness_script_hash):
    """
    Generates a P2WSH redeem script.

    :param witness_script_hash: The 32-byte SHA-256 hash of the witness script (bytes)
    :return: The redeem script in bytes
    """
    return b'\x00\x20' + witness_script_hash

def generate_address(redeem_script):
    """
    Generates the P2SH address

    :param: redeem_script: The redeem script in bytes
    :return: The P2SH address in bytes
    """
    sha256_hash = hashlib.sha256(redeem_script).digest()
    script_hash = hashlib.new('ripemd160', sha256_hash).digest()
    prefix = b'\x05'
    payload = prefix + script_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address_bytes = payload + checksum
    p2sh_address = base58.b58encode(address_bytes).decode('utf-8')
    return p2sh_address

def calculate_signature_hash(tx,witness_script, value):
    """
    Calculates the signature hash for a transaction input.
    This function generates a signature hash for a SegWit transaction

    :param tx: The transaction object to sign.
    :param witness_script: The witness script corresponding to the input.
    :param value: The amount being spent (in satoshis).
    :return: The computed signature hash
    """
    sighash = SignatureHash(script=CScript(bytes(witness_script)), txTo=tx, inIdx=0, hashtype=SIGHASH_ALL, amount=value, sigversion=1)
    return sighash

def sign_with_ecdsa(sighash, private_key_hex):
    """
    Signs a given signature hash using ECDSA with a SECP256k1 private key.

    :param sighash: The hash of the transaction input to sign (bytes).
    :param private_key_hex: The private key in hexadecimal format (str).
    :return: The DER-encoded ECDSA signature with SIGHASH_ALL appended (bytes).
    """
    private_key_bytes = bytes.fromhex(private_key_hex)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    signature = signing_key.sign_digest_deterministic(sighash, sigencode=util.sigencode_der)
    r, s = util.sigdecode_der(signature, signing_key.curve.order)
    curve_order = signing_key.curve.order
    if s > curve_order // 2:
        s = curve_order - s 
    modified_signature = util.sigencode_der(r, s, curve_order)
    return modified_signature + bytes([SIGHASH_ALL])

def add_witness_stack(tx,witness_items):
    """
    Adds the witness stack to a SegWit transaction input

    :param tx: The transaction object to sign.
    :param witness_items: The witness stack.
    :return: The modified transaction object.
    """
    script_witness = CScriptWitness(witness_items)  
    input_witness = CTxInWitness(script_witness)   
    tx.wit = CTxWitness([input_witness]) 
    return tx

def main():
    private_key_1 = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"
    private_key_2 = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d"
    witness_script, witness_script_hash = generate_witness_script_hash(private_key_1, private_key_2)
    redeem_script=generate_redeem_script(witness_script_hash)
    recipient_address = generate_address(redeem_script)

    txid ="0000000000000000000000000000000000000000000000000000000000000000"
    index = 0
    sequence = 0xFFFFFFFF
    value = 100000 
    scriptSig = CScript([x('0020') + witness_script_hash])
    outpoint = COutPoint(bytes.fromhex(txid), index)
    
    recipient_hash = base58.b58decode_check(recipient_address)[1:] 
    scriptPubKey = CScript([OP_HASH160, recipient_hash, OP_EQUAL]) 
   
    txin = CTxIn(outpoint,scriptSig=scriptSig, nSequence=sequence)
    txout = CTxOut(value, scriptPubKey)
    
    mtx = CMutableTransaction([txin], [txout])
    
    sighash = calculate_signature_hash(mtx, witness_script, value)
    
    signature2 = sign_with_ecdsa(sighash, private_key_2)
    signature1 = sign_with_ecdsa(sighash, private_key_1)

    witness_stack = [b'', signature2 , signature1 ,bytes(witness_script)]
    mtx = add_witness_stack(mtx ,witness_stack)
    
    tx_hex = mtx.serialize().hex()                

    with open("out.txt", "w") as file:
        file.write(tx_hex)
    print("Signed transaction written to 'out.txt'")

if __name__ == "__main__":
    main()