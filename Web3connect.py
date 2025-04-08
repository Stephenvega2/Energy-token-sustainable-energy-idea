import hashlib
import os
from datetime import datetime
from pysolar.solar import get_altitude
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import logging
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load private key from .env file
load_dotenv()
private_key = os.getenv("PRIVATE_KEY")
if not private_key:
    raise ValueError("PRIVATE_KEY not set in .env")
account = Account.from_key(private_key)

# Connect to Hardhat node
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
contract_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Update with your deployed address
with open("EnergyCreditContract.abi", "r") as f:
    contract_abi = json.load(f)
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def compute_credit(latitude, longitude, utc_offset, timestamp, entropy, solar_input):
    sigma_x, sigma_y, sigma_z = np.array([[0, 1], [1, 0]]), np.array([[0, -1j], [1j, 0]]), np.array([[1, 0], [0, -1]])
    
    # Eigenvalues: ±1 for each matrix, sum of absolute values = 2 per matrix
    eig_sum = 2 + 2 + 2  # |1| + |-1| for sigma_x, sigma_y, sigma_z
    base = len(entropy) * eig_sum  # Eigenvalue-based base
    
    solar_alt = get_altitude(latitude, longitude, datetime.fromtimestamp(timestamp))
    solar_factor = max(0, solar_alt) / 90
    credit = min(int(base * 5 + solar_input * solar_factor), 2**96 - 1)
    logger.info(f"Computed credit with eigenvalue offset: {credit} Wh (base: {base}, solar: {solar_input * solar_factor})")
    return credit

def encrypt_code(text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce, ciphertext = cipher.nonce, cipher.encrypt(text.encode())
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    hash_bytes = bytes.fromhex(hashlib.sha256(encrypted.encode()).hexdigest()[2:])
    logger.info(f"Encrypted code, hash: {hash_bytes.hex()}")
    return encrypted, hash_bytes

# Prepare and send transaction
try:
    code = "import numpy as np\n# Your code"
    encrypted, encrypted_hash = encrypt_code(code)
    timestamp = int(datetime.now().timestamp())
    entropy = get_random_bytes(32)  # 32 bytes of secure randomness
    credit = compute_credit(33.4484, -112.0740, -7, timestamp, entropy, 10)

    metadata = {
        "encryptedCode": encrypted,
        "timestampStr": datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
        "energySaved": credit,
        "location": "Lat: 33.4484, Lon: -112.0740"
    }
    metadata_hash = bytes.fromhex(hashlib.sha256(json.dumps(metadata).encode()).hexdigest()[2:])
    logger.info(f"Metadata prepared, hash: {metadata_hash.hex()}")

    # Get nonce
    nonce = contract.functions.getNonce(account.address).call()
    logger.info(f"Current nonce: {nonce}")

    # Sign transaction
    message_hash = Web3.solidity_keccak(
        ["address", "bytes32", "uint96", "uint256", "uint256"],
        [account.address, encrypted_hash, credit, timestamp, nonce]
    )
    signature = Account.signHash(message_hash, account.key).signature

    # Build transaction with dynamic gas
    tx = contract.functions.mintECT(
        encrypted_hash, metadata_hash, credit, timestamp, signature
    ).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 0,  # Placeholder
        "gasPrice": w3.to_wei("20", "gwei")
    })
    gas_estimate = w3.eth.estimate_gas(tx)
    tx["gas"] = gas_estimate + 10000  # Buffer
    logger.info(f"Estimated gas: {gas_estimate}, using: {tx['gas']}")

    # Send transaction
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    logger.info(f"Transaction sent: {tx_hash.hex()}")

    # Wait for confirmation
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logger.info(f"Transaction confirmed in block {receipt.blockNumber}")

except Exception as e:
    logger.error(f"Error: {str(e)}")
    raise
