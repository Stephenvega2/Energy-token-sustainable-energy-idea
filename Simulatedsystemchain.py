import sqlite3
import random
import time
from datetime import datetime, timedelta
import platform # To get some basic device info, though not truly unique/secure

# --- 1. Simulated Blockchain Environment ---
class SimulatedBlockchain:
    def __init__(self):
        self.blocks = []
        self.gas_prices_history = []
        self.current_block_number = 0
        self.base_gas_price = 20  # Gwei
        self.congestion_factor = 0.5 # How much congestion impacts gas fees
        self.block_time = 15 # seconds per block

    def generate_block(self):
        # Simulate network congestion affecting gas prices
        # Higher congestion -> higher gas price
        current_congestion = random.uniform(0.1, 1.5)
        current_gas_price = self.base_gas_price * (1 + self.congestion_factor * current_congestion)
        self.gas_prices_history.append((datetime.now(), current_gas_price))

        block = {
            "block_number": self.current_block_number,
            "timestamp": datetime.now(),
            "gas_price_gwei": current_gas_price,
            "transactions": [] # We'll add minting transactions here
        }
        self.blocks.append(block)
        self.current_block_number += 1
        time.sleep(self.block_time) # Simulate block time
        print(f"Generated Block {self.current_block_number-1} with Gas Price: {current_gas_price:.2f} Gwei")
        return block

# --- 2. Gas Fee Oracle/Predictor ---
class GasOracle:
    def __init__(self, db_path="blockchain_data.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._setup_db()

    def _setup_db(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS gas_prices (
                timestamp TEXT,
                gas_price REAL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS minted_tokens (
                token_id TEXT PRIMARY KEY,
                rarity TEXT,
                mint_timestamp TEXT,
                gas_cost REAL,
                encrypted_data TEXT,
                encryption_details TEXT
            )
        ''')
        self.conn.commit()

    def record_gas_price(self, timestamp, gas_price):
        self.cursor.execute("INSERT INTO gas_prices VALUES (?, ?)", (timestamp.isoformat(), gas_price))
        self.conn.commit()

    def get_historical_gas_prices(self, lookback_hours=24):
        cutoff_time = datetime.now() - timedelta(hours=lookback_hours)
        self.cursor.execute("SELECT timestamp, gas_price FROM gas_prices WHERE timestamp > ?", (cutoff_time.isoformat(),))
        return self.cursor.fetchall()

    def predict_optimal_mint_time(self, lookahead_minutes=60):
        # Simple prediction: Find the average gas price in recent history
        # and suggest minting when current gas price is below average.
        # For a more advanced system, you'd use statistical models, AI, etc.
        historical_prices = [p[1] for p in self.get_historical_gas_prices()]
        if not historical_prices:
            return None, "No historical data to predict."

        avg_gas_price = sum(historical_prices) / len(historical_prices)
        print(f"Historical Average Gas Price: {avg_gas_price:.2f} Gwei")

        # In a real simulation, you'd monitor the simulated blockchain's gas prices
        # to identify a real-time dip. Here, we'll just return the current average
        # and let the optimizer decide based on the current simulated price.
        return avg_gas_price, f"Consider minting when gas price is below {avg_gas_price:.2f} Gwei."

    def record_minted_token(self, token_id, rarity, mint_timestamp, gas_cost, encrypted_data, encryption_details):
        self.cursor.execute("INSERT INTO minted_tokens VALUES (?, ?, ?, ?, ?, ?)",
                            (token_id, rarity, mint_timestamp.isoformat(), gas_cost, encrypted_data, encryption_details))
        self.conn.commit()

    def close(self):
        self.conn.close()

# --- 3. Rare Token Minting Logic ---
class NFTMintingContract:
    def __init__(self, simulation_env):
        self.simulation_env = simulation_env
        self.total_tokens_minted = 0

    def calculate_rarity(self):
        # Emulate rarity based on a random chance
        # In a real scenario, this could be tied to on-chain factors,
        # specific minting conditions, or even time of day/block number.
        rand_val = random.random()
        if rand_val < 0.01:
            return "Super Elite" # 1% chance
        elif rand_val < 0.10:
            return "Elite"     # 9% chance
        else:
            return "Common"    # 90% chance

    def mint_token(self, gas_price_gwei, gas_limit=100000):
        self.total_tokens_minted += 1
        token_id = f"TOKEN-{self.total_tokens_minted}"
        rarity = self.calculate_rarity()
        mint_timestamp = datetime.now()
        gas_cost_eth = (gas_price_gwei * gas_limit) / (10**9) # Convert Gwei to Ether

        print(f"Attempting to mint Token ID: {token_id}, Rarity: {rarity}, Est. Gas Cost: {gas_cost_eth:.6f} ETH")

        # Simulate transaction success/failure based on gas limit vs actual consumption
        # For simplicity, we'll assume success if we attempt to mint.
        actual_gas_used = random.randint(gas_limit // 2, gas_limit) # Simulate variable gas usage
        final_gas_cost_eth = (gas_price_gwei * actual_gas_used) / (10**9)

        print(f"Minted Token {token_id}. Actual Gas Cost: {final_gas_cost:.6f} ETH (used {actual_gas_used} gas)")
        return token_id, rarity, mint_timestamp, final_gas_cost_eth

# --- 4. "Grounded" and "Entangled" Encryption Module (Conceptual) ---
class GroundedEntangledEncryption:
    # MODIFICATION START: Pass device parameters
    def __init__(self, device_parameters):
        self.device_parameters = device_parameters
        # This module conceptually represents a secure hardware enclave or a physically grounded system.
        # It's where sensitive keys would be stored and encryption operations performed.
        # The "grounded" aspect implies physical security, power stability, and perhaps thermal management.
    # MODIFICATION END

    def _generate_entangled_key_parts(self, data_to_encrypt):
        # Conceptual "entanglement": key is derived from multiple factors
        # 1. Randomness (quantum-inspired PRNG if available, or just strong CSPRNG)
        # 2. Hardware-specific fingerprint (self.unique_hardware_id) - NOW FROM DEVICE
        # 3. Data-specific nonce
        # 4. A 'grounding' parameter (e.g., current temperature, system uptime, secure time source) - NOW FROM DEVICE
        
        # This is a placeholder for a complex cryptographic process.
        # In reality, this would involve quantum key distribution (QKD) principles,
        # multi-party computation (MPC), or homomorphic encryption.
        
        # MODIFICATION START: Incorporate device_parameters
        seed_material = (
            f"{data_to_encrypt}-"
            f"{random.randint(0, 1000000)}-"
            f"{self.device_parameters.get('device_id', 'UNKNOWN_DEVICE')}-" # Use device ID
            f"{self.device_parameters.get('uptime', time.time())}-"         # Use simulated uptime
            f"{time.time()}"
        )
        # MODIFICATION END
        
        # Simulate generating "entangled" key parts - meaning derived from multiple sources
        key_part_A = hash(seed_material + "partA")
        key_part_B = hash(seed_material + "partB")
        
        # A single, derived master key from these parts
        master_key_hash = hash(f"{key_part_A}{key_part_B}")
        
        # For conceptual demonstration, let's use a simple XOR based on the hash
        return str(master_key_hash) # Return a string representation of the key for storage

    def encrypt_token_data(self, token_id, rarity, sensitive_data="private_token_info"):
        # The data to be encrypted might be additional metadata, ownership proofs, etc.
        key = self._generate_entangled_key_parts(token_id)
        
        # Simulate encryption using the 'entangled' key
        encrypted_data = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(sensitive_data))
        
        # MODIFICATION START: Include more device details in encryption_details
        encryption_details = {
            "method": "Conceptual_Entangled_XOR_with_Device_Grounding",
            "device_info": self.device_parameters, # Store the parameters from your device
            "key_derivation_factors_conceptual": ["randomness", "device_fingerprint", "data_nonce", "grounding_parameter_from_device"]
        }
        # MODIFICATION END
        
        print(f"Encrypted data for {token_id} using entangled encryption, grounded by your device.")
        return encrypted_data, encryption_details

    def decrypt_token_data(self, encrypted_data, token_id, encryption_details):
        # To decrypt, you'd need to re-derive the exact same key using the same logic and parameters.
        # This highlights the "entanglement" - the key is tied to specific environmental/hardware factors.
        
        # For demonstration, we'll re-derive the key based on token_id (a proxy for the original seed material)
        # In a real system, you'd need all the original derivation factors and access to the 'grounded' system.
        key = self._generate_entangled_key_parts(token_id) # This re-derivation needs to be exact
        
        decrypted_data = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted_data))
        print(f"Decrypted data for {token_id}.")
        return decrypted_data


# --- 5. Optimization Engine ---
class MintingOptimizer:
    def __init__(self, gas_oracle, minting_contract, encryption_module, target_rarity="Elite"):
        self.gas_oracle = gas_oracle
        self.minting_contract = minting_contract
        self.encryption_module = encryption_module
        self.target_rarity = target_rarity
        self.max_gas_price_threshold = 30 # Gwei, example threshold

    def optimize_and_mint(self, attempts=10):
        print(f"\n--- Starting Optimization for '{self.target_rarity}' Token ---")
        best_gas_cost = float('inf')
        minted_rare_token_info = None

        for i in range(attempts):
            print(f"\nAttempt {i+1}/{attempts}:")
            current_simulated_block = simulated_blockchain.generate_block()
            current_gas_price = current_simulated_block["gas_price_gwei"]
            self.gas_oracle.record_gas_price(current_simulated_block["timestamp"], current_gas_price)

            avg_gas_price, _ = self.gas_oracle.predict_optimal_mint_time()

            if current_gas_price <= self.max_gas_price_threshold and \
               (avg_gas_price is None or current_gas_price < avg_gas_price):
                print(f"Current gas price ({current_gas_price:.2f} Gwei) is favorable. Attempting to mint...")
                token_id, rarity, mint_timestamp, final_gas_cost = self.minting_contract.mint_token(current_gas_price)

                if rarity == self.target_rarity or (rarity == "Super Elite" and self.target_rarity in ["Elite", "Super Elite"]):
                    print(f"SUCCESS! Minted a {rarity} token with ID {token_id} at a cost of {final_gas_cost:.6f} ETH.")

                    # Apply "Grounded" and "Entangled" Encryption
                    # MODIFICATION START: Use the encryption module initialized with device parameters
                    encrypted_data, encryption_details = self.encryption_module.encrypt_token_data(token_id, rarity)
                    # MODIFICATION END
                    
                    self.gas_oracle.record_minted_token(token_id, rarity, mint_timestamp, final_gas_cost, encrypted_data, str(encryption_details))
                    
                    if final_gas_cost < best_gas_cost:
                        best_gas_cost = final_gas_cost
                        minted_rare_token_info = {
                            "token_id": token_id,
                            "rarity": rarity,
                            "gas_cost": final_gas_cost,
                            "encrypted_data": encrypted_data,
                            "encryption_details": encryption_details
                        }
                    # We might stop after finding the first rare token, or continue to find the cheapest one
                    # if minted_rare_token_info: break # Uncomment to stop after first successful rare mint
                else:
                    print(f"Minted a {rarity} token (not target rarity).")
            else:
                print(f"Current gas price ({current_gas_price:.2f} Gwei) is too high or not optimal. Skipping minting this block.")

        if minted_rare_token_info:
            print(f"\n--- Best '{self.target_rarity}' Token Minted ---")
            print(f"Token ID: {minted_rare_token_info['token_id']}")
            print(f"Rarity: {minted_rare_token_info['rarity']}")
            print(f"Gas Cost: {minted_rare_token_info['gas_cost']:.6f} ETH")
            
            # Demonstrate decryption
            decrypted_info = self.encryption_module.decrypt_token_data(
                minted_rare_token_info['encrypted_data'],
                minted_rare_token_info['token_id'],
                minted_rare_token_info['encryption_details']
            )
            print(f"Decrypted Data (conceptual): {decrypted_info}")

        else:
            print(f"\n--- No '{self.target_rarity}' token minted within {attempts} attempts or at optimal gas price. ---")


# --- Main Execution ---
if __name__ == "__main__":
    # MODIFICATION START: Gather conceptual device parameters
    # In a real scenario, these would come from actual device sensors or secure hardware features.
    # For simulation, we'll use basic system info and random values.
    my_device_parameters = {
        "device_id": platform.node(), # A basic identifier for your machine
        "os": platform.system(),
        "processor": platform.processor(),
        "simulated_temperature_celsius": random.uniform(25.0, 45.0), # Simulate current temp
        "simulated_uptime_seconds": time.time() - time.monotonic_ns() / 1_000_000_000 # Rough uptime
        # You could add more, like 'battery_level', 'network_strength', etc.
    }
    print(f"Initializing with Device Parameters: {my_device_parameters}")
    # MODIFICATION END

    # Initialize components
    simulated_blockchain = SimulatedBlockchain()
    gas_oracle = GasOracle()
    nft_contract = NFTMintingContract(simulated_blockchain)
    # MODIFICATION START: Pass device parameters to the encryption module
    grounded_encryption = GroundedEntangledEncryption(my_device_parameters)
    # MODIFICATION END

    optimizer = MintingOptimizer(gas_oracle, nft_contract, grounded_encryption, target_rarity="Elite")

    # Run the simulation and optimization
    # Let's pre-generate some blocks to populate historical gas data
    print("Pre-generating some blocks for historical gas data...")
    for _ in range(5):
        block = simulated_blockchain.generate_block()
        gas_oracle.record_gas_price(block["timestamp"], block["gas_price_gwei"])
    print("\nStarting minting optimization attempts...")
    
    optimizer.optimize_and_mint(attempts=20)

    # You can query the SQLite database directly here if you want to inspect data
    conn = sqlite3.connect("blockchain_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM minted_tokens")
    print("\n--- All Minted Tokens in DB ---")
    for row in cursor.fetchall():
        print(row)
    conn.close()

    gas_oracle.close()
