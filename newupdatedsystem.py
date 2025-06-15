import numpy as np
from scipy.integrate import odeint
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime, timezone, timedelta
from pysolar.solar import get_altitude
import json # To store metadata in a readable format

# --- Simulated Blockchain Ledger ---
# In a real off-chain setup, this would be a smart contract on a blockchain.
# For demonstration, we'll use a simple dictionary.
# Key: token_id, Value: dictionary containing code_hash, nonce, tag, sender, receiver
simulated_blockchain_ledger = {}

class EnergyCommSystem:
    """A system for simulating energy dynamics, encrypting messages, and minting energy credit tokens."""

    def __init__(self, latitude: float = 32.2226, longitude: float = -110.9747, utc_offset: int = -7,
                 user_id: str = "0xMockSender"):
        """Initialize the system with location and cryptographic parameters."""
        self.latitude = latitude
        self.longitude = longitude
        self.utc_offset = utc_offset
        self.timestamp = int(datetime.now(timezone.utc).timestamp())
        self.timestamp_str = datetime.now(timezone.utc).astimezone(
            timezone(timedelta(hours=utc_offset))).strftime('%Y-%m-%d %H:%M:%S')

        # Pauli matrices for quantum-inspired calculations
        self.sigma_x = np.array([[0, 1], [1, 0]])
        self.sigma_y = np.array([[0, -1j], [1j, 0]])
        self.sigma_z = np.array([[1, 0], [0, -1]])
        self.entropy_pool = get_random_bytes(32)

        # Blockchain-like storage (local to this instance, not global like the ledger)
        self.ects = {}  # Energy Credit Tokens
        self.metadata_map = {}
        self.ect_counter = 0
        self.user_id = user_id # This identifies the sender/receiver
        self.total_energy_saved = 0
        self.energy_credits = {} # Stored per user

    def simulate_circuit(self, t: np.ndarray, surge_voltage: float = 10000) -> np.ndarray:
        """Simulate circuit dynamics for grounding a voltage surge."""
        R, C, R_ground = 50, 1e-6, 10
        def circuit_dynamics(V, t):
            return -(V / (R * C)) - (V / R_ground)
        return odeint(circuit_dynamics, surge_voltage, t).flatten()

    def simulate_signal(self, t: np.ndarray, initial_snr: float = 10) -> np.ndarray:
        """Simulate signal-to-noise ratio degradation over time."""
        distance_factor = 0.5
        interference = 0.1 * np.sin(100 * t)
        return initial_snr * np.exp(-distance_factor * t) + interference

    def generate_aes_key(self, params: np.ndarray) -> bytes:
        """Generate an AES-256 key from optimization parameters."""
        return hashlib.sha256(params.tobytes()).digest()

    def encrypt_message(self, key: bytes, message: str) -> tuple:
        """Encrypt a message using AES-256 in EAX mode."""
        if not message.endswith('.'):
            message += '.'
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        return cipher.nonce, ciphertext, tag

    def decrypt_message(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> tuple:
        """Decrypt a message and verify its integrity."""
        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
            return message, message.endswith('.')
        except ValueError as e:
            print(f"Decryption failed: {e}. Message tampered with or incorrect key/nonce/tag.")
            return None, False

    def optimize_params(self, final_voltage: float) -> np.ndarray:
        """Run classical optimization using a quantum-inspired Hamiltonian."""
        ZZ = np.kron(self.sigma_z, self.sigma_z)
        XI = np.kron(self.sigma_x, np.eye(2))
        IX = np.kron(np.eye(2), self.sigma_x)
        hamiltonian = 1.0 * ZZ + 0.5 * XI + 0.5 * IX

        def ansatz_state(theta):
            state = np.zeros(4)
            state[0] = np.cos(theta / 2)
            state[3] = np.sin(theta / 2)
            return state / np.linalg.norm(state)

        def objective(theta):
            state = ansatz_state(theta)
            return np.real(state.T @ hamiltonian @ state)

        params = np.array([0.0])
        learning_rate = 0.05
        for _ in range(200):
            grad = (objective(params + 0.01) - objective(params - 0.01)) / 0.02
            params -= learning_rate * grad
            if np.abs(grad) < 1e-4:
                break
        return params

    def calculate_energy_credit(self, final_voltage: float, final_snr: float,
                             solar_energy_input: float) -> int:
        """Calculate energy credits based on grounding, signal, and solar input."""
        sigma_sum = int(self.sigma_x.sum().real + self.sigma_y.sum().real + self.sigma_z.sum().real)
        entropy_factor = len(self.entropy_pool)
        grounding_energy = (10000 - final_voltage) * 0.001
        base_energy = entropy_factor * abs(sigma_sum)

        utc_dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        local_dt = utc_dt.astimezone(timezone(timedelta(hours=self.utc_offset)))
        try:
            # Pysolar can sometimes return non-finite values if location/time is problematic
            solar_altitude = get_altitude(self.latitude, self.longitude, local_dt)
            solar_factor = max(0, solar_altitude) / 90
        except ValueError: # Handle cases where pysolar might fail
            solar_factor = 0.0
            print("Warning: Could not calculate solar altitude. Solar factor set to 0.")


        return int(base_energy * 5 + grounding_energy + solar_energy_input * solar_factor)

    def mint_ect(self, message: str, receiver_id: str, solar_energy_input: float = 10) -> tuple:
        """Mint an Energy Credit Token with encrypted message and energy credits."""
        # Simulate dynamics
        t = np.linspace(0, 1, 100)
        voltages = self.simulate_circuit(t)
        snr_values = self.simulate_signal(t)
        final_voltage, final_snr = voltages[-1], snr_values[-1]

        # Generate encryption key
        params = self.optimize_params(final_voltage)
        aes_key = self.generate_aes_key(params)

        # Encrypt the message
        nonce, ciphertext, tag = self.encrypt_message(aes_key, message)
        # The encrypted_code represents what would be sent off-chain as the actual message payload
        encrypted_code_payload = base64.b64encode(nonce + ciphertext + tag).decode('utf-8') # Include tag in payload for transfer

        # Create a hash of the *encrypted payload* to be stored on the blockchain
        code_hash = hashlib.sha256(encrypted_code_payload.encode('utf-8')).hexdigest()

        # Create token ID (unique for demonstration)
        trace_sum = int(self.sigma_x.trace().real + self.sigma_y.trace().real +
                       self.sigma_z.trace().real)
        # Use a more robust way to generate a unique token ID for demonstration purposes
        token_id = int(hashlib.sha256(
            (str(trace_sum) + str(self.timestamp) + str(self.ect_counter) + self.user_id + receiver_id).encode()
        ).hexdigest(), 16) % 100000000 # Make it a larger range for better uniqueness

        # Calculate energy credit
        energy_credit = self.calculate_energy_credit(final_voltage, final_snr, solar_energy_input)

        # Store metadata (what would be on-chain or easily verifiable)
        metadata = {
            'code_hash': code_hash,
            'timestamp': self.timestamp,
            'timestamp_str': self.timestamp_str,
            'description': 'Grounding Energy and Secure Communication',
            'energy_saved': energy_credit,
            'final_voltage': final_voltage,
            'final_snr': final_snr,
            'location': f'Lat: {self.latitude}, Lon: {self.longitude}',
            'optimal_params': params.tolist(),
            'sender_id': self.user_id,
            'receiver_id': receiver_id,
            # IMPORTANT: nonce and tag are part of the *off-chain* payload,
            # but we're also storing them here to simulate retrieval from the ledger for decryption demo
            # In a real system, the receiver would get these with the ciphertext payload off-chain.
            'nonce_b64': base64.b64encode(nonce).decode('utf-8'),
            'tag_b64': base64.b64encode(tag).decode('utf-8')
        }

        # --- Simulate On-Chain Transaction ---
        # Only store the hash and relevant metadata on the 'blockchain'
        simulated_blockchain_ledger[token_id] = {
            'code_hash': code_hash,
            'energy_saved': energy_credit,
            'timestamp': self.timestamp,
            'sender_id': self.user_id,
            'receiver_id': receiver_id,
            # For demonstration, we'll also store nonce/tag for receiver to 'query'
            # In real blockchain, this would imply encrypting the key with receiver's public key
            # and the receiver gets the key to decrypt these parts directly.
            'nonce_b64': base64.b64encode(nonce).decode('utf-8'),
            'tag_b64': base64.b64encode(tag).decode('utf-8')
        }

        # Update local state
        self.ects[token_id] = {
            'encrypted_code_payload': encrypted_code_payload, # This is the full encrypted message
            'metadata': metadata,
            'energy_credit': energy_credit,
            'timestamp_str': self.timestamp_str
        }
        self.metadata_map[code_hash] = metadata
        self.energy_credits[self.user_id] = self.energy_credits.get(self.user_id, 0) + energy_credit
        self.total_energy_saved += energy_credit
        self.ect_counter += 1

        print(f"\n--- ECT Minted by {self.user_id} ---")
        print(f"Minted ECT ID {token_id}: Energy Saved = {energy_credit} Wh, SNR = {final_snr:.2f} dB")
        print(f"Message Encrypted and Hashed. Hash (On-Chain): {code_hash}")
        print(f"Encrypted Payload (Off-Chain): {encrypted_code_payload[:50]}...") # Show truncated payload

        return token_id, encrypted_code_payload, aes_key # Return AES key for local demo decryption

    def redeem_credits(self, amount: int) -> None:
        """Redeem energy credits for the sender."""
        if self.energy_credits.get(self.user_id, 0) >= amount:
            self.energy_credits[self.user_id] -= amount
            self.total_energy_saved -= amount
            print(f"Redeemed {amount} Wh for {self.user_id}. Remaining: {self.energy_credits[self.user_id]} Wh")
        else:
            print("Error: Insufficient credits")

    def get_energy_credits(self, user: str) -> int:
        """Get the energy credit balance for a user."""
        return self.energy_credits.get(user, 0)

# --- Demonstration Script ---
if __name__ == '__main__':
    print("--- Setting up the Secure Communication Network ---")

    # 1. Initialize Sender (Alice) and Receiver (Bob) instances
    # Each instance represents a participant in the network.
    # Alice sends messages, Bob receives.
    alice_system = EnergyCommSystem(user_id="Alice")
    bob_system = EnergyCommSystem(user_id="Bob")

    # --- Scenario 1: Alice sends a message to Bob ---
    print("\n--- Alice sends a message to Bob ---")
    message_to_bob = "Hello Bob, this is a very secure message from Alice!"

    # Alice mints an ECT for the message.
    # This also simulates the 'on-chain' part by adding the hash to simulated_blockchain_ledger.
    # The 'aes_key' here is used for direct demonstration; in a real system, it would be securely exchanged.
    alice_token_id, alice_encrypted_payload, alice_aes_key = \
        alice_system.mint_ect(message_to_bob, receiver_id="Bob")

    print(f"\nAlice's ECT minted successfully. Token ID: {alice_token_id}")

    # --- Simulated Off-Chain Delivery ---
    # Alice sends the encrypted payload, the token ID, and her 'session key' (simulated AES key)
    # to Bob through a separate secure channel (e.g., P2P).
    # In a real system, the AES key would be derived from a shared secret or encrypted with Bob's public key.
    # For this demo, we'll pass the AES key directly to Bob.
    delivered_payload_to_bob = {
        'token_id': alice_token_id,
        'encrypted_payload': alice_encrypted_payload,
        'aes_key': alice_aes_key # This simulates key exchange or derivation
    }
    print(f"Off-chain: Encrypted payload and Token ID delivered to Bob.")

    # --- Bob receives and verifies the message ---
    print("\n--- Bob receives and verifies the message ---")

    # Bob extracts components from the delivered payload
    received_token_id = delivered_payload_to_bob['token_id']
    received_encrypted_payload = delivered_payload_to_bob['encrypted_payload']
    bob_aes_key = delivered_payload_to_bob['aes_key'] # Bob gets the key securely

    # 1. Bob computes the hash of the received encrypted payload
    computed_payload_hash = hashlib.sha256(received_encrypted_payload.encode('utf-8')).hexdigest()
    print(f"Bob computes hash of received payload: {computed_payload_hash}")

    # 2. Bob queries the 'simulated blockchain ledger' for the ECT metadata using the token ID
    # In a real system, this is a smart contract call.
    print(f"Bob queries simulated blockchain for Token ID: {received_token_id}")
    on_chain_data = simulated_blockchain_ledger.get(received_token_id)

    if on_chain_data:
        print(f"Blockchain data found for Token ID {received_token_id}.")
        print(f"On-chain recorded hash: {on_chain_data['code_hash']}")

        # 3. Bob verifies the integrity by comparing hashes
        if computed_payload_hash == on_chain_data['code_hash']:
            print("Hash verification successful! Message integrity confirmed by blockchain record.")

            # 4. Bob decodes the encrypted payload to get nonce, ciphertext, and tag
            decoded_payload = base64.b64decode(received_encrypted_payload)
            # In EAX mode, nonce is typically 16 bytes, ciphertext follows, then tag (16 bytes)
            nonce_len = 16 # AES GCM standard nonce size (often 12 or 16 bytes)
            tag_len = 16 # AES GCM standard tag size
            # Assuming nonce is at the beginning, tag at the end
            # This order (nonce + ciphertext + tag) was used in mint_ect
            received_nonce = decoded_payload[:nonce_len]
            received_ciphertext = decoded_payload[nonce_len:-tag_len]
            received_tag = decoded_payload[-tag_len:]

            # 5. Bob decrypts the message using his AES key, nonce, and tag
            # Note: Bob's system instance doesn't have the key directly, it's 'given' to it for the demo
            decrypted_message, is_valid_format = bob_system.decrypt_message(
                bob_aes_key, received_nonce, received_ciphertext, received_tag
            )

            if decrypted_message:
                print(f"Decryption successful! Decrypted message: '{decrypted_message}'")
                if is_valid_format:
                    print("Message format is valid (ends with '.').")
                else:
                    print("Warning: Message format might be incomplete (does not end with '.').")
            else:
                print("Decryption failed. Could not retrieve original message.")
        else:
            print("Hash verification FAILED! Message might have been tampered with or is not linked to this ECT.")
    else:
        print(f"Error: Token ID {received_token_id} not found on the simulated blockchain ledger.")

    # --- Scenario 2: Bob sends a message to Alice ---
    print("\n--- Bob sends a message to Alice ---")
    message_to_alice = "Alice, understood! Over and out from Bob."

    bob_token_id, bob_encrypted_payload, bob_aes_key = \
        bob_system.mint_ect(message_to_alice, receiver_id="Alice")

    print(f"\nBob's ECT minted successfully. Token ID: {bob_token_id}")

    delivered_payload_to_alice = {
        'token_id': bob_token_id,
        'encrypted_payload': bob_encrypted_payload,
        'aes_key': bob_aes_key
    }
    print(f"Off-chain: Encrypted payload and Token ID delivered to Alice.")

    print("\n--- Alice receives and verifies the message ---")
    received_token_id_alice = delivered_payload_to_alice['token_id']
    received_encrypted_payload_alice = delivered_payload_to_alice['encrypted_payload']
    alice_aes_key_for_bob_msg = delivered_payload_to_alice['aes_key'] # Alice gets Bob's key securely

    computed_payload_hash_alice = hashlib.sha256(received_encrypted_payload_alice.encode('utf-8')).hexdigest()
    print(f"Alice computes hash of received payload: {computed_payload_hash_alice}")

    on_chain_data_alice = simulated_blockchain_ledger.get(received_token_id_alice)

    if on_chain_data_alice:
        print(f"Blockchain data found for Token ID {received_token_id_alice}.")
        print(f"On-chain recorded hash: {on_chain_data_alice['code_hash']}")

        if computed_payload_hash_alice == on_chain_data_alice['code_hash']:
            print("Hash verification successful! Message integrity confirmed by blockchain record.")

            decoded_payload_alice = base64.b64decode(received_encrypted_payload_alice)
            received_nonce_alice = decoded_payload_alice[:nonce_len]
            received_ciphertext_alice = decoded_payload_alice[nonce_len:-tag_len]
            received_tag_alice = decoded_payload_alice[-tag_len:]

            decrypted_message_alice, is_valid_format_alice = alice_system.decrypt_message(
                alice_aes_key_for_bob_msg, received_nonce_alice, received_ciphertext_alice, received_tag_alice
            )

            if decrypted_message_alice:
                print(f"Decryption successful! Decrypted message: '{decrypted_message_alice}'")
            else:
                print("Decryption failed for Alice. Could not retrieve original message.")
        else:
            print("Hash verification FAILED for Alice! Message might have been tampered with.")
    else:
        print(f"Error: Token ID {received_token_id_alice} not found on the simulated blockchain ledger.")

    # --- Demonstrate energy credit balances ---
    print("\n--- Energy Credit Balances ---")
    print(f"Alice's energy credits: {alice_system.get_energy_credits('Alice')} Wh")
    print(f"Bob's energy credits: {bob_system.get_energy_credits('Bob')} Wh")

    print("\n--- Simulated Blockchain Ledger Contents ---")
    for tid, data in simulated_blockchain_ledger.items():
        print(f"Token ID: {tid}, Data: {json.dumps(data, indent=2)}")

