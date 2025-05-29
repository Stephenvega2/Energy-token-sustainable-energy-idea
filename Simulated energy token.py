import hashlib
import os
from datetime import datetime, timedelta, timezone
from pysolar.solar import get_altitude
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class EnergyCreditContract:
    def __init__(self, latitude=33.4484, longitude=-112.0740, utc_offset=-7):
        print("Starting initialization...")
        self.transactions = []
        self.metadataMap = {} # This will now primarily store off-chain metadata hashes or pointers
        self.off_chain_metadata_store = {} # Simulate off-chain storage
        self.ects = {}
        self.ectCounter = 0
        self.sender = "0xMockAddress"
        self.timestamp = int(datetime.now().timestamp())
        self.timestampStr = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.sigma_x = np.array([[0, 1], [1, 0]])
        self.sigma_y = np.array([[0, -1j], [1j, 0]])
        self.sigma_z = np.array([[1, 0], [0, -1]])
        self.entropy_pool = os.urandom(32)
        self.totalEnergySaved = 0
        self.energyCredits = {}
        self.latitude = latitude
        self.longitude = longitude
        self.utc_offset = utc_offset
        self.simulated_gas_cost = 0 # To track simulated gas costs
        self.simulated_off_chain_cost = 0 # To track off-chain costs
        print(f"Initialized with location: Lat {self.latitude}, Lon {self.longitude}, UTC offset {self.utc_offset}")

    def _calculate_on_chain_gas_cost(self, data_size_bytes):
        """
        Simulates on-chain gas cost based on data size.
        (Conceptual: 1 unit of gas per byte, plus a base transaction cost)
        """
        return 1000 + data_size_bytes * 10 # Base cost + cost per byte

    def _calculate_off_chain_cost(self, data_size_bytes):
        """
        Simulates off-chain storage/computation cost. Much cheaper than on-chain.
        """
        return data_size_bytes * 0.1 # Very low cost per byte

    def setMetadata(self, key, codeHash, timestamp, timestampStr, description, energySaved, full_metadata_payload):
        # We now store a hash of the full metadata payload on-chain
        # And the full payload in our simulated off-chain store
        metadata_hash = hashlib.sha256(str(full_metadata_payload).encode('utf-8')).hexdigest()
        self.metadataMap[key] = {
            'metadataHash': metadata_hash,
            'timestamp': timestamp,
            'timestampStr': timestampStr,
            'energySaved': energySaved, # This can be stored on-chain for quick lookups
        }
        self.off_chain_metadata_store[metadata_hash] = full_metadata_payload

        # Simulate gas cost for storing metadata hash and key info on-chain
        on_chain_data = f"{key}{metadata_hash}{timestamp}{timestampStr}{energySaved}".encode('utf-8')
        self.simulated_gas_cost += self._calculate_on_chain_gas_cost(len(on_chain_data))

        # Simulate off-chain cost for storing the full metadata
        self.simulated_off_chain_cost += self._calculate_off_chain_cost(len(str(full_metadata_payload).encode('utf-8')))

        print(f"Set Metadata: codeHash={codeHash}, energySaved={energySaved}, timestamp={self.timestamp}, timestampStr={timestampStr}")
        print(f"On-chain cost for setMetadata: {self._calculate_on_chain_gas_cost(len(on_chain_data))} gas units")
        print(f"Off-chain cost for setMetadata: {self._calculate_off_chain_cost(len(str(full_metadata_payload).encode('utf-8')))} cost units")


    def mintECT(self, metadata, entropy, solarEnergyInput):
        # Extract values from metadata dict
        encryptedCode = metadata['encryptedCode']
        codeHash = metadata['codeHash']
        timestamp = metadata['timestamp']
        timestampStr = metadata['timestampStr']
        description = metadata['description']
        signature = metadata['signature']

        token_id = self.generateTokenId()
        sigma_x_sum = int(self.sigma_x.sum().real)
        sigma_y_sum = int(self.sigma_y.sum().real)
        sigma_z_sum = int(self.sigma_z.sum().real)
        entropy_mix = hashlib.sha256(self.entropy_pool + str(sigma_x_sum + sigma_y_sum + sigma_z_sum).encode('utf-8')).digest()
        entropy_hash = hashlib.sha256((encryptedCode + entropy_mix.hex() + str(sigma_x_sum + sigma_y_sum + sigma_z_sum)).encode('utf-8')).hexdigest()

        energy_credit = self.calculateEnergyCredit(sigma_x_sum, sigma_y_sum, sigma_z_sum, entropy, solarEnergyInput)
        self.totalEnergySaved += energy_credit
        self.energyCredits[self.sender] = self.energyCredits.get(self.sender, 0) + energy_credit
        print(f"CreditEarned: recipient={self.sender}, credits={energy_credit}, timestamp={self.timestamp}, timestampStr={timestampStr}")

        # The full_metadata is now stored off-chain, and only its hash on-chain
        full_metadata_payload = {
            'codeHash': codeHash,
            'timestamp': timestamp,
            'timestampStr': timestampStr,
            'description': description,
            'energySaved': energy_credit,
            'sigma_x': str(self.sigma_x),
            'sigma_y': str(self.sigma_y),
            'sigma_z': str(self.sigma_z),
            'entropyHash': entropy_hash,
            'location': f'Lat: {self.latitude}, Lon: {self.longitude}',
            'utc_offset': self.utc_offset
        }
        metadata_hash_for_ect = hashlib.sha256(str(full_metadata_payload).encode('utf-8')).hexdigest()
        self.off_chain_metadata_store[metadata_hash_for_ect] = full_metadata_payload

        self.ects[token_id] = {
            'encryptedCode': encryptedCode, # This could also be a hash if `encryptedCode` is very large
            'metadataHash': metadata_hash_for_ect, # Store only the hash on-chain
            'entropyHash': entropy_mix.hex()[:32],
            'energyCredit': energy_credit,
            'timestampStr': timestampStr
        }
        self.ectCounter += 1

        # Simulate gas cost for minting an ECT (on-chain data includes token_id, metadataHash, energyCredit, etc.)
        on_chain_ect_data = f"{token_id}{encryptedCode}{metadata_hash_for_ect}{entropy_mix.hex()[:32]}{energy_credit}{timestampStr}".encode('utf-8')
        self.simulated_gas_cost += self._calculate_on_chain_gas_cost(len(on_chain_ect_data))
        self.simulated_off_chain_cost += self._calculate_off_chain_cost(len(str(full_metadata_payload).encode('utf-8')))

        print(f"Minted ECT ID {token_id}. On-chain stores hash of metadata.")
        print(f"On-chain cost for mintECT: {self._calculate_on_chain_gas_cost(len(on_chain_ect_data))} gas units")
        print(f"Off-chain cost for mintECT: {self._calculate_off_chain_cost(len(str(full_metadata_payload).encode('utf-8')))} cost units")

        return token_id

    def generateTokenId(self):
        trace_x = int(self.sigma_x[0,0].real + self.sigma_x[1,1].real)
        trace_y = int(self.sigma_y[0,0].real + self.sigma_y[1,1].real)
        trace_z = int(self.sigma_z[0,0].real + self.sigma_z[1,1].real)
        return int(hashlib.sha256(str(trace_x + trace_y + trace_z + self.timestamp + self.ectCounter).encode('utf-8')).hexdigest(), 16) % 1000000

    def calculateEnergyCredit(self, sigmaXSum, sigmaYSum, sigmaZSum, entropy, solarEnergyInput):
        try:
            entropy_factor = len(entropy) if entropy else 1
            base_energy = entropy_factor * (abs(sigmaXSum) + abs(sigmaYSum) + abs(sigmaZSum))
            utc_dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
            local_dt = utc_dt.astimezone(timezone(timedelta(hours=self.utc_offset)))
            print(f"Calculating solar altitude for {local_dt} at Lat {self.latitude}, Lon {self.longitude}")
            solar_altitude = get_altitude(self.latitude, self.longitude, local_dt)
            print(f"Solar altitude: {solar_altitude}")
            solar_factor = max(0, solar_altitude) / 90
            print(f"Solar factor: {solar_factor}")
            return int(base_energy * 5 + solarEnergyInput * solar_factor)
        except Exception as e:
            print(f"Error in calculateEnergyCredit: {e}")
            return 0

    def getEnergyCredits(self, user):
        return self.energyCredits.get(user, 0)

    def getECTMetadata(self, token_id):
        """
        Retrieves the full metadata for an ECT by looking up its hash
        in the off-chain store.
        """
        if token_id in self.ects:
            metadata_hash = self.ects[token_id]['metadataHash']
            # Simulate cost to retrieve off-chain
            self.simulated_off_chain_cost += self._calculate_off_chain_cost(len(str(self.off_chain_metadata_store.get(metadata_hash, {})).encode('utf-8')))
            return self.off_chain_metadata_store.get(metadata_hash)
        return None

def encrypt_text(plain_text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

if __name__ == "__main__":
    print("\nExecuting Simulated Energy Token with Grounding System:")
    try:
        contract = EnergyCreditContract(
            latitude=32.2226,    # Tucson, AZ
            longitude=-110.9747,
            utc_offset=-7       # Arizona UTC-7
        )
        current_time = int(datetime.now().timestamp())
        current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        code = """
        import numpy as np
        sigma_x = np.array([[0, 1], [1, 0]])
        sigma_y = np.array([[0, -1j], [1j, 0]])
        sigma_z = np.array([[1, 0], [0, -1]])
        # This is a much longer code snippet to demonstrate data size impact
        def calculate_some_quantum_value():
            # Imagine complex quantum calculations here
            return np.trace(sigma_x @ sigma_y @ sigma_z)
        """

        code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
        encrypted_code = encrypt_text(code)

        # Full metadata payload that would be stored off-chain
        full_metadata_payload = {
            'encryptedCode': encrypted_code,
            'codeHash': code_hash,
            'timestamp': current_time,
            'timestampStr': current_time_str,
            'description': "Quantum-AES Encryption Code with extended details for off-chain storage. This part contains verbose information that would be expensive to store on-chain directly.",
            'signature': "mock_signature",
            'additional_data': "This could be sensor readings, detailed audit logs, or any other large data." * 5 # Simulate larger data
        }

        # First, set metadata - we pass the full payload to setMetadata for off-chain storage
        # Only a hash and critical summary are conceptually stored on-chain
        contract.setMetadata(
            key=code_hash,
            codeHash=code_hash,
            timestamp=current_time,
            timestampStr=current_time_str,
            description="Quantum-AES Encryption Code Summary", # Shorter description for on-chain
            energySaved=0, # Initial value
            full_metadata_payload=full_metadata_payload
        )

        # Then mint the ECT, referencing the off-chain metadata
        token_id = contract.mintECT(
            metadata=full_metadata_payload, # Pass the full payload to mint, which will hash it
            entropy=os.urandom(32),
            solarEnergyInput=10  # solarEnergyInput
        )

        print(f"\n--- Simulation Results ---")
        print(f"Total Energy Saved (Community): {contract.totalEnergySaved} Wh")
        print(f"Redeemable Energy Credits for {contract.sender}: {contract.getEnergyCredits(contract.sender)} Wh")

        retrieved_metadata = contract.getECTMetadata(token_id)
        if retrieved_metadata:
            print("\nRetrieved ECT Metadata (from simulated off-chain store):")
            for key, value in retrieved_metadata.items():
                if key == 'encryptedCode' and len(value) > 100: # Truncate for display
                    print(f"  {key}: {value[:100]}...")
                else:
                    print(f"  {key}: {value}")
        else:
            print("Error: No metadata found for token ID")

        print(f"\nSimulated Total On-chain Gas Cost: {contract.simulated_gas_cost} gas units (Lower is better)")
        print(f"Simulated Total Off-chain Storage/Computation Cost: {contract.simulated_off_chain_cost} cost units (Very low cost)")
        print(f"Message: Use your {contract.getEnergyCredits(contract.sender)} Wh credits to offset your energy bill or trade for carbon offsets!")

    except Exception as e:
        print(f"Execution error: {type(e).__name__}: {str(e)}")

