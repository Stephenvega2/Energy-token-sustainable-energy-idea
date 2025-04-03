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
        self.metadataMap = {}
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
        self.utc_offset = utc_offset  # Arizona is UTC-7, no DST
        print(f"Initialized with location: Lat {self.latitude}, Lon {self.longitude}, UTC offset {self.utc_offset}")

    def setMetadata(self, key, codeHash, timestamp, timestampStr, description, energySaved):
        self.metadataMap[key] = {
            'codeHash': codeHash,
            'timestamp': timestamp,
            'timestampStr': timestampStr,
            'description': description,
            'energySaved': energySaved,
            'sigma_x': str(self.sigma_x),
            'sigma_y': str(self.sigma_y),
            'sigma_z': str(self.sigma_z),
            'location': f'Lat: {self.latitude}, Lon: {self.longitude}',
            'utc_offset': self.utc_offset
        }
        hash_value = hashlib.sha256(codeHash.encode('utf-8')).hexdigest()
        print(f"EnergySaved: codeHash={hash_value}, energySaved={energySaved}, timestamp={self.timestamp}, timestampStr={timestampStr}")

    def mintECT(self, encryptedCode, codeHash, timestamp, timestampStr, description, signature, entropy, solarEnergyInput):
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

        metadata = {
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
        self.ects[token_id] = {
            'encryptedCode': encryptedCode,
            'metadata': metadata,
            'entropyHash': entropy_mix.hex()[:32],
            'energyCredit': energy_credit,
            'timestampStr': timestampStr
        }
        self.metadataMap[codeHash] = metadata
        self.ectCounter += 1
        print(f"Minted ECT ID {token_id}: {{'encryptedCode': '{encryptedCode}', 'metadata': {metadata}, 'energyCredit': {energy_credit}, 'timestampStr': '{timestampStr}'}}")
        print(f"EnergySaved: codeHash={codeHash}, energySaved={energy_credit}, timestamp={self.timestamp}, timestampStr={timestampStr}")
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
            # Create timezone-aware datetime for Arizona (UTC-7)
            utc_dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)  # UTC time
            local_dt = utc_dt.astimezone(timezone(timedelta(hours=self.utc_offset)))  # Arizona time
            print(f" Calculating solar altitude for {local_dt} at Lat {self.latitude}, Lon {self.longitude}")
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

def encrypt_text(plain_text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

if __name__ == "__main__":
    print("\nExecuting Simulated Energy Token:")
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
        """
        
        code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
        encrypted_code = encrypt_text(code)
        solar_energy_input = 10
        
        token_id = contract.mintECT(
            encrypted_code,
            code_hash,
            current_time,
            current_time_str,
            "Quantum-AES Encryption Code",
            "mock_signature",
            os.urandom(32),
            solar_energy_input
        )
        
        print(f"Total Energy Saved (Community): {contract.totalEnergySaved} Wh")
        print(f"Redeemable Energy Credits for {contract.sender}: {contract.getEnergyCredits(contract.sender)} Wh")
        if token_id in contract.ects:
            print("ECT Metadata:")
            for key, value in contract.ects[token_id]['metadata'].items():
                print(f"  {key}: {value}")
        else:
            print("Error: No metadata found for token ID")
        print(f"ECT Timestamp: {contract.ects[token_id]['timestampStr']}")
        print(f"Message: Use your {contract.getEnergyCredits(contract.sender)} Wh credits to offset your energy bill or trade for carbon offsets!")
    except Exception as e:
        print(f"Execution error: {type(e).__name__}: {str(e)}")
