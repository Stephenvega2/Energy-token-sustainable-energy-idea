import numpy as np
from scipy.integrate import odeint
import hashlib
from Crypto.Cipher import AES
import base64
from datetime import datetime, timezone, timedelta
from pysolar.solar import get_altitude
import os
import json
import platform
import uuid

from kivy.app import App
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.core.clipboard import Clipboard

# --- Blockchain-like Block ---
class Block:
    def __init__(self, index, token_id, prev_hash, metadata, entropy_hash):
        self.index = index
        self.token_id = token_id
        self.prev_hash = prev_hash
        self.metadata = metadata
        self.entropy_hash = entropy_hash
        self.timestamp = metadata.get('timestamp', int(datetime.now(timezone.utc).timestamp()))
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.token_id}{self.prev_hash}{json.dumps(self.metadata, sort_keys=True)}{self.entropy_hash}{self.timestamp}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class EnergyCommSystem:
    def __init__(self, latitude=32.2226, longitude=-110.9747, utc_offset=-7):
        # Device-specific entropy
        self.device_id = str(uuid.getnode())
        self.device_entropy = hashlib.sha256(
            (platform.platform() + self.device_id).encode()
        ).digest()

        # Blockchain-like storage
        self.chain = []
        self.ectCounter = 0
        self.sender = "0xMockAddress"
        self.totalEnergySaved = 0
        self.energyCredits = {}

        # Location and time
        self.latitude = latitude
        self.longitude = longitude
        self.utc_offset = utc_offset
        self.timestamp = int(datetime.now(timezone.utc).timestamp())
        self.timestampStr = datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=self.utc_offset))).strftime('%Y-%m-%d %H:%M:%S')

        # Quantum-inspired
        self.sigma_x = np.array([[0, 1], [1, 0]])
        self.sigma_y = np.array([[0, -1j], [1j, 0]])
        self.sigma_z = np.array([[1, 0], [0, -1]])
        self.entropy_pool = os.urandom(32) + self.device_entropy

        # Genesis block
        self.genesis_block()

    def genesis_block(self):
        genesis_metadata = {
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "description": "Genesis Block",
            "device_id": self.device_id,
            "device_info": platform.platform(),
            "entropyHash": hashlib.sha256(self.device_entropy).hexdigest()[:32],
        }
        block = Block(0, 0, "0"*64, genesis_metadata, genesis_metadata['entropyHash'])
        self.chain.append(block)

    def simulate_circuit_with_grounding(self, t, surge_voltage=10000):
        R, C = 50, 1e-6
        def circuit_dynamics(V, t):
            return -(V / (R * C)) - (V / 10)  # R_ground = 10
        V0 = surge_voltage
        voltages = odeint(circuit_dynamics, V0, t).flatten()
        return voltages

    def simulate_signal(self, t, initial_snr=10):
        distance_factor = 0.5
        interference = 0.1 * np.sin(100 * t)
        snr = initial_snr * np.exp(-distance_factor * t) * 1.0 + interference
        return snr

    def generate_aes256_key_from_params(self, params):
        param_bytes = np.array(params).tobytes()
        return hashlib.sha256(param_bytes).digest()

    def encrypt_aes256(self, key, data):
        if not data.endswith('.'):
            data += '.'
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return cipher.nonce, ciphertext, tag

    def decrypt_aes256(self, key, nonce, ciphertext, tag):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return decrypted_message, decrypted_message.endswith('.')

    def run_classical_optimization(self, final_voltage):
        ZZ = np.kron([[1, 0], [0, -1]], [[1, 0], [0, -1]])
        XI = np.kron([[0, 1], [1, 0]], [[1, 0], [0, 1]])
        IX = np.kron([[1, 0], [0, 1]], [[0, 1], [1, 0]])
        hamiltonian = 1.0 * ZZ + 0.5 * XI + 0.5 * IX

        def ansatz_state(params):
            theta = params[0]
            state = np.zeros(4)
            state[0] = np.cos(theta / 2)
            state[3] = np.sin(theta / 2)
            return state / np.linalg.norm(state)

        def objective(params):
            state = ansatz_state(params)
            return np.real(state.T @ hamiltonian @ state)

        params = np.array([0.0])
        learning_rate = 0.05
        for _ in range(200):
            grad = (objective(params + 0.01) - objective(params - 0.01)) / 0.02
            params -= learning_rate * grad
            if np.abs(grad) < 1e-4:
                break
        return params

    def calculate_energy_credit(self, final_voltage, snr, solar_energy_input):
        sigma_x_sum = int(self.sigma_x.sum().real)
        sigma_y_sum = int(self.sigma_y.sum().real)
        sigma_z_sum = int(self.sigma_z.sum().real)
        entropy_factor = len(self.entropy_pool)
        grounding_energy = (10000 - final_voltage) * 0.001
        base_energy = entropy_factor * (abs(sigma_x_sum) + abs(sigma_y_sum) + abs(sigma_z_sum))
        utc_dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        local_dt = utc_dt.astimezone(timezone(timedelta(hours=self.utc_offset)))
        solar_altitude = get_altitude(self.latitude, self.longitude, local_dt)
        solar_factor = max(0, solar_altitude) / 90
        return int(base_energy * 5 + grounding_energy + solar_energy_input * solar_factor)

    def mint_ect(self, message, solar_energy_input=10):
        t = np.linspace(0, 1, 100)
        voltages = self.simulate_circuit_with_grounding(t)
        final_voltage = voltages[-1]
        snr_values = self.simulate_signal(t)
        final_snr = snr_values[-1]

        optimal_params = self.run_classical_optimization(final_voltage)
        aes_key = self.generate_aes256_key_from_params(optimal_params)
        nonce, ciphertext, tag = self.encrypt_aes256(aes_key, message)
        encrypted_code = base64.b64encode(nonce + ciphertext).decode('utf-8')

        # Quantum-inspired gas cost: Lower final_voltage is better (closer to ground = lower cost)
        gas_discount_factor = max(0.1, 1 - (10000 - final_voltage) / 10000)
        base_gas_cost = 100
        minting_gas_cost = base_gas_cost * gas_discount_factor

        energy_credit = self.calculate_energy_credit(final_voltage, final_snr, solar_energy_input)
        trace_x = int(self.sigma_x[0,0].real + self.sigma_x[1,1].real)
        trace_y = int(self.sigma_y[0,0].real + self.sigma_y[1,1].real)
        trace_z = int(self.sigma_z[0,0].real + self.sigma_z[1,1].real)
        token_id = int(hashlib.sha256(str(trace_x + trace_y + trace_z + self.timestamp + self.ectCounter).encode('utf-8')).hexdigest(), 16) % 1000000

        code_hash = hashlib.sha256(encrypted_code.encode('utf-8')).hexdigest()
        entropy_hash = hashlib.sha256(self.entropy_pool).hexdigest()[:32]
        metadata = {
            'codeHash': code_hash,
            'timestamp': self.timestamp,
            'timestampStr': self.timestampStr,
            'description': 'Grounding Energy and Secure Communication',
            'energySaved': energy_credit,
            'gasCost': minting_gas_cost,
            'groundingVoltage': final_voltage,
            'finalVoltage': final_voltage,
            'finalSNR': final_snr,
            'sigma_x': str(self.sigma_x),
            'sigma_y': str(self.sigma_y),
            'sigma_z': str(self.sigma_z),
            'entropyHash': entropy_hash,
            'location': f'Lat: {self.latitude}, Lon: {self.longitude}',
            'utc_offset': self.utc_offset,
            'optimalParams': optimal_params.tolist(),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'device_id': self.device_id,
            'device_info': platform.platform(),
        }

        prev_block = self.chain[-1]
        block = Block(
            index=len(self.chain),
            token_id=token_id,
            prev_hash=prev_block.hash,
            metadata=metadata,
            entropy_hash=entropy_hash
        )
        self.chain.append(block)

        self.totalEnergySaved += energy_credit
        self.energyCredits[self.sender] = self.energyCredits.get(self.sender, 0) + energy_credit

        print(f"Minted ECT ID {token_id}: Energy Saved = {energy_credit} Wh, Gas Cost = {minting_gas_cost:.2f}, SNR = {final_snr:.2f} dB")
        print(f"Credit Earned: {self.sender} earned {energy_credit} Wh")
        return token_id, encrypted_code, aes_key, nonce, tag

    def redeem_credits(self, amount):
        if self.energyCredits.get(self.sender, 0) >= amount:
            self.energyCredits[self.sender] -= amount
            self.totalEnergySaved -= amount
            print(f"Credits Redeemed: {self.sender}, Amount: {amount} Wh, Remaining: {self.energyCredits[self.sender]} Wh")
        else:
            print("Error: Insufficient credits")

    def get_energy_credits(self, user):
        return self.energyCredits.get(user, 0)

    # Blockchain-like retrievals
    def find_block_by_entropy(self, entropy_hash):
        for block in self.chain:
            if block.entropy_hash == entropy_hash:
                return block
        return None

    def find_block_by_code_hash(self, code_hash):
        for block in self.chain:
            if block.metadata.get('codeHash') == code_hash:
                return block
        return None

    def find_block_by_token_id(self, token_id):
        for block in self.chain:
            if block.token_id == token_id:
                return block
        return None

# --- Kivy UI (same as before) ---
class EncryptionTab(BoxLayout):
    def __init__(self, system, **kwargs):
        super().__init__(orientation='vertical', padding=10, spacing=10, **kwargs)
        self.system = system

        self.add_widget(Label(text="Alice's Encryption", font_size=20))
        self.message_input = TextInput(hint_text="Enter message to encrypt", multiline=True)
        self.add_widget(self.message_input)

        self.encrypt_button = Button(text="Encrypt and Mint NFT", size_hint=(1, 0.2))
        self.encrypt_button.bind(on_press=self.encrypt)
        self.add_widget(self.encrypt_button)

        self.copy_button = Button(text="Copy NFT Bundle", size_hint=(1, 0.2), disabled=True)
        self.copy_button.bind(on_press=self.copy_bundle)
        self.add_widget(self.copy_button)

        self.save_button = Button(text="Save NFT Bundle to File", size_hint=(1, 0.2), disabled=True)
        self.save_button.bind(on_press=self.save_bundle)
        self.add_widget(self.save_button)

        self.result_label = Label(text="Result will appear here", size_hint=(1, 0.4))
        self.add_widget(self.result_label)

        self.token_id = None
        self.bundle = None

    def encrypt(self, instance):
        message = self.message_input.text.strip()
        if not message:
            self.result_label.text = "Error: Please enter a message"
            return

        try:
            self.token_id, encrypted_code, aes_key, nonce, tag = self.system.mint_ect(message)
            block = self.system.find_block_by_token_id(self.token_id)
            self.bundle = {
                'token_id': self.token_id,
                'encrypted_code': encrypted_code,
                'optimal_params': block.metadata['optimalParams'],
                'nonce': block.metadata['nonce'],
                'tag': block.metadata['tag'],
                'entropy_hash': block.entropy_hash,
                'code_hash': block.metadata['codeHash'],
                'block_hash': block.hash,
            }
            self.result_label.text = f"NFT Minted:\n{json.dumps(self.bundle, indent=2)}\nEnergy Credits: {self.system.get_energy_credits(self.system.sender)} Wh"
            self.copy_button.disabled = False
            self.save_button.disabled = False
        except Exception as e:
            self.result_label.text = f"Error: Failed to encrypt and mint NFT\n{str(e)}"

    def copy_bundle(self, instance):
        if self.bundle:
            Clipboard.copy(json.dumps(self.bundle, indent=2))
            self.result_label.text += "\nBundle copied to clipboard"

    def save_bundle(self, instance):
        if self.bundle:
            with open('nft_bundle.json', 'w') as f:
                json.dump(self.bundle, f)
            self.result_label.text += "\nSaved to nft_bundle.json"

class DecryptionTab(BoxLayout):
    def __init__(self, system, **kwargs):
        super().__init__(orientation='vertical', padding=10, spacing=10, **kwargs)
        self.system = system

        self.add_widget(Label(text="Bob's Decryption", font_size=20))

        self.bundle_input = TextInput(hint_text="Paste JSON bundle here", multiline=True)
        self.add_widget(self.bundle_input)

        self.paste_button = Button(text="Paste Bundle from Clipboard", size_hint=(1, 0.2))
        self.paste_button.bind(on_press=self.paste_bundle)
        self.add_widget(self.paste_button)

        self.file_chooser = FileChooserListView(size_hint=(1, 0.4), filters=['*.json'])
        self.add_widget(self.file_chooser)

        self.load_button = Button(text="Load Bundle from File", size_hint=(1, 0.2))
        self.load_button.bind(on_press=self.load_bundle)
        self.add_widget(self.load_button)

        self.decrypt_button = Button(text="Decrypt", size_hint=(1, 0.2))
        self.decrypt_button.bind(on_press=self.decrypt)
        self.add_widget(self.decrypt_button)

        self.result_label = Label(text="Result will appear here", size_hint=(1, 0.4))
        self.add_widget(self.result_label)

    def paste_bundle(self, instance):
        try:
            pasted_text = Clipboard.paste()
            json.loads(pasted_text)
            self.bundle_input.text = pasted_text
            self.result_label.text = "Bundle pasted from clipboard"
        except json.JSONDecodeError:
            self.result_label.text = "Error: Invalid JSON in clipboard"
        except Exception as e:
            self.result_label.text = f"Error pasting from clipboard: {str(e)}"

    def load_bundle(self, instance):
        selected = self.file_chooser.selection
        if selected:
            try:
                with open(selected[0], 'r') as f:
                    self.bundle_input.text = json.dumps(json.load(f), indent=2)
                self.result_label.text = "Bundle loaded from file"
            except Exception as e:
                self.result_label.text = f"Error loading file: {str(e)}"

    def decrypt(self, instance):
        try:
            bundle = json.loads(self.bundle_input.text)
            optimal_params = np.array(bundle['optimal_params'])
            aes_key = self.system.generate_aes256_key_from_params(optimal_params)
            encrypted_bytes = base64.b64decode(bundle['encrypted_code'])
            nonce = base64.b64decode(bundle['nonce'])
            ciphertext = encrypted_bytes[len(nonce):]
            tag = base64.b64decode(bundle['tag'])

            decrypted_message, dot_marker_found = self.system.decrypt_aes256(aes_key, nonce, ciphertext, tag)
            message = decrypted_message[:-1] if dot_marker_found else decrypted_message
            self.result_label.text = f"Decrypted Message: {message}\nDot Marker Found: {dot_marker_found}"
            if not dot_marker_found:
                self.result_label.text += "\nWarning: No dot marker found. Message may be invalid or tampered."
        except Exception as e:
            self.result_label.text = f"Error: Decryption failed\n{str(e)}"

class CryptoApp(TabbedPanel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.system = EnergyCommSystem()
        self.do_default_tab = False

        encrypt_tab = TabbedPanelItem(text="Encrypt & Mint")
        encrypt_tab.add_widget(EncryptionTab(self.system))
        self.add_widget(encrypt_tab)

        decrypt_tab = TabbedPanelItem(text="Decrypt")
        decrypt_tab.add_widget(DecryptionTab(self.system))
        self.add_widget(decrypt_tab)

class MainApp(App):
    def build(self):
        return CryptoApp()

if __name__ == '__main__':
    MainApp().run()
