import ast
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pysolar.solar import get_altitude
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

class CodeTranslator:
    def __init__(self):
        self.solidity_code = """pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract EnergyCreditContract is ERC721 {
    using ECDSA for bytes32;
    using SafeMath for uint256;

    struct Transaction {
        address sender;
        uint amount;
        uint timestamp;
        string timestampStr;
    }
    Transaction[] public transactions;

    event TransactionRecorded(address sender, uint amount, uint timestamp, string timestampStr);

    struct Metadata {
        string codeHash;
        uint timestamp;
        string timestampStr;
        string description;
        uint energySaved;
        string sigma_x;
        string sigma_y;
        string sigma_z;
        string entropyHash;
        string location;
        int utc_offset;
    }
    mapping(string => Metadata) public metadataMap;
    event EnergySaved(string codeHash, uint energySaved, uint timestamp, string timestampStr);

    int[2][2] public sigma_x = [[0, 1], [1, 0]];
    int[2][2] public sigma_y = [[0, -1], [1, 0]];
    int[2][2] public sigma_z = [[1, 0], [0, -1]];

    struct EnergyCreditToken {
        string encryptedCode;
        string metadata;
        bytes entropyHash;
        uint energyCredit;
        string timestampStr;
    }
    mapping(uint => EnergyCreditToken) public ects;
    uint public ectCounter;

    uint public totalEnergySaved;
    mapping(address => uint) public energyCredits;
    event CreditEarned(address recipient, uint credits, uint timestamp, string timestampStr);

    int public latitude = 334484;  // Phoenix, AZ (33.4484 * 10000)
    int public longitude = -1120740;  // -112.0740 * 10000
    int public utc_offset = -7;  // Arizona UTC-7

    constructor() ERC721("EnergyCreditToken", "ECT") {
        totalEnergySaved = 0;
    }
"""
        self.python_code = """import hashlib
import os
from datetime import datetime, timedelta, timezone
from pysolar.solar import get_altitude
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class EnergyCreditContract:
    def __init__(self, latitude=33.4484, longitude=-112.0740, utc_offset=-7):
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
        self.utc_offset = utc_offset
"""

    def parse_python_code(self, python_code):
        try:
            tree = ast.parse(python_code)
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    self.translate_security_function(node)
                elif isinstance(node, ast.Assign):
                    if isinstance(node.targets[0], ast.Name) and node.targets[0].id in ["latitude", "longitude", "utc_offset"]:
                        self.translate_assignment_to_solidity(node)
                elif isinstance(node, ast.Dict):
                    self.translate_map_to_solidity(node)
            self.solidity_code += """
    function mintECT(string memory encryptedCode, bytes memory signature, bytes memory entropy, uint solarEnergyInput) public returns (uint) {
        bytes32 hashResult = keccak256(abi.encodePacked(encryptedCode));
        require(hashResult.toEthSignedMessageHash().recover(signature) == msg.sender, "Invalid signature");

        int sigmaXSum = sigma_x[0][0].add(sigma_x[0][1]).add(sigma_x[1][0]).add(sigma_x[1][1]);
        int sigmaYSum = sigma_y[0][0].add(sigma_y[0][1]).add(sigma_y[1][0]).add(sigma_y[1][1]);
        int sigmaZSum = sigma_z[0][0].add(sigma_z[0][1]).add(sigma_z[1][0]).add(sigma_z[1][1]);
        bytes32 entropyMix = keccak256(abi.encodePacked(entropy, sigmaXSum, sigmaYSum, sigmaZSum));
        bytes32 entropyHash = keccak256(abi.encodePacked(encryptedCode, entropyMix));

        uint energyCredit = calculateEnergyCredit(sigmaXSum, sigmaYSum, sigmaZSum, entropy, solarEnergyInput);
        string memory timestampStr = uint2str(block.timestamp);
        uint tokenId = generateTokenId();
        string memory codeHash = string(abi.encodePacked(entropyHash));
        string memory metadataStr = string(abi.encodePacked(
            "{'codeHash':'", codeHash, 
            "','timestamp':", uint2str(block.timestamp), 
            ",'timestampStr':'", timestampStr, 
            "','description':'Quantum-AES Encryption Code',",
            "'energySaved':", uint2str(energyCredit), 
            ",'sigma_x':'[[0,1][1,0]]',",
            "'sigma_y':'[[0,-1][1,0]]',",
            "'sigma_z':'[[1,0][0,-1]]',",
            "'entropyHash':'", string(abi.encodePacked(entropyHash)), 
            "','location':'Lat: ", int2str(latitude), ", Lon: ", int2str(longitude), 
            "','utc_offset':", int2str(utc_offset), "}"
        ));

        // State updates BEFORE external call
        totalEnergySaved = totalEnergySaved.add(energyCredit);
        energyCredits[msg.sender] = energyCredits[msg.sender].add(energyCredit);
        ects[tokenId] = EnergyCreditToken(encryptedCode, metadataStr, abi.encodePacked(entropyHash), energyCredit, timestampStr);
        metadataMap[codeHash] = Metadata(codeHash, block.timestamp, timestampStr, "Quantum-AES Encryption Code", energyCredit, "[[0,1][1,0]]", "[[0,-1][1,0]]", "[[1,0][0,-1]]", string(abi.encodePacked(entropyHash)), string(abi.encodePacked("Lat: ", int2str(latitude), ", Lon: ", int2str(longitude))), utc_offset);
        ectCounter = ectCounter.add(1);

        // Events and external call AFTER state updates
        emit CreditEarned(msg.sender, energyCredit, block.timestamp, timestampStr);
        emit EnergySaved(codeHash, energyCredit, block.timestamp, timestampStr);
        _mint(msg.sender, tokenId);

        return tokenId;
    }

    function generateTokenId() public view returns (uint) {
        int traceX = sigma_x[0][0].add(sigma_x[1][1]);
        int traceY = sigma_y[0][0].add(sigma_y[1][1]);
        int traceZ = sigma_z[0][0].add(sigma_z[1][1]);
        return uint(keccak256(abi.encodePacked(traceX, traceY, traceZ, block.timestamp, ectCounter))) % 1000000;
    }

    function calculateEnergyCredit(int sigmaXSum, int sigmaYSum, int sigmaZSum, bytes memory entropy, uint solarEnergyInput) internal pure returns (uint) {
        uint entropyFactor = entropy.length > 0 ? entropy.length : 1;
        uint baseEnergy = entropyFactor * (uint(sigmaXSum.abs()) + uint(sigmaYSum.abs()) + uint(sigmaZSum.abs()));
        return baseEnergy.mul(5).add(solarEnergyInput);
    }

    function redeemCredits(uint amount) public {
        require(energyCredits[msg.sender] >= amount, "Insufficient credits");
        energyCredits[msg.sender] = energyCredits[msg.sender].sub(amount);
        totalEnergySaved = totalEnergySaved.sub(amount);
        emit CreditEarned(msg.sender, 0 - amount, block.timestamp, uint2str(block.timestamp));
    }

    function uint2str(uint _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        uint j = _i;
        uint len;
        while (j != 0) { len++; j /= 10; }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) { k = k-1; bstr[k] = bytes1(uint8(48 + _i % 10)); _i /= 10; }
        return string(bstr);
    }

    function int2str(int _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        bool negative = _i < 0;
        uint u = uint(negative ? -_i : _i);
        uint j = u;
        uint len;
        while (j != 0) { len++; j /= 10; }
        if (negative) len++;
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (u != 0) { k = k-1; bstr[k] = bytes1(uint8(48 + u % 10)); u /= 10; }
        if (negative) bstr[0] = "-";
        return string(bstr);
    }

    function getEnergyCredits(address user) public view returns (uint) {
        return energyCredits[user];
    }
}
"""
        except Exception as e:
            print(f"Error parsing Python: {e}")

    def translate_security_function(self, node):
        func_name = self.resolve_name_conflicts(node.name)
        arguments = [arg.arg for arg in node.args.args]
        args_solidity = ", ".join([f"string memory {arg}" if "text" in arg or "data" in arg else f"uint {arg}" for arg in arguments])
        if "encrypt" in func_name.lower():
            self.solidity_code += f"""
    function {func_name}({args_solidity}, bytes memory signature, bytes memory entropy) public payable returns (string memory, bytes memory) {{
        string memory timestampStr = uint2str(block.timestamp);
        transactions.push(Transaction(msg.sender, msg.value, block.timestamp, timestampStr));
        emit TransactionRecorded(msg.sender, msg.value, block.timestamp, timestampStr);
        bytes32 hashResult = keccak256(abi.encodePacked({arguments[0]}));
        require(hashResult.toEthSignedMessageHash().recover(signature) == msg.sender, "Invalid signature");
        bytes32 entropyHash = keccak256(abi.encodePacked({arguments[0]}, entropy));
        emit EnergySaved(string(abi.encodePacked(entropyHash)), 0, block.timestamp, timestampStr);
        return ({arguments[0]}, abi.encodePacked(entropyHash));
    }}
"""

    def translate_assignment_to_solidity(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = self.resolve_name_conflicts(target.id)
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                    value = int(node.value.value * 10000) if "latitude" in var_name or "longitude" in var_name else node.value.value
                    self.solidity_code += f"    int public {var_name} = {value};\n"
                else:
                    self.solidity_code += f"    string public {var_name} = '';\n"

    def translate_map_to_solidity(self, node):
        self.solidity_code += """
    function setMetadata(string memory key, string memory codeHash, uint timestamp, string memory timestampStr, string memory description, uint energySaved) public {
        metadataMap[key] = Metadata(codeHash, timestamp, timestampStr, description, energySaved, "[[0,1][1,0]]", "[[0,-1][1,0]]", "[[1,0][0,-1]]", "", string(abi.encodePacked("Lat: ", int2str(latitude), ", Lon: ", int2str(longitude))), utc_offset);
        emit EnergySaved(codeHash, energySaved, timestamp, timestampStr);
    }
"""

    def parse_solidity_code(self, solidity_code):
        try:
            lines = solidity_code.split("\n")
            for line in lines:
                line = line.strip()
                if "function" in line:
                    self.translate_function_to_python(line)
                elif "mapping" in line and "metadataMap" in line:
                    self.translate_mapping_to_python(line)
                elif "int public" in line or "string public" in line:
                    self.translate_variable_to_python(line)
            self.python_code += "\n"
        except Exception as e:
            print(f"Error parsing Solidity: {e}")

    def translate_function_to_python(self, line):
        if "mintECT" in line:
            self.python_code += """    def mintECT(self, metadata, entropy, solarEnergyInput):
        encryptedCode = metadata['encryptedCode']
        codeHash = metadata.get('codeHash', hashlib.sha256(encryptedCode.encode('utf-8')).hexdigest())
        timestamp = metadata.get('timestamp', int(datetime.now().timestamp()))
        timestampStr = metadata.get('timestampStr', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        description = metadata.get('description', 'Quantum-AES Encryption Code')
        signature = metadata.get('signature', 'mock_signature')

        token_id = self.generateTokenId()
        sigma_x_sum = int(self.sigma_x.sum().real)
        sigma_y_sum = int(self.sigma_y.sum().real)
        sigma_z_sum = int(self.sigma_z.sum().real)
        entropy_mix = hashlib.sha256(self.entropy_pool + str(sigma_x_sum + sigma_y_sum + sigma_z_sum).encode('utf-8')).digest()
        entropy_hash = hashlib.sha256((encryptedCode + entropy_mix.hex()).encode('utf-8')).hexdigest()

        energy_credit = self.calculateEnergyCredit(sigma_x_sum, sigma_y_sum, sigma_z_sum, entropy, solarEnergyInput)
        self.totalEnergySaved += energy_credit
        self.energyCredits[self.sender] = self.energyCredits.get(self.sender, 0) + energy_credit
        print(f"CreditEarned: recipient={self.sender}, credits={energy_credit}, timestamp={timestamp}, timestampStr={timestampStr}")

        full_metadata = {
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
            'metadata': full_metadata,
            'entropyHash': entropy_mix.hex()[:32],
            'energyCredit': energy_credit,
            'timestampStr': timestampStr
        }
        self.metadataMap[codeHash] = full_metadata
        self.ectCounter += 1
        print(f"Minted ECT ID {token_id}: {{'encryptedCode': '{encryptedCode}', 'metadata': {full_metadata}, 'energyCredit': {energy_credit}, 'timestampStr': '{timestampStr}'}}")
        print(f"EnergySaved: codeHash={codeHash}, energySaved={energy_credit}, timestamp={timestamp}, timestampStr={timestampStr}")
        return token_id
"""
        elif "generateTokenId" in line:
            self.python_code += """    def generateTokenId(self):
        trace_x = int(self.sigma_x[0,0].real + self.sigma_x[1,1].real)
        trace_y = int(self.sigma_y[0,0].real + self.sigma_y[1,1].real)
        trace_z = int(self.sigma_z[0,0].real + self.sigma_z[1,1].real)
        return int(hashlib.sha256(str(trace_x + trace_y + trace_z + self.timestamp + self.ectCounter).encode('utf-8')).hexdigest(), 16) % 1000000
"""
        elif "calculateEnergyCredit" in line:
            self.python_code += """    def calculateEnergyCredit(self, sigmaXSum, sigmaYSum, sigmaZSum, entropy, solarEnergyInput):
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
"""
        elif "redeemCredits" in line:
            self.python_code += """    def redeemCredits(self, amount):
        if self.energyCredits.get(self.sender, 0) >= amount:
            self.energyCredits[self.sender] -= amount
            self.totalEnergySaved -= amount
            print(f"Credits Redeemed: recipient={self.sender}, amount={amount}, remaining={self.energyCredits[self.sender]} Wh, timestamp={self.timestamp}")
        else:
            print("Error: Insufficient credits")
"""
        elif "getEnergyCredits" in line:
            self.python_code += """    def getEnergyCredits(self, user):
        return self.energyCredits.get(user, 0)
"""

    def translate_variable_to_python(self, line):
        parts = line.split("public")[1].strip().split("=")
        var_name = parts[0].strip().rstrip(";")
        if var_name in ["latitude", "longitude", "utc_offset", "ectCounter", "totalEnergySaved"]:
            return
        if len(parts) > 1:
            value_str = parts[1].strip().rstrip(";").strip()
            try:
                value = int(value_str)
                if "latitude" in var_name or "longitude" in var_name:
                    value = value / 10000
            except ValueError:
                value = f"'{value_str}'"
        else:
            value = "0" if "int" in line else "''"
        if f"self.{var_name} =" not in self.python_code:
            self.python_code = self.python_code.replace(
                "        self.energyCredits = {}\n",
                f"        self.energyCredits = {{}}\n        self.{var_name} = {value}\n"
            )

    def translate_mapping_to_python(self, line):
        self.python_code += """    def setMetadata(self, key, codeHash, timestamp, timestampStr, description, energySaved):
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
"""

    def resolve_name_conflicts(self, name):
        if name in self.solidity_code or name in self.python_code:
            return f"{name}_conflict"
        return name

    def get_solidity_code(self):
        return self.solidity_code

    def get_python_code(self):
        return self.python_code

if __name__ == "__main__":
    code = """
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
# Define Pauli matrices (rest of the code)...
"""
    code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
    real_time = datetime.fromtimestamp(1743724248)
    timestamp = 1743724248
    timestamp_str = "2025-04-03 16:50:48"
    metadata = {'hash': code_hash, 'timestamp': timestamp, 'timestampStr': timestamp_str, 'description': 'Quantum-AES Encryption Code'}

    def encrypt_text(plain_text):
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
        return base64.b64encode(nonce + ciphertext).decode('utf-8'), key

    encrypted_code, encryption_key = encrypt_text(code)
    nft_metadata = {'metadata': metadata, 'encrypted_code': encrypted_code}

    with open('nft_metadata.json', 'w') as f:
        json.dump(nft_metadata, f)

    print("Code Hash:", code_hash)
    print("Timestamp (Unix):", timestamp)
    print("Timestamp (Readable):", timestamp_str)
    print("Encrypted Code:", encrypted_code)
    print("NFT Metadata:", nft_metadata)

    translator = CodeTranslator()
    input_python_code = f"""
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime
import json

code = \"""
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
# Define Pauli matrices (rest of the code)...
\"""

code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
real_time = datetime.fromtimestamp(1743724248)
timestamp = 1743724248
timestamp_str = "2025-04-03 16:50:48"
metadata = {{'hash': code_hash, 'timestamp': timestamp, 'timestampStr': timestamp_str, 'description': 'Quantum-AES Encryption Code'}}

def encrypt_text(plain_text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8'), key

encrypted_code, encryption_key = encrypt_text(code)
nft_metadata = {{'metadata': metadata, 'encrypted_code': encrypted_code}}

with open('nft_metadata.json', 'w') as f:
    json.dump(nft_metadata, f)

print("Code Hash:", code_hash)
print("Timestamp (Unix):", timestamp)
print("Timestamp (Readable):", timestamp_str)
print("Encrypted Code:", encrypted_code)
print("NFT Metadata:", nft_metadata)
"""
    print("\nGenerating Solidity Code:")
    translator.parse_python_code(input_python_code)
    with open('EnergyCreditContract.sol', 'w') as f:
        f.write(translator.get_solidity_code())
    print("Solidity code saved to 'EnergyCreditContract.sol'")

    print("\nGenerating Python Code (from Solidity):")
    translator.parse_solidity_code(translator.get_solidity_code())
    generated_python = translator.get_python_code()
    print("Generated Python Code:")
    print(generated_python)
    with open('EnergyCreditContract.py', 'w') as f:
        f.write(generated_python)
    print("Python code saved to 'EnergyCreditContract.py'")

    print("\nExecuting Combined Code with Sustainable Utility:")
    try:
        exec(generated_python)
        contract = EnergyCreditContract(latitude=32.2226, longitude=-110.9747)
        current_time = 1743724248
        current_time_str = "2025-04-03 16:50:48"
        metadata = {
            'encryptedCode': encrypted_code,
            'codeHash': code_hash,
            'timestamp': current_time,
            'timestampStr': current_time_str,
            'description': "Quantum-AES Encryption Code",
            'signature': "mock_signature"
        }
        token_id = contract.mintECT(metadata, os.urandom(32), 10)
        print(f"Total Energy Saved (Community): {contract.totalEnergySaved} Wh")
        print(f"Redeemable Energy Credits for {contract.sender}: {contract.getEnergyCredits(contract.sender)} Wh")
        print("ECT Metadata:")
        for key, value in contract.ects[token_id]['metadata'].items():
            print(f"  {key}: {value}")
        print(f"ECT Timestamp: {contract.ects[token_id]['timestampStr']}")
        print(f"Message: Use your {contract.getEnergyCredits(contract.sender)} Wh credits to offset your energy bill or trade for carbon offsets!")
        contract.redeemCredits(100)
        print(f"After Redemption - Total Energy Saved: {contract.totalEnergySaved} Wh")
        print(f"After Redemption - Remaining Credits: {contract.getEnergyCredits(contract.sender)} Wh")
    except Exception as e:
        print(f"Execution error: {e}")
