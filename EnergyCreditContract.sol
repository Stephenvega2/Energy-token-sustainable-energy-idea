pragma solidity ^0.8.0;

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

    function encrypt_text(string memory plain_text, bytes memory signature, bytes memory entropy) public payable returns (string memory, bytes memory) {
        string memory timestampStr = uint2str(block.timestamp);
        transactions.push(Transaction(msg.sender, msg.value, block.timestamp, timestampStr));
        emit TransactionRecorded(msg.sender, msg.value, block.timestamp, timestampStr);
        bytes32 hashResult = keccak256(abi.encodePacked(plain_text));
        require(hashResult.toEthSignedMessageHash().recover(signature) == msg.sender, "Invalid signature");
        bytes32 entropyHash = keccak256(abi.encodePacked(plain_text, entropy));
        emit EnergySaved(string(abi.encodePacked(entropyHash)), 0, block.timestamp, timestampStr);
        return (plain_text, abi.encodePacked(entropyHash));
    }

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
