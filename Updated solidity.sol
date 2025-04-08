pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract EnergyCreditContract is ERC721, Ownable {
    using ECDSA for bytes32;
    using SafeMath for uint256;

    mapping(address => uint256) public nonces;
    event TransactionRecorded(address indexed sender, uint96 amount, uint256 timestamp);
    mapping(bytes32 => bytes32) public metadataHashes;
    event EnergySaved(bytes32 indexed codeHash, uint96 energySaved, uint256 timestamp);

    struct EnergyCreditToken {
        bytes32 encryptedCodeHash;
        bytes32 metadataHash;
        uint96 energyCredit;
    }
    mapping(uint256 => EnergyCreditToken) public ects;
    uint256 public ectCounter;

    uint256 public totalEnergySaved;
    mapping(address => uint256) public energyCredits;
    event CreditEarned(address indexed recipient, uint96 credits, uint256 timestamp, uint256 tokenId);

    int32 public immutable latitude = 334484;
    int32 public immutable longitude = -1120740;
    int16 public immutable utcOffset = -7;

    constructor() ERC721("EnergyCreditToken", "ECT") Ownable(msg.sender) {}

    modifier nonZero(uint256 value) {
        require(value > 0, "Value must be non-zero");
        _;
    }

    function mintECT(
        bytes32 encryptedCodeHash,
        bytes32 metadataHash,
        uint96 energyCredit,
        uint256 timestamp,
        bytes memory signature
    ) external nonZero(timestamp) nonZero(energyCredit) returns (uint256) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender, encryptedCodeHash, energyCredit, timestamp, nonces[msg.sender]
        ));
        require(ECDSA.recover(messageHash, signature) == msg.sender, "Invalid signature");
        nonces[msg.sender] = nonces[msg.sender].add(1);

        uint256 tokenId = uint256(keccak256(abi.encodePacked(
            block.chainid, msg.sender, timestamp, ectCounter
        )));
        bytes32 codeHash = keccak256(abi.encodePacked(encryptedCodeHash, tokenId));

        totalEnergySaved = totalEnergySaved.add(energyCredit);
        energyCredits[msg.sender] = energyCredits[msg.sender].add(energyCredit);
        metadataHashes[codeHash] = metadataHash;

        ects[tokenId] = EnergyCreditToken({
            encryptedCodeHash: encryptedCodeHash,
            metadataHash: metadataHash,
            energyCredit: energyCredit
        });
        ectCounter = ectCounter.add(1);

        _safeMint(msg.sender, tokenId);
        emit CreditEarned(msg.sender, energyCredit, timestamp, tokenId);
        emit EnergySaved(codeHash, energyCredit, timestamp);
        emit TransactionRecorded(msg.sender, energyCredit, timestamp);

        return tokenId;
    }

    function redeemCredits(uint96 amount) external nonZero(amount) {
        uint256 senderCredits = energyCredits[msg.sender];
        require(senderCredits >= amount, "Insufficient credits");
        energyCredits[msg.sender] = senderCredits - amount;
        totalEnergySaved -= amount;  // Native subtraction
        emit TransactionRecorded(msg.sender, amount, block.timestamp);
    }

    function getEnergyCredits(address user) external view returns (uint256) {
        return energyCredits[user];
    }

    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}
