// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    FHE,
    euint16,
    euint256,
    externalEuint16,
    externalEuint256,
    ebool
} from "@fhevm/solidity/lib/FHE.sol";
import {SepoliaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ConfidentialTranscript is SepoliaConfig, ERC721, Ownable {
    using FHE for *;

    struct TranscriptRecord {
        address issuer; // university address (issuer)
        address owner; // student address (soulbound)
        euint256 encCID; // encrypted CID digest
        euint16 encGPA; // encrypted GPA scaled by 100
        uint256 issuedAt; // timestamp
    }

    struct DecryptCIDRequest {
        address owner;
        uint256 timestamp;
    }

    // Storage
    mapping(address => TranscriptRecord) public _transcripts;
    mapping(address => uint256) public _studentToken; // student => tokenId (one transcript per student)

    mapping(uint256 => DecryptCIDRequest) public _decryptCIDRequests;
    mapping(address => uint256) public _decryptedCID;

    // Roles
    address public uni_address; // minter (university)
    address public pg_address; // allow post graduate address to request scholarship checks

    // Events
    event TranscriptMinted(
        uint256 indexed tokenId,
        address indexed student,
        address indexed issuer,
        euint256 cidDigest,
        euint16 gpa
    );
    event RequestCIDDecryption(address indexed owner, uint256 indexed tokenId, uint256 timestamp);
    event TranscriptRevoked(uint256 indexed tokenId, address indexed issuer);
    event UniversityUpdated(address newUniversity);
    event PGAddressUpdated(address newAuthority);
    event DecryptedCID(address indexed requester, uint256 indexed requestId, uint256 timestamp);

    modifier onlyUniversity() {
        require(msg.sender == uni_address, "not university");
        _;
    }

    modifier onlyPG() {
        require(msg.sender == pg_address, "not pg authority");
        _;
    }

    constructor(address _uni_address, address _pg_address) ERC721("ConfidentialTranscript", "CTS") Ownable(msg.sender) {
        require(_uni_address != address(0), "zero uni");
        require(_pg_address != address(0), "zero pg");
        uni_address = _uni_address;
        pg_address = _pg_address;
    }

    // --- Soulbound enforcement ---
    function _update(address to, uint256 tokenId, address /* auth */) internal override returns (address) {
        address from = _ownerOf(tokenId);
        require(
            (from == address(0) && to != address(0)) || (from != address(0) && to == address(0)), // mint // burn
            "SBT: transfers disabled"
        );
        return super._update(to, tokenId, address(0));
    }

    function approve(address, uint256) public pure override {
        revert("SBT: approvals disabled");
    }

    function setApprovalForAll(address, bool) public pure override {
        revert("SBT: approvals disabled");
    }

    // --- Minting (University supplies encrypted inputs) ---
    function mintTranscriptExternal(
        address student,
        uint256 studentID,
        externalEuint256 _encCID,
        externalEuint16 _encGpa,
        bytes calldata inputProof
    ) external onlyUniversity returns (uint256) {
        require(balanceOf(student) == 0, "student already has transcript");
        require(student != address(0), "zero student");

        // Convert submitted external ciphertext into internal euint types (and supply proof)
        euint256 encCID = FHE.fromExternal(_encCID, inputProof);
        euint16 encGPA = FHE.fromExternal(_encGpa, inputProof);

        FHE.allowThis(encCID);
        FHE.allow(encCID, student);

        FHE.allowThis(encGPA);
        FHE.allow(encGPA, pg_address);

        _safeMint(student, studentID);

        _transcripts[student] = TranscriptRecord({
            issuer: msg.sender,
            owner: student,
            encCID: encCID,
            encGPA: encGPA,
            issuedAt: block.timestamp
        });
        _studentToken[student] = studentID;

        emit TranscriptMinted(studentID, student, msg.sender, encCID, encGPA);
        return studentID;
    }

    function decryptCid() public returns (uint256 requestId) {
        bytes32[] memory cts = new bytes32[](1);
        cts[0] = FHE.toBytes32(_transcripts[msg.sender].encCID);

        requestId = FHE.requestDecryption(cts, this.resolveCidCallback.selector);
        _decryptCIDRequests[requestId] = DecryptCIDRequest({owner: msg.sender, timestamp: block.timestamp});

        emit RequestCIDDecryption(msg.sender, requestId, block.timestamp);
        return requestId;
    }

    function resolveCidCallback(uint256 requestId, bytes memory cleartexts, bytes memory decryptionProof) public {
        FHE.checkSignatures(requestId, cleartexts, decryptionProof);

        (uint256 revealedCid) = abi.decode(cleartexts, (uint256));

        DecryptCIDRequest memory request = _decryptCIDRequests[requestId];
        require(request.owner != address(0), "Invalid request ID");

        _decryptedCID[request.owner] = revealedCid;
        emit DecryptedCID(request.owner, requestId, request.timestamp); //great
    }

    // --- Scholarship Eligibility ---
    function checkScholarshipEligibilityByAddress(address student, uint16 threshold) external onlyPG returns (ebool) {
        return _checkEligibility(student, threshold);
    }

    function checkScholarshipEligibilityByToken(uint256 tokenId, uint16 threshold) public onlyPG returns (ebool) {
        address student = _ownerOf(tokenId);
        return _checkEligibility(student, threshold);
    }

    function _checkEligibility(address student, uint16 threshold) internal returns (ebool) {
        TranscriptRecord memory rec = _transcripts[student];
        euint16 encThreshold = FHE.asEuint16(threshold);
        // set threshold to be 350
        ebool eligible = FHE.ge(rec.encGPA, encThreshold);
        return eligible;
    }

    // --- Revoke (burn) ---
    function revokeTranscript(uint256 tokenId) external onlyUniversity {
        require(_ownerOf(tokenId) != address(0), "token not exist");
        address student = _ownerOf(tokenId);
        delete _transcripts[student];
        delete _studentToken[student];
        _update(address(0), tokenId, address(0));
        emit TranscriptRevoked(tokenId, msg.sender);
    }

    // --- Views for debugging (do NOT reveal decrypted data) ---
    // Return existence of encrypted CID (ciphertext is opaque)
    function getEncryptedCID(uint256 tokenId) external view returns (euint256) {
        require(_ownerOf(tokenId) != address(0), "invalid token");
        address student = _ownerOf(tokenId);
        return (_transcripts[student].encCID);
    }

    function getEncryptedGPA(uint256 tokenId) external view returns (euint16) {
        require(_ownerOf(tokenId) != address(0), "invalid token");
        address student = _ownerOf(tokenId);
        return _transcripts[student].encGPA;
    }

    // Admin
    function setUniversity(address _uni_address) external onlyOwner {
        uni_address = _uni_address;
        emit UniversityUpdated(_uni_address);
    }

    function setPGAddress(address _pg_address) external onlyOwner {
        pg_address = _pg_address;
        emit PGAddressUpdated(_pg_address);
    }
}
