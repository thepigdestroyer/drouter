// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DRouterRegistry
/// @notice On-chain registry of confidential-compute inference nodes for dRouter.
///         Operators stake native USDC (18 decimals on Arc), verifiers attest to node
///         measurements, and anyone can anchor proof-of-privacy receipt hashes.
contract DRouterRegistry {
    uint8 public constant STATUS_ACTIVE = 0;
    uint8 public constant STATUS_SUSPENDED = 1;
    uint8 public constant STATUS_REVOKED = 2;

    struct Node {
        address operator;
        string kind;
        string name;
        string endpoint;
        bytes32 measurement;
        string region;
        uint256 stake;
        uint8 status;
        uint64 registeredAt;
        uint64 lastVerifiedAt;
        bool lastVerifiedOk;
    }

    address public owner;
    uint256 public minStake;
    mapping(address => bool) public verifiers;

    mapping(bytes32 => Node) private nodes;
    bytes32[] private nodeIds;

    event NodeRegistered(
        bytes32 indexed id,
        address indexed operator,
        string kind,
        string name,
        string endpoint,
        bytes32 measurement,
        string region,
        uint256 stake
    );
    event StakeAdded(bytes32 indexed id, uint256 amount, uint256 totalStake);
    event NodeVerified(bytes32 indexed id, bool ok, bytes32 evidenceHash, uint256 timestamp);
    event ReceiptAnchored(address indexed sender, bytes32 indexed receiptHash, uint256 timestamp);
    event StatusChanged(bytes32 indexed id, uint8 status);
    event Slashed(bytes32 indexed id, address indexed to, uint256 amount);
    event VerifierSet(address indexed verifier, bool allowed);

    error NotOwner();
    error NotVerifier();
    error NotOperator();
    error UnknownNode();
    error NodeExists();
    error StakeTooLow();
    error InvalidStatus();
    error ZeroAddress();
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyVerifier() {
        if (!verifiers[msg.sender]) revert NotVerifier();
        _;
    }

    constructor(uint256 _minStake) {
        owner = msg.sender;
        minStake = _minStake;
    }

    function setVerifier(address verifier, bool allowed) external onlyOwner {
        verifiers[verifier] = allowed;
        emit VerifierSet(verifier, allowed);
    }

    function registerNode(
        bytes32 id,
        string memory kind,
        string memory name,
        string memory endpoint,
        bytes32 measurement,
        string memory region
    ) external payable {
        if (msg.value < minStake) revert StakeTooLow();
        if (nodes[id].operator != address(0)) revert NodeExists();

        Node storage n = nodes[id];
        n.operator = msg.sender;
        n.kind = kind;
        n.name = name;
        n.endpoint = endpoint;
        n.measurement = measurement;
        n.region = region;
        n.stake = msg.value;
        n.status = STATUS_ACTIVE;
        n.registeredAt = uint64(block.timestamp);
        nodeIds.push(id);

        emit NodeRegistered(id, msg.sender, kind, name, endpoint, measurement, region, msg.value);
    }

    function addStake(bytes32 id) external payable {
        Node storage n = nodes[id];
        if (n.operator == address(0)) revert UnknownNode();
        if (n.operator != msg.sender) revert NotOperator();
        n.stake += msg.value;
        emit StakeAdded(id, msg.value, n.stake);
    }

    function recordVerification(bytes32 id, bool ok, bytes32 evidenceHash) external onlyVerifier {
        Node storage n = nodes[id];
        if (n.operator == address(0)) revert UnknownNode();
        n.lastVerifiedAt = uint64(block.timestamp);
        n.lastVerifiedOk = ok;
        emit NodeVerified(id, ok, evidenceHash, block.timestamp);
    }

    /// @notice Anchor a proof-of-privacy receipt hash. Event-only; nothing is stored.
    function anchorReceipt(bytes32 receiptHash) external {
        emit ReceiptAnchored(msg.sender, receiptHash, block.timestamp);
    }

    function setStatus(bytes32 id, uint8 status) external onlyOwner {
        if (nodes[id].operator == address(0)) revert UnknownNode();
        if (status > STATUS_REVOKED) revert InvalidStatus();
        nodes[id].status = status;
        emit StatusChanged(id, status);
    }

    function slash(bytes32 id, address payable to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        Node storage n = nodes[id];
        if (n.operator == address(0)) revert UnknownNode();

        uint256 amount = n.stake;
        n.stake = 0;
        n.status = STATUS_REVOKED;
        emit StatusChanged(id, STATUS_REVOKED);
        emit Slashed(id, to, amount);

        if (amount > 0) {
            (bool sent, ) = to.call{value: amount}("");
            if (!sent) revert TransferFailed();
        }
    }

    function nodeCount() external view returns (uint256) {
        return nodeIds.length;
    }

    function nodeIdAt(uint256 index) external view returns (bytes32) {
        return nodeIds[index];
    }

    function getNode(bytes32 id) external view returns (Node memory) {
        if (nodes[id].operator == address(0)) revert UnknownNode();
        return nodes[id];
    }
}
