//SPDX-License-identifier: MIT
pragma solidity 0.8.24;

import "@oz/contracts/access/Ownable.sol";
import "@oz/contracts/proxy/utils/Initializable.sol";
import "@oz/contracts/interfaces/IERC1271.sol";
import "@oz/contracts/utils/cryptography/ECDSA.sol";
import "@oz/contracts/utils/cryptography/WebAuthn.sol";

import "src/interface/ISmartWallet.sol";

/// @title SmartWallet
/// @author Mavvverick
/// @notice Minimal smart contract wallet with passkey (WebAuthn) support
/// @notice Supports ERC-1271 (for EOAs), WebAuthn meta-transactions, batch calls
/// @dev Designed to be deployed via minimal proxy (EIP-1167)
contract SmartWallet is Ownable, IERC1271, ISmartWallet, Initializable {
    /// @notice Nonce per passkey address (prevents replay)
    mapping(address => uint256) public nonces;

    /// @notice Passkey public key X coordinate storage
    mapping(address => bytes32) public passkeyPublicKeyX;

    /// @notice Passkey public key Y coordinate storage
    mapping(address => bytes32) public passkeyPublicKeyY;

    /// @notice Whether at least one passkey has ever been added
    bool public hasPasskey;

    /// @notice credentialId → passkey derived address (used during login)
    mapping(bytes32 => address) public credentialIdToPasskey;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(address(1)) {
        _disableInitializers();
    }

    /// @notice Called once by the factory when deploying the proxy
    /// @param initialOwner The initial owner of this wallet
    function initialize(address initialOwner) external initializer {
        _transferOwnership(initialOwner);
    }

    /// @notice Derive deterministic address from WebAuthn public key coordinates
    function computePasskeyAddress(bytes32 qx, bytes32 qy) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(qx, qy)))));
    }

    /// @notice Register a new passkey
    /// @param qx X coordinate of the public key
    /// @param qy Y coordinate of the public key
    /// @param credentialIdHash keccak256(credentialId) — used for frontend lookup
    function registerPasskey(bytes32 qx, bytes32 qy, bytes32 credentialIdHash) external onlyOwner {
        address passkeyAddr = computePasskeyAddress(qx, qy);

        if (passkeyPublicKeyX[passkeyAddr] != bytes32(0)) {
            revert PasskeyAlreadyRegistered();
        }

        passkeyPublicKeyX[passkeyAddr] = qx;
        passkeyPublicKeyY[passkeyAddr] = qy;
        credentialIdToPasskey[credentialIdHash] = passkeyAddr;

        if (!hasPasskey) {
            hasPasskey = true;
        }

        emit PasskeyRegistered(passkeyAddr, qx, qy);
    }

    /// @notice Remove an existing passkey
    function removePasskey(bytes32 qx, bytes32 qy) external onlyOwner {
        address passkeyAddr = computePasskeyAddress(qx, qy);

        if (passkeyPublicKeyX[passkeyAddr] == bytes32(0)) {
            revert PasskeyNotRegistered();
        }

        delete passkeyPublicKeyX[passkeyAddr];
        delete passkeyPublicKeyY[passkeyAddr];

        emit PasskeyRemoved(passkeyAddr);
    }

    /// @notice Check if given address is a registered passkey
    function isRegisteredPasskey(address account) external view returns (bool) {
        return passkeyPublicKeyX[account] != bytes32(0);
    }

    /// @notice Lookup passkey info by credentialId hash (used in login flow)
    function getPasskeyInfo(bytes32 credentialIdHash)
        external
        view
        returns (address passkeyAddr, bytes32 qx, bytes32 qy)
    {
        passkeyAddr = credentialIdToPasskey[credentialIdHash];
        if (passkeyAddr != address(0)) {
            qx = passkeyPublicKeyX[passkeyAddr];
            qy = passkeyPublicKeyY[passkeyAddr];
        }
    }

    /// @notice Execute a single call (only owner)
    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory result)
    {
        (bool success, bytes memory ret) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();

        emit WalletExecuted(target, value, data);
        return ret;
    }

    /// @notice Execute multiple calls atomically (only owner)
    function executeBatch(Call[] calldata calls) external onlyOwner returns (bytes[] memory results) {
        results = new bytes[](calls.length);

        for (uint256 i = 0; i < calls.length; ++i) {
            (bool success, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert ExecutionFailed();

            emit WalletExecuted(calls[i].target, calls[i].value, calls[i].data);
            results[i] = ret;
        }

        emit BatchExecuted(calls.length);
    }

    /// @notice Execute single call via WebAuthn signature (relayed)
    function executeViaPasskey(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 qx,
        bytes32 qy,
        uint256 deadline,
        WebAuthn.WebAuthnAuth calldata auth
    ) external returns (bytes memory result) {
        if (block.timestamp > deadline) revert SignatureExpired();

        address signer = computePasskeyAddress(qx, qy);
        if (passkeyPublicKeyX[signer] != qx || passkeyPublicKeyY[signer] != qy) {
            revert PasskeyNotRegistered();
        }

        bytes32 digest =
            keccak256(abi.encodePacked(block.chainid, address(this), target, value, data, nonces[signer], deadline));

        if (!WebAuthn.verify(abi.encodePacked(digest), auth, qx, qy)) {
            revert InvalidSignature();
        }

        nonces[signer]++;

        (bool success, bytes memory ret) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();

        emit MetaTxExecuted(signer, target, value, data);
        return ret;
    }

    /// @notice Execute batch via WebAuthn signature (relayed)
    function executeBatchViaPasskey(
        Call[] calldata calls,
        bytes32 qx,
        bytes32 qy,
        uint256 deadline,
        WebAuthn.WebAuthnAuth calldata auth
    ) external returns (bytes[] memory results) {
        if (block.timestamp > deadline) revert SignatureExpired();

        address signer = computePasskeyAddress(qx, qy);
        if (passkeyPublicKeyX[signer] != qx || passkeyPublicKeyY[signer] != qy) {
            revert PasskeyNotRegistered();
        }

        bytes32 digest = keccak256(
            abi.encodePacked(block.chainid, address(this), keccak256(abi.encode(calls)), nonces[signer], deadline)
        );

        if (!WebAuthn.verify(abi.encodePacked(digest), auth, qx, qy)) {
            revert InvalidSignature();
        }

        nonces[signer]++;

        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            (bool success, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert ExecutionFailed();

            emit MetaTxExecuted(signer, calls[i].target, calls[i].value, calls[i].data);
            results[i] = ret;
        }
    }

    /// @dev ERC-1271 only supports ECDSA owner signatures
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        address recovered = ECDSA.recover(hash, signature);
        return recovered == owner() ? IERC1271.isValidSignature.selector : bytes4(0);
    }

    receive() external payable {}

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }
}

