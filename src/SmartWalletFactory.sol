// SPDX-License-Identifier: MIT
pragma solidity >=0.8.24 <0.9.0;

import "./SmartWallet.sol";
import "./Clones.sol";

/// @title SmartWalletFactory
/// @author Mavvverick
/// @notice Deploys deterministic minimal proxy clones of SmartWallet
contract SmartWalletFactory {
    address public immutable implementation;

    event WalletDeployed(address indexed owner, address indexed wallet, bytes32 salt);

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function deployWallet(address owner, bytes32 salt) external returns (address wallet) {
        bytes32 finalSalt = keccak256(abi.encodePacked(owner, salt));

        wallet = Clones.cloneDeterministic(implementation, finalSalt);
        SmartWallet(payable(wallet)).initialize(owner);

        emit WalletDeployed(owner, wallet, salt);
    }

    function predictWalletAddress(address owner, bytes32 salt) external view returns (address predicted) {
        bytes32 finalSalt = keccak256(abi.encodePacked(owner, salt));
        return Clones.predictDeterministicAddress(implementation, finalSalt, address(this));
    }
}
