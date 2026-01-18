//SPDX-License-identifier: MIT
pragma solidity ^0.8.20;

interface ISmartWallet {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    // EVENTS
    event WalletExecuted(address indexed target, uint256 value, bytes data);
    event BatchExecuted(uint256 callCount);
    event PasskeyRegistered(address indexed passkeyAddr, bytes32 qx, bytes32 qy);
    event PasskeyRemoved(address indexed passkeyAddr);
    event MetaTxExecuted(address indexed signer, address indexed target, uint256 value, bytes data);

    // ERRORS
    error NotAuthorized();
    error ExecutionFailed();
    error InvalidSignature();
    error SignatureExpired();
    error PasskeyAlreadyRegistered();
    error PasskeyNotRegistered();
}
