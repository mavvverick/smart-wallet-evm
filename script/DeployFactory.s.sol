// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {SmartWalletFactory} from "../src/SmartWalletFactory.sol";
import {SmartWallet} from "../src/SmartWallet.sol";

contract DeployFactory is Script {
    function run() external returns (address factoryAddress) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        SmartWallet implementation = new SmartWallet();
        SmartWalletFactory factory = new SmartWalletFactory(address(implementation));

        vm.stopBroadcast();

        return address(factory);
    }
}
