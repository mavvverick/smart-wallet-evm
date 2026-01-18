// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SmartWallet} from "../src/SmartWallet.sol";
import {SmartWalletFactory} from "../src/SmartWalletFactory.sol";
import {Clones} from "../src/Clones.sol";

import {ISmartWallet} from "../src/interface/ISmartWallet.sol";

import {IERC1271} from "@oz/contracts/interfaces/IERC1271.sol";
import {Ownable} from "@oz/contracts/access/Ownable.sol";
import {ECDSA} from "@oz/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@oz/contracts/utils/cryptography/MessageHashUtils.sol";

contract SmartWalletTest is Test {
    SmartWallet public implementation;
    SmartWalletFactory public factory;

    address public owner;
    address public user;
    address public random;

    uint256 public ownerPk = 0xA11CE;
    uint256 public userPk = 0xB0B;

    bytes32 constant SALT = bytes32(uint256(12345));

    receive() external payable {}

    function setUp() public {
        owner = vm.addr(ownerPk);
        user = vm.addr(userPk);
        random = makeAddr("random");

        vm.deal(owner, 100 ether);
        vm.deal(user, 10 ether);

        // Deploy implementation
        implementation = new SmartWallet();

        // Deploy factory pointing to implementation
        factory = new SmartWalletFactory(address(implementation));

        // Label addresses for better traces
        vm.label(address(implementation), "SmartWallet Impl");
        vm.label(address(factory), "Factory");
        vm.label(owner, "Owner");
        vm.label(user, "User");
    }

    function test_factory_can_predict_address() public {
        address predicted = factory.predictWalletAddress(owner, SALT);

        vm.prank(owner);
        address deployed = factory.deployWallet(owner, SALT);

        assertEq(predicted, deployed, "Predicted address should match deployed");
        assertTrue(predicted != address(0));
    }

    function test_factory_deploys_different_addresses_with_different_salts() public {
        vm.prank(owner);

        address walletA = factory.deployWallet(owner, bytes32(uint256(1)));
        address walletB = factory.deployWallet(owner, bytes32(uint256(2)));

        assertTrue(walletA != walletB);
    }

    function test_factory_emits_event_on_deploy() public {
        address wallet = factory.predictWalletAddress(owner, SALT);

        vm.expectEmit(true, true, false, false);
        emit SmartWalletFactory.WalletDeployed(owner, wallet, SALT);

        vm.prank(owner);
        factory.deployWallet(owner, SALT);
    }

    function test_deployed_wallet_has_correct_owner() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));

        SmartWallet wallet = SmartWallet(walletAddr);

        assertEq(wallet.owner(), owner);
    }

    function test_cannot_initialize_twice() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));

        SmartWallet wallet = SmartWallet(walletAddr);

        vm.expectRevert(); // OZ Initializable: already initialized
        wallet.initialize(address(0xdead));
    }

    function test_non_owner_can_deploy_for_someone_else() public {
        vm.prank(user);
        address payable walletAddr = payable(factory.deployWallet(random, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        assertEq(wallet.owner(), random);
    }

    function test_owner_can_execute_simple_call() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        vm.deal(address(wallet), 5 ether);

        address recipient = makeAddr("recipient");

        vm.prank(owner);
        wallet.execute(recipient, 1 ether, "");

        assertEq(recipient.balance, 1 ether);
        assertEq(address(wallet).balance, 4 ether);
    }

    function test_non_owner_cannot_execute() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        wallet.execute(address(0), 0, "");
    }

    function test_owner_can_register_and_remove_passkey() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        bytes32 qx = bytes32(uint256(777));
        bytes32 qy = bytes32(uint256(888));
        bytes32 credHash = keccak256("test-credential-id");

        vm.prank(owner);
        wallet.registerPasskey(qx, qy, credHash);

        (address pAddr,,) = wallet.getPasskeyInfo(credHash);
        assertTrue(wallet.isRegisteredPasskey(pAddr));
        assertTrue(wallet.hasPasskey());

        vm.prank(owner);
        wallet.removePasskey(qx, qy);

        assertFalse(wallet.isRegisteredPasskey(pAddr));
    }

    function test_cannot_register_same_passkey_twice() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        bytes32 qx = bytes32(uint256(999));
        bytes32 qy = bytes32(uint256(111));
        bytes32 credHash = keccak256("dup-cred");

        vm.prank(owner);
        wallet.registerPasskey(qx, qy, credHash);

        vm.expectRevert(ISmartWallet.PasskeyAlreadyRegistered.selector);
        vm.prank(owner);
        wallet.registerPasskey(qx, qy, credHash);
    }

    function test_non_owner_cannot_register_passkey() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        wallet.registerPasskey(bytes32(0), bytes32(0), bytes32(0));
    }

    function test_erc1271_validates_owner_signature() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        bytes32 rawHash = keccak256("hello world");

        // Sign the raw hash (no Ethereum prefix)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, rawHash);

        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 magic = wallet.isValidSignature(rawHash, sig);
        assertEq(magic, IERC1271.isValidSignature.selector, "Should return magic value");
    }

    function test_erc1271_rejects_wrong_signature() public {
        vm.prank(owner);
        address payable walletAddr = payable(factory.deployWallet(owner, SALT));
        SmartWallet wallet = SmartWallet(walletAddr);

        bytes32 hash = keccak256("hello world");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, MessageHashUtils.toEthSignedMessageHash(hash));

        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 magic = wallet.isValidSignature(hash, sig);
        assertEq(magic, bytes4(0));
    }

    function testFuzz_predict_different_salts(address _owner, bytes32 saltA, bytes32 saltB) public {
        vm.assume(saltA != saltB);
        vm.assume(_owner != address(0));

        address addrA = factory.predictWalletAddress(_owner, saltA);
        address addrB = factory.predictWalletAddress(_owner, saltB);

        assertTrue(addrA != addrB);
    }
}
