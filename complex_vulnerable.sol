// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @dev This contract contains multiple security vulnerabilities for testing purposes.
 * DO NOT USE IN PRODUCTION!
 */
contract VulnerableBank {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public whitelisted;
    uint256 public totalDeposits;
    address[] public users;
    
    // Vulnerability #1: Using tx.origin for authentication
    modifier onlyOwner() {
        require(tx.origin == owner, "Not the owner");
        _;
    }
    
    // Vulnerability #2: No reentrancy guard
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerability #3: Unchecked math
    function deposit() public payable {
        balances[msg.sender] += msg.value; // No SafeMath used
        totalDeposits += msg.value;
        
        if (balances[msg.sender] > 0 && !isUser(msg.sender)) {
            users.push(msg.sender);
        }
    }
    
    // Vulnerability #4: Classic reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable to reentrancy - state updated after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }
    
    // Vulnerability #5: Integer overflow potential
    function transferToUser(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount; // Potential overflow if to.balance + amount > uint256.max
    }
    
    // Vulnerability #6: Private data exposed
    function getPrivateData() public view onlyOwner returns (address[] memory) {
        return users;
    }
    
    // Vulnerability #7: DoS vulnerability
    function distributeRewards() public onlyOwner {
        uint256 rewardAmount = address(this).balance / users.length;
        
        for (uint256 i = 0; i < users.length; i++) {
            // If any transfer fails, the entire function fails
            // Vulnerable to DoS if a malicious contract rejects transfers
            payable(users[i]).transfer(rewardAmount);
        }
    }
    
    // Vulnerability #8: Timestamp dependency
    function randomReward() public returns (uint256) {
        // Using block.timestamp for randomness is insecure
        uint256 randomValue = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
        
        if (randomValue > 50 && balances[msg.sender] > 0) {
            balances[msg.sender] += 1 ether;
            return 1 ether;
        }
        
        return 0;
    }
    
    // Vulnerability #9: Unchecked external call
    function riskyCall(address target, bytes memory data) public onlyOwner {
        // Arbitrary call to any address with any calldata
        // Vulnerable to malicious use
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }
    
    function addToWhitelist(address user) public onlyOwner {
        whitelisted[user] = true;
    }
    
    function removeFromWhitelist(address user) public onlyOwner {
        whitelisted[user] = false;
    }
    
    function isUser(address user) internal view returns (bool) {
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == user) {
                return true;
            }
        }
        return false;
    }
    
    // Fallback function to accept ether
    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
} 