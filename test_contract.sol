// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableContract
 * @dev This contract contains intentional vulnerabilities for testing security scanning
 */
contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    bool public paused;
    uint256 public totalSupply;
    
    // Reentrancy vulnerability - missing nonReentrant modifier
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: state update after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // This should be done before the external call to prevent reentrancy
        balances[msg.sender] -= amount;
    }
    
    // Integer overflow (though protected in Solidity 0.8+, still a pattern to detect)
    function addToBalance(uint256 amount) external {
        balances[msg.sender] += amount;
    }
    
    // Unchecked external call
    function sendFunds(address payable recipient, uint256 amount) external {
        // Unsafe external call without checking return value
        recipient.call{value: amount}("");
    }
    
    // Unprotected function (missing onlyOwner modifier)
    function setPaused(bool _paused) external {
        paused = _paused;
    }
    
    // Use of tx.origin for authentication
    function transferOwnership(address newOwner) external {
        // Vulnerable - using tx.origin
        require(tx.origin == owner, "Not authorized");
        owner = newOwner;
    }
    
    // Hardcoded secret (bad practice)
    function checkSecret(string memory secret) external pure returns (bool) {
        return keccak256(abi.encodePacked(secret)) == keccak256(abi.encodePacked("hardcoded_secret_key"));
    }
    
    // Fixed block timestamp dependency
    function generateRandomNumber(uint256 seed) external view returns (uint256) {
        // Vulnerable - miners can manipulate block.timestamp
        return uint256(keccak256(abi.encodePacked(block.timestamp, seed, msg.sender))) % 100;
    }
    
    // DoS with unexpected revert
    function distributeRewards(address[] calldata recipients) external {
        for (uint i = 0; i < recipients.length; i++) {
            // If one transfer fails, the entire function will revert
            payable(recipients[i]).transfer(1 ether / recipients.length);
        }
    }
    
    // Uninitialized storage pointer
    function createVulnerability() external {
        // This can potentially point to unexpected storage locations
        uint[] memory values;
        values.push(10); // This will cause runtime error
    }
    
    receive() external payable {
        // Not checking sender or amount
        balances[msg.sender] += msg.value;
    }
} 