// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Reentrancy vulnerability - state is updated after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable to reentrancy - external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State updated after external call
        balances[msg.sender] -= amount;
        
        emit Withdrawal(msg.sender, amount, block.timestamp);
    }
    
    // Integer overflow vulnerability (in Solidity < 0.8.0)
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        // Vulnerable to overflow
        return a + b;
    }
    
    // Unchecked return value
    function transfer(address payable recipient, uint256 amount) public {
        // Unchecked return value from low-level call
        recipient.send(amount);
    }
    
    // Missing visibility specifier
    function initializeContract(address _owner) {
        // Missing visibility specifier (public by default)
        owner = _owner;
    }
    
    // Function to receive ETH
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
    
    event Withdrawal(address indexed user, uint256 amount, uint256 timestamp);
} 