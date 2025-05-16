// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/**
 * @title TokenContract
 * @dev A simple token contract with vulnerabilities for testing
 */
contract TokenContract {
    string public name = "VulnerableToken";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**uint256(decimals);
    
    // Mapping of address to token balance
    mapping(address => uint256) public balanceOf;
    
    // Mapping of address to mapping of address to allowance
    mapping(address => mapping(address => uint256)) public allowance;
    
    // List of accounts to process in batch operations
    address[] public accounts;
    
    // Variable with incorrect naming convention
    uint256 public Token_balance;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() public {
        balanceOf[msg.sender] = totalSupply;
        Token_balance = totalSupply;
    }
    
    // Function without visibility specifier - vulnerability
    function transfer(address to, uint256 amount) returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    // Reentrancy vulnerability in withdraw function
    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerability: state change after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        if(success) {
            balanceOf[msg.sender] -= amount;
        }
    }
    
    // DoS vulnerability with loop and external calls
    function processPayments(address[] memory recipients) public {
        for (uint i = 0; i < recipients.length; i++) {
            // Vulnerability: external call in loop without handling failures
            recipients[i].transfer(1 ether);
        }
    }
    
    // Integer overflow vulnerability
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        // Vulnerability: no overflow check
        uint256 c = a + b;
        return c;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        
        emit Transfer(from, to, amount);
        return true;
    }
    
    // Unchecked return value vulnerability
    function sendEther(address payable recipient, uint256 amount) public {
        // Vulnerability: return value of low-level call not checked
        recipient.call{value: amount}("");
    }
} 