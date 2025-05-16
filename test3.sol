// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test3 {
    mapping(address => uint256) private balances;
    
    // Vulnerable function with integer overflow potential
    function deposit() public payable {
        // No check for overflow
        balances[msg.sender] += msg.value;
    }
    
    // Function with unchecked return value
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        // No event emission for transfers
    }
    
    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }
}
