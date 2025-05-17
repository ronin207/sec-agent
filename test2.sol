// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test2 {
    address payable public owner;
    
    constructor() {
        owner = payable(msg.sender);
    }
    
    // This function has a reentrancy vulnerability for testing
    function withdraw(uint256 amount) public {
        require(amount <= address(this).balance, "Insufficient balance");
        
        // Vulnerability: State change after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update should happen before the external call
        // to prevent reentrancy attacks
    }
    
    receive() external payable {}
}
