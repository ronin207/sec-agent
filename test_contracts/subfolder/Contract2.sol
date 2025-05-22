// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Contract2 {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Function with potential vulnerability
    function transferOwnership(address newOwner) public {
        // Missing access control
        owner = newOwner;
    }
} 