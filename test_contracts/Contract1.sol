// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Contract1 {
    uint256 public value;
    
    constructor() {
        value = 100;
    }
    
    function setValue(uint256 newValue) public {
        value = newValue;
    }
} 