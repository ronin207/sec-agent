// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SimpleToken
 * @dev A simple ERC20-like token with vulnerabilities for demonstration
 */
contract SimpleToken {
    string public name = "SimpleToken";
    string public symbol = "STK";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**18;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public owner;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() {
        owner = msg.sender;
        balanceOf[msg.sender] = totalSupply;
    }
    
    // Unsafe due to lack of overflow/underflow checks (on older compiler versions)
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    // Reentrancy vulnerability - state changes after external call
    function withdraw(uint256 _amount) public {
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
        // Vulnerability: state is updated after external call
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        balanceOf[msg.sender] -= _amount;
    }
    
    // Unauthorized access - no ownership check
    function mint(address _to, uint256 _amount) public {
        // Vulnerability: No access control check
        totalSupply += _amount;
        balanceOf[_to] += _amount;
        emit Transfer(address(0), _to, _amount);
    }
    
    // Integer overflow/underflow (on older compiler versions)
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    // Insecure transfer
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _value, "Insufficient allowance");
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    // Unprotected self-destruct function - anyone can call it
    function destroy() public {
        // Vulnerability: No ownership check
        selfdestruct(payable(msg.sender));
    }
    
    // Unchecked return value
    function unsafeCall(address target, bytes memory data) public {
        // Vulnerability: Return value not checked
        target.call(data);
    }
} 