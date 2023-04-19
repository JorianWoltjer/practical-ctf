---
description: A few small bits about attacking Smart Contracts in Web3
---

# Smart Contracts

## Compiling .sol to .abi

A contract's source code is found in `.sol` files, but code often requires a general structure instead, which is the Application Binary Interface (ABI) format, simply encoded in JSON. You can compile Solidity code into `.abi` files that you can use in your attacking script to interact with the contract in a known way.&#x20;

You can compile a single file to ABI into the current directory using the following command:

```shell-session
$ npx solc --abi <NAME>.sol -o <DIRECTORY>
# # For example
$ npx solc --abi Setup.sol -o .
```

It might complain about having the wrong compiler version installed, but this can often be circumvented by changing the version in the contract source itself. You might get a `ParserError` like this:

{% code overflow="wrap" %}
```solidity
Setup.sol:1:1: ParserError: Source file requires different compiler version (current compiler is 0.7.3+commit.9bfce1f6.Emscripten.clang) - note that nightly builds are considered to be strictly less than the released version
```
{% endcode %}

It says the current version is `0.7.3`, so simply change that first line in the source:

```diff
- pragma solidity ^0.8.18;
+ pragma solidity ^0.7.3;
```

## Simple Interaction

Take the following contract as a simple example:

<pre class="language-solidity"><code class="lang-solidity">pragma solidity ^0.8.18;

contract Example {
    bool public updated;

<strong>    function call_me(uint256 number) external {
</strong><strong>        if (number == 42) {
</strong><strong>            updated = true;
</strong>        }
    }
}
</code></pre>

To interact with a smart contract on a private chain, you need the following:

* [ ] A private key with some ether
* [ ] The contract's address
* [ ] URL for RPC to interact with

Then you can use libraries like [web3.py](https://github.com/ethereum/web3.py) or [web3.js](https://web3js.readthedocs.io/) to do the heavy lifting. The libraries are very similar in usage, but in the following examples, I will use the Python version.&#x20;

It starts with connecting to the RPC provider, and creating an account object from your private key:

```python
from web3 import Web3

# Connect to the private chain using an RPC provider
web3 = Web3(Web3.HTTPProvider('http://<HOST>:<PORT>'))

# Set the account that will execute transactions
private_key = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
account = web3.eth.account.privateKeyToAccount(private_key)
```

From here, you likely want to interact with a contract. You can get an instance of the contract in Python by opening the `.abi` file (see [#compiling-.sol-to-.abi](smart-contracts.md#compiling-.sol-to-.abi "mention")) and providing the address of the contract on the server.&#x20;

```python
# Create an instance of the contract
contract_address = '0x9876543210abcdef0123456789ABCDEF01234567'
contract_abi = open('Example.abi').read()
example = web3.eth.contract(address=contract_address, abi=contract_abi)
```

Now that we have an instance of the contract, we can interact with it by calling functions on it. In the example Solidity code above, we need to call the `call_me()` function with an argument of `42`. In our script that would look like this:

```python
tx_hash = example.functions.call_me(42).transact()
print(tx_hash)  # b'\x91\xfb\x10\x93...
```

If you run this script and the `tx_hash` prints something, it probably worked. Otherwise, you will likely receive a clear Exception on why it did not work.&#x20;

## Manual Transactions

These function calls abstract away a lot of details, but sometimes we as the attacker want more low-level control over the transaction being sent. Here are two examples.&#x20;

### The `fallback()` method

The contract might contain a payable method named `fallback()`:

```solidity
fallback() external payable {
    ...
}
```

You cannot call this function directly, because it has a special meaning. This function is called when **the function you try to call does not exist**. It is often used for updated contracts that need to handle the case when scripts interacting with it don't update. But to intentionally call this function we would need to try and call a wrong function name in our script.

Web3 won't actually let you do this straight away, to help you not make mistakes. But in the case where you intentionally want to do this, you can trick it into thinking the wrong method does exist.&#x20;

```python
tx_hash = example.functions.wrong().transact()
print(tx_hash)
```

{% code title="Error before transaction" overflow="wrap" %}
```python
web3.exceptions.ABIFunctionNotFound: ("The function 'wrong' was not found in this contract's abi. ", 'Are you sure you provided the correct contract abi?')
```
{% endcode %}

To bypass this, we can just manually change the `.abi` file to add a function called `wrong`, and make it think it exists:

```json
  {
    "inputs": [],
    "name": "wrong",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
```

When we now run the script again, it will correctly pass it through to the `fallback()` method.&#x20;

### The `receive()` method

Your contract may also have `receive()` method:

```solidity
receive() external payable {
    ...
}
```

This method is used when you **aren't calling a function at all**, so when there is no data involved in your transaction, specifically a transaction directly to the contract address. To trigger this function we just have to manually create a transaction and send it over, without the `data:` component. Here is an example:

```python
transaction = {
    'from': account.address,
    'to': contract_address,
    'value': web3.toWei(0, 'ether'),
    'gas': 2000000,
    'gasPrice': web3.toWei('50', 'gwei'),
}

tx_hash = web3.eth.send_transaction(transaction)
print(tx_hash)
```

In this case, we send 0 ether with some gas price configuration. It is sent `to` the contract address which will trigger the `receive()` method.&#x20;

{% hint style="info" %}
As I hinted, you can add a `data` component to this `transaction` which calling functions will automatically do for you. Here you can manually craft any call you want to make.&#x20;
{% endhint %}

## Requirements

With more involved contracts, you'll likely find the `modifier` keyword and the `require()` function. These can set specific conditions for if you can call a method or not. If this condition fails, your call will not go through. For example:

<pre class="language-solidity"><code class="lang-solidity">contract ShootingArea {
    bool public allowed;
    bool public updated;

<strong>    modifier isAllowed() {
</strong><strong>        require(allowed);
</strong>        _;
    }
    
    function open_gates() public {
<strong>        allowed = true;
</strong>    }

<strong>    function enter() public isAllowed {
</strong>        updated = true;
    }
}
</code></pre>

Here, someone would first have to call `open_gates()` before they could call `enter()`. Keep in mind that this state is remembered, so if you set `allowed = true` it will now forever be true, and you will be allowed in the next call.&#x20;
