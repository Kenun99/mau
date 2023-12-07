// SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.15;

contract ReturnValue {

  function callchecked(address callee) public {
    require(callee.call());
  }

  function callnotchecked(address callee) public {
     // <yes> <report> UNCHECKED_LL_CALLS
    callee.call();
  }
}
