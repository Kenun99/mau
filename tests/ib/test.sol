// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.4.25;


contract main {
    uint res;
    function flashLoan(uint a, uint b) public {
        // res += a;
        // res += b;
        // res + 10000;
        res = a + b;
    }
}
