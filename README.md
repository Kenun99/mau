# ItyFuzz-Mau

## How to build

### Build your Runner from Mau
1. Download the source code from https://github.com/Kenun99/Mau-Artifact
2. build
```
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Releas -DCUDAPATH=/usr/local/cuda-11.4/ ..
cmake --build . --target all
```

### Build the Fuzzer
1. put your Mau's target to `build.rs`
2. build by `cd cli && cargo build --release`

## Example
`bash run.sh  ./tests/2018-10299/ BecToken --run-forever`
Check the tirggered bug orcales from the stdout.
i.e., `Oracle: IntegerBug`

## Bug Oracles
see `src/evm/host.rs`

# ItyFuzz 🍦
Fast hybrid fuzzer for EVM & MoveVM (WIP) smart contracts.  

You can generate exploits **instantly** by just providing the contract address:
![](https://ityfuzz.assets.fuzz.land/demo2.gif)

[中文版README](https://github.com/fuzzland/ityfuzz/blob/master/README_CN.md) / [Research Paper](https://scf.so/ityfuzz.pdf) / [Development Info](#development)

### Run ItyFuzz with UI
Install [Docker](https://www.docker.com/) and run docker image suitable for your system architecture:

```
docker pull fuzzland/ityfuzz:stable
docker run -p 8000:8000 fuzzland/ityfuzz:stable
```

Then, you can visit the interface at http://localhost:8000

<sub>Note: The container uses public ETH RPC, may time out / be slow</sub>

### Statistics & Comparison

Time taken for finding vulnerabilities / generating exploits: 

| Project Name             | Vulnerability           | **Mythril** | **SMARTIAN**    | **Slither** | **ItyFuzz** |
|---------------|-------------------------|---------|-------------|---------|---------|
| AES           | Business Logic          | Inf     | Unsupported | No      | 4hrs    |
| Carrot        | Arbitrary External Call | 17s     | 11s         | Yes     | 1s      |
| Olympus       | Access Control          | 36s     | Inf         | Yes     | 1s      |
| MUMUG         | Price Manipulation      | Inf     | Unsupported         | No      | 18hrs   |
| Omni          | Reentrancy              | Inf     | Unsupported         | Yes*    | 22hrs   |
| Verilog CTF-2 | Reentrancy              | Inf     | Unsupported         | Yes*    | 3s      |

<sub>\* Slither only finds the reentrancy location, but not how to leverage reentrancy to trigger final buggy code. The output also contains significant amount of false positives. </sub>

Test Coverage:

| **Dataset** | **SMARTIAN** | **Echidna** | **ItyFuzz** |
|-------------|--------------|-------------|-------------|
| B1          | 97.1%        | 47.1%       | 99.2%       |
| B2          | 86.2%        | 82.9%       | 95.4%       |
| Tests       | Unsupported  | 52.9%       | 100%        |

<sub>\* B1 and B2 contain 72 single-contract projects from SMARTIAN artifacts. Tests are the projects in `tests` directory. The coverage is calculated as `(instruction covered) / (total instruction - dead code)`. </sub>


# Development

### Building

You need to have `libssl-dev` (OpenSSL) and `libz3-dev` (refer to [Z3 Installation](#z3-installation) section for instruction) installed.  

```bash
# download move dependencies
git submodule update --recursive --init
cd cli/
cargo build --release
```

You can enable certain debug gates in `Cargo.toml`

`solc` is needed for compiling smart contracts. You can use `solc-select` tool to manage the version of `solc`.

### Run
Compile Smart Contracts:
```bash
cd ./tests/multi-contract/
# include the library from ./solidity_utils for example
solc *.sol -o . --bin --abi --overwrite --base-path ../../
```
Run Fuzzer:
```bash
# if cli binary exists
cd ./cli/
#./cli -t '../tests/multi-contract/*'
LD_LIBRARY_PATH=/home/weimin/build/runner/ ./target/release/cli -t '../tests/complex-condition/*
```

CUDA mode

complex-condition
```bash
~/build/sema/src/standalone-ptxsema /data_HDD/weimin/EXP-Artifact/ityfuzz/tests/complex-condition/main.bin -o ./bytecode.ll --hex --dump && llvm-link ~/build/rt.o.bc ./bytecode.ll -o ./kernel.bc && llvm-dis kernel.bc -o kernel.ll && ~/wasmfuzz/ethfuzz/repo/scripts/llc-16 -mcpu=sm_86 kernel.bc -o kernel.ptx && LD_LIBRARY_PATH=/home/weimin/build/runner/ /data_HDD/weimin/EXP-Artifact/ityfuzz/cli/target/release/cli -t '/data_HDD/weimin/EXP-Artifact/ityfuzz/tests/complex-condition/*' --ptx-path kernel.ptx --gpu-dev 0
```

storage
```
~/build/sema/src/standalone-ptxsema /data_HDD/weimin/EXP-Artifact/ityfuzz/tests/storage/main.bin  -o ./bytecode.ll --hex --dump && llvm-link ~/build/rt.o.bc ./bytecode.ll -o ./kernel.bc && llvm-dis kernel.bc -o kernel.ll && ~/wasmfuzz/ethfuzz/repo/scripts/llc-16 -mcpu=sm_86 kernel.bc -o kernel.ptx && LD_LIBRARY_PATH=/home/weimin/build/runner/ /data_HDD/weimin/EXP-Artifact/ityfuzz/cli/target/release/cli -t '/data_HDD/weimin/EXP-Artifact/ityfuzz/tests/storage/*' --ptx-path kernel.ptx --gpu-dev 2
```

### maze
`~/build/sema/src/standalone-ptxsema /data_HDD/weimin/EXP-Artifact/ityfuzz/tests/maze-0/Maze.bin  -o ./bytecode.ll --hex --dump && llvm-link ~/build/rt.o.bc ./bytecode.ll -o ./kernel.bc && llvm-dis kernel.bc -o kernel.ll && ~/wasmfuzz/ethfuzz/repo/scripts/llc-16 -mcpu=sm_86 kernel.bc -o kernel.ptx && LD_LIBRARY_PATH=/home/weimin/build/runner/ RUST_BACKTRACE=1 /data_HDD/weimin/EXP-Artifact/ityfuzz/cli/target/release/cli -t '/data_HDD/weimin/EXP-Artifact/ityfuzz/tests/maze-0/*' --ptx-path kernel.ptx --gpu-dev 3 > log-1 2>&1`

calculate the unique bugs
`cat log-1|grep log| awk '{split($0, arr, " "); print arr[2];}'|sort|uniq|wc -l`

### Demo

**Verilog CTF Challenge 2**
`tests/verilog-2/`

Flashloan attack + Reentrancy. The target is to reach line 34 in `Bounty.sol`. 

Exact Exploit:
```
0. Borrow k MATIC such that k > balance() / 10
1. depositMATIC() with k MATIC
2. redeem(k * 1e18) -- reentrancy contract --> getBounty()
3. Return k MATIC
```

Use fuzzer to detect the vulnerability and generate the exploit (takes 0 - 200s):
```bash
# build contracts in tests/verilog-2/
solc *.sol -o . --bin --abi --overwrite --base-path ../../
# run fuzzer
./cli -f -t "./tests/verilog-2/*"
```

`-f` flag enables automated flashloan, which hooks all ERC20 external calls and make any users to have infinite balance. 

cuda mode
```
~/build/sema/src/standalone-ptxsema /data_HDD/weimin/EXP-Artifact/ityfuzz/tests/verilog-2/WMATICV2.bin  -o ./bytecode.ll --hex --dump && llvm-link ~/build/rt.o.bc ./bytecode.ll -o ./kernel.bc && llvm-dis kernel.bc -o kernel.ll && ~/wasmfuzz/ethfuzz/repo/scripts/llc-16 -mcpu=sm_86 kernel.bc -o kernel.ptx && LD_LIBRARY_PATH=/home/weimin/build/runner/ /data_HDD/weimin/EXP-Artifact/ityfuzz/cli/target/release/cli -f -t "./tests/verilog-2/*" --ptx-path kernel.ptx --gpu-dev 0
```

offline mode
```
/data_HDD/weimin/EXP-Artifact/mau-maze-test/baselines/ityfuzz/cli/target/release/cli -t "./tests/verilog-2/*"  
```

### Fuzz a Project (Offline)
You can fuzz a project by providing a path to the project directory. 
```bash
./cli -t '[DIR_PATH]/*'
```
ItyFuzz would attempt to deploy all artifacts in the directory to a blockchain with no other smart contracts.

Specifically, the project directory should contain 
a few `[X].abi` and `[X].bin` files. For example, to fuzz a contract named `main.sol`, you should
ensure `main.abi` and `main.bin` exist in the project directory.
The fuzzer will automatically detect the contracts in directory, the correlation between them (see `tests/multi-contract`),
and fuzz them.

Optionally, if ItyFuzz fails to infer the correlation between contracts, you
can add a `[X].address`, where `[X]` is the contract name, to specify the address of the contract.

Caveats:

* Keep in mind that ItyFuzz is fuzzing on a clean blockchain, 
so you should ensure all related contracts (e.g., ERC20 token, Uniswap, etc.) are deployed to the blockchain before fuzzing.

* You also need to overwrite all `constructor(...)` in the smart contract to 
to make it have no function argument. ItyFuzz assumes constructors have no argument.

### Fuzz a Project (Online)

Rebuild with `flashloan_v2` (only supported in onchain) enabled to get better result. 
```bash
sed -i 's/\"default = [\"/\"default = [flashloan_v2,\"/g' ./Cargo.toml
cd ./cli/
cargo build --release
```

To effectively cache the costly RPC calls to blockchains, third-party APIs, and Etherscan, a proxy is built. 
To run the proxy:
```bash
pip3 install -r proxy/requirements.txt
python3 proxy/main.py
```

You can fuzz a project by providing an address, a block, and a chain type.
```bash
./cli -o -t [TARGET_ADDR] --onchain-block-number [BLOCK] -c [CHAIN_TYPE] 
```

Example:
Fuzzing WETH contract (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) on Ethereum mainnet at latest block.
```bash
./cli -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH
```
Fuzzing with flashloan and oracles enabled:
```bash
./cli -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH -f -i -p
```

ItyFuzz would pull the ABI of the contract from Etherscan and fuzz it.
If ItyFuzz encounters an unknown slot in the memory, it would pull the slot from chain RPC.
If ItyFuzz encounters calls to external unknown contract, it would pull the bytecode and ABI of that contract. 
If its ABI is not available, ItyFuzz would not send any transaction to that contract.

To use proxy, append `--onchain-local-proxy-addr http://localhost:5003` to your CLI command. 

### Onchain Fetching
ItyFuzz attempts to fetch storage from blockchain nodes when SLOAD is encountered and the target is uninitialized.
There are three ways of fetching: 
* OneByOne: fetch one slot at a time. This is the default mode. It is slow but never fails.
* All: fetch all slots at once using custom API `eth_getStorageAll` on our nodes. This is the fastest mode, but it may fail if the contract is too large. 
* Dump: dump storage using debug API `debug_storageRangeAt`. This only works for ETH (for now) and fails most of the time.

### Z3 Installation
**macOS**
```bash
git clone https://github.com/Z3Prover/z3 && cd z3
python scripts/mk_make.py --prefix=/usr/local
cd build && make -j64 && sudo make install
```
If the build command still fails for not finding `z3.h`, do `export Z3_SYS_Z3_HEADER=/usr/local/include/z3.h` 

**Ubuntu**

```bash
apt install libz3-dev
```

### Telemetry
ItyFuzz collects telemetry data to help us improve the fuzzer. The data is collected anonymously and is not used for any commercial purpose.
You can disable telemetry by setting `NO_TELEMETRY=1` in your environment variable.


### Acknowledgement

This work was supported in part by NSF grants CCF-1900968, CCF1908870, and CNS1817122 and SKY Lab industrial sponsors and
affiliates Astronomer, Google, IBM, Intel, Lacework, Microsoft, Mohamed Bin Zayed University of Artificial Intelligence, Nexla, Samsung SDS, Uber, and VMware. Any opinions, findings, conclusions,
or recommendations in this repo do not necessarily reflect the position or the policy of the
sponsors.

Grants:
| Grants | Description |
|:----:|:-----------:|
| <img src=https://ityfuzz.assets.fuzz.land/sui.jpg width=100px/> | Grants from Sui Foundation for building Move and chain-specfic support |
| <img src=https://ityfuzz.assets.fuzz.land/web3.png width=100px/> | Grants from Web3 Foundation for building Substrate pallets and Ink! support |



on-chain test

1. Gym
ganache-cli -p 5003 -f  https://bsc-mainnet.nodereal.io/v1/32f5543e19e6421da4b4219ea9d4da24@18501049

LD_LIBRARY_PATH=/home/weimin/build/runner/ /data_HDD/weimin/EXP-Artifact/ityfuzz/cli/target/release/cli 
  -f -o -c BSC --onchain-block-number 18501049 -i -t 0xA8987285E100A8b557F06A7889F79E0064b359f2,0x6CD71A07E72C514f5d511651F6808c6395353968,0x7109709ECfa91a80626fF3989D68f67F5b1D
D12D,0x3a0d9d7764FAE860A659eb96A500F1323b411e68 --onchain-local-proxy-addr http://localhost:5003  --flashloan-price-oracle onchain
