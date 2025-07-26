MAU_BASE_PATH=$HOME"/wasmfuzz/ethfuzz/repo"
TRANSFORMER_PATH=$MAU_BASE_PATH"/build/sema/src/standalone-ptxsema"


$TRANSFORMER_PATH $1/$2.bin -o ./bytecode.ll --hex --dump && \
    llvm-link-13 $MAU_BASE_PATH/build/rt.o.bc ./bytecode.ll -o ./kernel.bc && \
    llvm-dis-13 kernel.bc -o kernel.ll && \
    $MAU_BASE_PATH/scripts/llc-16 -mcpu=sm_86 kernel.bc -o kernel.ptx
    
LD_LIBRARY_PATH=$MAU_BASE_PATH/build/runner/ ./cli/target/release/cli  -t "$1/*" --corpus-path "./corpus"   --ptx-path kernel.ptx --gpu-dev 0 $3
