package network.platon.contracts;

import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.*;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tuples.generated.Tuple3;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.GasProvider;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * <p>Auto generated code.
 * <p><strong>Do not modify!</strong>
 * <p>Please use the <a href="https://docs.web3j.io/command_line.html">web3j command line tools</a>,
 * or the org.web3j.codegen.SolidityFunctionWrapperGenerator in the 
 * <a href="https://github.com/web3j/web3j/tree/master/codegen">codegen module</a> to update.
 *
 * <p>Generated with web3j version 0.7.5.0.
 */
public class BasicDataTypeContract2 extends Contract {
    private static final String BINARY = "60806040526040518060400160405280600581526020017f68656c6c6f0000000000000000000000000000000000000000000000000000008152506000908051906020019061004f9291906100ae565b506040518060400160405280600581526020017f776f726c640000000000000000000000000000000000000000000000000000008152506001908051906020019061009b9291906100ae565b503480156100a857600080fd5b50610153565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100ef57805160ff191683800117855561011d565b8280016001018555821561011d579182015b8281111561011c578251825591602001919060010190610101565b5b50905061012a919061012e565b5090565b61015091905b8082111561014c576000816000905550600101610134565b5090565b90565b610b60806101626000396000f3fe6080604052600436106100fe5760003560e01c80637d82a1e111610095578063ac917d6511610064578063ac917d65146104a7578063e064d48014610516578063ea07cdfa146105a6578063f38a79ad146105d1578063f8b2cb4f146106d4576100fe565b80637d82a1e114610357578063a0ee573514610390578063a5749710146103ec578063ac80575914610417576100fe565b806338023fb9116100d157806338023fb91461026657806338cc4831146102aa57806359a1cf1114610301578063627389981461032c576100fe565b80630a94e56d146101035780630ebefd6b14610170578063166aa6e6146101a95780632096525514610209575b600080fd5b34801561010f57600080fd5b50610118610739565b60405180827dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916815260200191505060405180910390f35b34801561017c57600080fd5b50610185610766565b6040518082600381111561019557fe5b60ff16815260200191505060405180910390f35b3480156101b557600080fd5b506101e5600480360360208110156101cc57600080fd5b81019080803560ff16906020019092919050505061077e565b604051808260038111156101f557fe5b60ff16815260200191505060405180910390f35b34801561021557600080fd5b5061021e610788565b60405180846fffffffffffffffffffffffffffffffff166fffffffffffffffffffffffffffffffff168152602001838152602001828152602001935050505060405180910390f35b6102a86004803603602081101561027c57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506107b9565b005b3480156102b657600080fd5b506102bf610803565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561030d57600080fd5b50610316610824565b6040518082815260200191505060405180910390f35b34801561033857600080fd5b50610341610841565b6040518082815260200191505060405180910390f35b34801561036357600080fd5b5061036c61084f565b6040518082600381111561037c57fe5b60ff16815260200191505060405180910390f35b610398610860565b604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200183815260200182151515158152602001935050505060405180910390f35b3480156103f857600080fd5b506104016108a7565b6040518082815260200191505060405180910390f35b34801561042357600080fd5b5061042c6108c6565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561046c578082015181840152602081019050610451565b50505050905090810190601f1680156104995780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b3480156104b357600080fd5b506104bc610968565b60405180827effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916815260200191505060405180910390f35b34801561052257600080fd5b5061052b610995565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561056b578082015181840152602081019050610550565b50505050905090810190601f1680156105985780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b3480156105b257600080fd5b506105bb610a99565b6040518082815260200191505060405180910390f35b3480156105dd57600080fd5b506105e6610ab2565b60405180847dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152602001837effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152602001827effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19168152602001935050505060405180910390f35b3480156106e057600080fd5b50610723600480360360208110156106f757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610b0a565b6040518082815260200191505060405180910390f35b6000807f01f400000000000000000000000000000000000000000000000000000000000090508091505090565b60008060038081111561077557fe5b90508091505090565b6000819050919050565b6000806000806003905060006404a817c80090506000660aa87bee5380009050828282955095509550505050909192565b8073ffffffffffffffffffffffffffffffffffffffff166108fc349081150290604051600060405180830381858888f193505050501580156107ff573d6000803e3d6000fd5b5050565b60008073ca35b7d915458ef540ade6068dfe2f44e8fa733c90508091505090565b600080805460018160011615610100020316600290049050905090565b600080600690508091505090565b600061085b600161077e565b905090565b600080600033348473ffffffffffffffffffffffffffffffffffffffff166108fc349081150290604051600060405180830381858888f19350505050925092509250909192565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b606060008054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561095e5780601f106109335761010080835404028352916020019161095e565b820191906000526020600020905b81548152906001019060200180831161094157829003601f168201915b5050505050905090565b6000807fc80000000000000000000000000000000000000000000000000000000000000090508091505090565b60608060008054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610a2e5780601f10610a0357610100808354040283529160200191610a2e565b820191906000526020600020905b815481529060010190602001808311610a1157829003601f168201915b505050505090507f610000000000000000000000000000000000000000000000000000000000000081600081518110610a6357fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508091505090565b60008060006003811115610aa957fe5b90508091505090565b6000806000807f01f400000000000000000000000000000000000000000000000000000000000090508081600060028110610ae957fe5b1a60f81b82600160028110610afa57fe5b1a60f81b93509350935050909192565b60008173ffffffffffffffffffffffffffffffffffffffff1631905091905056fea265627a7a723158205567714e9bffff6e63888745c44da81ff149b9f1e735e020ad7ea2be5d6817f464736f6c634300050d0032";

    public static final String FUNC_GETADDRESS = "getAddress";

    public static final String FUNC_GETBALANCE = "getBalance";

    public static final String FUNC_GETCURRENTBALANCE = "getCurrentBalance";

    public static final String FUNC_GETHEXLITERA2 = "getHexLitera2";

    public static final String FUNC_GETHEXLITERA3 = "getHexLitera3";

    public static final String FUNC_GETHEXLITERAL = "getHexLiteral";

    public static final String FUNC_GETINT = "getInt";

    public static final String FUNC_GETSEASON1 = "getSeason1";

    public static final String FUNC_GETSEASON2 = "getSeason2";

    public static final String FUNC_GETSEASONINDEX = "getSeasonIndex";

    public static final String FUNC_GETSTR1 = "getStr1";

    public static final String FUNC_GETSTR1LENGTH = "getStr1Length";

    public static final String FUNC_GETVALUE = "getValue";

    public static final String FUNC_GOSEND = "goSend";

    public static final String FUNC_GOTRANSFER = "goTransfer";

    public static final String FUNC_PRINTSEASON = "printSeason";

    public static final String FUNC_SETSTR1 = "setStr1";

    @Deprecated
    protected BasicDataTypeContract2(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    protected BasicDataTypeContract2(String contractAddress, Web3j web3j, Credentials credentials, GasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider);
    }

    @Deprecated
    protected BasicDataTypeContract2(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    protected BasicDataTypeContract2(String contractAddress, Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public RemoteCall<TransactionReceipt> getAddress() {
        final Function function = new Function(
                FUNC_GETADDRESS, 
                Arrays.<Type>asList(),
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteCall<BigInteger> getBalance(String addr) {
        final Function function = new Function(FUNC_GETBALANCE,
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(addr)),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<BigInteger> getCurrentBalance() {
        final Function function = new Function(FUNC_GETCURRENTBALANCE,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<byte[]> getHexLitera2() {
        final Function function = new Function(FUNC_GETHEXLITERA2,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Bytes2>() {}));
        return executeRemoteCallSingleValueReturn(function, byte[].class);
    }

    public RemoteCall<Tuple3<byte[], byte[], byte[]>> getHexLitera3() {
        final Function function = new Function(FUNC_GETHEXLITERA3,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Bytes2>() {}, new TypeReference<Bytes1>() {}, new TypeReference<Bytes1>() {}));
        return new RemoteCall<Tuple3<byte[], byte[], byte[]>>(
                new Callable<Tuple3<byte[], byte[], byte[]>>() {
                    @Override
                    public Tuple3<byte[], byte[], byte[]> call() throws Exception {
                        List<Type> results = executeCallMultipleValueReturn(function);
                        return new Tuple3<byte[], byte[], byte[]>(
                                (byte[]) results.get(0).getValue(), 
                                (byte[]) results.get(1).getValue(), 
                                (byte[]) results.get(2).getValue());
                    }
                });
    }

    public RemoteCall<byte[]> getHexLiteral() {
        final Function function = new Function(FUNC_GETHEXLITERAL,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Bytes1>() {}));
        return executeRemoteCallSingleValueReturn(function, byte[].class);
    }

    public RemoteCall<TransactionReceipt> getInt() {
        final Function function = new Function(
                FUNC_GETINT, 
                Arrays.<Type>asList(),
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteCall<BigInteger> getSeason1() {
        final Function function = new Function(FUNC_GETSEASON1,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint8>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<BigInteger> getSeason2() {
        final Function function = new Function(FUNC_GETSEASON2,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint8>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<BigInteger> getSeasonIndex() {
        final Function function = new Function(FUNC_GETSEASONINDEX,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<String> getStr1() {
        final Function function = new Function(FUNC_GETSTR1,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Utf8String>() {}));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public RemoteCall<BigInteger> getStr1Length() {
        final Function function = new Function(FUNC_GETSTR1LENGTH,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<Tuple3<BigInteger, BigInteger, BigInteger>> getValue() {
        final Function function = new Function(FUNC_GETVALUE,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint128>() {}, new TypeReference<Uint256>() {}, new TypeReference<Uint256>() {}));
        return new RemoteCall<Tuple3<BigInteger, BigInteger, BigInteger>>(
                new Callable<Tuple3<BigInteger, BigInteger, BigInteger>>() {
                    @Override
                    public Tuple3<BigInteger, BigInteger, BigInteger> call() throws Exception {
                        List<Type> results = executeCallMultipleValueReturn(function);
                        return new Tuple3<BigInteger, BigInteger, BigInteger>(
                                (BigInteger) results.get(0).getValue(), 
                                (BigInteger) results.get(1).getValue(), 
                                (BigInteger) results.get(2).getValue());
                    }
                });
    }

    public RemoteCall<TransactionReceipt> goSend(BigInteger weiValue) {
        final Function function = new Function(
                FUNC_GOSEND, 
                Arrays.<Type>asList(),
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function, weiValue);
    }

    public RemoteCall<TransactionReceipt> goTransfer(String addr, BigInteger weiValue) {
        final Function function = new Function(
                FUNC_GOTRANSFER, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(addr)),
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function, weiValue);
    }

    public RemoteCall<BigInteger> printSeason(BigInteger s) {
        final Function function = new Function(FUNC_PRINTSEASON,
                Arrays.<Type>asList(new org.web3j.abi.datatypes.generated.Uint8(s)),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint8>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteCall<String> setStr1() {
        final Function function = new Function(FUNC_SETSTR1,
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Utf8String>() {}));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public static RemoteCall<BasicDataTypeContract2> deploy(Web3j web3j, Credentials credentials, GasProvider contractGasProvider) {
        return deployRemoteCall(BasicDataTypeContract2.class, web3j, credentials, contractGasProvider, BINARY, "");
    }

    @Deprecated
    public static RemoteCall<BasicDataTypeContract2> deploy(Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(BasicDataTypeContract2.class, web3j, credentials, gasPrice, gasLimit, BINARY, "");
    }

    public static RemoteCall<BasicDataTypeContract2> deploy(Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider) {
        return deployRemoteCall(BasicDataTypeContract2.class, web3j, transactionManager, contractGasProvider, BINARY, "");
    }

    @Deprecated
    public static RemoteCall<BasicDataTypeContract2> deploy(Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(BasicDataTypeContract2.class, web3j, transactionManager, gasPrice, gasLimit, BINARY, "");
    }

    @Deprecated
    public static BasicDataTypeContract2 load(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return new BasicDataTypeContract2(contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    @Deprecated
    public static BasicDataTypeContract2 load(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return new BasicDataTypeContract2(contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    public static BasicDataTypeContract2 load(String contractAddress, Web3j web3j, Credentials credentials, GasProvider contractGasProvider) {
        return new BasicDataTypeContract2(contractAddress, web3j, credentials, contractGasProvider);
    }

    public static BasicDataTypeContract2 load(String contractAddress, Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider) {
        return new BasicDataTypeContract2(contractAddress, web3j, transactionManager, contractGasProvider);
    }
}
