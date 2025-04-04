#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#ifndef BOOST_FILESYSTEM_NO_DEPRECATED
#define BOOST_FILESYSTEM_NO_DEPRECATED
#endif
#ifndef BOOST_SYSTEM_NO_DEPRECATED
#define BOOST_SYSTEM_NO_DEPRECATED
#endif

#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>
#include <boost/json.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <iostream>
#include <cstring>
#include <map>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/blueprint/utils/satisfiability_check.hpp>

#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/Support/Casting.h"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::blueprint;

/*
 * ToDO List:
 * 1.
 * 2.动态内存访问优化（线性 O（KN），waksam网络（(n+k)long(n+k)）,xjsnark优化 （k根号（n）））
*/
//std::vector<std::string> circuit;

std::unordered_map<std::string , int> IrToCircuitNumber;//将中间文件的输入表示装换成电路输入编号
std::unordered_map<int , int> CircuitNumberValue;//存储电路输入编号对应的输入值 用于生成nizkinput
std::unordered_map<std::string, std::pair<std::string, std::string> > PtrAddress; //用于处理getelementptr 获取数组内存地址的，用于存储寄存器标识符所对应的内存地址  key：寄存器标识符 value: 内存地址
std::unordered_map<std::string, int> AddressWireNumber;//用于处理load命令 key: 内存地址 value: 电路线编号
std::unordered_map<std::string , std::vector<int> > Ptr;
std::unordered_map<std::string , std::vector<int> > IrToCircuitBinaryNumber;//将中间文件的输入表示装换成电路输入二进制编号
std::unordered_map<std::string , std::vector<std::vector<int>> > ConstCji; //只读内存共分sqrt(n),这里用于映射存储每一子组的系数

std::unordered_map<std::string , std::string > ConstBinaryNumber; //常数的二进制形式

std::unordered_map<std::string , std::string > RegType;//用于记录IR中寄存器（变量，数组）的类型 i8/i16/i32,主要用于保证新建数组大小的正确性

int type=0;//数据类型 默认uint32_t 0 , uint8_t 1 , uint16_t 2

struct ModuleInformation{//用于模块存储其产生的电路信息和见证者信息
    std::vector<std::string> Circuit;
    std::vector<std::string> Witness;

};

std::string toHexString(int64_t value){
    std::stringstream  stream;
    stream << std::hex << value;
    return stream.str();
}
std::string in_wire(int InNumber, int LWireId, int RWireId = 0){
    std::string InWire = " in ";
    InWire += std::to_string(InNumber);
    if(InNumber == 1){
        InWire += " <" + std::to_string(LWireId) + ">";
    }else{
        InWire += " <" + std::to_string(LWireId) + " " + std::to_string(RWireId) + ">";
    }
    return InWire;
}
std::string in_wirearry(int InNumber, std::vector<int> &WireId){
    std::string InWire = " in ";
    InWire += std::to_string(InNumber);
    InWire += " <";
    for(size_t i=0; i<InNumber-1; i++){
        InWire += std::to_string(WireId[i]) + " ";
    }
    InWire += std::to_string(WireId[InNumber-1]) + ">";
    return InWire;

}
std::string out_wire(int OutNumber, int WireId){
    std::string OutWire = " out ";
    OutWire += std::to_string(OutNumber);
    OutWire += " <" + std::to_string(WireId) + ">";
    return OutWire;
}
std::string out_wirearry(int OutNumber, std::vector<int> &WireId){
    std::string OutWire = " out ";
    OutWire += std::to_string(OutNumber);
    OutWire += " <";
    for(auto i=0; i<OutNumber-1; i++){
        OutWire += std::to_string(WireId[i]) + " ";
    }
    OutWire += std::to_string(WireId[OutNumber-1]) + ">";
//    std::cout<<OutWire.size()<<"\n";
    return OutWire;
}
std::string split(std::string Str, int len, int &WireNumber){  //从低位存储到高位 例：binary[0] 存储 x*2^0
    std::string Split = "split";
//    std::cout<<"cirnum:"<<Str<<" "<<IrToCircuitNumber[Str]<<"\n";
//    std::cout<<"Wire2: "<<WireNumber<<"\n";
    std::vector<int> binary(len);
    for(auto i=0;i<len;i++){
        binary[i]=WireNumber++;
//        binary.push_back(WireNumber++);
    }
//    std::cout<<"Wire3: "<<WireNumber<<"\n";
//    std::cout<<"bin: ";
//    for(auto num:binary){
//        std::cout<<num<<" ";
//    }
//    std::cout<<"\n";
    IrToCircuitBinaryNumber[Str]=binary;

    Split += in_wire(1,IrToCircuitNumber[Str]);
    Split += out_wirearry(len,binary);
    return Split;
}
std::string pack(const std::string& Str, int &WireNumber){
    std::string Pack = "pack";
    auto len = IrToCircuitBinaryNumber[Str].size();
    Pack += in_wirearry(len,IrToCircuitBinaryNumber[Str]);

    IrToCircuitNumber[Str] = WireNumber++;

    Pack += out_wire(1, IrToCircuitNumber[Str]);
    return Pack;
}
std::vector<std::string> packcheck(std::vector<std::string> ValueStr, int  &WireNumber){
    std::vector<std::string> Circuitpack;
    std::string PackWire;
    if(IrToCircuitNumber.find(ValueStr[0]) == IrToCircuitNumber.end() && IrToCircuitBinaryNumber.find(ValueStr[0]) != IrToCircuitBinaryNumber.end()){
       PackWire = pack(ValueStr[0],WireNumber);
       Circuitpack.push_back(PackWire);
    }
    if(IrToCircuitNumber.find(ValueStr[1]) == IrToCircuitNumber.end() && IrToCircuitBinaryNumber.find(ValueStr[1]) != IrToCircuitBinaryNumber.end()){
        PackWire = pack(ValueStr[1],WireNumber);
        Circuitpack.push_back(PackWire);
    }
    return Circuitpack;
}
std::string const_mul(int ConstValue, int WireId, int &WireNumber,bool neg = false){
    std::string ConstMul = "const-mul-";
    if(neg){
        ConstMul += "neg-";
    }
    else if(ConstValue<0){
        ConstMul += "neg-";
        ConstValue *= (-1);
    }
    std::stringstream ss;
    ss << std::hex << ConstValue;
    ConstMul += ss.str();
    ConstMul += in_wire(1, WireId);
    ConstMul += out_wire(1,WireNumber++);
    return ConstMul;
}

std::string var_mul(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::string Mul = "mul";
    Mul += in_wire(2, IrToCircuitNumber[ValueStr[0]], IrToCircuitNumber[ValueStr[1]]);

    IrToCircuitNumber[InstructionStr] = WireId++;
    Mul += out_wire(1, IrToCircuitNumber[InstructionStr]);
    return Mul;
}
std::string var_sdiv(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::string Sdiv = "assert";// Assertion for division result
    Sdiv += in_wire(2, IrToCircuitNumber[ValueStr[1]], IrToCircuitNumber[InstructionStr]);

    Sdiv += out_wire(1,IrToCircuitNumber[ValueStr[0]]);
    return Sdiv;

}
std::string var_add(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::string Add = "add";

    Add += in_wire(2, IrToCircuitNumber[ValueStr[0]], IrToCircuitNumber[ValueStr[1]]);

    IrToCircuitNumber[InstructionStr] = WireId++;
    Add += out_wire(1, IrToCircuitNumber[InstructionStr]);
    return Add;

}
std::vector<std::string> var_binary_add(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<std::string> CircuitBinaryAdd;
    std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
    std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
    std::vector<int> C(B.size());
    for(int i=0;i<A.size();i++){
        if((A[i]==0&&B[i]==0)||(A[i]==1&&B[i]==1)){
            C[i]=1;
        }else if((A[i]==0&&B[i]==1)||(A[i]==1&&B[i]==0)){
            C[i]=0;
        }else if(A[i]==1){
            C[i]=B[i];
        }else if(B[i]==1){
            C[i]=A[i];
        }else{
            int AddRes=WireId++;
            std::string Add = "add";
            Add += in_wire(2,A[i],B[i]);
            Add += out_wire(1,AddRes);
            CircuitBinaryAdd.push_back(Add);
            C[i]=AddRes;
        }
    }

    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitBinaryAdd;
}
std::vector<std::string> var_binary_sub(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<std::string> CircuitBinarySub;
    std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
    std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
    std::vector<int> C(B.size());
    for(int i=0;i<A.size();i++){
        if((A[i]==0&&B[i]==0)||(A[i]==1&&B[i]==1)){
            C[i]=1;
        }else if(A[i]==0&&B[i]==1){
            C[i]=0;
        }else if(A[i]==1&&B[i]==0){
            if(IrToCircuitNumber.find("-1")==IrToCircuitNumber.end()){
                IrToCircuitNumber["-1"] = WireId;
                CircuitBinarySub.push_back(const_mul(-1, 0, WireId));
            }
            C[i]=IrToCircuitNumber["-1"];
        }else if(B[i]==1){
            C[i]=A[i];
        }else{
            int ConstmulRes=WireId++;
            std::string ConstMul = "const-mul-neg-1";
            ConstMul += in_wire(1,B[i]);
            ConstMul += out_wire(1,ConstmulRes);
            CircuitBinarySub.push_back(ConstMul);

            int AddRes=WireId++;
            std::string Add = "add";
            Add += in_wire(2,A[i],ConstmulRes);
            Add += out_wire(1,AddRes);
            CircuitBinarySub.push_back(Add);

            C[i]=AddRes;
        }

    }

    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitBinarySub;
}
std::vector<std::string> var_binary_mul(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<std::string> CircuitBinaryMul;
    std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
    std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
    std::vector<int> C(B.size());
    for(int i=0;i<A.size();i++){
        if(A[i]==1||B[i]==1){
            C[i]=1;
        }else if(A[i]==0){
            C[i]=B[i];
        }else if(B[i]==0){
            C[i]=A[i];
        }else{
            int MulRes=WireId++;
            std::string Mul = "mul";
            Mul += in_wire(2,A[i],B[i]);
            Mul += out_wire(1,MulRes);
            CircuitBinaryMul.push_back(Mul);
            C[i]=MulRes;
        }
    }

    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitBinaryMul;
}
void const_binary_add(const std::string& InstructionStr, std::vector<std::string> ValueStr,std::vector<std::string> ValueType, int &WireId){
    std::vector<int> C;
    int ConstNumber = 0;
    if(ValueStr[0][0]!='%' && ValueStr[0][1]!='%'){
        if(ConstBinaryNumber.find(ValueStr[0]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }

        }
        if(ConstBinaryNumber.find(ValueStr[1]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }

        }
        std::string BinaryNumber1 = ConstBinaryNumber[ValueStr[0]];
        std::string BinaryNumber2 = ConstBinaryNumber[ValueStr[1]];
        for(int i=0;i<BinaryNumber1.size();i++){
            if(BinaryNumber1[i]==BinaryNumber2[i])
                C.push_back(1);
            else
                C.push_back(0);
        }
    }else if(ValueStr[0][0]!='%'){
        if(ConstBinaryNumber.find(ValueStr[0]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }
        }
        std::string BinaryNumber1 = ConstBinaryNumber[ValueStr[0]];

    }

}
std::vector<std::string> const_binary_mul(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<std::string> CircuitBinaryMul;

    std::vector<int> C;
    int ConstNumber = 0;
    std::string Const;
    if(ValueStr[0][0]!='%'){
        std::stringstream(ValueStr[0]) >> ConstNumber;
        std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
        for(int i : B){
            int ConstMulRes = WireId;
            std::string ConstMul = const_mul(ConstNumber,i, WireId);
            CircuitBinaryMul.push_back(ConstMul);
            C.push_back(ConstMulRes);
        }

    }else{
        std::stringstream(ValueStr[1]) >> ConstNumber;
        std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
        for(int i : A){
            int ConstMulRes = WireId;
            std::string ConstMul = const_mul(ConstNumber,i, WireId);
            CircuitBinaryMul.push_back(ConstMul);
            C.push_back(ConstMulRes);
        }
    }
    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitBinaryMul;
}
std::vector<std::string> const_xor(const std::string& InstructionStr, std::vector<std::string> ValueStr, std::vector<std::string> ValueType, int &WireId){

    std::vector<std::string> CircuitXor;
    std::vector<int> C;
    std::string Const;
    if(ValueStr[0][0]!='%'){
        Const = ValueStr[0];
        if(ConstBinaryNumber.find(ValueStr[0]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }
//            std::bitset<32> bin(std::stoi(ValueStr[0]));
//            ConstBinaryNumber[ValueStr[0]] = bin.to_string();
        }
        std::string BinaryNumber = ConstBinaryNumber[ValueStr[0]];
        std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
        for(int i = 0; i< B.size(); i++){
            if(BinaryNumber[BinaryNumber.size()-1-i]=='0') C.push_back(B[i]);
            else{
                int ConstmulRes=WireId++;
                std::string ConstMul = "const-mul-neg-1";
                ConstMul += in_wire(1,B[i]);
                ConstMul += out_wire(1,ConstmulRes);
                CircuitXor.push_back(ConstMul);

                int AddRes=WireId++;
                std::string Add = "add";
                Add += in_wire(2, 0, ConstmulRes);
                Add += out_wire(1,AddRes);
                CircuitXor.push_back(Add);

                C.push_back(AddRes);
            }
        }
    }else{
        Const = ValueStr[1];
        if(ConstBinaryNumber.find(ValueStr[1]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }
        }
        std::string BinaryNumber = ConstBinaryNumber[ValueStr[1]];
        std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
        for(int i = 0; i< A.size(); i++){
            if(BinaryNumber[BinaryNumber.size()-1-i]=='0') C.push_back(A[i]);
            else{
                int ConstmulRes=WireId++;
                std::string ConstMul = "const-mul-neg-1";
                ConstMul += in_wire(1,A[i]);
                ConstMul += out_wire(1,ConstmulRes);
                CircuitXor.push_back(ConstMul);

                int AddRes=WireId++;
                std::string Add = "add";
                Add += in_wire(2, 0, ConstmulRes);
                Add += out_wire(1,AddRes);
                CircuitXor.push_back(Add);

                C.push_back(AddRes);
            }
        }
    }
    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitXor;
}
void const_or(const std::string& InstructionStr, std::vector<std::string> ValueStr, std::vector<std::string> ValueType, int &WireId){
    std::vector<int> C;
    std::string Const;
    if(ValueStr[0][0]!='%'){
        Const = ValueStr[0];
        if(ConstBinaryNumber.find(ValueStr[0]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }
//            std::bitset<32> bin(std::stoi(ValueStr[0]));
//            ConstBinaryNumber[ValueStr[0]] = bin.to_string();
        }
        std::string BinaryNumber = ConstBinaryNumber[ValueStr[0]];
        std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
        for(int i = 0; i< B.size(); i++){
            if(BinaryNumber[BinaryNumber.size()-1-i]=='0') C.push_back(B[i]);
            else C.push_back(0);
        }
    }else{
        Const = ValueStr[1];
        if(ConstBinaryNumber.find(ValueStr[1]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }
        }
        std::string BinaryNumber = ConstBinaryNumber[ValueStr[1]];
        std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
        for(int i = 0; i< A.size(); i++){
            if(BinaryNumber[BinaryNumber.size()-1-i]=='0') C.push_back(A[i]);
            else C.push_back(0);
        }
    }
    IrToCircuitBinaryNumber[InstructionStr] = C;
}
void const_and(const std::string& InstructionStr, std::vector<std::string> ValueStr, std::vector<std::string> ValueType, int &WireId){
    std::vector<int> C;
    std::string Const;
    if(ValueStr[0][0]!='%'){
        Const = ValueStr[0];
        if(ConstBinaryNumber.find(ValueStr[0]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[0]));
                ConstBinaryNumber[ValueStr[0]] = bin.to_string();
            }
//            std::bitset<32> bin(std::stoi(ValueStr[0]));
//            ConstBinaryNumber[ValueStr[0]] = bin.to_string();
        }
        std::string BinaryNumber = ConstBinaryNumber[ValueStr[0]];
        std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
        for(int i = 0; i< B.size(); i++){
            if(BinaryNumber[BinaryNumber.size()-1-i]=='1') C.push_back(B[i]);
            else C.push_back(1);
        }
    }else{
        Const = ValueStr[1];
        if(ConstBinaryNumber.find(ValueStr[1]) == ConstBinaryNumber.end()){
            if(type==0){
                std::bitset<32> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }else if(type==1){
                std::bitset<8> bin(std::stoi(ValueStr[1]));
                ConstBinaryNumber[ValueStr[1]] = bin.to_string();
            }
        }
        std::string BinaryNumber = ConstBinaryNumber[ValueStr[1]];
        std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
        for(int i = 0; i< A.size(); i++){
            if(BinaryNumber[BinaryNumber.size()-1-i]=='1') C.push_back(A[i]);
            else C.push_back(1);
        }
    }
    IrToCircuitBinaryNumber[InstructionStr] = C;
}
std::vector<std::string> var_xor(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
    std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
    std::vector<int> C(B.size());
    std::vector<std::string> CircuitXor;
    for(size_t i=0;i<A.size();i++){//按位异或 (A+B)-2*(A*B)
        if(A[i]==1){
            C[i]=B[i];
        }else if(B[i]==1){
            C[i]=A[i];
        }else if(A[i]==0){
            int ConstmulRes=WireId++;
            std::string ConstMul = "const-mul-neg-1";
            ConstMul += in_wire(1,B[i]);
            ConstMul += out_wire(1,ConstmulRes);
            CircuitXor.push_back(ConstMul);

            int AddRes=WireId++;
            std::string Add = "add";
            Add += in_wire(2, 0, ConstmulRes);
            Add += out_wire(1,AddRes);
            CircuitXor.push_back(Add);

            C[i] = AddRes;
        }else if(B[i]==0){
            int ConstmulRes=WireId++;
            std::string ConstMul = "const-mul-neg-1";
            ConstMul += in_wire(1,A[i]);
            ConstMul += out_wire(1,ConstmulRes);
            CircuitXor.push_back(ConstMul);

            int AddRes=WireId++;
            std::string Add = "add";
            Add += in_wire(2, 0, ConstmulRes);
            Add += out_wire(1,AddRes);
            CircuitXor.push_back(Add);

            C[i]=AddRes;
        }else{
            //(A+B)
            int AddRes=WireId++;
            std::string Add = "add";
            Add += in_wire(2,A[i],B[i]);
            Add += out_wire(1,AddRes);
            CircuitXor.push_back(Add);
            //(A*B)
            int MulRes=WireId++;
            std::string Mul = "mul";
            Mul += in_wire(2,A[i],B[i]);
            Mul += out_wire(1,MulRes);
            CircuitXor.push_back(Mul);
            //-2*(A*B)
            int ConstmulRes=WireId++;
            std::string ConstMul = "const-mul-neg-2";
            ConstMul += in_wire(1,MulRes);
            ConstMul += out_wire(1,ConstmulRes);
            CircuitXor.push_back(ConstMul);
            //(A+B)+(-2*(A*B))
            int ResultBinary=WireId++;
            std::string Result = "add";
            Result += in_wire(2,AddRes,ConstmulRes);
            Result += out_wire(1,ResultBinary);
            CircuitXor.push_back(Result);

            //save binary result
            C[i]=ResultBinary;
        }

    }
    IrToCircuitBinaryNumber[InstructionStr] = C;

    return CircuitXor;
}

std::vector<std::string> var_or(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
    std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
    std::vector<int> C(B.size());
    std::vector<std::string> CircuitOr;

    for(size_t i=0; i<A.size(); i++){//按位或 (A+B)-(A*B)
        if(A[i]==1){
            C[i]=B[i];
        }else if(B[i]==1){
            C[i]=A[i];
        }else if(A[i]==0||B[i]==0){
            C[i]=0;
        }else{
            //(A+B)
            int AddRes=WireId++;
            std::string Add = "add";
            Add += in_wire(2,A[i],B[i]);
            Add += out_wire(1,AddRes);
            CircuitOr.push_back(Add);

            //(A*B)
            int MulRes=WireId++;
            std::string Mul = "mul";
            Mul += in_wire(2,A[i],B[i]);
            Mul += out_wire(1,MulRes);
            CircuitOr.push_back(Mul);

            //-1*(A*B)
            int ConstmulRes=WireId++;
            std::string ConstMul = "const-mul-neg-1";
            ConstMul += in_wire(1,MulRes);
            ConstMul += out_wire(1,ConstmulRes);
            CircuitOr.push_back(ConstMul);

            //((A+B)+(-1*(A*B))
            int ResultBinary=WireId++;
            std::string Result = "add";
            Result += in_wire(2,AddRes,ConstmulRes);
            Result += out_wire(1,ResultBinary);
            CircuitOr.push_back(Result);

            C[i]=ResultBinary;
        }

    }

    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitOr;
}

std::vector<std::string> var_and(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){
    std::vector<int> A(IrToCircuitBinaryNumber[ValueStr[0]]);
    std::vector<int> B(IrToCircuitBinaryNumber[ValueStr[1]]);
    std::vector<int> C(B.size());
    std::vector<std::string> CircuitAnd;
//    std::cout<<"testor1\n";
//    std::cout<<A.size()<<"  "<<B.size()<<"\n";
    for(size_t i=0; i<A.size(); i++){//按位与 (A*B)
        if(A[i]==1||B[i]==1){
            C[i]=1;
        }else if(A[i]==0){
            C[i]=B[i];
        }else if(B[i]==0){
            C[i]=A[i];
        }else{
            //(A*B)
            int MulRes=WireId++;
            std::string Mul = "mul";
            Mul += in_wire(2,A[i],B[i]);
            Mul += out_wire(1,MulRes);
            CircuitAnd.push_back(Mul);

            C[i]=MulRes;
        }


    }
//    std::cout<<"testor3\n";
    IrToCircuitBinaryNumber[InstructionStr] = C;
    return CircuitAnd;
}

void var_shl(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){//left

//    std::cout << "test shl 2\n";

    // 安全转换字符串到整数
    char* end;
    long len = std::strtol(ValueStr[1].c_str(), &end, 10);
    if (*end != '\0' || len < 0) {
        std::cerr << "Invalid shift length: " << ValueStr[1] << std::endl;
        return;
    }

    std::vector<int> A = IrToCircuitBinaryNumber[ValueStr[0]];
    std::vector<int> C(A.size(), 0); // 确保C初始化为0

//    std::cout << "test shl 3\n";

    if (len >= A.size()) {
        std::cerr << "Shift length exceeds vector size." << std::endl;
        return;
    }

    for(int i = A.size() - 1; i >= len; i--) {
        C[i] = A[i - len];
    }

//    std::cout << "test shl 4\n";

    for(int i = len - 1; i >= 0; i--) {
        C[i] = 1;
    }

//    std::cout << "test shl 5\n";

    IrToCircuitBinaryNumber[InstructionStr] = C;
}
void var_lshr(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireId){//right
    char* end;
    long len = std::strtol(ValueStr[1].c_str(), &end, 10);
    if (*end != '\0' || len < 0) {
        std::cerr << "Invalid shift length: " << ValueStr[1] << std::endl;
        return;
    }

    // 获取输入的二进制数
    std::vector<int> A = IrToCircuitBinaryNumber[ValueStr[0]];
    std::vector<int> C(A.size(), 0); // 确保 C 初始化为 0

    // 检查 shift 长度是否超出数组 A 的大小
    if (len >= A.size()) {
        std::cerr << "Shift length exceeds vector size." << std::endl;
        return;
    }

    // 第一个循环：将 A 中的值移到 C
    for (int i = A.size() - len - 1; i >= 0; i--) {
        C[i] = A[i + len];
    }

    // 第二个循环：将 C 的剩余部分填充为 电路线 1
    for (int i = A.size() - 1; i >= A.size() - len; i--) {
        C[i] = 1;
    }

    // 将结果存回 IrToCircuitBinaryNumber
    IrToCircuitBinaryNumber[InstructionStr] = C;
}

std::string var_zerop(const int& instructionWire, int &WireId){//用于检测输入是否为0   输出结果不为0返回1,为0则返回0
    std::string Zero = "zerop";
    Zero += in_wire(1, instructionWire);
    std::vector<int> ZeroNumber(2);
    ZeroNumber[0] = WireId++;
    ZeroNumber[1] = WireId++;
    Zero += out_wirearry(2,ZeroNumber);
    return Zero;
}
std::vector<std::string> var_eq(const std::string& InstructionStr, std::vector<std::string> &ValueStr, int &EqWireNumber){
    std::string EqWire;
    std::vector<std::string> EqCircuit;
    IrToCircuitNumber["neg " + ValueStr[1]] = EqWireNumber;
    EqWire = const_mul(1, IrToCircuitNumber[ValueStr[1]], EqWireNumber, true);
    EqCircuit.push_back(EqWire);
    ValueStr[1] = "neg " + ValueStr[1];

    std::string Add = "add";
    int AddWire = EqWireNumber++;
    Add += in_wire(2, IrToCircuitNumber[ValueStr[0]], IrToCircuitNumber[ValueStr[1]]);
    Add += out_wire(1, AddWire);
    EqCircuit.push_back(Add);

    int ZeroRs = EqWireNumber+1;
    EqWire = var_zerop(AddWire,EqWireNumber);
    EqCircuit.push_back(EqWire);

    int ConstMul = EqWireNumber;
    EqWire = const_mul(1, ZeroRs, EqWireNumber, true);
    EqCircuit.push_back(EqWire);

    //result
    std::string Res = "add";
    IrToCircuitNumber[InstructionStr] = EqWireNumber++;
    Res += in_wire(2, 0, ConstMul);
    Res += out_wire(1, IrToCircuitNumber[InstructionStr]);
    EqCircuit.push_back(Res);

    return EqCircuit;
}
std::vector<std::string> var_neq(const std::string& InstructionStr, std::vector<std::string> &ValueStr, int &NeqWireNumber){
    std::string NeqWire;
    std::vector<std::string> NeqCircuit;
    IrToCircuitNumber["neg " + ValueStr[1]] = NeqWireNumber;
    NeqWire = const_mul(1, IrToCircuitNumber[ValueStr[1]], NeqWireNumber, true);
    NeqCircuit.push_back(NeqWire);
    ValueStr[1] = "neg " + ValueStr[1];

    std::string Add = "add";
    int AddWire = NeqWireNumber++;
    Add += in_wire(2, IrToCircuitNumber[ValueStr[0]], IrToCircuitNumber[ValueStr[1]]);
    Add += out_wire(1, AddWire);
    NeqCircuit.push_back(Add);

    int ZeroRs = NeqWireNumber+1;
    NeqWire = var_zerop(AddWire,NeqWireNumber);
    NeqCircuit.push_back(NeqWire);
    IrToCircuitNumber[InstructionStr] = ZeroRs;

//    int ConstMul = EqWireNumber;
//    EqWire = const_mul(1, ZeroRs, EqWireNumber, true);
//    EqCircuit.push_back(EqWire);
//
//    //result
//    std::string Res = "add";
//    IrToCircuitNumber[InstructionStr] = EqWireNumber++;
//    Res += in_wire(2, 0, ConstMul);
//    Res += out_wire(1, IrToCircuitNumber[InstructionStr]);
//    EqCircuit.push_back(Res);

    return NeqCircuit;
}
std::vector<std::string> var_select(const std::string& InstructionStr, std::vector<std::string> &ValueStr, int &SelectWireNumber){
    std::string SelectWire;
    std::vector<std::string> SelectCircuit;

    std::string MulFr = "mul";
    int MulWireFr = SelectWireNumber++;
    MulFr += in_wire(2,IrToCircuitNumber[ValueStr[0]],IrToCircuitNumber[ValueStr[1]]);
    MulFr += out_wire(1,MulWireFr);
    SelectCircuit.push_back(MulFr);

    int  ConstMulNegOne = SelectWireNumber;
    SelectWire = const_mul(1, IrToCircuitNumber[ValueStr[0]], SelectWireNumber, true);
    SelectCircuit.push_back(SelectWire);

    std::string Add = "add";
    int AddWire = SelectWireNumber++;
    Add += in_wire(2, ConstMulNegOne, 0);
    Add += out_wire(1, AddWire);
    SelectCircuit.push_back(Add);

    std::string MulSe = "mul";
    int MulWireSe = SelectWireNumber++;
    MulSe += in_wire(2, AddWire, IrToCircuitNumber[ValueStr[2]]);
    MulSe += out_wire(1, MulWireSe);
    SelectCircuit.push_back(MulSe);

    std::string Rs = "add";
    int RsWire = SelectWireNumber++;
    Rs += in_wire(2, MulWireFr, MulWireSe);
    Rs += out_wire(1, RsWire);
    SelectCircuit.push_back(Rs);

    IrToCircuitNumber[InstructionStr] = RsWire;

    return SelectCircuit;
}
std::vector<std::string> LinearScan(const std::string& InstructionStr, std::vector<std::string> ValueStr, int &WireNumber){
    std::vector<std::string> LinearScanCircuit;
    std::string LinearScanWire;
    int AdrNumber = IrToCircuitNumber[PtrAddress[ValueStr[0]].second];
    int TotNumber;
    int num = Ptr[PtrAddress[ValueStr[0]].first].size();
    for(int i = 0; i < num; i++){
        int ZeroRs = WireNumber+1;
        LinearScanWire = var_zerop(AdrNumber,WireNumber);
        LinearScanCircuit.push_back(LinearScanWire);
//        std::cout<<"test ls1\n";

        int ConstMul = WireNumber;
        LinearScanWire = const_mul(1, ZeroRs, WireNumber, true);
        LinearScanCircuit.push_back(LinearScanWire);
//        std::cout<<"test ls2\n";
        //zerop result
        std::string Res = "add";
//        IrToCircuitNumber[InstructionStr] = WireNumber++;
        int ResNumber = WireNumber;
        Res += in_wire(2, 0, ConstMul);
        Res += out_wire(1, WireNumber++);
        LinearScanCircuit.push_back(Res);

//        std::cout<<"test ls3\n";

        std::string Mul = "mul";
        int MulNumber = WireNumber;
        int inputNumber = AddressWireNumber[PtrAddress[ValueStr[0]].first+" "+std::to_string(i)];
        Mul += in_wire(2,ResNumber,inputNumber);
        Mul += out_wire(1,WireNumber++);
        LinearScanCircuit.push_back(Mul);

//        std::cout<<"test ls4\n";

        if(i==0){
            TotNumber = MulNumber;

            //遍历下一个位置
            std::string NextAdr = "add";
            int NegOneWire;
            if(!IrToCircuitNumber.count("-1")){
                IrToCircuitNumber["-1"] = WireNumber;
                LinearScanCircuit.push_back(const_mul(-1,0,WireNumber));
            }
            NegOneWire = IrToCircuitNumber["-1"];

            NextAdr += in_wire(2,AdrNumber,NegOneWire);
            NextAdr += out_wire(1,WireNumber);
            LinearScanCircuit.push_back(NextAdr);
            AdrNumber = WireNumber++;


        }else if(i!=num-1){
            std::string TotAdd = "add";
            int TotAddNumber = WireNumber;
            TotAdd += in_wire(2, TotNumber, MulNumber);
            TotAdd += out_wire(1,WireNumber++);
            LinearScanCircuit.push_back(TotAdd);

            //遍历下一个位置
            std::string NextAdr = "add";
            int NegOneWire;
            if(!IrToCircuitNumber.count("-1")){
                IrToCircuitNumber["-1"] = WireNumber;
                LinearScanCircuit.push_back(const_mul(-1,0,WireNumber));
            }
            NegOneWire = IrToCircuitNumber["-1"];

            NextAdr += in_wire(2,AdrNumber,NegOneWire);
            NextAdr += out_wire(1,WireNumber);
            LinearScanCircuit.push_back(NextAdr);
            AdrNumber = WireNumber++;
            TotNumber = TotAddNumber;
        }else{
            std::string TotAdd = "add";
            int TotAddNumber = WireNumber;
            TotAdd += in_wire(2, TotNumber, MulNumber);
            TotAdd += out_wire(1,WireNumber++);
            LinearScanCircuit.push_back(TotAdd);


            IrToCircuitNumber[InstructionStr] = TotAddNumber;
        }

    }
    return LinearScanCircuit;
}

int nextPoewrOfTwo(int x){
    int power=0;
    while((1<<power)<=x) power++;
    return power;
}
std::vector<std::string> RomCheck(const std::string& InstructionStr, const int MaxValue,const int times, std::vector<std::string> ValueStr,const int NizkWire,int &WireNumber){
    std::vector<std::string> RomCheckCircuit;
    std::string RomCheckWire;
    int len=32;
    int nizkinput = CircuitNumberValue[IrToCircuitNumber[PtrAddress[ValueStr[0]].second]];
    auto ConstVector = Ptr[PtrAddress[ValueStr[0]].first];
    auto n = ConstVector.size();
    auto num = std::sqrt(n);
//    auto maxIt = std::max_element(ConstVector.begin(), ConstVector.end());
//    auto MaxValue = *maxIt;

//    std::cout<<"test Rom "<<n<<" "<<num<<"\n";

    //范围检测 0<b<maxValue(ConstArray) 位分解  n为2的幂次
    std::string Split = "split";
    std::vector<int> binary(len);
    for(auto i=0;i<len;i++){
        binary[i]=WireNumber++;
    }
    Split += in_wire(1,NizkWire);
    Split += out_wirearry(len,binary);
    RomCheckCircuit.push_back(Split);

    int NewBWire = 1;
    int pow=1;
    for(int i=0;i<times;i++){
        int  Powb=WireNumber;
        RomCheckWire = const_mul(pow,binary[i],WireNumber);
        RomCheckCircuit.push_back(RomCheckWire);

        std::string Result = "add";
        int ResultNumber = WireNumber;
        Result += in_wire(2,Powb,NewBWire);
        Result += out_wire(1,WireNumber++);
        RomCheckCircuit.push_back(Result);

        NewBWire=ResultNumber;
        pow *=2;
    }

    //计算唯一标识符z_i = b+n*a
    int MulNumber=WireNumber;
    RomCheckWire = const_mul(MaxValue,IrToCircuitNumber[PtrAddress[ValueStr[0]].second],WireNumber);
    RomCheckCircuit.push_back(RomCheckWire);

    std::string Z_i="add";
    int Z_iNUmber = WireNumber;
//    Z_i += in_wire(2,NizkWire,MulNumber);
    Z_i += in_wire(2,NewBWire,MulNumber);
    Z_i += out_wire(1,WireNumber++);
    RomCheckCircuit.push_back(Z_i);

    //预计算z_i 到 z_i^(根n)
    std::vector<int> Z_iWireNumber(num);
    Z_iWireNumber[0]=0;
    Z_iWireNumber[1]=Z_iNUmber;
    for(auto i=2;i<num;i++){
        std::string Mul = "mul";
        int Z_iMulNumber = WireNumber;
        Mul += in_wire(2,Z_iWireNumber[i-1],Z_iNUmber);
        Mul += out_wire(1,WireNumber++);
//        std::cout<<Z_iMulNumber<<" ";
        Z_iWireNumber[i]=Z_iMulNumber;
        RomCheckCircuit.push_back(Mul);
    }
//    std::cout<<"\n";
    //循环多项式求值 计算P_K(z)
//    std::cout<<"ValueStr: "<<PtrAddress[ValueStr[0]].first<<"\n";

    auto CijVector = ConstCji[PtrAddress[ValueStr[0]].first]; //获取所有的系数值
//    std::vector<int> MulWire(num);
    int mulWireNumber = 0;
    for(const auto& groups : CijVector){
        int addWireNumber = 1;
        for(size_t j=0;j<num;j++){//乘法
            int CijMulNumber = WireNumber;
//            MulWire[j]=WireNumber;
            RomCheckWire = const_mul(groups[j],Z_iWireNumber[j],WireNumber);
            RomCheckCircuit.push_back(RomCheckWire);

            int CijAddWire = WireNumber;
            std::string Add="add";
            Add += in_wire(2,addWireNumber,CijMulNumber);
            Add += out_wire(1,WireNumber++);
            addWireNumber = CijAddWire;

            RomCheckCircuit.push_back(Add);
        }
        int  checkMulNumber = WireNumber;
        std::string Mul = "mul";
        Mul += in_wire(2,mulWireNumber,addWireNumber);
        Mul += out_wire(1,WireNumber++);
        mulWireNumber = checkMulNumber;
        RomCheckCircuit.push_back(Mul);
    }


    //验证结果 断言P_k(z) = 0
    std::string Check="assert";
    Check += in_wire(2,mulWireNumber,0);
    Check += out_wire(1,1);
    RomCheckCircuit.push_back(Check);

    std::string RomResult = "mul";
    int RomResultNumber = WireNumber;
//    RomResult += in_wire(2,NizkWire,0);
    RomResult += in_wire(2,NewBWire,0);
    RomResult += out_wire(1,WireNumber++);
    RomCheckCircuit.push_back(RomResult);

    IrToCircuitNumber[InstructionStr] = RomResultNumber;


    return RomCheckCircuit;
}
//只读内存 系数计算
void coeff_cal(std::string &ConstName,const int MaxValue, const std::vector<int> &ConstArray){
    auto n = ConstArray.size();
//    auto maxIt = std::max_element(ConstArray.begin(), ConstArray.end());
//    auto MaxValue = *maxIt;
    //step 1 生成唯一的标识符z_i = value + n * index
    std::vector<int> z_values;
    for(size_t i = 0; i < ConstArray.size(); i++){
        z_values.push_back(ConstArray[i]+ MaxValue * i);
    }
//    std::cout<<"生成的唯一标识符z_i: ";
//    for(auto z:z_values) std::cout<< z << " ";
//    std::cout<<"\n";

    //step 2 分组(组大小 = sqrt(n))
    size_t group_size = std::sqrt(n);
    std::vector<std::vector<int>> groups;
    std::vector<int> current_group;
    for(auto z : z_values) {
        current_group.push_back(z);
        if(current_group.size() == group_size){
            groups.push_back(current_group);
            current_group.clear();
        }
    }
    if(!current_group.empty()){
        groups.push_back(current_group);
    }

    //step 3 计算每组的多项式系数
    std::vector<std::vector<int>> all_coeff;
    for(const auto& group : groups){
        std::vector<int> coeffs = {1};
        for(auto z_k : group){
            std::vector<int>  new_coeffs(coeffs.size()+1,0);
            for(size_t i = 0; i < coeffs.size(); i++){
                new_coeffs[i] += coeffs[i] * (-z_k);
                new_coeffs[i+1] += coeffs[i];
            }
            coeffs = std::move(new_coeffs);
        }
        all_coeff.push_back(coeffs);

//        std::cout<<"\n组 根：";
//        for(auto z : group) std::cout<< z << " ";
//        std::cout<< "\n 多项式系数（从 c0到c）"<< coeffs.size()-1 <<"):";
//        for(auto c: coeffs) std::cout<< c<< " ";
//        std::cout<<"\n";
    }

    ConstCji[ConstName] = all_coeff;

}
std::vector<std::string> const_input(const std::string& InstructionStr){

}
/*
 * 针对排序算法的约束优化
 * 传统方式即用电路模拟合并排序的步骤，时间复杂度为O(n^2),且约束数量较多
 * 所以我们改变思路，不再去模拟排序的步骤，而是调用外部代码进行排序，然后用电路去实现排序验证。
 * 排序验证分为两部分
 * 1.排序后的序列是未排序的序列的一个置换，该部分使用置换网络去实现
 * 2.排序后的序列是单调不下降/单调不上升的
 */

//构造置换网络
std::vector<std::pair<int, int>> Network(int n, int j = 0) {
    if (n <= 1)
        return {};
    int k = n / 2;
    int lbitn = n / 2;
    int rbitn = n / 2 + (n % 2) - 1;
    std::vector<std::pair<int, int>> net;
    // 输入阶段交换器
    for (int i = 0; i < lbitn; i++) {
        net.emplace_back(j + i, j + i + k);
    }
    // 递归构造上半部分和下半部分子网络
    std::vector<std::pair<int, int>> upperNet = Network(k, j);
    net.insert(net.end(), upperNet.begin(), upperNet.end());
    std::vector<std::pair<int, int>> lowerNet = Network(n - k, j + k);
    net.insert(net.end(), lowerNet.begin(), lowerNet.end());
    // 输出阶段交换器
    for (int i = 0; i < rbitn; i++) {
        net.emplace_back(j + i, j + i + k);
    }
    return net;
}
//控制比特生成
std::vector<int> GenBits(const std::vector<int>& lft, const std::vector<int>& rgt, bool no_rec = false) {
    int n = std::min(lft.size(), rgt.size());
    if (n <= 1)
        return {};
    int k = n / 2;
    int lbitn = n / 2;
    int rbitn = n / 2 + (n % 2) - 1;

    // 根据 lft 和 rgt 生成查找表
    std::vector<int> ls(n), rs(n);
    std::iota(ls.begin(), ls.end(), 0);
    std::iota(rs.begin(), rs.end(), 0);
    std::sort(ls.begin(), ls.end(), [&](int a, int b) { return lft[a] < lft[b]; });
    std::sort(rs.begin(), rs.end(), [&](int a, int b) { return rgt[a] < rgt[b]; });
    std::vector<int> l2r(n, -1), r2l(n, -1);
    for (int i = 0; i < n; i++) {
        int l = ls[i];
        int r = rs[i];
        l2r[r] = l;
        r2l[l] = r;
    }

    // 初始化左右比特，-1 表示未设置
    std::vector<int> lbits(lbitn, -1);
    std::vector<int> rbits(rbitn, -1);

    // 根据 n 的奇偶性分别生成比特
    if (n % 2 == 0) {
        int l = n - 1;
        int r = l2r[l];
        while (true) {
            lbits[r % k] = (r < k) ? 1 : 0;
            r = (r < k) ? (r + k) : (r - k);
            l = r2l[r];
            if (l == k - 1)
                break;
            rbits[l % k] = (l < k) ? 0 : 1;
            l = (l < k) ? (l + k) : (l - k);
            r = l2r[l];
        }
    } else {
        int l = n - 1;
        int r = l2r[l];
        while (true) {
            if (r == n - 1)
                break;
            lbits[r % k] = (r < k) ? 1 : 0;
            r = (r < k) ? (r + k) : (r - k);
            l = r2l[r];
            rbits[l % k] = (l < k) ? 0 : 1;
            l = (l < k) ? (l + k) : (l - k);
            r = l2r[l];
        }
    }

    // 补充未生成的比特（rbits 中仍为 -1 的部分）
    while (true) {
        int idx = -1;
        for (int j = rbitn - 1; j >= 0; j--) {
            if (rbits[j] == -1) {
                idx = j;
                break;
            }
        }
        if (idx == -1)
            break;
        int l_val = idx + k;
        int r_val = l2r[l_val];
        while (true) {
            lbits[r_val % k] = (r_val < k) ? 1 : 0;
            r_val = (r_val < k) ? (r_val + k) : (r_val - k);
            l_val = r2l[r_val];
            rbits[l_val % k] = (l_val < k) ? 0 : 1;
            l_val = (l_val < k) ? (l_val + k) : (l_val - k);
            r_val = l2r[l_val];
            if (l_val == idx + k)
                break;
        }
    }

    if (no_rec) {
        std::vector<int> ret;
        ret.insert(ret.end(), lbits.begin(), lbits.end());
        ret.insert(ret.end(), rbits.begin(), rbits.end());
        return ret;
    }

    // 对左右部分应用交换：根据 lbits 对左侧排列进行局部交换
    std::vector<int> ulft(lft.begin(), lft.begin() + k);
    std::vector<int> dlft(lft.begin() + k, lft.end());
    for (int i = 0; i < lbitn; i++) {
        if (lbits[i] != 0)  // 若为 1，则交换
            std::swap(ulft[i], dlft[i]);
    }
    std::vector<int> urgt(rgt.begin(), rgt.begin() + k);
    std::vector<int> drgt(rgt.begin() + k, rgt.end());
    for (int i = 0; i < rbitn; i++) {
        if (rbits[i] != 0)
            std::swap(urgt[i], drgt[i]);
    }
    // 递归生成上半部分和下半部分的控制比特
    std::vector<int> ubits = GenBits(ulft, urgt);
    std::vector<int> dbits = GenBits(dlft, drgt);
    // 连接 lbits、ubits、dbits 和 rbits 后返回
    std::vector<int> result;
    result.insert(result.end(), lbits.begin(), lbits.end());
    result.insert(result.end(), ubits.begin(), ubits.end());
    result.insert(result.end(), dbits.begin(), dbits.end());
    result.insert(result.end(), rbits.begin(), rbits.end());
    return result;
}
//置换正确性验证
ModuleInformation permutation_network_verify(const std::string& InstructionStr,int &WireNumber,std::vector<int>& unsortedArray,const std::vector<int>& sortedArray,const std::vector<int>& sortedArrayWire){
    std::vector<std::string> PermutationCircuit;
    std::vector<std::string> PermutationWitness;
    std::string PermutationWitnessNumber;
    std::string PermutationWire;
    int n=unsortedArray.size();
    //构造置换网络
    auto net = Network(n);
//    std::cout << "Network connections:" << std::endl;
//    for (const auto &p : net) {
//        std::cout << "(" << p.first << ", " << p.second << ")" << std::endl;
//    }
    //生成控制位
    auto bits = GenBits(unsortedArray, sortedArray);

//    std::cout << "\nControl bits:" << std::endl;
//    for (auto bit : bits) {
//        std::cout << bit << " ";
//    }
//    std::cout << "\n";

    std::vector<int> src(unsortedArray);
    std::vector<int> unsortedWireNumber;

    for(int i=0;i<unsortedArray.size();i++){
        int UnWireNumber = AddressWireNumber[InstructionStr+" "+std::to_string(i)];
        unsortedWireNumber.push_back(UnWireNumber);
    }


    for (size_t i = 0; i < net.size() && i < bits.size(); i++) {
        int LWireNumber = AddressWireNumber[InstructionStr+" "+std::to_string(net[i].first)];
        int RWireNumber = AddressWireNumber[InstructionStr+" "+std::to_string(net[i].second)];

        int NizkInputNumber = WireNumber;
        if (bits[i]){
            PermutationWitnessNumber = std::to_string(WireNumber) +" "+ std::to_string(CircuitNumberValue[RWireNumber]);
            PermutationWire = "nizkinput " + std::to_string(WireNumber++);

            std::swap(src[net[i].first], src[net[i].second]);
        }else{
            PermutationWitnessNumber = std::to_string(WireNumber) +" "+ std::to_string(CircuitNumberValue[LWireNumber]);
            PermutationWire = "nizkinput " + std::to_string(WireNumber++);
        }
        PermutationWitness.push_back(PermutationWitnessNumber);
        PermutationCircuit.push_back(PermutationWire);

        //-----------------------------------------------------电路约束
        //a0+a1
        std::string Add = "add";
        int AddWireNumber = WireNumber;
        Add += in_wire(2,LWireNumber,RWireNumber);
        Add += out_wire(1,WireNumber++);
        PermutationCircuit.push_back(Add);
        //-x0
        int NegWireNumber = WireNumber;
        PermutationWire = const_mul(-1,NizkInputNumber,WireNumber);
        PermutationCircuit.push_back(PermutationWire);
        //a0-x0
        std::string Add0 = "add";
        int AddWireNumber0 = WireNumber;
        Add0 += in_wire(2,LWireNumber,NegWireNumber);
        Add0 += out_wire(1,WireNumber++);
        PermutationCircuit.push_back(Add0);
        //a1-x0
        std::string Add1 = "add";
        int AddWireNumber1 = WireNumber;
        Add1 += in_wire(2,RWireNumber,NegWireNumber);
        Add1 += out_wire(1,WireNumber++);
        PermutationCircuit.push_back(Add1);
        //assert x0=a0/a1
        std::string Check="assert";
        Check += in_wire(2,AddWireNumber0,AddWireNumber1);
        Check += out_wire(1,1);
        PermutationCircuit.push_back(Check);
        //result x1=a0+a1-x0
        std::string Result ="add";
        int ResultWireNumber = WireNumber;
        Result += in_wire(2,AddWireNumber,NegWireNumber);
        Result += out_wire(1,WireNumber++);
        PermutationCircuit.push_back(Result);

        AddressWireNumber[InstructionStr+" "+std::to_string(net[i].first)] = NizkInputNumber;
        AddressWireNumber[InstructionStr+" "+std::to_string(net[i].second)] = ResultWireNumber;

        CircuitNumberValue[NizkInputNumber] = src[net[i].first];
        CircuitNumberValue[ResultWireNumber] = src[net[i].second];
//
    }
    //置换前后一一断言是否相等
//    for(int i=0;i<unsortedWireNumber.size();i++){
//        std::string Check="assert";
//        Check += in_wire(2,AddWireNumber0,AddWireNumber1);
//        Check += out_wire(1,1);
//        PermutationCircuit.push_back(Check);
//
//
//    }



//    for(int i : src){
//        std::cout<<i<<" ";
//    }
//    std::cout<<"\n";

//    for(int i=0;i<src.size();i++){
//        std::cout<<AddressWireNumber[InstructionStr+" "+std::to_string(i)]<<" "<<CircuitNumberValue[AddressWireNumber[InstructionStr+" "+std::to_string(i)]]<<"\n";
//    }
//    std::cout<<"\n";

    ModuleInformation Permutation;
    Permutation.Circuit=PermutationCircuit;
    Permutation.Witness=PermutationWitness;



    return Permutation;
}
//有序性验证
std::vector<std::string> OrderlinessVerify(const std::vector<int>& sortWire,int &WireNumber){
    std::vector<std::string> OrderlinessCircuit;
    std::string OrderlinessWire;
    int MaxNum = 65536;
    int len = 17;
    if(!IrToCircuitNumber.count(std::to_string(MaxNum))){
        IrToCircuitNumber[std::to_string(MaxNum)] = WireNumber;
        OrderlinessWire = const_mul(MaxNum, 0, WireNumber);
        OrderlinessCircuit.push_back(OrderlinessWire);
    }
    int ConstWire = IrToCircuitNumber[std::to_string(MaxNum)];

    //a[i]<=a[i+1]
    for(int i=0;i<sortWire.size()-1;i++){
        //a[i+1]+MaxNum
        std::string Add ="add";
        int AddNumber = WireNumber;
        Add += in_wire(2,ConstWire,sortWire[i+1]);
        Add += out_wire(1,WireNumber++);
        OrderlinessCircuit.push_back(Add);

        //-a[i]
        int NegNumber = WireNumber;
        OrderlinessWire = const_mul(-1, sortWire[i], WireNumber);
        OrderlinessCircuit.push_back(OrderlinessWire);

        //a[i+1]+MaxNum-a[i]
        std::string Result = "add";
        int ResultNumber = WireNumber;
        Result += in_wire(2,AddNumber,NegNumber);
        Result += out_wire(1,WireNumber++);
        OrderlinessCircuit.push_back(Result);

        //位分解
        std::string Split = "split";
        std::vector<int> binary(len);
        for(auto i=0;i<len;i++){
            binary[i]=WireNumber++;
        }
        Split += in_wire(1,ResultNumber);
        Split += out_wirearry(len,binary);
        OrderlinessCircuit.push_back(Split);

        //检测位分解的最高位是否为1,如果为1则a[i]<=a[i+1]，反之a[i]>a[i+1]
        std::string Check = "assert";
        Check += in_wire(2,binary[len-1],0);
        Check += out_wire(1,0);
        OrderlinessCircuit.push_back(Check);

    }

    return OrderlinessCircuit;

}

std::vector<std::string>  CallFunction(llvm::CallInst *callInst, llvm::Function *calledFunction, int &CallWireNumber,const std::string& Instruction,const bool flag){//暂时只考虑单层函数调用情况 flag用于表示是否所有操作均为按位操作

    std::vector<std::string> CircuitCall;
    std::string CallWire;
    std::string CallWitnessNumber;
    std::string CallInstructionStr;
    std::vector<std::string> CallValueStr;
    std::vector<std::string> CallValueType;
    std::vector<std::string> CallCircuitBinary;



    std::unordered_map<std::string, std::string> paramMapping;
    std::string title;
    if (calledFunction && callInst) {
        // 遍历函数定义中的形参
        title += calledFunction->getName().str();
        int idx = 0;
        for (auto &arg : calledFunction->args()) {
              std::string par = "%"+std::to_string(idx);
//            std::string paramName = arg.getName().str();  // 获取形参名称
            llvm::Value *callArg = callInst->getArgOperand(idx);  // 获取实际参数
            std::string actualParam;
            std::string actualParamType;
            // 获取实际参数名称
            llvm::raw_string_ostream CallStrStream(actualParam);
            callArg->printAsOperand(CallStrStream, false);

            llvm::Type *CallOperandType = callArg->getType();
            llvm::raw_string_ostream OperandStrStream(actualParamType);
            CallOperandType->print(OperandStrStream, false);
            // 将形参和实际参数映射起来
            paramMapping[par] = actualParam;
            if(flag){
                if(actualParam[0]!='%'){
                    if(ConstBinaryNumber.find(actualParam) == ConstBinaryNumber.end()){
                        if(actualParamType=="i8"){
                            std::bitset<8> bin(std::stoi(actualParam));
                            ConstBinaryNumber[actualParam] = bin.to_string();
                        }else if(actualParamType=="i32"){
                            std::bitset<32> bin(std::stoi(actualParam));
                            ConstBinaryNumber[actualParam] = bin.to_string();
                        }

                    }
                    std::string BinaryNumber = ConstBinaryNumber[actualParam];
                    std::vector<int> C(BinaryNumber.size());
                    for(int i=0;i<BinaryNumber.size();i++) if(BinaryNumber[i]=='0') C[i]=1;else C[i]=0;
                    IrToCircuitBinaryNumber[actualParam] = C;
                }else{
                    if(IrToCircuitBinaryNumber.find(actualParam) == IrToCircuitBinaryNumber.end()){
                        if(actualParamType=="i32")
                            CallWire = split(actualParam,32,CallWireNumber);
                        else if(actualParamType=="i8")
                            CallWire = split(actualParam,8,CallWireNumber);
                        CircuitCall.push_back(CallWire);
                    }

                }
            }
            title += actualParam;
            idx++;
//            std::cout<<"param:"<<par<<" "<<actualParam<<"\n";
        }

//        std::cout<<"idx = "<<idx<<"\n";
        // 输出映射关系
//        std::cout << "Parameter Mapping:\n";
//        for (const auto &entry : paramMapping) {
//            std::cout << "Function Param: " << entry.first << " <== Call Argument: " << entry.second << "\n";
//        }
    }
//    std::cout<<"title: "<< title<<"\n";



    int CallConstNumber=0;
    CallValueStr.resize(2);
    CallValueType.resize(2);
    for (llvm::BasicBlock &BB : *calledFunction) {
        // 遍历基本块中的每一条指令
        for (llvm::Instruction &I : BB) {
            // 输出指令的字符串表示
            llvm::Instruction *Ins = &I;
            llvm::raw_string_ostream InstructionStrStream(CallInstructionStr);
            Ins->printAsOperand(InstructionStrStream, false);
            CallInstructionStr += title;
//            std::cout << "Instruction: " << CallInstructionStr << "\n";

//            llvm::outs() << "Instruction Opcode: " << Ins->getOpcodeName() << "\n";
//
//            llvm::outs() << " Number of Operands: " << Ins->getNumOperands() << "\n\n";
            auto num = Ins->getNumOperands();
            CallValueStr.resize(num);
            CallValueType.resize(num);
            for(auto OpIdx = 0; OpIdx < Ins->getNumOperands(); ++OpIdx){
                llvm::Value *Operand = Ins->getOperand(OpIdx);
                llvm::raw_string_ostream CallValueStrStream(CallValueStr[OpIdx]);
                Operand->printAsOperand(CallValueStrStream, false);


                llvm::Type *CallOperandType = Operand->getType();

                llvm::raw_string_ostream OperandStrStream(CallValueType[OpIdx]);
                CallOperandType->print(OperandStrStream, false);

                if(!llvm::isa<llvm::GetElementPtrInst>(Ins) && CallValueStr[OpIdx][0]!='%' && !IrToCircuitNumber.count(CallValueStr[OpIdx])){

                    std::stringstream(CallValueStr[OpIdx]) >> CallConstNumber;

                    IrToCircuitNumber[CallValueStr[OpIdx]] = CallWireNumber;

                    CallWire = const_mul(CallConstNumber, 0, CallWireNumber);
                    CircuitCall.push_back(CallWire);
                }else{
                    if(paramMapping.find(CallValueStr[OpIdx])!=paramMapping.end()){
                        CallValueStr[OpIdx] = paramMapping[CallValueStr[OpIdx]];
                    }else{
                        CallValueStr[OpIdx] += title;
                    }

                }
            }
            if(llvm::isa<llvm::GetElementPtrInst>(Ins)){
                PtrAddress[CallInstructionStr] = std::make_pair(CallValueStr[0], CallValueStr[1]);
            }
            else if(llvm::isa<llvm::LoadInst>(Ins)){
                IrToCircuitNumber[CallInstructionStr] = AddressWireNumber[PtrAddress[CallValueStr[0]].first + " " + PtrAddress[CallValueStr[0]].second];
            }
            else if(llvm::isa<llvm::StoreInst>(Ins)){
//                std::cout<<"test store\n";
                if(IrToCircuitNumber.find(CallValueStr[0]) == IrToCircuitNumber.end() && IrToCircuitBinaryNumber.find(CallValueStr[0]) != IrToCircuitBinaryNumber.end()){
                    CallWire = pack(CallValueStr[0],CallWireNumber);
                    CircuitCall.push_back(CallWire);
                }
                AddressWireNumber[PtrAddress[CallValueStr[1]].first + " " + PtrAddress[CallValueStr[1]].second] = IrToCircuitNumber[CallValueStr[0]];

            }
            else if(auto *binOp = llvm::dyn_cast<llvm::BinaryOperator>(Ins)){ //二元操作
                //算术操作
                if(binOp->getOpcode() == llvm::Instruction::Add){
                    if(!flag){//整形运算
                        CallCircuitBinary = packcheck(CallValueStr, CallWireNumber);
                        if(!CallCircuitBinary.empty()) CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
                        CallWire = var_add(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.push_back(CallWire);
                    }else{//按位运算

                        CallCircuitBinary = var_binary_add(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                        std::cout<<"testcallbinaryadd\n";
                    }

                }
                else if(binOp->getOpcode() == llvm::Instruction::Sub){
                    if(!flag){
                        CallCircuitBinary = packcheck(CallValueStr, CallWireNumber);
                        if(!CallCircuitBinary.empty()) CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());

                        IrToCircuitNumber["neg " + CallValueStr[1]] = CallWireNumber;
                        CallWire = const_mul(1, IrToCircuitNumber[CallValueStr[1]], CallWireNumber, true);
                        CircuitCall.push_back(CallWire);
                        CallValueStr[1] = "neg " + CallValueStr[1];
                        CallWire = var_add(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.push_back(CallWire);
                    }else{
                        CallCircuitBinary = var_binary_sub(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                        std::cout<<"testcallbinarysub\n";
                    }

                }
                else if(binOp->getOpcode() == llvm::Instruction::Mul){
                    if(!flag){
                        CallCircuitBinary = packcheck(CallValueStr, CallWireNumber);
                        if(!CallCircuitBinary.empty()) CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                   std::cout<<"testmul\n";
                        CallWire = var_mul(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.push_back(CallWire);
                    }else{

                        CallCircuitBinary = var_binary_mul(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                        std::cout<<"testcallbinarymul\n";
                    }

                }
                else{//逻辑操作

                    if(binOp->getOpcode() == llvm::Instruction::Xor){

                        if(!CallValueStr[0].empty() && CallValueStr[0][0]=='%'&& IrToCircuitBinaryNumber.find(CallValueStr[0]) == IrToCircuitBinaryNumber.end()){
                            if(CallValueType[0]=="i32")
                                CallWire = split(CallValueStr[0],32,CallWireNumber);
                            else if(CallValueStr[0]=="i8")
                                CallWire = split(CallValueStr[0],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                        }
                        if(!CallValueStr[1].empty() && CallValueStr[1][0] == '%' && IrToCircuitBinaryNumber.find(CallValueStr[1])==IrToCircuitBinaryNumber.end()){
                            if(CallValueType[1]=="i32")
                                CallWire = split(CallValueStr[1],32,CallWireNumber);
                            else if(CallValueType[1]=="i8")
                                CallWire = split(CallValueStr[1],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                        }
                        if(CallValueStr[0][0] != '%' || CallValueStr[1][0]!='%') CallCircuitBinary = const_xor(CallInstructionStr, CallValueStr, CallValueType, CallWireNumber);
                        else CallCircuitBinary = var_xor(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                        std::cout<<"testcallxor\n";
                    }
                    else if(binOp->getOpcode() == llvm::Instruction::Or){

                        if(!CallValueStr[0].empty() && CallValueStr[0][0]=='%'&& IrToCircuitBinaryNumber.find(CallValueStr[0]) == IrToCircuitBinaryNumber.end()){
                            if(CallValueType[0]=="i32")
                                CallWire = split(CallValueStr[0],32,CallWireNumber);
                            else if(CallValueStr[0]=="i8")
                                CallWire = split(CallValueStr[0],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                            CircuitCall.push_back(CallWire);
                        }
                        if(!CallValueStr[1].empty() && CallValueStr[1][0] == '%' && IrToCircuitBinaryNumber.find(CallValueStr[1])==IrToCircuitBinaryNumber.end()){
                            if(CallValueType[1]=="i32")
                                CallWire = split(CallValueStr[1],32,CallWireNumber);
                            else if(CallValueType[1]=="i8")
                                CallWire = split(CallValueStr[1],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                        }
                        if(CallValueStr[0][0] != '%' || CallValueStr[1][0]!='%') const_or(CallInstructionStr, CallValueStr, CallValueType,CallWireNumber);
                        else CallCircuitBinary = var_or(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                        std::cout<<"tescalltor\n";
                    }
                    else if(binOp->getOpcode() == llvm::Instruction::And){

                        if(!CallValueStr[0].empty() && CallValueStr[0][0]=='%'&& IrToCircuitBinaryNumber.find(CallValueStr[0]) == IrToCircuitBinaryNumber.end()){
                            if(CallValueType[0]=="i32")
                                CallWire = split(CallValueStr[0],32,CallWireNumber);
                            else if(CallValueStr[0]=="i8")
                                CallWire = split(CallValueStr[0],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                            CircuitCall.push_back(CallWire);
                        }
                        if(!CallValueStr[1].empty() && CallValueStr[1][0] == '%' && IrToCircuitBinaryNumber.find(CallValueStr[1])==IrToCircuitBinaryNumber.end()){
                            if(CallValueType[1]=="i32")
                                CallWire = split(CallValueStr[1],32,CallWireNumber);
                            else if(CallValueType[1]=="i8")
                                CallWire = split(CallValueStr[1],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                        }
                        if(CallValueStr[0][0] != '%' || CallValueStr[1][0]!='%') const_and(CallInstructionStr, CallValueStr, CallValueType, CallWireNumber);
                        else CallCircuitBinary = var_and(CallInstructionStr, CallValueStr, CallWireNumber);
                        CircuitCall.insert(CircuitCall.end(),CallCircuitBinary.begin(),CallCircuitBinary.end());
//                        std::cout<<"testcallAND\n";
                    }
                    else if(binOp->getOpcode() == llvm::Instruction::Shl){//逻辑左移

                        if(IrToCircuitBinaryNumber.find(CallValueStr[0])==IrToCircuitBinaryNumber.end()){
                            if(CallValueType[0]=="i32")
                                CallWire = split(CallValueStr[0],32,CallWireNumber);
                            else if(CallValueStr[0]=="i8")
                                CallWire = split(CallValueStr[0],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                            CircuitCall.push_back(CallWire);
                        }
//                        std::cout<<"test shl st\n";
                        var_shl(CallInstructionStr, CallValueStr, CallWireNumber);
//                        std::cout<<"test shl ed\n";
                    }
                    else if(binOp->getOpcode() == llvm::Instruction::LShr){//逻辑右移

                        if(IrToCircuitBinaryNumber.find(CallValueStr[0])==IrToCircuitBinaryNumber.end()){
                            if(CallValueType[0]=="i32")
                                CallWire = split(CallValueStr[0],32,CallWireNumber);
                            else if(CallValueStr[0]=="i8")
                                CallWire = split(CallValueStr[0],8,CallWireNumber);
                            CircuitCall.push_back(CallWire);
                            CircuitCall.push_back(CallWire);
                        }

                        var_lshr(CallInstructionStr, CallValueStr, CallWireNumber);
                    }

//                    CallWire = pack(CallInstructionStr,CallWireNumber);
                }

            }
            else if(llvm::isa<llvm::ReturnInst> (Ins)){
                CallValueStr.emplace_back("0");
                CallWire = var_mul(Instruction, CallValueStr, CallWireNumber);
                CircuitCall.push_back(CallWire);
                break;

            }
            CallInstructionStr = "";
            CallValueStr.clear();
            CallValueType.clear();
//            CallValueStr[0] = CallValueStr[1] = "";
        }

    }

    return CircuitCall;

}
bool read_json(const std::string& input_file_name, boost::json::value &input_json_value) {
    std::ifstream input_file(input_file_name.c_str());
    if (!input_file.is_open()) {
        std::cerr << "Could not open the file - '" << input_file_name << "'" << std::endl;
        return false;
    }

    boost::json::stream_parser p;
    boost::json::error_code ec;
    while (!input_file.eof()) {
        char input_string[512];
        input_file.read(input_string, sizeof(input_string) - 1);
        input_string[input_file.gcount()] = '\0';
//        std::cout << "Read data: " << input_string << std::endl;
        p.write(input_string, ec);
        if (ec) {
            std::cerr << "JSON parsing of input failed 1" << std::endl;
            return false;
        }
    }
    p.finish(ec);
    if (ec) {
        std::cerr << "JSON parsing of input failed 2" << std::endl;
        return false;
    }
    input_json_value = p.release();
    if (!input_json_value.is_array()) {
        std::cerr << "Array of arguments is expected in JSON file" << std::endl;
        return false;
    }
    return true;
}

void print_circuit(std::vector<std::string> &circuit, const std::string& CircuitName, const std::string& OutputFileName, std::vector<std::string> &witness, const int &WireNumber){
    //------输出电路信息
    std::ofstream  outputCircuit(CircuitName);
    if(outputCircuit){
        outputCircuit << "total " << WireNumber << std::endl;
        int num=0;
//        std::cout<<"testoutput1\n";
        for(size_t i=0;i<circuit.size();i++){
            outputCircuit << circuit[i] << std::endl;
        }
//        for(auto  i : circuit){
//            std::cout<<num++<<"\n";
//            outputCircuit << i << std::endl;
//        }
        outputCircuit.close();
    }else{
        std::cerr << "Unable to create or open circuit file.\n";
    }
    //-----------------------------
//    std::cout<<"testoutput2\n";
    //-------输出电路见证值信息
    std::ofstream  outputFile(OutputFileName.c_str());
    if(outputFile.is_open()){
        for(const auto & i : witness){
            outputFile << i << "\n";
        }
        outputFile.close();
    }else{
        std::cerr << "Unable to create or open witness file.\n";
    }
//    std::cout<<"testoutput3\n";
    //--------
}
void print_R1CS(const std::string& CircuitName, const std::string& OutputFileName, const std::string& R1CSOutFile){
    std::string command = "libs/libsnark/build/libsnark/jsnark_interface/run_ppzksnark";
    command = command + " " + CircuitName + " " + OutputFileName + " " + R1CSOutFile;
    std::stringstream output;

    FILE* pipe = popen(command.c_str(), "r");
    if(!pipe){
        std::cerr << "Error executing command\n";
        return ;
    }

    char buffer[128];
    while(fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output << buffer;
    }

    pclose(pipe);

//    //输出执行结果
//    std::cout << "\n----------------------------------------------RUNNING LIBSNARK----------------------------------------------\n";
//    std::cout << output.str() << "\n";
}
int main(int argc, char *argv[]) {

    auto start = std::chrono::high_resolution_clock::now();
    //读取命令行指令
    boost::program_options::options_description options_desc("assigner");

    options_desc.add_options()
            ("bytecode,b", boost::program_options::value<std::string>(), "Bytecode input file")
            ("public-input,i", boost::program_options::value<std::string>(), "Public input file")
            ("circuit,c", boost::program_options::value<std::string>(), "Circuit output file")
            ("output-file,o", boost::program_options::value<std::string>(), "Output file for public input column")
            ("R1CS,r", boost::program_options::value<std::string>(), "R1CS output file")
            ;

    boost::program_options::variables_map vm;
    try {
        boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options_desc).run(), vm);
        boost::program_options::notify(vm);
    } catch (const boost::program_options::unknown_option &e) {
        std::cerr << "Invalid command line argument: " << e.what() << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }

    std::string BytecodeName;
    std::string PublicInputName;
    std::string CircuitName;
    std::string OutputFileName;
    std::string R1CSFileName;
    if(vm.count("bytecode")){
        BytecodeName = vm["bytecode"].as<std::string>();
    }else{
        std::cerr << "Invalid command line argument - bytecode file name is not specified" << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }
    if(vm.count("public-input")){
        PublicInputName = vm["public-input"].as<std::string>();
    }else{
        std::cerr << "Public input file names are not specified" << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }
    if(vm.count("circuit")){
        CircuitName = vm["circuit"].as<std::string>();
    }else{
        std::cerr << "Circuit output file names are not specified" << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }
    if(vm.count("output-file")){
        OutputFileName = vm["output-file"].as<std::string>();
    }else{
        std::cerr << "Output file names are not specified" << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }
    if(vm.count("R1CS")){
        R1CSFileName = vm["R1CS"].as<std::string>();
    }else{
        std::cerr << "R1CS output file names are not specified" << std::endl;
        std::cout << options_desc << std::endl;
        return 1;
    }
    //--------------------------------------------------------------------

    std::vector<std::string> circuit;
    std::vector<std::string> witness;
    std::string Wire;
    std::string WitnessNumber;

    //----------------------read Bytecode file
    llvm::LLVMContext context;
    std::unique_ptr<llvm::Module> module;
    llvm::Function *circuit_function;
    llvm::SMDiagnostic diagnostic; //表示详细的诊断信息
    //读取并格式化LLVM IR字节码文件, 返回LLVM Module(Module是LLVM IR的顶级容器)
    module = llvm::parseIRFile(BytecodeName, diagnostic, context);
    if (module == nullptr) {
        diagnostic.print("assigner", llvm::errs());
        return 0;
    }
    //---------------------------------------

    //--------------------------------------read input file
    boost::json::value PublicInputJsonValue;
    if(PublicInputName.empty()) {
        PublicInputJsonValue = boost::json::array();
    } else if (!read_json(PublicInputName, PublicInputJsonValue)){
        return 1;
    }

//    std::cout << "Json value: " << PublicInputJsonValue << "\n";
    //--------------------------------------


    //获取主函数地址
    auto entry_point_it = module->end();
    for (auto function_it = module->begin(); function_it != module->end(); ++function_it) {

         
        if (function_it->hasFnAttribute(llvm::Attribute::Circuit)) {
            if (entry_point_it != module->end()) {
                std::cerr << "More then one functions with [[circuit]] attribute in the module"
                          << std::endl;
                return 0;
            }
            entry_point_it = function_it;
        }
    }
    if (entry_point_it == module->end()) {
        std::cerr << "Entry point is not found" << std::endl;
        return 0;
    }

    circuit_function = &*entry_point_it;

    //------------output test
//    circuit_function->print(llvm::outs(), nullptr);



    int WireNumber=0;

    //step 1--------------------set  value of wire 0 = 1 / value of wire 1 = 0 one-inout wire 初始化
    Wire = "input " + std::to_string(WireNumber++);
    circuit.push_back(Wire);
    IrToCircuitNumber["1"] = 0;


    IrToCircuitNumber["0"] = 1;
    Wire = const_mul(0, 0, WireNumber);
    circuit.push_back(Wire);

    WitnessNumber = "0 1";
    witness.push_back(WitnessNumber);
    //--------------------

    //step 2----------------------------------获取函数参数相关信息
    std::string ArgStr;
    boost::json::array intValues = PublicInputJsonValue.as_array();
    std::vector<int> ArgPtr;
    for(size_t i=0; i<circuit_function->arg_size(); ++i){

        llvm::Argument *current_arg = circuit_function->getArg(i);
        llvm::Type *ArgType = current_arg->getType();
        llvm::raw_string_ostream ArgStrStream(ArgStr);
        ArgType->print(ArgStrStream);

        boost::json::object obj = intValues[i].as_object();
        if(ArgStr == "i32"){
            if(obj.contains("int")){
//                std::cout << obj.at("int").kind() << "\n";

//                WitnessNumber = std::to_string(WireNumber) + " " +  std::to_string(obj.at("int").as_int64());
                RegType["%"+std::to_string(i)] = "int";
                WitnessNumber = std::to_string(WireNumber) + " " +  toHexString(obj.at("int").as_int64());
                CircuitNumberValue[WireNumber] = obj.at("int").as_int64();
                witness.push_back(WitnessNumber);
            }
            else if(obj.contains("uint32_t")){
                RegType["%"+std::to_string(i)] = "uint32_t";
                WitnessNumber = std::to_string(WireNumber) + " " +  toHexString(obj.at("uint32_t").as_int64());
                CircuitNumberValue[WireNumber] = obj.at("uint32_t").as_int64();
                witness.push_back(WitnessNumber);
            }else if(obj.contains("uint8_t")){
                type = 1;
                RegType["%"+std::to_string(i)] = "uint8_t";
                WitnessNumber = std::to_string(WireNumber) + " " +  toHexString(obj.at("uint8_t").as_int64());
                CircuitNumberValue[WireNumber] = obj.at("uint8_t").as_int64();
                witness.push_back(WitnessNumber);
            }
            IrToCircuitNumber["%"+std::to_string(i)] = WireNumber;

            Wire = "input " + std::to_string(WireNumber++);
            circuit.push_back(Wire);

        }else if(ArgStr == "ptr"){
            if(obj.contains("array[int]")){
                boost::json::array arr = obj.at("array[int]").as_array();
                for(const boost::json::value &elem : arr){
                    ArgPtr.push_back(elem.as_int64());
                }
                RegType["%"+std::to_string(i)] = "int";
                Ptr["%"+std::to_string(i)] = ArgPtr;
                PtrAddress["%"+std::to_string(i)] = std::make_pair("%" + std::to_string(i), "0");

                for(int argi = 0; argi < ArgPtr.size(); argi++){
                    WitnessNumber = std::to_string(WireNumber) + " " +toHexString(ArgPtr[argi]);
                    CircuitNumberValue[WireNumber] = ArgPtr[argi];
                    AddressWireNumber["%" + std::to_string(i) + " " + std::to_string(argi)] = WireNumber;
                    Wire = "input " + std::to_string(WireNumber++);
                    circuit.push_back(Wire);
                    witness.push_back(WitnessNumber);
                }

            }else if(obj.contains("array[uint32_t]")){
                boost::json::array arr = obj.at("array[uint32_t]").as_array();
                for(const boost::json::value &elem : arr){
                    ArgPtr.push_back(elem.as_int64());
                }
                RegType["%"+std::to_string(i)] = "uint32_t";
                Ptr["%"+std::to_string(i)] = ArgPtr;
                PtrAddress["%"+std::to_string(i)] = std::make_pair("%" + std::to_string(i), "0");

                for(int argi = 0; argi < ArgPtr.size(); argi++) {
                    WitnessNumber = std::to_string(WireNumber) + " " + toHexString(ArgPtr[argi]);
                    CircuitNumberValue[WireNumber] = ArgPtr[argi];
                    AddressWireNumber["%" + std::to_string(i) + " " + std::to_string(argi)] = WireNumber;
                    Wire = "input " + std::to_string(WireNumber++);
                    circuit.push_back(Wire);
                    witness.push_back(WitnessNumber);
                }
            }else if(obj.contains("array[uint8_t]")){
                type = 1;
                boost::json::array arr = obj.at("array[uint8_t]").as_array();
                for(const boost::json::value &elem : arr){
                    ArgPtr.push_back(elem.as_int64());
                }
                RegType["%"+std::to_string(i)] = "uint8_t";
                Ptr["%"+std::to_string(i)] = ArgPtr;
                PtrAddress["%"+std::to_string(i)] = std::make_pair("%" + std::to_string(i), "0");

//                std::cout<<"uint8_t: ";
                for(int argi = 0; argi < ArgPtr.size(); argi++) {
//                    std::cout<<ArgPtr[argi]<<" ";
                    WitnessNumber = std::to_string(WireNumber) + " " + toHexString(ArgPtr[argi]);
                    CircuitNumberValue[WireNumber] = ArgPtr[argi];
                    AddressWireNumber["%" + std::to_string(i) + " " + std::to_string(argi)] = WireNumber;
                    Wire = "input " + std::to_string(WireNumber++);
                    circuit.push_back(Wire);
                    witness.push_back(WitnessNumber);
                }
//                std::cout<<"\n";
            }
            ArgPtr.clear();
        }

//        llvm::outs() << "Argument :" << ArgStr << "\n";
        ArgStr = "";
    }
//    std::cout<<"vec %1: ";
//    for(const auto &i : Ptr["%1"]){
//        std::cout<< i <<" ";
//    }
//    std::cout<<"\n";

    //step3-----------------------------获取函数全部指令信息并构造电路
    std::string InstructionStr;
    std::vector<std::string> ValueStr;
    std::vector<std::string> ValueType;
    std::vector<std::string> CircuitBinary;

    int NewSize = 0;
    int ConstNumber = 0;
    ValueStr.resize(2);
    ValueType.resize(2);
    //-----------------------------这部分可以做一个函数封装
    for(auto & BB : *circuit_function){
        for(auto & i : BB){
            llvm::Instruction *Ins = &i;
            llvm::raw_string_ostream InstructionStrStream(InstructionStr);
            Ins->printAsOperand(InstructionStrStream, false);

//            std::cout << "Instruction: " << InstructionStr << "\n";

//            llvm::outs() << "Instruction Opcode: " << Ins->getOpcodeName() << "\n";
//
//            llvm::outs() << " Number of Operands: " << Ins->getNumOperands() << "\n\n";
//

//            llvm::outs() << "Instruction Type: " << *Ins->getType() << "\n";

            if (auto *callInst = llvm::dyn_cast<llvm::CallInst>(Ins)) {//函数调用
                // Check if the call instruction has a valid called function
                llvm::Function *calledFunction = callInst->getCalledFunction();
                if (calledFunction) {
//                    std::cout << "Found call to function: " << calledFunction->getName().str() << "\n";
                    if(calledFunction->getName().str() == "_Znam"){//官方函数调用  _Znam 表示 new 操作符
                        llvm::Value *arg = callInst->getArgOperand(0);
                        std::string SizeStr;
                        llvm::raw_string_ostream ValueStrStream(SizeStr);
                        arg->printAsOperand(ValueStrStream, false);
                        std::stringstream(SizeStr) >> NewSize;
                        std::vector<int> NewVector(NewSize);
                        Ptr[InstructionStr] = NewVector;
                        PtrAddress[InstructionStr] = std::make_pair(InstructionStr,"0");
//                        std::cout<<"new test:"<<SizeStr<<"\n";
//                        arg->print(llvm::outs());
                    }else if(calledFunction->getName().str() == "_ZNSt3__14sortB7v170002IPjEEvT_S2_"){ //排序操作
                        llvm::Value *arg = callInst->getArgOperand(0);
                        std::string ArrayID;
                        llvm::raw_string_ostream ValueStrStream(ArrayID);
                        arg->printAsOperand(ValueStrStream, false);
//                        std::cout<<"sort test:"<<ArrayID<<"\n";

                        std::vector<int> sortArrayNizkInputWire;
                        std::vector<int> sortArray(Ptr[ArrayID]);
                        std::vector<int> unsortArray(Ptr[ArrayID]);
                        std::sort(sortArray.begin(),sortArray.end());
                        for(int i : sortArray){
//                            IrToCircuitNumber
                            sortArrayNizkInputWire.push_back(WireNumber);
                            WitnessNumber = std::to_string(WireNumber) +" "+ std::to_string(i);
                            Wire = "nizkinput " + std::to_string(WireNumber++);
                            circuit.push_back(Wire);
                            witness.push_back(WitnessNumber);
                        }
                        //检验排序的置换正确性，即用置换网络电路验证排序后的数组是未排序数组的一个排列
                        auto sortverifycircuit = permutation_network_verify(ArrayID,WireNumber,unsortArray,sortArray,sortArrayNizkInputWire);
                        witness.insert(witness.end(),sortverifycircuit.Witness.begin(),sortverifycircuit.Witness.end());
                        circuit.insert(circuit.end(),sortverifycircuit.Circuit.begin(),sortverifycircuit.Circuit.end());
                        //验证排序的有序性即 sortArray[i]<=sortArray[i+1],这里需要保证0<=sortArray[i]<65536(0x10000)
                        auto OrderlinessVerifyCircuit = OrderlinessVerify(sortArrayNizkInputWire,WireNumber);
                        circuit.insert(circuit.end(),OrderlinessVerifyCircuit.begin(),OrderlinessVerifyCircuit.end());

                    }else{//自定义函数调用
                        std::string callFunctionName = calledFunction->getName().str().substr(3,3);
                        bool flag = false;
                        if(callFunctionName == "Bit" || callFunctionName == "BIT") flag = true;
                        auto callcircuit = CallFunction(callInst, calledFunction, WireNumber,InstructionStr,flag);
                        circuit.insert(circuit.end(),callcircuit.begin(),callcircuit.end());
                    }
                }
//                std::cout<<"Calltest3\n";

                // Loop through the operands and check for arguments
//                for (unsigned i = 0; i < callInst->getNumOperands(); ++i) {
//                    llvm::Value *arg = callInst->getOperand(i);  // Get the operand at index i
//                    std::cout << "Operand " << i << ": ";
//                    arg->print(llvm::outs());  // Use print method to output the Value
//                    std::cout << "\n";
//                }
                InstructionStr = "";
                continue;
            }
            auto num = Ins->getNumOperands();
            ValueStr.resize(num);
            ValueType.resize(num);
            for(auto OpIdx = 0; OpIdx < num; ++OpIdx){
                llvm::Value *Operand = Ins->getOperand(OpIdx);
                llvm::raw_string_ostream ValueStrStream(ValueStr[OpIdx]);
                Operand->printAsOperand(ValueStrStream, false);

                llvm::Type *OperandType = Operand->getType();

                llvm::raw_string_ostream OperandStrStream(ValueType[OpIdx]);
                OperandType->print(OperandStrStream, false);

                if(!llvm::isa<llvm::GetElementPtrInst>(Ins) && ValueStr[OpIdx][0]!='%' && !IrToCircuitNumber.count(ValueStr[OpIdx])){//这部分的功能是在做什么？ 利用one-input 将后续所需的常数电路线构造出来

                    IrToCircuitNumber[ValueStr[OpIdx]] = WireNumber;

                    std::stringstream(ValueStr[OpIdx]) >> ConstNumber;
                    Wire = const_mul(ConstNumber, 0, WireNumber);
//                    std::cout<<"Const test: "<<Wire<<"\n";
                    circuit.push_back(Wire);
                }
//                std::cout << "op: " << ValueType[OpIdx] << "\n";
//                llvm::outs() << "Operand " << OpIdx << ": " << *Operand <<"\n";
            }
//            std::cout<<"\n";
            if(auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(Ins)){
                llvm::Type *elementType = GEP->getSourceElementType();
                std::string elementTypeStr;
                if (elementType->isIntegerTy()) {
                    elementTypeStr = "i" + std::to_string(elementType->getIntegerBitWidth());
                    if(RegType.find(ValueStr[0])==RegType.end()){
                        if(elementTypeStr=="i32"){
                            Ptr[ValueStr[0]].resize(Ptr[ValueStr[0]].size()/4);
                            RegType[ValueStr[0]]="uint32_t";
                        }else if(elementTypeStr=="i8"){
                            RegType[ValueStr[0]]="uint8_t";
                        }

                    }
                }


                if(ValueStr.size()>2){
//                    std::cout<<"Getptr: "<<ValueStr[0]<<" "<<ValueStr[1]<<" "<<ValueStr[2]<<"\n";
                    PtrAddress[InstructionStr] = std::make_pair(ValueStr[0], ValueStr[2]);
                }else{
                    PtrAddress[InstructionStr] = std::make_pair(ValueStr[0], ValueStr[1]);
                }


            }
            else if(llvm::isa<llvm::LoadInst>(Ins)){
                if(PtrAddress[ValueStr[0]].second[0]!='%'){//常量地址访问
                    IrToCircuitNumber[InstructionStr] = AddressWireNumber[PtrAddress[ValueStr[0]].first + " " + PtrAddress[ValueStr[0]].second];

                }else{//随机变量内存访问  线性 O（kn）
//                    std::cout<<"test Linear\n";
                    if(PtrAddress[ValueStr[0]].first[0]=='@'){//动态内存访问 获取常量数组数值 利用 const-mul来实现
//                        std::cout<<"TEST LOAD " << PtrAddress[ValueStr[0]].first<<"\n";
                        std::string GlobalName(PtrAddress[ValueStr[0]].first.begin()+1,PtrAddress[ValueStr[0]].first.end());
//                        std::cout<<"TEST LOAD GLOBAL " <<  GlobalName <<"\n";
                        llvm::GlobalVariable* globalVar = module->getNamedGlobal(GlobalName);
                        int MaxValue=0;
                        int n;
                        if (globalVar->getValueType()->isArrayTy()) {
                            // The array type is [8 x i32], let's extract its contents
//                            std::cout << "Initializer Type: " << globalVar->getInitializer()->getType()->getTypeID() << std::endl;
                            // Get the constant array
                            if (auto* constDataArray = llvm::dyn_cast<llvm::ConstantDataArray>(globalVar->getInitializer())) {
//                                std::cout << "It is a ConstantDataArray!" << std::endl;

                                // Extract values from ConstantDataArray (if that's the case)
                                std::vector<int> arrayValues;
                                for (unsigned k = 0; k < constDataArray->getNumElements(); ++k) {
                                    auto* element = constDataArray->getElementAsConstant(k);
                                    if (auto* constInt = llvm::dyn_cast<llvm::ConstantInt>(element)) {
//                                        arrayValues.push_back(constInt->getSExtValue());
                                        if (constInt->getType()->isIntegerTy(8)) {
                                            // 如果是 i8 类型，获取字节值
                                            uint8_t byteValue = constInt->getZExtValue() & 0xFF;
                                            arrayValues.push_back(byteValue);  // 将字节值加入数组
                                        }
                                        else if (constInt->getType()->isIntegerTy(32)) {
                                            // 如果是 i32 类型，获取32位整数值
                                            int32_t intValue = constInt->getSExtValue();  // 使用 sign extension 获取整数值
                                            arrayValues.push_back(intValue);  // 将32位整数加入数组
                                        }
                                    }
                                }

//                                std::cout << "Array values: ";
//                                for (int val : arrayValues) {
//                                    std::cout << val << " ";
//                                }
//                                std::cout << std::endl;

                                Ptr[PtrAddress[ValueStr[0]].first] = arrayValues;
                                PtrAddress[PtrAddress[ValueStr[0]].first] = std::make_pair(PtrAddress[ValueStr[0]].first, "0");

                                for(auto k=0; k<arrayValues.size(); k++){//只读内存硬布线
                                    CircuitNumberValue[WireNumber] = arrayValues[k];
                                    MaxValue = std::max(MaxValue,arrayValues[k]);
                                    AddressWireNumber[PtrAddress[ValueStr[0]].first + " " + std::to_string(k)] = WireNumber;
                                    Wire = const_mul(arrayValues[k],0,WireNumber);
                                    circuit.push_back(Wire);
                                }
                                n = nextPoewrOfTwo(MaxValue);
                                MaxValue =std::pow(2,n);
                                if(!IrToCircuitNumber.count(std::to_string(MaxValue))){
                                    IrToCircuitNumber[std::to_string(MaxValue)] = WireNumber;
                                    Wire = const_mul(MaxValue, 0, WireNumber);
                                    circuit.push_back(Wire);
                                }
                                //只读内存的高效访问算法,不再使用模拟的思想,而是使用隐私输入后再验证的思想
                                if(ConstCji.find(PtrAddress[ValueStr[0]].first)==ConstCji.end()){//该只读变量系数还没有计算
                                    //预处理系数
                                    coeff_cal(PtrAddress[ValueStr[0]].first, MaxValue, arrayValues);
                                }
                            }
                        }
                        //只读内存在线验证（这部分要体现在算术电路中）
                        //step 1 输入声明
                        WitnessNumber = std::to_string(WireNumber) + " " + std::to_string(CircuitNumberValue[IrToCircuitNumber[PtrAddress[ValueStr[0]].second]]);
                        Wire = "nizkinput " + std::to_string(WireNumber++);
                        witness.push_back(WitnessNumber);
                        circuit.push_back(Wire);

                        //声明范围检查 0<b<n-1 保证z_i的唯一性 使用位分解去验证
                        CircuitBinary = RomCheck(InstructionStr, MaxValue, n,ValueStr, WireNumber-1, WireNumber);
//                        circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

                    }else{
                        CircuitBinary = LinearScan(InstructionStr, ValueStr, WireNumber);
                    }
                    circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
                }

            }
            else if(llvm::isa<llvm::StoreInst>(Ins)){
//                std::cout<<"test store\n";
                if(IrToCircuitNumber.find(ValueStr[0]) == IrToCircuitNumber.end() && IrToCircuitBinaryNumber.find(ValueStr[0]) != IrToCircuitBinaryNumber.end()){
                    Wire = pack(ValueStr[0],WireNumber);
                    circuit.push_back(Wire);
                }
                AddressWireNumber[PtrAddress[ValueStr[1]].first + " " + PtrAddress[ValueStr[1]].second] = IrToCircuitNumber[ValueStr[0]];
                Ptr[PtrAddress[ValueStr[1]].first][std::stoi(PtrAddress[ValueStr[1]].second)]= CircuitNumberValue[IrToCircuitNumber[ValueStr[0]]];

            }else if(llvm::isa<llvm::SExtInst>(Ins)){
                IrToCircuitNumber[InstructionStr] = IrToCircuitNumber[ValueStr[0]];
//                std::cout<<ValueStr[0]<<"\n";
//                std::cout<<"test sext\n";
            }else if(llvm::isa<llvm::TruncInst>(Ins)){
                IrToCircuitNumber[InstructionStr] = IrToCircuitNumber[ValueStr[0]];
//                std::cout<<ValueStr[0]<<"\n";
//                std::cout<<"test Trunc\n";
            }

           if(auto *binOp = llvm::dyn_cast<llvm::BinaryOperator>(Ins)){ //二元操作
               //算术操作
               if(binOp->getOpcode() == llvm::Instruction::Add){

                   CircuitBinary = packcheck(ValueStr, WireNumber);
                   if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
                   Wire = var_add(InstructionStr, ValueStr, WireNumber);
                   circuit.push_back(Wire);
               }
               else if(binOp->getOpcode() == llvm::Instruction::Sub){
                   CircuitBinary = packcheck(ValueStr, WireNumber);
                   if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

                   IrToCircuitNumber["neg " + ValueStr[1]] = WireNumber;
                   Wire = const_mul(1, IrToCircuitNumber[ValueStr[1]], WireNumber, true);
                   circuit.push_back(Wire);
                   ValueStr[1] = "neg " + ValueStr[1];
                   Wire = var_add(InstructionStr, ValueStr, WireNumber);
                   circuit.push_back(Wire);
               }
               else if(binOp->getOpcode() == llvm::Instruction::Mul){

                   CircuitBinary = packcheck(ValueStr, WireNumber);
                   if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

//                   std::cout<<"testmul\n";
                   Wire = var_mul(InstructionStr, ValueStr, WireNumber);
                   circuit.push_back(Wire);
               }
               else if(binOp->getOpcode() == llvm::Instruction::SDiv){
                   CircuitBinary = packcheck(ValueStr, WireNumber);
                   if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

                   IrToCircuitNumber[InstructionStr] = WireNumber; //NIZKINPUT 商
                   //       std::cout<<ValueStr[0]<<" "<<ValueStr[1]<<"\n";
                   //     std::cout<<IrToCircuitNumber[ValueStr[0]]<<" "<<IrToCircuitNumber[ValueStr[1]]<<"\n";
                   WitnessNumber = std::to_string(WireNumber) + " " + std::to_string(CircuitNumberValue[IrToCircuitNumber[ValueStr[0]]]/CircuitNumberValue[IrToCircuitNumber[ValueStr[1]]]);
                   Wire = "nizkinput " + std::to_string(WireNumber++);
                   circuit.push_back(Wire);
                   witness.push_back(WitnessNumber);

                   Wire = var_sdiv(InstructionStr, ValueStr, WireNumber);
                   circuit.push_back(Wire);
               }
               else{//逻辑操作
//                   if(!ValueStr[0].empty() && IrToCircuitBinaryNumber.find(ValueStr[0]) == IrToCircuitBinaryNumber.end()){
//                       Wire = split(ValueStr[0],32,WireNumber);
//                       circuit.push_back(Wire);
//                   }
//                   if(!ValueStr[1].empty() && IrToCircuitBinaryNumber.find(ValueStr[1])==IrToCircuitBinaryNumber.end()){
//                       Wire = split(ValueStr[1],32,WireNumber);
//                       circuit.push_back(Wire);
//                   }
                   if(binOp->getOpcode() == llvm::Instruction::Xor){

                       if(!ValueStr[0].empty() && ValueStr[0][0]=='%'&& IrToCircuitBinaryNumber.find(ValueStr[0]) == IrToCircuitBinaryNumber.end()){
                           if(type==0)
                                Wire = split(ValueStr[0],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[0],8,WireNumber);
                           circuit.push_back(Wire);
                       }
                       if(!ValueStr[1].empty() && ValueStr[1][0] == '%' && IrToCircuitBinaryNumber.find(ValueStr[1])==IrToCircuitBinaryNumber.end()){
                           if(type==0)
                                Wire = split(ValueStr[1],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[1],8,WireNumber);
                           circuit.push_back(Wire);
                       }
                       if(ValueStr[0][0] != '%' || ValueStr[1][0]!='%') CircuitBinary =const_xor(InstructionStr, ValueStr, ValueType, WireNumber);
                       else CircuitBinary = var_xor(InstructionStr, ValueStr, WireNumber);
                       circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
//                       std::cout<<"testxor\n";
                   }
                   else if(binOp->getOpcode() == llvm::Instruction::Or){

                       if(!ValueStr[0].empty() && ValueStr[0][0]=='%'&& IrToCircuitBinaryNumber.find(ValueStr[0]) == IrToCircuitBinaryNumber.end()){
                           if(type==0)
                               Wire = split(ValueStr[0],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[0],8,WireNumber);
                           circuit.push_back(Wire);
                       }
                       if(!ValueStr[1].empty() && ValueStr[1][0] == '%' && IrToCircuitBinaryNumber.find(ValueStr[1])==IrToCircuitBinaryNumber.end()){
                           if(type==0)
                               Wire = split(ValueStr[1],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[1],8,WireNumber);
                           circuit.push_back(Wire);
                       }
                       if(ValueStr[0][0] != '%' || ValueStr[1][0]!='%') const_or(InstructionStr,ValueStr, ValueType, WireNumber);
                       else CircuitBinary = var_or(InstructionStr, ValueStr, WireNumber);
                       circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
//                       std::cout<<"testor\n";
                   }
                   else if(binOp->getOpcode() == llvm::Instruction::And){

                       if(!ValueStr[0].empty() && ValueStr[0][0]=='%'&& IrToCircuitBinaryNumber.find(ValueStr[0]) == IrToCircuitBinaryNumber.end()){
                           if(type==0)
                               Wire = split(ValueStr[0],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[0],8,WireNumber);
                           circuit.push_back(Wire);
                       }
                       if(!ValueStr[1].empty() && ValueStr[1][0] == '%' && IrToCircuitBinaryNumber.find(ValueStr[1])==IrToCircuitBinaryNumber.end()){
                           if(type==0)
                               Wire = split(ValueStr[1],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[1],8,WireNumber);
                           circuit.push_back(Wire);
                       }
                       if(ValueStr[0][0] != '%' || ValueStr[1][0]!='%') const_and(InstructionStr,ValueStr, ValueType, WireNumber);
                       else CircuitBinary = var_and(InstructionStr, ValueStr, WireNumber);
                       circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
//                       std::cout<<"testAND\n";
                   }
                   else if(binOp->getOpcode() == llvm::Instruction::Shl){//逻辑左移 使用生成的电路线 0 作为补位
//                       std::cout<<"test shl st\n";
                       if(!ValueStr[0].empty() && IrToCircuitBinaryNumber.find(ValueStr[0]) == IrToCircuitBinaryNumber.end()){
                           if(type==0)
                               Wire = split(ValueStr[0],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[0],8,WireNumber);
                           circuit.push_back(Wire);
                       }

                       var_shl(InstructionStr, ValueStr, WireNumber);
//                       std::cout<<"test shl ed\n";
                   }
                   else if(binOp->getOpcode() == llvm::Instruction::LShr){//逻辑右移

                       if(!ValueStr[0].empty() && IrToCircuitBinaryNumber.find(ValueStr[0]) == IrToCircuitBinaryNumber.end()){
                           if(type==0)
                               Wire = split(ValueStr[0],32,WireNumber);
                           else if(type==1)
                               Wire = split(ValueStr[0],8,WireNumber);
                           circuit.push_back(Wire);
                       }

                       var_lshr(InstructionStr, ValueStr, WireNumber);
                   }

//                   Wire = pack(InstructionStr,WireNumber);
//                   circuit.push_back(Wire);
               }

           }
           else if(auto *icmpInst = llvm::dyn_cast<llvm::ICmpInst>(Ins)){//比较操作 实现上有些疑惑，先按照自己想的去实现吧
               if(icmpInst->getPredicate() == llvm::ICmpInst::ICMP_EQ ){

                   CircuitBinary = packcheck(ValueStr, WireNumber);
                   if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

                   CircuitBinary = var_eq(InstructionStr, ValueStr, WireNumber);
                   circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
//                   std::cout<<"Found icmp eq\n";
               }
               else if(icmpInst->getPredicate() == llvm::ICmpInst::ICMP_NE){
                   CircuitBinary = packcheck(ValueStr, WireNumber);
                   if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

                   CircuitBinary = var_neq(InstructionStr, ValueStr, WireNumber);
                   circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
//                   std::cout<<"Found icmp neq\n";
               }

           }else if(auto *selectInst = llvm::dyn_cast<llvm::SelectInst>(Ins)){ //三元运算符 select 一般与eq/neq
               std::vector<std::string> pk(ValueStr.begin()+1,ValueStr.end());
               CircuitBinary = packcheck(pk, WireNumber);
               if(!CircuitBinary.empty()) circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());

               CircuitBinary = var_select(InstructionStr, ValueStr, WireNumber);
               circuit.insert(circuit.end(),CircuitBinary.begin(),CircuitBinary.end());
//               std::cout<<"Found select\n";
           }



            if (auto *ReturnInstruction = llvm::dyn_cast<llvm::ReturnInst>(Ins)) {
                llvm::Value *ReturnValue = ReturnInstruction->getReturnValue();
                if (ReturnValue) {
                    llvm::Type *valueType = ReturnValue->getType();

                    std::string typeStr;
                    llvm::raw_string_ostream(typeStr) << *valueType;
//                    std::cout << "Return value type: " << typeStr << "\n";

                    if(typeStr == "i32"||typeStr== "i8"){

                        if(IrToCircuitNumber.find(ValueStr[0]) == IrToCircuitNumber.end() && IrToCircuitBinaryNumber.find(ValueStr[0]) != IrToCircuitBinaryNumber.end()){
                            Wire = pack(ValueStr[0],WireNumber);
                            circuit.push_back(Wire);
                        }

                        std::string Mul="mul";
                        int RetResult = WireNumber++;
                        Mul += in_wire(2,IrToCircuitNumber[ValueStr[0]],0);
                        Mul += out_wire(1,RetResult);
                        circuit.push_back(Mul);

//                        Wire = var_mul(InstructionStr, ValueStr, WireNumber);
//                        circuit.push_back(Wire);

                        Wire = "output " + std::to_string(RetResult);
                        circuit.push_back(Wire);
                    }else if(typeStr == "ptr"){
                        auto RetNum = Ptr[ValueStr[0]].size();
//                        std::cout<<"ptrtype: "<<RetNum<<"\n";
                        for(int k=0;k < RetNum;k++){
                            if(AddressWireNumber[ValueStr[0]+" "+ std::to_string(k)]){
                                std::string Mul="mul";
                                int RetResult = WireNumber++;
                                Mul += in_wire(2,AddressWireNumber[ValueStr[0]+" "+ std::to_string(k)],0);
                                Mul += out_wire(1,RetResult);
                                circuit.push_back(Mul);

                                Wire = "output " + std::to_string(RetResult);
                                circuit.push_back(Wire);

                            }else{
                                std::string Mul="mul";
                                int RetResult = WireNumber++;
                                Mul += in_wire(2,0,1);
                                Mul += out_wire(1,RetResult);
                                circuit.push_back(Mul);

                                Wire = "output " + std::to_string(RetResult);
                                circuit.push_back(Wire);
                            }
                        }
                    }
                }
            }
            InstructionStr = "";
            ValueStr.clear();
            ValueType.clear();
//            ValueStr[0] = ValueStr[1] = "";

//            std::cout << "\n";
        }
    }

//step4-------------------------------------------------------输出电路以及见证者信息
    print_circuit(circuit, CircuitName, OutputFileName, witness, WireNumber);
    print_R1CS(CircuitName, OutputFileName, R1CSFileName);
//step 5-------------------------调用libsnark接口，执行零知识证明验证

    //run_libsnark(CircuitName, OutputFileName, R1);

//----------------------------
//    printf("\ntest assigner success!\n");
    auto end = std::chrono::high_resolution_clock::now();

    auto Duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout <<  "Program execution time: " << std::chrono::duration<double>(Duration).count() << " seconds\n";
    return 0;
}
