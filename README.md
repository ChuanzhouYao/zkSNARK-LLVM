# zkSNARK-LLVM 编译器



## 项目概述

zkSNARK-LLVM 编译器 - 一种基于 LLVM 的支持高级编程语言的零知识证明编译器的设计方案, 它可以将类 C++以及类Rust代码转换成一阶约束系统 (Rank-1 Constraint System, R1CS) 格式, 为零知识证明协议提供可以接受的输入格式.由于 LLVM 具有目标无关以及支持多种高级编程语言的特性并且编译器后端集成了多种约束优化策略, 相比与现有的编译器, zkSNARK-LLVM 编译器有着更好的通用性和更少的约束数量. 



## 项目部署

### 部署环境



#### 系统需求

#### Linux



#### 软件依赖

* [Boost](https://www.boost.org/) >= 1.76.0
* [CMake](https://cmake.org/) >= 3.5
* [Clang](https://clang.llvm.org/) >= 12.0
* [Python](https://www.python.org/) >= 3.7

在 Ububtu 系统上，除了 Boost 之外的所有内容都可以使用以下命令安装：

```
sudo apt install build-essential libssl-dev cmake clang-12 git curl pkg-config
```



### 部署步骤

#### **1. 克隆存储库**

```bash
git clone https://github.com/ChuanzhouYao/zkSNARK-LLVM.git
cd zkSNARK-LLVM
```

#### **2. 配置CMake**

```bash
cmake -G "Unix Makefiles" -B ${zkllvm_BUILD:-build} -DCMAKE_BUILD_TYPE=Release .
```
#### **3. 构建编译器**

注: 在构建编译器前需要将测试样例 .cpp文件放入examples/cpp文件夹中, 将.inp文件放入examples/inputs文件夹中

```bash
make -C ${zkllvm_BUILD:-build} assigner clang -j$(nproc)
```

### 测试用例

注: 这里使用AES128.cpp以及AES128.inp作为样例演示

**1. 编译器读入测试样例AES128.cpp并在build/examples/cpp文件夹中生成IR文件AES128.ll**

```bash
make -C ${zkllvm_BUILD:-build} AES128 -j$(nproc)
```

 **2. 编译器读入测试样例IR文件AES128.ll, 输出相应的算术电路文本文件AES128.arith以及R1CS文本文件AES128.r1cs**
```bash
${zkllvm_BUILD:-build}/bin/assigner/assigner -b ${zkllvm_BUILD:-build}/examples/cpp/AES128.ll -i examples/inputs/AES128.inp -c AES128.arith -o AES128.in -r AES128.r1cs
```
