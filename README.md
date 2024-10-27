# openssl-demo
OpenSSL学习示例

### 项目构建
#### macOS
cmake -G "Ninja Multi-Config" -S . -B build -DCMAKE_CXX_COMPILER="/usr/local/opt/llvm/bin/clang++"
cmake --build build --config Release