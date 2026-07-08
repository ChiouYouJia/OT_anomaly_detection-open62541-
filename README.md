## Usage  
open62541 (v1.5.5) 已經在裡面了，整個一起pull下來後  
```bash
cd open62541
mkdir -p build && cd build //如果有看到build記得先刪掉
git submodule update --init --recursive
cmake -DCMAKE_BUILD_TYPE=Release \
      -DUA_ENABLE_PUBSUB=ON \
      -DUA_ENABLE_ENCRYPTION=ON \
      -DUA_ENABLE_ENCRYPTION_MBEDTLS=ON \
      -DUA_ENABLE_PUBSUB_SKS=ON \
      -DUA_NAMESPACE_ZERO=FULL \
      -DUA_BUILD_EXAMPLES=OFF \
      -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local ..
make
sudo make install
sudo ldconfig
```

## 進度
目前完成到PubSub sks加密，但是SKS尚要查詢確切規範  
加密過的封包有擷取的問題(可能要透過修改open62541的code來解決金鑰的問題)  
gds_server尚有很多bug，且debug和維護有難度
