## About this project
This project is used to reproduce the issue described [here](https://github.com/azure-rtos/netxduo/issues/107).

## How to run
1. Open the project in codespace.
1. Open a terminal and run following commands.
  ```
  cd tools
  sudo ./init_network.sh
  ./cert_gen.sh
  head -c 1024KiB test.txt |openssl s_server -port 4433 -quiet -cert cert.pem -key privkey.pem -CApath . -keylogfile keylog
  ```
1. Open a new terminal and build the project. Make sure the path is at the root of this repository.
  ```
  cmake -GNinja -Bbuild
  cmake --build build
  ```
1. Run NetX simulator.
  ```
  sudo ./build/issue_107/issue_107
  ```

## Output from NetX
```
NetXDuo is running
IP address: 192.168.1.2
Mask: 255.255.255.0
TCP connection established
TLS session established
Received packet: 16384 bytes, total 0016384 bytes
Received packet: 16384 bytes, total 0032768 bytes
Received packet: 16384 bytes, total 0049152 bytes
Received packet: 16384 bytes, total 0065536 bytes
Received packet: 16384 bytes, total 0081920 bytes
Received packet: 16384 bytes, total 0098304 bytes
Received packet: 16384 bytes, total 0114688 bytes
Received packet: 16384 bytes, total 0131072 bytes
Received packet: 16384 bytes, total 0147456 bytes
Received packet: 16384 bytes, total 0163840 bytes
Received packet: 16384 bytes, total 0180224 bytes
Received packet: 16384 bytes, total 0196608 bytes
Received packet: 16384 bytes, total 0212992 bytes
Received packet: 16384 bytes, total 0229376 bytes
Received packet: 16384 bytes, total 0245760 bytes
Received packet: 16384 bytes, total 0262144 bytes
Received packet: 16384 bytes, total 0278528 bytes
Received packet: 16384 bytes, total 0294912 bytes
Received packet: 16384 bytes, total 0311296 bytes
Received packet: 16384 bytes, total 0327680 bytes
Received packet: 16384 bytes, total 0344064 bytes
Received packet: 16384 bytes, total 0360448 bytes
Received packet: 16384 bytes, total 0376832 bytes
Received packet: 16384 bytes, total 0393216 bytes
Received packet: 16384 bytes, total 0409600 bytes
Received packet: 16384 bytes, total 0425984 bytes
Received packet: 16384 bytes, total 0442368 bytes
Received packet: 16384 bytes, total 0458752 bytes
Received packet: 16384 bytes, total 0475136 bytes
Received packet: 16384 bytes, total 0491520 bytes
Received packet: 16384 bytes, total 0507904 bytes
Received packet: 16384 bytes, total 0524288 bytes
Received packet: 16384 bytes, total 0540672 bytes
Received packet: 16384 bytes, total 0557056 bytes
Received packet: 16384 bytes, total 0573440 bytes
Received packet: 16384 bytes, total 0589824 bytes
Received packet: 16384 bytes, total 0606208 bytes
Received packet: 16384 bytes, total 0622592 bytes
Received packet: 16384 bytes, total 0638976 bytes
Received packet: 16384 bytes, total 0655360 bytes
Received packet: 16384 bytes, total 0671744 bytes
Received packet: 16384 bytes, total 0688128 bytes
Received packet: 16384 bytes, total 0704512 bytes
Received packet: 16384 bytes, total 0720896 bytes
Received packet: 16384 bytes, total 0737280 bytes
Received packet: 16384 bytes, total 0753664 bytes
Received packet: 16384 bytes, total 0770048 bytes
Received packet: 16384 bytes, total 0786432 bytes
Received packet: 16384 bytes, total 0802816 bytes
Received packet: 16384 bytes, total 0819200 bytes
Received packet: 16384 bytes, total 0835584 bytes
Received packet: 16384 bytes, total 0851968 bytes
Received packet: 16384 bytes, total 0868352 bytes
Received packet: 16384 bytes, total 0884736 bytes
Received packet: 16384 bytes, total 0901120 bytes
Received packet: 16384 bytes, total 0917504 bytes
Received packet: 16384 bytes, total 0933888 bytes
Received packet: 16384 bytes, total 0950272 bytes
Received packet: 16384 bytes, total 0966656 bytes
Received packet: 16384 bytes, total 0983040 bytes
Received packet: 16384 bytes, total 0999424 bytes
Received packet: 16384 bytes, total 1015808 bytes
Received packet: 16384 bytes, total 1032192 bytes
Received packet: 16384 bytes, total 1048576 bytes
```

