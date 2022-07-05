## About this project
This project is used to reproduce the issue described [here](https://github.com/azure-rtos/netxduo/issues/112).

## How to run
1. Open the project in codespace.
1. Open a terminal and run following commands.
  ```
  cd tools
  sudo ./init_network.sh
  ./cert_gen.sh
  ```
1. Open a new terminal and build the project. Make sure the path is at the root of this repository.
  ```
  cmake -GNinja -Bbuild
  cmake --build build
  ```
1. Run NetX simulator.
  ```
  sudo ./build/issue_112/issue_112
  ```

## Output from NetX
```
DHCP In Progress...
IP address: 192.168.1.100
Mask: 255.255.255.0
Gateway: 192.168.1.1
DNS Server address: 1.1.1.1
Resolving hostname: github.com
IP address of github.com: : 20.205.243.166
TCP connection established
TLS session established
```

