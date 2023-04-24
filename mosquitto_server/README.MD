## About this project
This project is used to validate TLS 1.3 connection with openssl and mosquitto server. 

### Note
This project is still **working in progress**.

## How to run
1. Open the project in codespace.
1. Open a terminal and run following commands.
    ```
    cd tools
    sudo ./init_network.sh
    cd ../mosquitto_server
    openssl s_server -port 8883 -cert server.crt -key server.key
    ```
1. Open a new terminal and build the project. Make sure the path is at the root of this repository.
    ```
    cd mosquitto_server
    cmake -GNinja -Bbuild
    cmake --build build
    ```
1. Run NetX simulator.
    ```
    sudo ./build/mosquitto_server
    ```

## Output from NetX
```
DHCP In Progress...
IP address: 192.168.1.100
Mask: 255.255.255.0
Gateway: 192.168.1.1
TCP connection established
TLS session established
```

