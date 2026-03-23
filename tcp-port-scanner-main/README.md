# TCP Port Scanner with Service Detection

## Requirements
Ubuntu / WSL2, gcc, g++, python3, make, docker

## Setup
```bash
sudo apt install -y gcc g++ python3 python3-pip make docker.io
sudo pip3 install flask --break-system-packages
make
```

## Start test targets
```bash
sudo systemctl start docker
sudo docker run -d -p 8080:80  --name test_http httpd:alpine
sudo docker run -d -p 2222:22 --name test_ssh  rastasheep/ubuntu-sshd:18.04
sudo docker run -d -p 2121:21 --name test_ftp  stilliard/pure-ftpd
```

## Get container IPs
```bash
sudo docker inspect test_http | grep '"IPAddress"'
sudo docker inspect test_ssh  | grep '"IPAddress"'
sudo docker inspect test_ftp  | grep '"IPAddress"'
```

## Run UI
```bash
sudo python3 python/server.py
```
Open http://localhost:5000

## Run scanner directly
```bash
sudo ./scanner_main --target <ip> --source <your-ip> --ports 1-1024 --threads 200 --timeout 2 --retries 1 --output results.json
```
