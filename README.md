# Denaro Wallet Client
This repo contains the source code for a wallet client developed for the Denaro cryptocurrency. Designed for high-level security and asset management, the client can be adapted for use with other cryptocurrencies. It employs multiple security mechanisms and dual-layer encryption, using ChaCha20-Poly1305 and AES-GCM, to safeguard cryptographic keys.

# Installation
```bash
git clone https://github.com/The-Sycorax/DenaroWalletClient.git
cd DenaroWalletClient
sudo apt install libgmp-dev
pip install virtualenv or sudo apt-get install python3-venv
python3 -m venv env
pip3 install -r requirements.txt