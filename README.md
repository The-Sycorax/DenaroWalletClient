# Denaro Wallet Client
This repo contains the source code for a wallet client developed for the Denaro cryptocurrency. Designed for high-level security and asset management, the client can be adapted for use with other cryptocurrencies. It employs multiple security mechanisms and dual-layer encryption, using ChaCha20-Poly1305 and AES-GCM, to safeguard cryptographic keys.

# Installation
```bash
git clone https://github.com/The-Sycorax/DenaroWalletClient.git
cd DenaroWalletClient
sudo apt install libgmp-dev
pip install virtualenv
sudo apt-get install python3-venv # Use this is pip installation fails for virtualenv
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
```

# Usage
### Command-Line Interface

The wallet client provides a CLI for managing and decrypting wallet data. 
The CLI supports various sub-commands (`generatewallet`, `generateaddress`, and `decryptwallet`) and their corresponding options.

### Options
#### `generatewallet`
*Note: `-password` must be set for encrypted and/or deterministic wallets.*
- `-wallet`: Specify the wallet filename (Required).
- `-encrypt`: Encrypt the new wallet.
- `-2fa`: Enables 2-Factor Authentication for the new encrypted wallet.
- `-password`: Password used for wallet encryption and/or deterministic address generation.
- `-deterministic`: Generates a deterministic wallet.
- `-backup`: Enables or disables the backup of an existing wallet. Choose either 'True' or 'False'.
- `-disable-overwrite-warning`: Disables warning when overwriting an existing wallet.
- `-overwrite-password`: Password to overwrite an existing wallet that is encrypted.
  
#### `generateaddress`
*Note: `-password` must be set if the wallet specified is encrypted and/or deterministic.*
- `-wallet`: Specify the wallet filename (Required).
- `-2fa-code`: Two-Factor Authentication code for 2FA enabled wallets (Generated from an authenticator app).
- `-password`: The password used for encryption and/or deterministic address generation of the specified wallet.

#### `decryptwallet`
*Note: `decryptwallet` will not work if a wallet is unencrypted.*
- `-wallet`: Specify the wallet filename (Required).
- `-2fa-code`: Two-Factor Authentication code for 2FA enabled wallets (Generated from an authenticator app).
- `-pretty`: Print formatted JSON output for better readability.
- `-password`: The password used for encryption of the specified wallet (Required).
- `-filter`: Filter wallet entries by address and/or field using the `-filter` argument. The format is `"address={ADDRESS},field={id,mnemonic,private_key,public_key,address}"`.

##### `decryptwallet filter`
`decryptwallet filter` is basically the same as `decryptwallet -filter` but `-address` and `-field` are two separate arguments.

*Note: This is a positional argument and should come directly after the other options for `decryptwallet`. Think of it as a sub-group `decryptwallet` but with it's own separate options.*
- `-address`: Address to filter entry by.
- `-field`: Field(s) to filter by. Provide one or more of the following, separated by commas: `id`, `mnemonic`, `private_key`, `public_key`, `address`.
- `-pretty`: Print formatted JSON output for better readability (Not required if already used).

------------
## Usage Examples:
#### Generating New Wallets:
*Note: The wallet filename does not require a .json extension to be added as it is entirely optional. The script will add the extension to the filename by default if not present.*

*If the wallet specified already exists the user will be prompted with a standard warning and asked if they want to backup the existing wallet. The user will be prompted with an additional warning and asked to confirm the overwrite of the existing wallet is they choose not to back it up. A password will be required if the existing wallet is encrypted. The user can choose to bypass one or more of these prompts with the use of `-backup`, `-disable-overwrite-warning`, or `-overwrite-password`.*

##### Examples:
- Generates an un-encrypted, non-deterministic wallet
```bash
python wallet_client.py generatewallet -wallet=wallet.json
```
- Generates an encrypted, non-deterministic wallet
```bash
python wallet_client.py generatewallet -encrypt -wallet=wallet.json -password=SecurePassword
```
- Generates a deterministic wallet
```bash
python wallet_client.py generatewallet -deterministic -wallet=wallet.json -password=SecurePassword
```
- Generates an encrypted, deterministic wallet, with 2-Factor Authentication
```bash
python wallet_client.py generatewallet -encrypt -deterministic -2fa -wallet=wallet.json -password=SecurePassword
```

------------

#### Address Generation
##### Examples:
- Generates an address for a wallet that is un-encrypted and/or non-deterministic
```bash
python wallet_client.py generateaddress -wallet=wallet.json
```
- Generates an address for a wallet that is encrypted and/or deterministic
```bash
python wallet_client.py generateaddress -wallet=wallet.json -password=SecurePassword
```

------------

#### Wallet Decryption
##### Example:
```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword
```

------------

#### Wallet Decryption with Filtering:
##### Overview:
- *To exclude specific addresses from the filtered results a hyphen ('-') can be added before the specified address.*
- *Addresses will only be filtered if they are apart of the wallet that is being decrypted.*
- *One or more addresses can be specified.*
- *If one or more fields are not specified then all fields are included in the filtered results (id, 
mnemonic, private_key, public_key, and address)*
- *When it comes to filtering wallet entries, there is no difference if the `-filter` argument is used instead of the `filter` positional argument en vice versa. The results will be always be the same.*

##### Filtering Examples:
*Note: The following addresses are used only for these examples.*

<details>
<summary>This filter will retrieve all of the data associated for 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4'.</summary>
  
```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4}"
```
</details>
<details>
<summary>This filter excludes 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' from the results, and will only retrieve the data associated with the rest of the wallet entries if any.</summary>
  
```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4}"
```
</details>
<details>
<summary>This filter excludes 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA' from the results, and will retrieve only the 'mnemonic' associated with the rest of the wallet entries if any.</summary>

```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=mnemonic
```
</details>
<details>
<summary>This filter will retrieve all of the data associated for 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' and 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA'.</summary>

```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA}"
```
</details>
<details>
<summary>This filter will retrieve only the 'private_key' and 'public_key' associated with 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' and 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA'.</summary>
  
```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA},field={private_key,public_key}"
```
</details>
<details>
<summary>This filter excludes 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' and 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA' from the results, and will retrieve only the 'public_key' and `id` associated with the rest of the wallet entries if any.</summary>

```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=public_key,id
```
</details>
<details>
<summary>This filter will retrieve only the 'address' associated with all wallet entries.</summary>
  
```bash
python wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -field=address
```
</details>
