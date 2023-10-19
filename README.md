# Denaro Wallet Client
This repo contains the source code for a wallet client developed for the Denaro cryptocurrency. Designed for high-level security and asset management, the client can be adapted for use with other cryptocurrencies. It employs multiple security mechanisms and dual-layer encryption, using ChaCha20-Poly1305 and AES-GCM, to safeguard cryptographic keys.

Github repo for the Denaro cryptocurrency: https://github.com/denaro-coin/denaro

## Installation Guide:
```bash
# Clone the repository
git clone https://github.com/The-Sycorax/DenaroWalletClient.git
cd DenaroWalletClient

# Update package list and install required library
sudo apt update
sudo apt install libgmp-dev

# Setting Up a Python Virtual Environment (optional but recommended)
# Install virtualenv with pip; if pip installation fails apt is used
pip install virtualenv || sudo apt install python3-venv
# Create and activate the virtual environment
python3 -m venv env && source env/bin/activate 

# Install the required packages
pip3 install -r requirements.txt
```

To Deactivate the Python Virtual Environment use:
```bash
deactivate
```
------------
## Usage
### Command-Line Interface:

The wallet client provides a CLI for managing and decrypting wallet data. 
The CLI supports various sub-commands (`generatewallet`, `generateaddress`, and `decryptwallet`) and their corresponding options.

### Sub-Commands:

#### `generatewallet`
<details>
<summary>Options</summary>

*Note: `-password` must be set for encrypted and/or deterministic wallets.*
* `-wallet`: Specify the wallet filename (Required).
* `-encrypt`: Encrypt the new wallet.
* `-2fa`: Enables 2-Factor Authentication for the new encrypted wallet.
* `-password`: Password used for wallet encryption and/or deterministic address generation.
* `-deterministic`: Generates a deterministic wallet.
* `-backup`: Enables or disables the backup of an existing wallet. Choose either 'True' or 'False'.
* `-disable-overwrite-warning`: Disables warning when overwriting an existing wallet.
* `-overwrite-password`: Password to overwrite an existing wallet that is encrypted.
</details>

#### `generateaddress`
<details>
<summary>Options</summary>

*Note: `-password` must be set if the wallet specified is encrypted and/or deterministic.*
* `-wallet`: Specify the wallet filename (Required).
* `-2fa-code`: Two-Factor Authentication code for 2FA enabled wallets (Generated from an authenticator app).
* `-password`: The password used for encryption and/or deterministic address generation of the specified wallet.
</details>

#### `decryptwallet`
<details>
<summary>Options</summary>

*Note: `decryptwallet` will not work if a wallet is unencrypted.*
* `-wallet`: Specify the wallet filename (Required).
* `-2fa-code`: Two-Factor Authentication code for 2FA enabled wallets (Generated from an authenticator app).
* `-password`: The password used for encryption of the specified wallet (Required).
* `-filter`: Filter wallet entries by address and/or field. Add a hyphen (-) to the beginning of an address to exclude it. 
The format is:`-filter="address={ADDRESS_1, ADDRESS_2, ADDRESS_3, ...},field={id,mnemonic,private_key,public_key,address}"`.The entire filter string must be enclosed in quotation marks and parameters must be enclosed in curly braces `{}`
* `-pretty`: Print formatted JSON output for better readability.
</details>

#### `decryptwallet filter`
<details>
<summary>Options</summary>

*Note: Using `decryptwallet filter` is basically the same as using `decryptwallet -filter` but in this case `-address` and `-field` are two separate options. Also this is a positional argument, therefore it should come directly after the other options for `decryptwallet`.*

* `-address`: One or more addresses to filter by. Add a hyphen (-) to the beginning of an address to exclude it. The format is: `filter address=ADDRESS_1, ADDRESS_2, ADDRESS_3,...`
* `-field`: One or more fields to filter by. The format is: `filter field=id,mnemonic,private_key,public_key,address`.
* `-pretty`: Print formatted JSON output for better readability.
</details>

------------

## Usage Examples:

### Generating New Wallets:
*Note: The wallet filename does not require a .json extension to be added as it is entirely optional. The script will add the extension to the filename by default if not present.*

*If the wallet specified already exists the user will be prompted with a standard warning and asked if they want to backup the existing wallet. If the user chooses not to back up an existing wallet, then they will be prompted with an additional warning and asked to confirm the overwrite of the existing wallet. A password will be required to overwrite an existing wallet if it is encrypted. The user can choose to bypass one or more of these prompts with the use of `-backup`, `-disable-overwrite-warning`, or `-overwrite-password` (Refer to [generatewallet](#generatewallet) options for details).*

#### Examples:
* Generates an un-encrypted, non-deterministic wallet:
    ```bash
    python3 wallet_client.py generatewallet -wallet=wallet.json
    ```
* Generates an encrypted, non-deterministic wallet:
    ```bash
    python3 wallet_client.py generatewallet -encrypt -wallet=wallet.json -password=MySecurePassword
    ```
* Generates a deterministic wallet:
    ```bash
    python3 wallet_client.py generatewallet -deterministic -wallet=wallet.json -password=MySecurePassword
    ```
* Generates an encrypted, deterministic wallet, with 2-Factor Authentication:
    ```bash
    python3 wallet_client.py generatewallet -encrypt -deterministic -2fa -wallet=wallet.json -password=MySecurePassword
    ```

------------

### Address Generation:
#### Examples:
* Generates an address for a wallet that is un-encrypted and/or non-deterministic:
    ```bash
    python3 wallet_client.py generateaddress -wallet=wallet.json
    ```
* Generates an address for a wallet that is encrypted and/or deterministic:
    ```bash
    python3 wallet_client.py generateaddress -wallet=wallet.json -password=MySecurePassword
    ```

------------

### Wallet Decryption:
#### Example:
* Decrypts an entire wallet:
    ```bash
    python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword
    ```

------------

### Wallet Decryption with Filtering:
#### Overview:
* *To exclude specific addresses from the filtered results a hyphen `-` can be added before the specified address.*
* *One or more addresses can be specified.*
* *Addresses will only be filtered if they are apart of the wallet that is being decrypted.*
* *If one or more fields are not specified then all fields are included in the filtered results (id, 
mnemonic, private_key, public_key, and address).*
* *When it comes to filtering wallet entries, there is no difference if the `-filter` option is used over of the `filter` positional argument et vice versa. The results will be always be the same.*
* *Various filtering combinations can be used.*

#### Filter Examples:
To get an idea of how filtering works, below are a few examples.

*Note: The following addresses are used only for these examples and you should use your own.*

<details>
<summary>Retrieves all of the data associated for 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4'.</summary>
  
```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4}"
```
</details>
<details>
<summary>Excludes 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' from the results, and will only retrieve the data associated with the rest of the wallet entries if any:</summary>
  
```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4}"
```
</details>
<details>
<summary>Excludes 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA' from the results, and will retrieve only the 'mnemonic' associated with the rest of the wallet entries if any:</summary>

```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=mnemonic
```
</details>
<details>
<summary>Retrieves all of the data associated for 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' and 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA':</summary>

```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA}"
```
</details>
<details>
<summary>Retrieves only the 'private_key' and 'public_key' associated with 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' and 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA':</summary>
  
```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA},field={private_key,public_key}"
```
</details>
<details>
<summary>Excludes 'DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4' and 'DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA' from the results, and will retrieve only the 'public_key' and `id` associated with the rest of the wallet entries if any:</summary>

```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=public_key,id
```
</details>
<details>
<summary>Retrieve only the 'address' associated with all wallet entries:</summary>
  
```bash
python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -field=address
```
</details>

------------

## License:
The Denaro Wallet Client is released under the terms of the MIT license. See [LICENSE](LICENSE) for more
information or see https://opensource.org/licenses/MIT.