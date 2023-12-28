# Denaro Wallet ClientV2
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
# Install virtualenv with pip
pip install virtualenv
# Sometimes virtualenv requires the apt package to be installed
sudo apt install python3-venv
# Create the virtual environment
python3 -m venv env
# Activate the virtual environment
source env/bin/activate

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

*Note: To ensure a high level of security, this wallet client is designed with an auto-delete feature for encrypted wallets. After 10 unsuccessful password attempts, the wallet will be automatically deleted in order to protect its contents and safeguard against unauthorized access. (For more details, please refer to: [feat: Wallet Annihilation](https://github.com/The-Sycorax/DenaroWalletClient/commit/e347b6622d47415ddc531e8b3292c96b42128c9a))*

### Sub-Commands:
<dl><dd>

#### `generatewallet`:
**Overview**: The `generatewallet` sub-command is used to generate new wallet files or overwrite existing ones. It will also generate an address for the wallet.
<dl><dd>
    
*Note: `-password` must be set for encrypted and/or deterministic wallets.*
* `-wallet`: Specifies the wallet filename (Required).
  
* `-encrypt`: Enables encryption for new wallets.
  
* `-2fa`: Enables 2-Factor Authentication for new encrypted wallets.
  
* `-password`: Password used for wallet encryption and/or deterministic address generation.
  
* `-deterministic`: Enables deterministic address generation for new wallets.
  
* `-backup`: Disables wallet backup warning when attempting to overwrite an existing wallet. A 'True' or 'False' parameter is required, and will specify if the wallet should be backed up or not.
  
* `-disable-overwrite-warning`: Disables overwrite warning if an existing wallet is not backed up.
  
* `-overwrite-password`: Used to bypass the password confirmation prompt when overwriteing a wallet that is encrypted. A string paramter is required, and should specify the password used for the encrypted wallet.
</dd></dl>

---

#### `generateaddress`:
**Overview**: The `genrateaddress` sub-command is used to generate new addresses and add them to wallet entry data. For encrypted wallets only the cryptographic keys for addresses are added, which are later used during decryption to derive the data associated with them (id, mnemonic, private_key, public_key, and address).
<dl><dd>

*Note: `-password` must be set if the wallet specified is encrypted and/or deterministic.*
* `-wallet`: Specifies the wallet filename (Required).
  
* `-2fa-code`: Two-Factor Authentication code for 2FA enabled wallets (Generated from an authenticator app).
  
* `-password`: Password used for encryption and/or deterministic address generation of the specified wallet.
</dd></dl>

---

#### `decryptwallet`:
**Overview**: The `decryptwallet` sub-command can either decrypt all wallet entries, or selectivly decrypt wallet entries based on a provided filter (See below), and return the data back to the console.  
<dl><dd>

*Note: `decryptwallet` will not work if a wallet is unencrypted.*
* `-wallet`: Specifies the wallet filename (Required).
  
* `-2fa-code`: Two-Factor Authentication code for 2FA enabled wallets (Generated from an authenticator app).
  
* `-password`: Password used for decryption of the specified wallet (Required).
  
* `-filter`: Filter wallet entries by one or more address and/or field. Adding a hyphen `-` to the beginning of an address will exclude it. The filter string must be enclosed in quotation marks and parameter values must be enclosed in curly braces `{}`. 
  * The format is: 
    ```bash 
    -filter="address={ADDRESS_1,-ADDRESS_2,...},field={id,mnemonic,private_key,public_key,address}"
    ```

* `-pretty`: Print formatted JSON output for better readability.
</dd></dl>

---

#### `decryptwallet filter`:
**Overview**: `decryptwallet filter` is basically the same as using `decryptwallet -filter` but in this case `-address` and `-field` are two separate options. This is a positional argument, and should come directly after the other options provided for `decryptwallet`.
<dl><dd>

* `-address`: One or more addresses to filter by. Adding a hyphen `-` to the beginning of an address will exclude it. 
    * The format is: 
        ```bash
        fliter -address=ADDRESS_1,-ADDRESS_2,...
        ```
  
* `-field`: One or more fields to filter by. 
    * The format is: 
        ```bash
        -field=id,mnemonic,private_key,public_key,address
        ```
  
* `-pretty`: Print formatted JSON output for better readability.
</dd></dl>

</dl></dd>

------------

## Usage Examples:

### Generating New Wallets:
<details>
<dl><dd>
<i>Note: The wallet filename does not require a .json extension to be added as this is entirely optional. By default, the script will add the extension to the filename if not present.</i>
</dd><dd>

*If the wallet specified already exists the user will be prompted with a warning and asked if they want to backup the existing wallet. If the user chooses not to back up an existing wallet, then they will be prompted with an additional warning and asked to confirm the overwrite of the existing wallet. When overwriting an encrypted wallet, the password associated with the it is required, and the user will be prompted to type it in. The user can choose to bypass one or more of these prompts with the use of `-backup`, `-disable-overwrite-warning`, or `-overwrite-password` (Refer to [generatewallet](#generatewallet) options for details).*

<summary>Expand:</summary>

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
* Creates a back up of an existing encrypted wallet and overwrites it with an un-encrypted, deterministic wallet, while skipping various prompts: 
    ```bash
    python3 wallet_client.py generatewallet -wallet=wallet.json -deterministic -backup=True -disable-overwrite-warning -overwrite-password=MySecurePassword
    ```
* Imports Privatekey Hex : 
    ```bash
    python3 wallet_client.py importkey -privatekey PK -wallet walletname
    ```
</details>

* Shows Imported Wallets information Privatekey, Publickey, Address, Mnemonic : 
    ```bash
    python3 wallet_client.py showimportedkeys -wallet wallet -password password
    ```
</details>

### Address Generation:
<details>
<summary>Expand:</summary>

* Generates an address for a wallet that is un-encrypted and/or non-deterministic:
    ```bash
    python3 wallet_client.py generateaddress -wallet=wallet.json
    ```
* Generates an address for a wallet that is encrypted and/or deterministic:
    ```bash
    python3 wallet_client.py generateaddress -wallet=wallet.json -password=MySecurePassword
    ```
</details>

### Wallet Decryption:
<details>
<summary>Expand:</summary>

* Decrypts an entire wallet:
    ```bash
    python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword
    ```
</details>

### Wallet Decryption with Filtering:
<details>
<summary>Overview:</summary>

* *To exclude specific addresses from the filtered data a hyphen `-` can be added before the specified address.*
* *One or more addresses can be specified.*
* *Addresses will only be filtered if they are apart of the wallet that is being decrypted.*
* *If one or more fields are not specified, then all fields are included in the filtered data (id, 
mnemonic, private_key, public_key, and address).*
* *When it comes to filtering wallet entries, there is no difference if the `-filter` option is used over of the `filter` positional argument et vice versa. The returned data will be always be the same.*
* *Various filtering combinations can be used.*
</details>
<details>
<summary>Filter Examples:</summary>

<dl>
<dd>
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
</dd>
</dl>
</details>

------------

## Disclaimer:

Neither The-Sycorax nor contributors of this project assume liability for any loss of funds incurred through the use of this software! This software is provided 'as is' under the [MIT License](LICENSE) without guarantees or warrenties of any kind, express or implied. It is strongly recommended that users back up their cryptographic keys. User are solely responsible for the security and management of their assets! The use of this software implies acceptance of all associated risks, including financial losses, with no liability on The-Sycorax or contributors of this project.

------------

## License:
The Denaro Wallet Client is released under the terms of the MIT license. See [LICENSE](LICENSE) for more
information or see https://opensource.org/licenses/MIT.
