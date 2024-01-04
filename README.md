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
# Install virtualenv with pip
pip install virtualenv
# Sometimes virtualenv requires the apt package to be installed
sudo apt install python3-venv
# Create the virtual environment
python3 -m venv env
# Activate the virtual environment. Should be executed every time that there is new terminal session.
source env/bin/activate

# Install the required packages
pip3 install -r requirements.txt
```

To exit the Python Virtual Environment use:
```bash
deactivate
```

------------

## Usage Documentation:
- ### Command-Line Interface:

    **Overview**: The wallet client provides a rebust CLI for operting the Denaro Wallet Client. 
    The CLI supports various sub-commands along with their corresponding options.
    
    *Note: To ensure a high level of security, this wallet client is designed with an auto-delete feature for encrypted wallets. After 10 unsuccessful password attempts, the wallet will be automatically deleted in order to protect its contents and safeguard against unauthorized access. (For more details, please refer to: [feat: Wallet Annihilation](https://github.com/The-Sycorax/DenaroWalletClient/commit/e347b6622d47415ddc531e8b3292c96b42128c9a))*    
    
    - ### Sub-Commands:   
        <details>
        <summary>Expand</summary>
        <dl><dd>
        
        #### `generatewallet`
        **Overview**: The `generatewallet` sub-command is used to generate new wallet files or overwrite existing ones. It will also generate an address for the wallet.
                
        <details>
        <summary>Usage:</summary>
        <dl><dd>
        
        - **Syntax**:
            ```bash
            generatewallet [-h] [-verbose] -wallet <wallet_filename> [-encrypt] [-2fa] [-deterministic] [-password <password>] [-backup <True/False>] [-disable-overwrite-warning] [-overwrite-password <overwrite_password>]
            ```
        
        - **Options**:    
            *Note: The `-password` option must be set for encrypted and/or deterministic wallets.*
        
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.  
            * `-encrypt`: Enables encryption for new wallets.  
            * `-2fa`: Enables 2-Factor Authentication for new encrypted wallets.    
            * `-deterministic`: Enables deterministic address generation for new wallets.
            * `-password`: Password used for wallet encryption and/or deterministic address generation.
            * `-backup`: Disables wallet backup warning when attempting to overwrite an existing wallet. A 'True' or 'False' parameter is required, and will specify if the wallet should be backed up or not.  
            * `-disable-overwrite-warning`: Disables overwrite warning if an existing wallet is not backed up.  
            * `-overwrite-password`: Used to bypass the password confirmation prompt when overwriteing a wallet that is encrypted. A string paramter is required, and should specify the password used for the encrypted wallet.
            
            * `-verbose`: Enables verbose logging of info and debug messages.
        
        </dd></dl>
        </details>
        
        ---
        
        #### `generateaddress`
        **Overview**: The `genrateaddress` sub-command is used to generate new addresses and add them to wallet entry data. For encrypted wallets only the cryptographic keys for addresses are added, which are later used during decryption to derive the data associated with them (e.g. private_key, public_key, and address).

        <details>
        <summary>Usage:</summary>
        <dl><dd>
        
        - **Syntax**:
            ```bash
            generateaddress [-h] [-verbose] -wallet <wallet_filename> [-password <password>] [-2fa-code <tfacode>] [-amount <amount>]
            ```
        
        - **Options**:
            *Note: The `-password` option must be set for encrypted and/or deterministic wallets.*
        
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
            * `-password`: The password of the specified wallet. Required for encrypted and/or deterministic wallets.  
            * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
            * `-amount`: Specifies the amount of addresses to generate (Maximum of 256).
            
            * `-verbose`: Enables verbose logging of info and debug messages.
        
        </dd></dl>
        </details>

        ---
        
        #### `decryptwallet`
        **Overview**: The `decryptwallet` sub-command can either decrypt all entries in a wallet file, or selectivly decrypt specific entries based on a provided filter, and return the decrypted data back to the console.        
        
        *Note: An encrypted wallet is not required to use this sub-command. Therefore, it has been designed to also return data from wallets that are not encrypted.*

        <details>
        <summary>Usage:</summary>  
        <dl><dd>
        
        - **Syntax**:
            ```bash
            decryptwallet [-h] -wallet <wallet_filename> [-2fa-code tfacode] [-pretty] [-password <password>] [-filter <filter>] {filter} ...
            ```
        
        - **Options**:
            *Note: The `-password` option must be set for encrypted wallets.*
            
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
            * `-password`: The password of the specified wallet. Required for wallets that are encrypted.
            * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.  
            * `-filter`: Filter wallet entries by one or more address and/or field. Adding a hyphen `-` to the beginning of an address will exclude it. The filter string must be enclosed in quotation marks and parameter values must be enclosed in curly braces `{}`. *To be removed*.
              * The format is: 
                ```bash 
                -filter="address={ADDRESS_1,-ADDRESS_2,...},field={id,mnemonic,private_key,public_key,address}"
                ```
            
            * `-pretty`: Print formatted JSON output for better readability.
        
        </dd></dl>
        </details>
        
        ---
        
        #### `decryptwallet filter`
        **Overview**: The `decryptwallet filter` sub-command is basically the same as using `decryptwallet -filter` but in this case `-address` and `-field` are two separate options. This sub-command should come directly after the other options that have been provided for `decryptwallet`. Wallet entries can also be filtered based on origin (See `-show` option for more details).
        
        <details>
        <summary>Usage:</summary> 
        <dl><dd>
        
        - **Syntax**:
            ```bash
            decryptwallet <options> filter [-h] [-address <address>] [-field <field>] [-show <generated/imported>][-pretty]
            ```
        
        - **Options**:
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
            * `-show`: Filters wallet entries based on origin. Use `-show generated` to retrieve balance of internally generated entries and `-show imported` for imported entries.
              
            * `-pretty`: Print formatted JSON output for better readability.
        
        </dd></dl>
        </details>

        ---
        
        #### `send`
        **Overview**: The `send` sub-command is used to initiate a transaction in the Denaro blockchain network. This sub-command allows users to send Denaro to a specified address. 
        
        *Note: The source of funds for the transaction (the sender) can be specified in two ways: either by using an address that is associated with a wallet file, or directly via a private key that corresponds to a particular address.*

        <details>
        <summary>Usage:</summary>         
        <dl><dd>
        
        - **Syntax**:
            ```bash
            send [-h] [-node <node_url>] -amount <amount> from [-wallet <wallet_filename>] [-address <sender_address>] [-private-key <private_key>] [-password <password>] [-2fa-code <tfacode>] to <receiver_address> [-message <message>]
            ```
        
        - **Options**:
            * `send`: Main command to initiate a transaction.
                * `-amount`: (Required) Specifies the amount of Denaro to be sent.
        
            * `from <options>`: Specifies the sender's details.
                * `-wallet`: Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
                * `-password`: The password of the specified wallet. Required for wallets that are encrypted.
                * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
                * `-address`: The address from which Denaro will be sent.
                
                * `-private-key`: Specifies the private key associated with the sender address. Not required if specifying an address from a wallet file.    
            
            * `to <options>`: Specifies the receiver's details.
                * `receiver`: (Required) The receiving address.            
                
                * `-message`: Optional transaction message.
        
            * `-node`: Specifies the Denaro node to connect to. Must be a valid IP Address or URL. If not specified or the node is not valid, then the wallet client will use the default Denaro node (https://denaro-node.gaetano.eu.org/).
        
        </dd></dl>
        </details>

        ---
        
        #### `balance`
        **Overview**: The `balance` sub-command is used to check the balance of addresses in the Denaro blockchain that are asociated with a specified wallet file. 
        
        *Note: Similar to `decryptwallet filter`, the `balance` sub-command also has a way to filter wallet entries. The `-address` option can be used to filter one or more addresses that are associated with a wallet. Addresses can be excluded by adding a hyphen (`-`) to the beginning of it. Wallet entries can also be filtered based on origin (See `-show` option for more details).*
        
        <details>
        <summary>Usage:</summary> 
        <dl><dd>
        
        - **Syntax**:
            ```bash
            balance -wallet <wallet_filename> [-password <password>] [-2fa-code <tfacode>] [-address <address>] [-json] [-to-file] [-show <generated/imported>]
            ```
        
        - **Options**:
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
            * `-password`: The password of the specified wallet. Required for wallets that are encrypted.
            * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
            * `-address`: Specifies one or more addresses to get the balance of. Adding a hyphen `-` to the beginning of an address will exclude it.
                * The format is: 
                    ```bash
                    -address=ADDRESS_1,-ADDRESS_2,...
                    ```
            * `-json`: Prints the balance information in JSON format.
            * `-to-file`: Saves the output of the balance information to a file. The resulting file will be in JSON format and named as "*[WalletName]​_balance_[Timestamp].json*" and stored in "*/[WalletDirectory]/balance_information/[WalletName]/*".    
            * `-show`: Filters balance information based on wallet entry origin. Use `-show generated` to retrieve balance of internally generated entries and `-show imported` for imported entries.
            
            * `-node`: Specifies the Denaro node to connect to. Must be a valid IP Address or URL. If not specified or the node is not valid, then the wallet client will use the default Denaro node (https://denaro-node.gaetano.eu.org/).
        
        </dd></dl>
        </details>

        ---
        
        #### `import`
        **Overview**: The `import` sub-command is designed to import a wallet entry into a specified wallet file using the private key of a Denaro address.

        <details>
        <summary>Usage:</summary> 
        <dl><dd>
        
        - **Syntax**:
            ```bash
            import [-h] -private-key <private_key> -wallet <wallet_filename> [-password <password>] [-2fa-code <tfacode>]
            ```
        
        - **Options**:
            * `-wallet`: (Required) Specifies the filename of the wallet file where the imported entries will be added. Defaults to the `./wallets/` directory if no specific filepath is provided.    
            * `-password`: The password of the specified wallet. Required for wallets that are encrypted.    
            * `-2fa-code=<tfacode>`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
            
            * `-private-key`: Specifies the private key of a Denaro address. Used to generate the corresponding entry data which will be imported into a wallet file.
            
        </dd></dl>
        </details>
        </dd></dl>
        </details>        

- ### Usage Examples:
    <details>
    <summary>Expand</summary>
    
    - ### Generating New Wallets:
        <details>
        <summary>Expand</summary>
        <dl><dd>
        <i>Note: The wallet filename does not require a .json extension to be added as this is entirely optional. By default, the script will add the extension to the filename if not present.</i>
        </dd><dd>
        
        *If the wallet specified already exists the user will be prompted with a warning and asked if they want to backup the existing wallet. If the user chooses not to back up an existing wallet, then they will be prompted with an additional warning and asked to confirm the overwrite of the existing wallet. When overwriting an encrypted wallet, the password associated with the it is required, and the user will be prompted to type it in. The user can choose to bypass one or more of these prompts with the use of `-backup`, `-disable-overwrite-warning`, or `-overwrite-password` (Refer to [generatewallet](#generatewallet) options for details).*
        
        
        
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
        </details>
    
    - ### Address Generation:
        <details>
        <summary>Expand</summary>
        
        * Generates an address for a wallet that is un-encrypted and/or non-deterministic:
            ```bash
            python3 wallet_client.py generateaddress -wallet=wallet.json
            ```
        * Generates an address for a wallet that is encrypted and/or deterministic:
            ```bash
            python3 wallet_client.py generateaddress -wallet=wallet.json -password=MySecurePassword
            ```
        </details>
    
    - ### Wallet Decryption:
        <details>
        <summary>Expand</summary>
        
        *Note: An encrypted wallet is not required to use this sub-command. Therefore, it has been designed to also return data from wallets that are not encrypted.*

        * Decrypts an entire wallet:
            ```bash
            python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword
            ```
        </details>
    
    - ### Wallet Decryption with Filtering:
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
        <summary>Filtering Examples:</summary>
        
        <dl><dd>
        To get an idea of how filtering works, below are a few examples.
        
        *Note: The following addresses are used only for these examples and you should use your own.*
        
        <details>
        <summary>Retrieves all of the data associated with the addess specified.</summary>
          
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4}"
        ```
        </details>
        <details>
        <summary>Excludes an address from the results, and will only retrieve the data associated with the rest of the wallet entries if any:</summary>
          
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4}"
        ```
        </details>
        <details>
        <summary>Excludes an address from the results, and will retrieve only the 'mnemonic' associated with the rest of the wallet entries if any:</summary>
        
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=mnemonic
        ```
        </details>
        <details>
        <summary>Retrieves all of the data associated for the multiple addresses specified:</summary>
        
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA}"
        ```
        </details>
        <details>
        <summary>Retrieves only the 'private_key' and 'public_key' associated with the multiple addresses specified:</summary>
          
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword -filter="address={DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA},field={private_key,public_key}"
        ```
        </details>
        <details>
        <summary>Excludes the specified addresses from the results, and will retrieve only the 'public_key' and `id` associated with the rest of the wallet entries if any:</summary>
        
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=public_key,id
        ```
        </details>
        <details>
        <summary>Retrieves only the 'address' associated with all wallet entries:</summary>
          
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -field=address
        ```
        </details>
        </dd></dl>
        </details>
    
    - ### Making a Transaction:
        <details>
        <summary>Expand</summary>
        
        *Note: If a wallet is encrypted, be sure to specify the password for it.*
        * Sends 100 Denaro to a recipient using an address associated with a wallet:        
            ```bash
            python3 wallet_client.py send -amount=100 from -wallet=wallet.json -address=DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4 to DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA
            ```
        * Sends 100 Denaro to a recipient using the priate key associated with a Denaro address:
            
            *Private keys should be in hexdecimal format and are generally 64 characters in length. It is not reccomended to directly specify a private key, as this could lead to the irreversable loss of funds if anyone has access to it. The private in this example was randomly generated and dose not have funds.*

            ```bash
            python3 wallet_client.py send -amount=100 from -private-key=43c718efb31e0fef4c94cbd182e3409f54da0a8eab8d9713f5b6b616cddbf4cf to DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA
            ```
        </details>
    
    - ### Checking Balances:
        <details>
        <summary>Expand</summary>
        
        *Note: If a wallet is encrypted, be sure to specify the password for it.*
        * Retrieves the balance information of all wallet entries:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json
            ```
        * Prints the balance information of wallet entries in json format:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -json
            ```
        * Saves the json output of balance information of wallet entries to a file:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -to-file
            ```
        </details>
        
        <details>
        <summary>Filtering Examples:</summary>
            
        As mentioned in the usage documentation, the `balance` sub-command has a way to filter wallet entries similar to `decryptwallet filter`. The `-address` option can be used to filter one or more addresses that are associated with a wallet. Addresses can be excluded by adding a hyphen (`-`) to the beginning of it. Addresses can also be filtered based on origin (See `-show` option for more details).
        
        Many filter combinations can be used. Below are just a few examples but for more information please refer to the "Wallet Decryption with Filtering" section.
        
        *Note: If a wallet is encrypted, be sure to specify the password for it.*
        
        * Will only retrieve the balance information of imported wallet entries:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -show=imported
            ```
        * Will only retrieve the balance information of generated wallet entries:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -show=generated
            ```
        * Retrieves the balance information of a specific address associated with a wallet:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -address=DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4
            ```
        
        * Retrieves the balance information of multiple addresses associated with a wallet:
            
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -address=DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA
            ```
            
        * Retrieves the balance information of all wallet entries but excludes specific addresses:
        
            ```bash
            python3 wallet_client.py balance -wallet=wallet.json -address=-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,-DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA
            ```
        </details>
    
    - ### Importing a Wallet Entry:
        <details>
        <summary>Expand</summary>
        
        *Note: If a wallet is encrypted, be sure to specify the password for it.*
        
        *Private keys should be in hexdecimal format and are generally 64 characters in length. It is not reccomended to directly specify a private key, as this could lead to the irreversable loss of funds if anyone has access to it. The private in this example was randomly generated and dose not have funds.*
        
        * Imports a wallet entry based on the private key of a Denaro address:
            
            ```bash
            python3 wallet_client.py import -wallet=wallet.json -private-key=43c718efb31e0fef4c94cbd182e3409f54da0a8eab8d9713f5b6b616cddbf4cf
            ```
        </details>
    </details>

------------

## Disclaimer:

Neither The-Sycorax nor contributors of this project assume liability for any loss of funds incurred through the use of this software! This software is provided 'as is' under the [MIT License](LICENSE) without guarantees or warrenties of any kind, express or implied. It is strongly recommended that users back up their cryptographic keys. User are solely responsible for the security and management of their assets! The use of this software implies acceptance of all associated risks, including financial losses, with no liability on The-Sycorax or contributors of this project.

------------

## License:
The Denaro Wallet Client is released under the terms of the MIT license. See [LICENSE](LICENSE) for more
information or see https://opensource.org/licenses/MIT.
