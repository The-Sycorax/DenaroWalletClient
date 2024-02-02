# Denaro wallet V0.0.6-Beta, DenaroWalletClient GUI #

make sure to import manually the file including wallets files .or generate a new one in the second tab encrypted or non encrypted

    New Features:
        The ability to view the real-world value of Denaro balances.
        Generating Denaro paper wallets.
        Improved wallet decryption.


RUN : UI.py

![Screenshot from 2024-02-02 02-53-57](https://github.com/Avecci-Claussen/DenaroWalletClient/assets/73264647/c69f5c81-ccde-496e-b22a-9d60270969e0)

![Screenshot from 2024-02-02 02-55-07](https://github.com/Avecci-Claussen/DenaroWalletClient/assets/73264647/8bfe2c91-b1a8-4fe7-b55e-daf0d27d5870)

![Screenshot from 2024-02-02 02-56-01](https://github.com/Avecci-Claussen/DenaroWalletClient/assets/73264647/014d272c-8b4b-4d82-9929-3334497f27d8)

![Screenshot from 2024-02-02 02-56-42](https://github.com/Avecci-Claussen/DenaroWalletClient/assets/73264647/dcf38751-bf34-4258-9897-5b6efce832ae)

# On Wallet Operations tab

 press load wallets and select your wallet (should be detected) give it a bit of time to load each time you press it or switch between wallets(it will be improved soon to refresh balance and load faster), Now encrypted wallets and 2fa totally supported. (except for 2fa wallets balances , they are under construction)
 
 you can send transactions by selecting the address with funds and filling the amount and address with corresponding ones make sure the address is correct to not lose your funds.
 
 one click copies the address and you get a message response confirming it.
 2FA is enabled in encrypted wallets transactions and upon selection if your wallet doesn't have 2fa code enabled just confirm the box empty (2fa if applicable)
 
 if you can't see your addresses in send tab list to send just keep the send tab open, refresh and open the wallet you want to use and the addresses list in send options should be refreshed and you should see and choose available addresses to send.

# ON Generate Options tab

 you can generate new wallets , encrypted wallets with passwords. and encrypted wallet with 2fa.
 
 you can generate new addresses for the current selected wallet , set amount of addresses you want max 256, and the more addresses you have the slower the balance loads, also for encrypted wallets with password (the password is required), for 2fa enabled wallets 2fa is required too

# On Wallet Settings tab

 you can import private keys in hexadecimal format to an existing wallet (one currently selected).
 
 you can backup your keys by selecting available wallet and pressing reveal key button to get it. never share your keys if you don't want to risk losing your funds.(encrypted wallets require password)



# Contact

i hope all is self explanatory let me know if there is any questions or bugs. 

now casino people can handle their telegram bot keys in denaro wallet too. enjoy




Donations : 


Denaro Address : DenarodT4s8p7JG5jvQCKDcXZaKMep49hWf3Ry4KE9YAr  



Telegram Wallet Donation QR code : 

  ![image](https://github.com/Avecci-Claussen/DenaroWalletClient/assets/73264647/fcadb1c5-5b99-4387-8336-7ad508f9cf99)



Telegram : @ProCryptoDealer

# Denaro Wallet Client

## Introduction
**This repo contains the source code for the Denaro Wallet Client, developed for the Denaro cryptocurrency. It has been designed with a strong emphasis on security, providing users with a secure and efficient way to manage their digital assets.** 

**The wallet client provides essential functionalities such as wallet creation, address generation, transaction processing, balance checking, and wallet imports. Advanced functionalities are also provided, including encryption and decryption capabilities, two-factor authentication (2FA), wallet entry filtering, support for deterministic wallets, and several security mechanisms to protect wallet data.**

**Github repo for the Denaro cryptocurrency: https://github.com/denaro-coin/denaro**

## Wallet Security Framework
Paramount to it's design, the wallet client has been developed with a high-level of security in mind, perticularly for encrypted wallets. It features several protective security measures to safeguard and fortify wallet data. These measures include proof-of-work based brute-force protection, two-factor authentication, double-hashed password verification, and rigorous integrity checks of wallet data. Additionally, there are measures to identify and record unauthorized access attempts, along with an automatic wallet deletion feature which activates after 10 failed access attempts, providing an added layer of defense *([feat: Wallet Annihilation](https://github.com/The-Sycorax/DenaroWalletClient/commit/e347b6622d47415ddc531e8b3292c96b42128c9a))*.

Inherent to its architecture, the wallet client deeply inegrates and bakes these security measures directly into the cryptographic processes that are responsible for encrypting and decrypting wallet data. Central to this approach is a unique dual-layer technique that combines both the ChaCha20-Poly1305 and AES-GCM encryption algorithms. 

This encryption method is implemented in stages, beginning with the encryption of individual JSON key-value pairs of wallet data using the dual-layer technique. Afterwhich, the entire JSON entry that contains these encrypted key-value pairs is also encrypted, resulting in multiple layers of encryption. By implementing this multi-layered encryption approach along with the various security mechanisms, the wallet client not only secures wallet data but also substantially fortifies its underlying cryptographic keys against a variety of threats.

## Installation Guide
*Note: The Denaro Wallet Client has not been tested Windows or MacOS and support is unknown at this time. It is reccomended to use the wallet client on Ubuntu/Debian Linux to avoid any compatibility or stability issues.*

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

## Usage Documentation
- ### Command-Line Interface:

    **Overview**: The wallet client provides a rebust CLI for operating the Denaro Wallet Client. 
    The CLI supports various sub-commands along with their corresponding options.
    
    *Note: To ensure a high level of security, this wallet client is designed with an auto-delete feature for encrypted wallets. After 10 unsuccessful password attempts, the wallet will be automatically deleted in order to protect its contents and safeguard against unauthorized access. (For more details, please refer to: [feat: Wallet Annihilation](https://github.com/The-Sycorax/DenaroWalletClient/commit/e347b6622d47415ddc531e8b3292c96b42128c9a))*    
    
    - ### Sub-Commands:   
        <details>
        <summary>Expand</summary>
        <dl><dd>
        
        #### `generate wallet`
        **Overview**: The `generate wallet` sub-command is used to generate new wallet files or overwrite existing ones. It will also generate an address for the wallet.
                
        <details>
        <summary>Usage:</summary>
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py generate wallet [-h] [-verbose] -wallet WALLET [-encrypt] [-2fa] [-deterministic] [-phrase PHRASE] [-password PASSWORD] [-backup {False,True}] [-disable-overwrite-warning] [-overwrite-password OVERWRITE_PASSWORD]
            ```
        
        - **Options**:    
            
            *Note: The `-password` option must be set for encrypted and/or deterministic wallets.*
        
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.  
            * `-encrypt`: Enables encryption for new wallets.  
            * `-2fa`: Enables 2-Factor Authentication for new encrypted wallets.    
            * `-deterministic`: Enables deterministic address generation for new wallets.
            * `-phrase`: Generates a wallet based on a 12 word mnemonic phrase provdided by the user. This option enables deterministic address generation, therefore password is required. The mnemonic phrase must also be enclosed in quotation marks.
            * `-password`: Password used for wallet encryption and/or deterministic address generation. 
            * `-backup`: Disables wallet backup warning when attempting to overwrite an existing wallet. A 'True' or 'False' parameter is required, and will specify if the wallet should be backed up or not.  
            * `-disable-overwrite-warning`: Disables overwrite warning if an existing wallet is not backed up.  
            * `-overwrite-password`: Used to bypass the password confirmation prompt when overwriteing a wallet that is encrypted. A string paramter is required, and should specify the password used for the encrypted wallet.
            
            * `-verbose`: Enables verbose logging of info and debug messages.
        
        </dd></dl>
        </details>
        
        ---
        
        #### `generate address`
        **Overview**: The `genrate address` sub-command is used to generate new addresses and add them to wallet entry data. For encrypted wallets only the cryptographic keys for addresses are added, which are later used during decryption to derive the data associated with them (e.g. private_key, public_key, and address).

        <details>
        <summary>Usage:</summary>
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py generate address [-h] [-verbose] -wallet WALLET [-password PASSWORD] [-2fa-code TFACODE] [-amount AMOUNT]
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
        
        #### `generate paperwallet`
        **Overview**: The `genrate paperwallet` sub-command is used to generate a Denaro paper wallet either by using an address that is associated with a wallet file, or directly via a private key that corresponds to a particular address.
             
        * *If specifying an address that is associated with a wallet file then the generated paper wallet will be stored in `./wallets/paper_wallet/[walletName]/`.*             
        * *If specifying a private key that corresponds to a particular address then the generated paper wallet will be stored in `./wallets/paper_wallets/`.* 
        
        * *All generated paper wallets inherit the name of it's associated address.*

        <details>
        <summary>Usage:</summary>
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py generate paperwallet [-h] [-verbose] [-wallet WALLET] [-password PASSWORD] [-2fa-code TFACODE] [-address ADDRESS] [-private-key PRIVATE_KEY] [-type {pdf,png}]
            ```
        
        - **Options**:
            
            *Note: The `-password` option must be set for encrypted and/or deterministic wallets.*
        
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
            * `-password`: The password of the specified wallet. Required for wallets that are encrypted.  
            * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
            * `-address`: Specifies a Denaro address associated with the wallet file. A paper wallet will be generated for this Denaro address.
            * `-private-key`: Specifies the private key associated with a Denaro address. Not required if specifying an address from a wallet file.
             
             * `-type`: Specifies the file type for the paper wallet. The default filetype is PDF.                 
                * `-type png` generates a PNG image of the front of the paper wallet. 
                * `-type pdf` generates a PDF file of the front and back of the paper wallet.          
        
        </dd></dl>
        </details>

        ---

        #### `decryptwallet`
        **Overview**: The `decryptwallet` sub-command can either decrypt all entries in a wallet file, or selectivly decrypt specific entries based on a provided filter, and returns the decrypted data back to the console.        
        
        *Note: An encrypted wallet is not required to use this sub-command. Therefore, it has been designed to also return data from wallets that are not encrypted.*

        <details>
        <summary>Usage:</summary>  
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py decryptwallet [-h] [-verbose] -wallet WALLET [-password PASSWORD] [-2fa-code TFACODE] [-json] {filter} ...
            ```
        
        - **Options**:
            *Note: The `-password` option must be set for encrypted wallets.*
            
            * `-wallet`: (Required) Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
            * `-password`: The password of the specified wallet. Required for wallets that are encrypted.
            * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.            
            * `-json`: Print formatted JSON output for better readability.
        
        </dd></dl>
        </details>
        
        ---
        
        #### `decryptwallet filter`
        **Overview**: The `decryptwallet filter` sub-command filters wallet entries by one or more addresses and/or fields. Adding a hyphen `-` to the beginning of an address will exclude it from the results. Wallet entries can also be filtered based on origin (See `-show` option for more details). This sub-command should come directly after the other options that have been provided for `decryptwallet`. 
        
        <details>
        <summary>Usage:</summary> 
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py decryptwallet <options> filter [-h] [-verbose] [-address ADDRESS] [-field FIELD] [-show {generated,imported}]
            ```
        
        - **Options**:
            * `-address`: One or more addresses to filter by. Adding a hyphen `-` to the beginning of an address will exclude it from the output. 
                * The format is: 
                    ```bash
                    fliter -address=ADDRESS_1,-ADDRESS_2,...
                    ```  
            * `-field`: One or more fields to filter by. 
                * The format is: 
                    ```bash
                    -field=id,mnemonic,private_key,public_key,address
                    ```
            * `-show`: Filters wallet entries origin. 
                * `-show generated` retrieves only the information of internally generated wallet entries. 
                * `-show imported` retrieves only the information of imported wallet entries.

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
            wallet_client.py send [-h] [-verbose] [-node NODE] -amount <AMOUNT> from [-wallet WALLET] [-password PASSWORD] [-2fa-code TFACODE] [-address ADDRESS] [-private-key PRIVATE_KEY] to <receiver> [-message MESSAGE]
            ```
        
        - **Options**:
            * `send`: Main command to initiate a transaction.
                * `-amount`: (Required) Specifies the amount of Denaro to be sent.
        
            * `from <options>`: Specifies the sender's details.
                * `-wallet`: Specifies the wallet filename. Defaults to the `./wallets/` directory if no specific filepath is provided.
                * `-password`: The password of the specified wallet. Required for wallets that are encrypted.
                * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
                * `-address`: The Denaro address to send from. The address must be associated with the specified wallet.                
                * `-private-key`: Specifies the private key associated with a Denaro address. Not required if specifying an address from a wallet file.    
            
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
            wallet_client.py balance [-h] [-verbose] [-node NODE] -wallet WALLET [-password PASSWORD] [-2fa-code TFACODE] [-address ADDRESS] [-convert-to CURRENCY_CODE] [-show {generated,imported}] [-json] [-to-file]
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
            * `-convert-to`: Converts the monetary value of balances to a user specified currency, factoring in current exchange rates against the USD value of DNR. Supports 161 international currencies and major cryptocurrencies. A valid currency code is required (e.g., 'USD', 'EUR', 'GBP', 'BTC'). By default balance values are calculated in USD.
             * `-show`: Filters balance information based on wallet entry origin. 
                * `-show generated` retrieves only the balance information of internally generated wallet entries.
                * `-show imported` retrieves only the balance information of imported wallet entries.
            * `-json`: Prints the balance information in JSON format.
            * `-to-file`: Saves the output of the balance information to a file. The resulting file will be in JSON format and named as "*[WalletName]​_balance_[Timestamp].json*" and will be stored in "*/[WalletDirectory]/balance_information/[WalletName]/*".    
           
            * `-node`: Specifies the Denaro node to connect to. Must be a valid IP Address or URL. If not specified or the node is not valid, then the wallet client will use the default Denaro node (https://denaro-node.gaetano.eu.org/).
        
        </dd></dl>
        </details>

        ---
        
        #### `import`
        **Overview**: The `import` sub-command is used to import a wallet entry into a specified wallet file using the private key of a Denaro address.

        <details>
        <summary>Usage:</summary> 
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py import [-h] [-verbose] -wallet WALLET [-password PASSWORD] [-2fa-code TFACODE] -private-key PRIVATE_KEY
            ```
        
        - **Options**:
            * `-wallet`: (Required) Specifies the filename of the wallet file where the imported entries will be added. Defaults to the `./wallets/` directory if no specific filepath is provided.    
            * `-password`: The password of the specified wallet. Required for wallets that are encrypted.    
            * `-2fa-code`: Optional Two-Factor Authentication code for encrypted wallets that have 2FA enabled. Should be the 6-digit code generated from an authenticator app.
            
            * `-private-key`: Specifies the private key of a Denaro address. Used to generate the corresponding entry data which will be imported into a wallet file.
            
        </dd></dl>
        </details>

        ---

        #### `backupwallet`
        **Overview**: The `backup` sub-command is used to create a backup of a wallet file. An option to choose the backup directory is availible.

        <details>
        <summary>Usage:</summary> 
        <dl><dd>
        
        - **Syntax**:
            ```bash
            wallet_client.py backupwallet [-h] -wallet WALLET [-path TO]
            ```
        
        - **Options**:
            * `-wallet`: (Required) Specifies the filename of the wallet file where the imported entries will be added. Defaults to the `./wallets/` directory if no specific filepath is provided.    
            
            * `-path`: Specifies the directory to save the wallet backup file. Defaults to the `./wallets/wallet_backups/` directory if no specific filepath is provided.    
            
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
        
        *If the wallet specified already exists the user will be prompted with a warning and asked if they want to backup the existing wallet. If the user chooses not to back up an existing wallet, then they will be prompted with an additional warning and asked to confirm the overwrite of the existing wallet. When overwriting an encrypted wallet, the password associated with the it is required, and the user will be prompted to type it in. The user can choose to bypass one or more of these prompts with the use of `-backup`, `-disable-overwrite-warning`, or `-overwrite-password` (Refer to [generate wallet](#generatewallet) options for details).*
        
        
        
        * Generates an un-encrypted, non-deterministic wallet:
            ```bash
            python3 wallet_client.py generate wallet -wallet=wallet.json
            ```
        * Generates an encrypted, non-deterministic wallet:
            ```bash
            python3 wallet_client.py generate wallet -encrypt -wallet=wallet.json -password=MySecurePassword
            ```
        * Generates a deterministic wallet:
            ```bash
            python3 wallet_client.py generate wallet -deterministic -wallet=wallet.json -password=MySecurePassword
            ```
        * Generates an encrypted, deterministic wallet, with 2-Factor Authentication:
            ```bash
            python3 wallet_client.py generate wallet -encrypt -deterministic -2fa -wallet=wallet.json -password=MySecurePassword
            ```
        * Creates a back up of an existing encrypted wallet and overwrites it with an un-encrypted, deterministic wallet, while skipping various prompts: 
            ```bash
            python3 wallet_client.py generate wallet -wallet=wallet.json -deterministic -backup=True -disable-overwrite-warning -overwrite-password=MySecurePassword
            ```
        </details>
    
    - ### Address Generation:
        <details>
        <summary>Expand</summary>
        
        * Generates an address for a wallet that is un-encrypted and/or non-deterministic:
            ```bash
            python3 wallet_client.py generat eaddress -wallet=wallet.json
            ```
        * Generates an address for a wallet that is encrypted and/or deterministic:
            ```bash
            python3 wallet_client.py generate address -wallet=wallet.json -password=MySecurePassword
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
        * *Addresses will only be filtered if they are apart of the wallet that is being decrypted.*
        * *One or more addresses can be specified and must be seperated by a comma `,`.*
        * *One or more fields can be specified and must be seperated by a comma `,`.*
        * *If one or more fields are not specified, then all fields are included in the filtered data (id, 
        mnemonic, private_key, public_key, and address).*
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
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4
        ```
        </details>
        <details>
        <summary>Excludes an address from the results, and will only retrieve the data associated with the rest of the wallet entries if any:</summary>
          
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter address=-DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4
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
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA
        ```
        </details>
        <details>
        <summary>Retrieves only the 'private_key' and 'public_key' associated with the multiple addresses specified:</summary>
          
        ```bash
        python3 wallet_client.py decryptwallet -wallet=wallet.json -password=MySecurePassword filter -address=DuxRWZXZSeuWGmjTJ99GH5Yj5ri4kVy55MGFAL74wZcW4,DwpnwDyCTEXP4q7fLRzo4vwQvGoGuDKxikpCHB9BwSiMA -field=private_key,public_key
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
            
            *Private keys should be in hexdecimal format and are generally 64 characters in length. It is not reccomended to directly specify a private key, as this could lead to the irreversable loss of funds if anyone has access to it. The private key in this example was randomly generated and dose not have funds.*

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
        
        *Private keys should be in hexdecimal format and are generally 64 characters in length. It is not reccomended to directly specify a private key, as this could lead to the irreversable loss of funds if anyone has access to it. The private key in this example was randomly generated and dose not have funds.*
        
        * Imports a wallet entry based on the private key of a Denaro address:
            
            ```bash
            python3 wallet_client.py import -wallet=wallet.json -private-key=43c718efb31e0fef4c94cbd182e3409f54da0a8eab8d9713f5b6b616cddbf4cf
            ```
        </details>
    </details>

------------

## Disclaimer

Neither The-Sycorax nor contributors of this project assume liability for any loss of funds incurred through the use of this software! This software is provided 'as is' under the [MIT License](LICENSE) without guarantees or warrenties of any kind, express or implied. It is strongly recommended that users back up their cryptographic keys. User are solely responsible for the security and management of their assets! The use of this software implies acceptance of all associated risks, including financial losses, with no liability on The-Sycorax or contributors of this project.

------------

## License
The Denaro Wallet Client is released under the terms of the MIT license. See [LICENSE](LICENSE) for more
information or see https://opensource.org/licenses/MIT.
