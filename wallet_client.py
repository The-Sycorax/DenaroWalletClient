import os
import json
import base64
import binascii
import logging
import argparse
import sys
import readline
import threading
import gc
from collections import Counter, OrderedDict
import re

# Get the absolute path of the directory containing the current script.
dir_path = os.path.dirname(os.path.realpath(__file__))

# Insert folder paths for modules
sys.path.insert(0, dir_path + "/denaro")
sys.path.insert(0, dir_path + "/denaro/wallet")
from denaro.key_generation import generate
from denaro.wallet.cryptographic_util import VerificationUtils, CryptoWallet, TOTP_Utils, DataManipulation
from denaro.wallet.interface_util import QRCodeUtils, UserPrompts

is_windows = os.name == 'nt'

if is_windows:
    import msvcrt
else:
    import termios, fcntl

# Get the root logger
root_logger = logging.getLogger()

# Set the level for the root logger
root_logger.setLevel(logging.INFO)

# Create a handler with the desired format
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)

# Clear any existing handlers from the root logger and add our handler
root_logger.handlers = []
root_logger.addHandler(handler)

#close_qr_window = False

# Filesystem Functions
def is_wallet_encrypted(data_segment):
    """
    Determine if a given segment of data appears to be encrypted.
    """
    # Try to decode the data as JSON.
    try:
        parsed_data = json.loads(data_segment)
        
        encrypted_indicators = ["hmac", "hmac_salt", "verification_salt", "verifier", "totp_secret"]
        
        # If any of the encrypted indicators are found, it seems encrypted.
        if any(key in parsed_data for key in encrypted_indicators):
            return True
        
        return False  # Data doesn't have encryption indicators, so it doesn't seem encrypted
    except json.JSONDecodeError:
        pass

    # If the above check fails, try to decode the data as base64 and then as UTF-8.
    try:
        decoded_base64 = base64.b64decode(data_segment)
        decoded_base64.decode('utf-8')  # Check if the decoded result can be further decoded as UTF-8
        return True  # Data seems encrypted as it's valid Base64 and can be decoded as UTF-8
    except (binascii.Error, UnicodeDecodeError):
        return False  # Data neither seems to be valid JSON nor valid Base64 encoded UTF-8 text
    
def ensure_wallet_directories_exist():
    """
    Ensures the "./wallets" and  "./wallets/wallet_backups" directories exist
    """
    os.makedirs("./wallets", exist_ok=True)
    os.makedirs(os.path.join("./wallets", 'wallet_backups'), exist_ok=True)

def get_normalized_filepath(filename):
    """
    Get a normalized file path, ensuring the directory exists.
    
    Parameters:
        filename (str): The name of the file where the data will be saved.
        default_directory (str): The default directory where files will be saved if no directory is specified.
        
    Returns:
        str: A normalized filepath.
    """
    default_directory="./wallets"

    # Ensure the filename has a .json extension
    _, file_extension = os.path.splitext(filename)
    # Add .json extention to the filename if it's not present
    if file_extension.lower() != ".json":
        filename += ".json"

    # Check if the directory part is already specified in the filename
    # If not, prepend the default directory to the filename
    if not os.path.dirname(filename):
        filename = os.path.join(default_directory, filename)
    
    # Normalize the path to handle ".." or "." segments
    normalized_filepath = os.path.normpath(filename)
    
    # Ensure the directory to save the file in exists
    file_directory = os.path.dirname(normalized_filepath)
    if not os.path.exists(file_directory):
        os.makedirs(file_directory)
    
    return normalized_filepath

def _load_data(filename, new_wallet):
    """
    Load wallet data from a specified file.
    """    
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        return data, True
    except (FileNotFoundError, json.JSONDecodeError) as e:
        if new_wallet:
            return {}, False
        else:
            logging.error(f"Error reading the wallet file or parsing its content: {str(e)}")
            return None, False
        #    raise
 
# Wallet Helper Functions
def generate_encrypted_wallet_data(wallet_data, current_data, password, totp_secret, hmac_salt, verification_salt, stored_verifier):
    """Overview:
        The `generate_encrypted_wallet_data` function servs as a utility in for constructing a fully encrypted representation 
        of the wallet's data. It works by individually encrypting fields like private keys or mnemonics and then organizing
        them in a predefined format. This function is vital in ensuring that sensitive wallet components remain confidential.
        
        Arguments:
        - wallet_data (dict): Contains essential wallet information like private keys or mnemonics.
        - current_data (dict): Existing wallet data, utilized to determine the next suitable ID for the entry.
        - password (str): The user's password, used for the encryption process.
        - totp_secret (str): The TOTP secret token used for Two-Factor Authentication.
        - hmac_salt (bytes): Salt for HMAC computation.
        - verification_salt (bytes): Salt for password verification.
        - stored_verifier (bytes): The stored hash of the password, used for verification.
        
        Returns:
        - dict: A structured dictionary containing the encrypted wallet data.
    """
    # Encrypt the wallet's private key
    encrypted_wallet_data = {
        "id": CryptoWallet.encrypt_data(str(len(current_data["wallet_data"]["entry_data"]["entries"]) + 1), password, totp_secret, hmac_salt, verification_salt, stored_verifier),
        "private_key": CryptoWallet.encrypt_data(wallet_data['private_key'], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
    }
    
    # If the wallet is non-deterministic, encrypt the mnemonic
    if current_data["wallet_data"]["wallet_type"] == "non-deterministic":        
        encrypted_wallet_data["mnemonic"] = CryptoWallet.encrypt_data(wallet_data['mnemonic'], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
        del encrypted_wallet_data["private_key"]
        # Ensure a specific order for the keys
        desired_key_order = ["id", "mnemonic"]
        ordered_entry = OrderedDict((k, encrypted_wallet_data[k]) for k in desired_key_order if k in encrypted_wallet_data)
        encrypted_wallet_data = ordered_entry
    result = encrypted_wallet_data
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def generate_unencrypted_wallet_data(wallet_data, current_data):
    """Overview:
        Contrasting its encrypted counterpart, the `generate_unencrypted_wallet_data` function focuses on constructing 
        plaintext wallet data entries. While it doesn't encrypt data, it organizes the it in a structured manner, ensuring 
        easy storage and retrieval. This function is pivotal in scenarios where encryption isn't mandated, but structured 
        data organization is requisite.
        
        Arguments:
        - wallet_data (dict): The unencrypted wallet data.
        - current_data (dict): Existing wallet data, utilized to determine the next suitable ID for the entry.
        
        Returns:
        - dict: A structured dictionary containing the plaintext wallet data.
    """
    # Structure the data without encryption
    unencrypted_wallet_data = {
        "id": str(len(current_data["wallet_data"]["entry_data"]["entries"]) + 1),
        "private_key": wallet_data['private_key'],
        "public_key": wallet_data['public_key'],
        "address": wallet_data['address']
    }
    # For non-deterministic wallets, include the mnemonic
    if current_data["wallet_data"]["wallet_type"] == "non-deterministic":
        unencrypted_wallet_data["mnemonic"] = wallet_data['mnemonic']
        # Ensure a specific order for the keys
        desired_key_order = ["id", "mnemonic", "private_key", "public_key", "address"]
        ordered_entry = OrderedDict((k, unencrypted_wallet_data[k]) for k in desired_key_order if k in unencrypted_wallet_data)
        unencrypted_wallet_data = ordered_entry
    result = unencrypted_wallet_data
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def handle_new_encrypted_wallet(password, totp_code, use2FA, filename, deterministic):
    """Overview:
        The `handle_new_encrypted_wallet` function facilitates the creation of a new encrypted wallet. It handles the 
        combination of user-provided credentials, cryptographic salts, and the option for Two-Factor Authentication (2FA) 
        to produce a secure and accessible wallet. The function can adapt to both deterministic and non-deterministic 
        wallet types based on user preference.
        
        Arguments:
        - password (str): The user's password intended for the encrypted wallet.
        - totp_code (str): Time-based One-Time Password for Two-Factor Authentication.
        - use2FA (bool): Indicates whether Two-Factor Authentication is enabled or not.
        - filename (str): The intended filename for storing the wallet data.
        - deterministic (bool): Specifies if the wallet is deterministic
        
        Returns:
        - tuple: Returns a tuple that encapsulates the wallet's structured data alongside essential cryptographic 
          components like salts and verifiers.
    """
    # Define the initial structure for the wallet data
    data = {
        "wallet_data": {
            "wallet_type": "deterministic" if deterministic else "non-deterministic",
            "version": "0.2.2",
            "entry_data": {
                "key_data": [],
                "entries": []
            },
            "hmac": "",
            "hmac_salt": "",
            "verification_salt": "",
            "verifier": "",
            "totp_secret": ""
        }
    }
    
    # Check if deterministic and adjust the data structure accordingly
    if not deterministic:
        del data["wallet_data"]["entry_data"]["key_data"]

    # Password is mandatory for encrypted wallets
    if not password:
        logging.error("Password is required for encrypted wallets.\n")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None, None

    # Generate random salts for HMAC and password verification
    hmac_salt = os.urandom(16)
    data["wallet_data"]["hmac_salt"] = base64.b64encode(hmac_salt).decode()

    verification_salt = os.urandom(16)
    data["wallet_data"]["verification_salt"] = base64.b64encode(verification_salt).decode()

    # Hash the password with the salt for verification
    verifier = VerificationUtils.hash_password(password, verification_salt)
    data["wallet_data"]["verifier"] = base64.b64encode(verifier).decode('utf-8')

    # If no TOTP code is provided, set it to an empty string
    if not totp_code:
        totp_code = ""

    # Handle Two-Factor Authentication (2FA) setup if enabled
    if use2FA:
        #global close_qr_window
        # Generate a secret for TOTP
        totp_secret = TOTP_Utils.generate_totp_secret(False,verification_salt)

        totp_qr_data = f'otpauth://totp/{filename}?secret={totp_secret}&issuer=Denaro Wallet Client'
        # Generate a QR code for the TOTP secret
        qr_img = QRCodeUtils.generate_qr_with_logo(totp_qr_data, "./denaro/wallet/denaro_logo.png")
        # Threading is used to show the QR window to the user while allowing input in the temrinal
        thread = threading.Thread(target=QRCodeUtils.show_qr_with_timer, args=(qr_img, filename, totp_secret,))
        thread.start()

        # Encrypt the TOTP secret for storage
        encrypted_totp_secret = CryptoWallet.encrypt_data(totp_secret, password, "", hmac_salt, verification_salt, verifier)
        data["wallet_data"]["totp_secret"] = encrypted_totp_secret
        
        # Validate the TOTP setup
        if not UserPrompts.handle_2fa_validation(totp_secret, totp_code):
            QRCodeUtils.close_qr_window(True)
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None, None, None, None, None
        else:
            QRCodeUtils.close_qr_window(True)
            thread.join()
    else:
        # If 2FA is not used, generate a predictable TOTP secret based on the verification salt.
        totp_secret = TOTP_Utils.generate_totp_secret(True,verification_salt)
        encrypted_totp_secret = CryptoWallet.encrypt_data(totp_secret, password, "", hmac_salt, verification_salt, verifier)
        data["wallet_data"]["totp_secret"] = encrypted_totp_secret
        totp_secret = ""

    result = data, totp_secret, hmac_salt, verification_salt, verifier
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def handle_existing_encrypted_wallet(filename, data, password, totp_code, deterministic):
    """
    Handles various operations for an existing encrypted wallet.
    
    Arguments:
    - filename: The name of the wallet file
    - data: The wallet data
    - password: The user's password
    - totp_code: The TOTP code for 2FA
    - deterministic: Boolean indicating if the wallet is deterministic
    
    Returns:
    - A tuple containing HMAC salt, verification salt, stored verifier, and TOTP secret
    """
    # Fail if no password is provided for an encrypted wallet
    if not password:
        logging.error("Password is required for encrypted wallets.")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None

    # Decode salts for verification
    verification_salt = base64.b64decode(data["wallet_data"]["verification_salt"])
    hmac_salt = base64.b64decode(data["wallet_data"]["hmac_salt"])

    # Verify the password and HMAC
    password_verified, hmac_verified, stored_verifier = VerificationUtils.verify_password_and_hmac(data, password, hmac_salt, verification_salt, deterministic)

    # Based on password verification, update or reset the number of failed attempts
    data = DataManipulation.update_or_reset_attempts(data, hmac_salt, password_verified, deterministic)
    DataManipulation._save_data(filename,data)

    # Verify the password and HMAC
    password_verified, hmac_verified, stored_verifier = VerificationUtils.verify_password_and_hmac(data, password, hmac_salt, verification_salt, deterministic)

    # Fail if either the password or HMAC verification failed
    if not (password_verified and hmac_verified):
        logging.error("Authentication failed or wallet data is corrupted.")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None

    # If 2FA is enabled, handle the TOTP validation
    totp_secret, tfa_enabled = VerificationUtils.verify_totp_secret(password, data["wallet_data"]["totp_secret"], hmac_salt, verification_salt, stored_verifier)
    if tfa_enabled:
        tfa_valid = UserPrompts.handle_2fa_validation(totp_secret, totp_code)
        if not tfa_valid or not tfa_valid.get("valid"):
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None, None, None, None
    result = hmac_salt, verification_salt, stored_verifier, totp_secret
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def parse_and_encrypt_mnemonic(words, password, totp_secret, hmac_salt, verification_salt, stored_verifier):
    """Overview:
        The `parse_and_encrypt_mnemonic` function is specifically designed to fortify the security of mnemonic phrases.
        It takes a string of mnemonic words, parses them, and encrypts each word individually. The function ensures 
        that each mnemonic word is securely encrypted, thereby enhancing the security of the mnemonic while protecting
        against potential threats. This heightened level of security is crucial given the critical nature of mnemonics
        in digital wallets.
        
        Arguments:
        - words (str): The mnemonic phrase.
        - password (str): The user's password, used for the encryption process.
        - totp_secret (str): The TOTP secret token used for Two-Factor Authentication.
        - hmac_salt (bytes): Salt for HMAC generation.
        - verification_salt (bytes): Salt for password verification.
        - stored_verifier (bytes): The stored hash of the password, used for verification.
        
        
        Returns:
        - list: A list encapsulating the encrypted representations of each mnemonic word.
    """
    # Split the mnemonic words by space
    word_list = words.split()
    
    # Ensure there are exactly 12 words in the mnemonic (standard mnemonic length)
    if len(word_list) != 12:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        raise ValueError("Input should contain exactly 12 words")
    
    # Encrypt each word, and structure it in a dictionary with its ID
    encrypted_key_data = [
        CryptoWallet.encrypt_data(
            json.dumps({
                "id": CryptoWallet.encrypt_data(str(i+1), password, totp_secret, hmac_salt, verification_salt, stored_verifier), 
                "word": CryptoWallet.encrypt_data(word, password, totp_secret, hmac_salt, verification_salt, stored_verifier)
            }), 
            password, totp_secret, hmac_salt, verification_salt, stored_verifier
        ) for i, word in enumerate(word_list)
    ]
    result = encrypted_key_data
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def decrypt_and_parse_mnemonic(encrypted_json, password, totp_secret, hmac_salt, verification_salt, stored_verifier):
    """Overview:
        Serving as the counterpart to `parse_and_encrypt_mnemonic`, this function plays an instrumental role in 
        key recovery operations. This function undertakes the task of decrypting each encrypted mnemonic word and
        assembling them back into their original, readable sequence. 
        
        Arguments:
        - encrypted_json (list): A list containing encrypted mnemonic words.
        - password (str): The user's password, used for the decryption process.
        - totp_secret (str): The TOTP secret token used for Two-Factor Authentication.
        - hmac_salt (bytes): Salt for HMAC computation.
        - verification_salt (bytes): Salt for password verification.
        - stored_verifier (bytes): The stored hash of the password, used for verification.
        
        Returns:
        - str: A string containing the decrypted sequence of mnemonic words.
    """
    decrypted_words = [
        CryptoWallet.decrypt_data(
            json.loads(CryptoWallet.decrypt_data(encrypted_index, password, totp_secret, hmac_salt, verification_salt, stored_verifier))["word"],
            password, totp_secret, hmac_salt, verification_salt, stored_verifier
        ) for encrypted_index in encrypted_json
    ]
    result =  " ".join(decrypted_words)
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

# Wallet Orchestrator Functions
def generateAddressHelper(filename, password, totp_code=None, new_wallet=False, encrypt=False, use2FA=False, deterministic=False,backup=None,disable_warning=False,overwrite_password=None,from_cli=False):
    """Overview:
        The `generateAddressHelper` function serves as a central orchestrator for facilitating the creation, 
        integration, and management of wallet data. This function is designed to accomodate different scenarios 
        for the generation and oversight of wallet addresses depending on the provided parameters. This function 
        can generate addresses for a new wallet or add addresses to an existing wallet. When considering address 
        generation, it can operate in a deterministic fashion, deriving addresses from a mnemonic phrase, or in a
        non-deterministic manner, generating addresses at random.
    
        When working with existing wallets, the function verifies if the wallet data is encrypted, if a password 
        is provided, and determines the method of address generation used for the wallet (deterministic or non-detministic).
        Depending on the characteristics of an existing wallet, the function adjusts subsequent operations accordingly.
        
        Security is paramount to the function's design. One of its features is the implementation of a unique
        double encryption technique. Initially, the individual JSON key-value pairs within the genrated wallet data 
        are encrypted with the use of helper functions and returned back to the `generateAddressHelper` function. 
        Afterwhich, the function encrypts the entire JSON entry that houses these encrypted pairs, effectively wrapping 
        the data in a second layer of encryption. 
        
        For users prioritizing additional layers of security, there's support for Two-Factor Authentication (2FA). 
        When 2FA is enabled, the function integrates the generated TOTP (Time-based One-Time Password) secret directly
        into the encryption and decryption processes, intertwining the 2FA token with the cryptographic operations, thereby
        adding an intricate layer of security. 
        
        To conclude its operations, the function ensures that any transient sensitive data, especially those retained in 
        memory, are securely eradicated, mitigating risks of unintended data exposure or leaks.
           
    Arguments:
    - filename: File path designated for the storage or retrieval of wallet data.
    - password (str): The user's password, used for the various cryptographic processes.
    - totp_code: An optional Time-based One-Time Password, used for Two-Factor Authentication.
    - new_wallet (bool, optional): Specifies if the operation involves creating a new wallet.
    - encrypt (bool, optional): Specifies if the wallet data should undergo encryption.
    - use2FA (bool, optional): Specifies if Two-Factor Authentication should be enabled.
    - deterministic (bool, optional): Specifies if deterministic address generation should
      be enabled for the wallet.
    
    Returns:
    - str: A string that represents a newly generated address.
    """
    # Initialize mnemonic to None
    mnemonic = None  
    #Make sure that the wallet directories exists
    ensure_wallet_directories_exist()
    
    #Normalize filename
    filename = get_normalized_filepath(filename)

    # Load the existing or new wallet data from a file (filename)
    data, wallet_exists = _load_data(filename, new_wallet)    
    
    # If wallet dose not exist return None
    if not new_wallet and not wallet_exists:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None
    
    if new_wallet:
        stored_encrypt_param = encrypt
        stored_deterministic_param = deterministic

    # Determine encryption status and wallet type for an existing wallet
    if wallet_exists or not new_wallet:
        # Convert part of the wallet data to a JSON string
        data_segment = json.dumps(data["wallet_data"])        
        # Check if the wallet data is encrypted and if a password is provided
        if is_wallet_encrypted(data_segment) and not password and not new_wallet:
            logging.error("Wallet is encrypted. Password is required to add additional addresses.")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
        if is_wallet_encrypted(data_segment):
            # If encrypted and password is provided, set encrypt flag to True
            encrypt = True
        if not is_wallet_encrypted(data_segment):
            encrypt = False
        # Check if the existing wallet type is deterministic
        if "wallet_type" in data["wallet_data"] and not new_wallet:
            deterministic = data["wallet_data"]["wallet_type"] == "deterministic"
        if len(data["wallet_data"]["entry_data"]["entries"]) > 255 and not new_wallet:
            logging.info("Cannot proceed. Max wallet entries reached.")
            return None
    
    #Handle backup and overwrite for an existing wallet
    if new_wallet and wallet_exists:
        if not UserPrompts.backup_and_overwrite_helper(data, filename, overwrite_password, encrypt, backup, disable_warning, from_cli, deterministic):
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return
        
    if new_wallet:
        encrypt = stored_encrypt_param    
        deterministic = stored_deterministic_param
    # Handle different scenarios based on whether the wallet is encrypted
    if encrypt:        
        if new_wallet:
            print("new_wallet is set to True")
            print("encrypt is set to True.")
            print("Handling new encrypted wallet...")
            # Handle creation of a new encrypted wallet
            data, totp_secret, hmac_salt, verification_salt, stored_verifier = handle_new_encrypted_wallet(password, totp_code, use2FA, filename, deterministic)
            if not data:
                logging.error(f"Error: Data from handle_new_encrypted_wallet is None!\nDebug: HMAC Salt: {hmac_salt}, Verification Salt: {verification_salt}, Stored Verifier: {stored_verifier}")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
        else:
            print("new_wallet is set to False")
            print("Existing wallet is encrypted.")
            print("Handling existing encrypted wallet...")
            # Handle operations on an existing encrypted wallet
            hmac_salt, verification_salt, stored_verifier, totp_secret = handle_existing_encrypted_wallet(filename, data, password, totp_code, deterministic)
            if not hmac_salt or not verification_salt or not stored_verifier:
                #logging.error(f"Error: Data from handle_existing_encrypted_wallet is None!\nDebug: HMAC Salt: {hmac_salt}, Verification Salt: {verification_salt}, Stored Verifier: {stored_verifier}")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None

    # If deterministic flag is set, generate addresses in a deterministic way
    if deterministic:
        if not password:
                logging.error("Password is required to derive the deterministic address")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
        if new_wallet:            
            print("deterministic is set to True")
            print("Generating wallet data")
            # Generate the initial data for a new deterministic wallet
            wallet_data = generate(passphrase=password,deterministic=True)
            if encrypt:
                print("Parseing and encrypting master mnemonic")
                # Parse and encrypt the mnemonic words individually
                data["wallet_data"]["entry_data"]["key_data"] = parse_and_encrypt_mnemonic(wallet_data["mnemonic"], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
            else:
                print("encrypt is set to False")
                print("Generating data for new unencrypted deterministic wallet...")
                # Structure for a new unencrypted deterministic wallet
                data = {
                    "wallet_data": {
                        "wallet_type": "deterministic",
                        "version": "0.2.2",
                        "entry_data": {
                            "master_mnemonic": wallet_data["mnemonic"],
                            "entries":[]
                        }
                    }
                }
        else:
            # Set the deterministic index value based on the length of the entries in the wallet 
            index = len(data["wallet_data"]["entry_data"]["entries"])
            if encrypt:
                print("Decrypting and parsing the master mnemonic")
                # Decrypt and parse the existing mnemonic for the deterministic wallet
                mnemonic = decrypt_and_parse_mnemonic(data["wallet_data"]["entry_data"]["key_data"], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
                wallet_data = generate(mnemonic_phrase=mnemonic,passphrase=password, index=index, deterministic=True)
            else:
                print("encrypt is set to False")
                print("Generating child address for existing unencrypted deterministic wallet...")
                # Use the existing mnemonic directly if it's not encrypted
                mnemonic = data["wallet_data"]["entry_data"]["master_mnemonic"]
            
                # Verify if the provided passphrase correctly derives child keys.
                # Derive the first child key using the master mnemonic and the given passphrase.
                first_child_data = generate(mnemonic_phrase=mnemonic,passphrase=password, index=0, deterministic=True)
                # Check if the derived child's private key matches the private key of the first entry in the stored wallet.
                if first_child_data["private_key"] != data["wallet_data"]["entry_data"]["entries"][0]["private_key"]:
                    # Log an error message if the private keys do not match, indicating that the provided passphrase is incorrect.
                    logging.error("Invalid passphrase. To derive the deterministic address, please re-enter the correct passphrase and try again.")
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                    return None
                else:
                    # Generate the new address based on the existing mnemonic
                    wallet_data = generate(mnemonic_phrase=mnemonic,passphrase=password, index=index, deterministic=True)
    else:
        print("Deterministic is set to False")
        # For non-deterministic wallets, generate a random wallet data
        wallet_data = generate()
        #print(wallet_data)
        if new_wallet and not encrypt:
            print("new_wallet is set to True")
            print("encrypt is set to False")
            print("Generating data for new unencrypted non-deterministic wallet...")
            data = {
                "wallet_data": {
                    "wallet_type": "non-deterministic",
                    "version": "0.2.2",
                    "entry_data": {
                        "entries":[]
                    }
                    
                }
            }

    # Prepare data to be saved based on encryption status
    if encrypt:
        # If the wallet is encrypted, encrypt the new address before saving
        encrypted_wallet_data = generate_encrypted_wallet_data(wallet_data, data, password, totp_secret, hmac_salt, verification_salt, stored_verifier)
        encrypted_data_entry = CryptoWallet.encrypt_data(json.dumps(encrypted_wallet_data), password, totp_secret, hmac_salt, verification_salt, stored_verifier)
        data["wallet_data"]["entry_data"]["entries"].append(encrypted_data_entry)

        if deterministic:
            hmac_msg = json.dumps(data["wallet_data"]["entry_data"]["entries"]).encode() + json.dumps(data["wallet_data"]["entry_data"]["key_data"]).encode()
        else:
            hmac_msg = json.dumps(data["wallet_data"]["entry_data"]["entries"]).encode()

        # Calculate HMAC for wallet's integrity verification
        computed_hmac = VerificationUtils.hmac_util(password=password,hmac_salt=hmac_salt,hmac_msg=hmac_msg,verify=False)
        data["wallet_data"]["hmac"] = base64.b64encode(computed_hmac).decode()
    else:
        # Prepare unencrypted data to be saved
        unencrypted_data_entry = generate_unencrypted_wallet_data(wallet_data, data)
        data["wallet_data"]["entry_data"]["entries"].append(unencrypted_data_entry)

    # Save the updated wallet data back to the file
    DataManipulation._save_data(filename, data)
    # Extract the newly generated address to be returned
    result = wallet_data['address']
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def decryptWalletEntries(filename, password, totp_code=None, address=[], fields=[], pretty=False):
    """Overview:
        The `decryptWalletEntries` function is designed to decrypt wallet entries stored within a specified file, 
        implementing an intricate decryption process with the collaboration of multiple helper functions.
    
        Initially, the function loads encrypted wallet data and validates its encrypted status. After validating and 
        ensuring the data is encrypted, cryptographic parameters are extracted using the `handle_existing_encrypted_wallet`
        function. These cryptographic parameters are used for subsequent decryption steps. The function then distinguishes
        between deterministic and non-deterministic wallets, applying specific decryption and data generation approaches
        respectively, based on the wallet type.
    
        The core decryption process involves iterating through each entry in the wallet data. The decryption relies on the 
        function `decrypt_data`, which performs the multi-layered decryption process, which includes the ChaCha20-Poly1305 
        and AES-GCM decryption layers.
    
        For deterministic wallets, only the master mnemonic phrase is decrypted using the `decrypt_and_parse_mnemonic`function. 
        Following decryption, the master mnemonic is utilized, along with a user-defined password and an entry index (ID), as 
        input parameters for the `generate` function. The `generate` function is used deterministically produces additional wallet
        entry data, consisting of the private key, public key, and address
    
        Conversely, for non-deterministic wallets, each wallet entry has its own unique mnemonic phrase that must undergo the same 
        decryption process. Once decrypted, the mnemonic is passed to the generate function to derive the corresponding wallet 
        entry data: private key, public key, and address. 
        
        The procedures described for both deterministic and non-deterministic wallets facilitate the independent and secure
        generation of supplementary wallet data. This methodology was adopted as an alternative to directly storing the complete data
        set (private key, public key, and address) for every wallet entry. Instead, encrypted wallet files are designed to contain only
        the minimal data required to derive these core components. During testing, this approach has been shown to significantly reduce
        the file size of encrypted wallet files.
        
        After decrypting and generating additional entry data, the function appends the entry data to a dictionary. This dictionary
        is subsequently ordered, and structured in a way that is dependant on the wallet type (deterministic or non-deterministic).
        The end result should be a JSON dictionary which closely matches the un-encrypted version of the wallet data.
        
        The latter stages of the function provides options to filter and format entry data based on the given arguments.
        Entry data can be filtered by specific addresses or specific field names and then formatted according to the 
        `pretty` flag, yielding either a prettified JSON string or a dictionary.
        
        Args:
        - filename (str): The path to the file that contains the encrypted wallet data.
        - password (str): User's password used for cryptographic operations during decryption.
        - totp_code (str, optional): A Time-based One-Time Password used in Two-Factor Authentication. Required if TFA was enabled during wallet encryption.
        - address (str, optional): If specified, filters the results to return only the data associated with this address. Otherwise, all entries are returned.
        - fields (list of str, optional): List of fields to decrypt and return. If not specified, all fields are decrypted.
        - pretty (bool, optional): If True, outputs a prettified JSON string. Otherwise, returns a dictionary.
    
        Returns:
        - dict or str: If "pretty" is True, returns a prettified JSON string. Otherwise, returns a dictionary of decrypted wallet entries and fields.
    """
    
    #Make sure that the wallet directories exists
    ensure_wallet_directories_exist()
    
    #Normalize filename
    filename = get_normalized_filepath(filename)
    
    # Load the existing wallet data from the specified file
    data, wallet_exists = _load_data(filename, False)

    # If wallet dose not exist return None
    if not wallet_exists:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None
    
    # Convert the wallet data segment to a JSON string and check if it appears to be encrypted
    data_segment = json.dumps(data["wallet_data"])
    if not is_wallet_encrypted(data_segment):
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        raise ValueError("Wallet data does not appear to be encrypted.")
    
    # Initialize a flag to check if the wallet type is deterministic
    deterministic = False

    # Check if the wallet type is present in the data and set the deterministic flag accordingly
    if "wallet_type" in data["wallet_data"]:
        deterministic = data["wallet_data"]["wallet_type"] == "deterministic"

    # Extract necessary cryptographic salts and secrets for the encrypted wallet
    hmac_salt, verification_salt, stored_verifier, totp_secret = handle_existing_encrypted_wallet(filename,data, password, totp_code, deterministic)
    
    # Ensure none of the cryptographic values are missing
    if not hmac_salt or not verification_salt or not stored_verifier:
        #print(f"Error: Data from handle_existing_encrypted_wallet is None!\nDebug: HMAC Salt: {hmac_salt}, Verification Salt: {verification_salt}, Stored Verifier: {stored_verifier}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None    
    
    # If the wallet is deterministic, decrypt and parse the mnemonic phrase
    if deterministic:
        mnemonic = decrypt_and_parse_mnemonic(data["wallet_data"]["entry_data"]["key_data"], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
        
    # List to hold decrypted wallet entries
    decrypted_entries = []    

    # If no fields are specified then all fields are considered
    if fields == []:
        fields = ["mnemonic", "id", "private_key", "public_key", "address"]

    # Decrypt each entry in the wallet data
    for encrypted_entry in data["wallet_data"]["entry_data"]["entries"]:
        entry_with_encrypted_values = json.loads(CryptoWallet.decrypt_data(encrypted_entry, password, totp_secret, hmac_salt, verification_salt, stored_verifier))
        
        fully_decrypted_entry = {}
        for key, encrypted_value in entry_with_encrypted_values.items():
            fully_decrypted_entry[key] = CryptoWallet.decrypt_data(encrypted_value, password, totp_secret, hmac_salt, verification_salt, stored_verifier)

        # Generate required data fields based on the mnemonic phrase and deterministic flag
        generated_data = {}
        if not deterministic:
            generated_data = generate(mnemonic_phrase=fully_decrypted_entry["mnemonic"], deterministic=deterministic,fields=fields)
            if address and not "address" in fields:
                generated_data.update(generate(mnemonic_phrase=fully_decrypted_entry["mnemonic"], deterministic=deterministic,fields=["address"]))
        else:
            generated_data = generate(mnemonic_phrase=mnemonic, passphrase=password, index=int(fully_decrypted_entry["id"]) - 1, deterministic=deterministic,fields=fields)
            if not "id" in fields:
                generated_data.update(generate(mnemonic_phrase=mnemonic, passphrase=password, index=int(fully_decrypted_entry["id"]) - 1, deterministic=deterministic,fields=["id"]))
            if address and not "address" in fields:
                generated_data.update(generate(mnemonic_phrase=mnemonic, passphrase=password, index=int(fully_decrypted_entry["id"]) - 1, deterministic=deterministic,fields=["address"]))
            generated_data["id"] = int(generated_data["id"]) + 1
            if "mnemonic" in generated_data:
                del generated_data["mnemonic"]

        # Update the decrypted entry with the generated data
        fully_decrypted_entry.update(generated_data)
        decrypted_entries.append(fully_decrypted_entry)

    # Initialize variables to hold addresses not found for inclusion and exclusion
    not_found_inclusion = []
    not_found_exclusion = []
    not_found_all = []
    
    # Initialize a set to hold addresses to be excluded
    addresses_to_exclude = set()
    
    # Initialize a list to hold unique filtered entries based on address
    unique_filtered_entries = []
    
    # Existing decrypted addresses
    all_decrypted_addresses = [entry.get("address") for entry in decrypted_entries]
    
    # If an address is specified, filter the decrypted entries based on that address
    if address:
        for addr in address:
            if addr.startswith("-"):
                if addr[1:] not in all_decrypted_addresses:
                    not_found_exclusion.append(addr[1:])
                addresses_to_exclude.add(addr[1:])
            else:
                filtered_entries = [entry for entry in decrypted_entries if entry.get("address") == addr]
                if filtered_entries:
                    unique_filtered_entries.extend(filtered_entries)
                else:
                    not_found_inclusion.append(addr)
    
        # Filter logic for address exclusion
        if addresses_to_exclude:
            unique_filtered_entries = [entry for entry in unique_filtered_entries if entry.get("address") not in addresses_to_exclude]
            if not unique_filtered_entries:
                unique_filtered_entries = [entry for entry in decrypted_entries if entry.get("address") not in addresses_to_exclude]
                decrypted_entries = unique_filtered_entries

        # Remove duplicate and excluded addresses from unique_filtered_entries
        seen_addresses = set()
        unique_filtered_entries = [entry for entry in unique_filtered_entries if entry['address'] not in (seen_addresses or addresses_to_exclude) and not seen_addresses.add(entry['address'])]
    
        # Check if there are any addresses not found for inclusion or exclusion
        if not_found_inclusion or not_found_exclusion:
            not_found_all = list(set(not_found_inclusion + not_found_exclusion))
            not_found_all.sort(key=lambda x: address.index(x) if x in address else address.index('-' + x))
            print(f"Warning: The following {'address was' if len(not_found_all) == 1 else 'addresses were'} not found: {', '.join(not_found_all)}")
    
        # Error logic
        if not unique_filtered_entries:
            if all(addr in addresses_to_exclude for addr in all_decrypted_addresses):
                print("All specified addresses are excluded. Returning no entries.")
            else:
                print(f"Error: {'The address specified is not' if len(address) == 1 else 'None of the addresses specified are'} associated with this wallet. Returning all wallet entries...")
        # Sort and return unique_filtered_entries
        else:
            unique_filtered_entries.sort(key=lambda x: x['id'])
            decrypted_entries = unique_filtered_entries
        
    # Specify the desired order of fields for output        
    ordered_field_names = ["id", "mnemonic", "private_key", "public_key", "address"]
        
    # If specific fields are requested, filter and order the decrypted entries based on those fields
    if fields:        
        decrypted_entries = [OrderedDict((field, entry[field]) for field in ordered_field_names if field in fields and field in entry) for entry in decrypted_entries]
    else:
        # Ensure the order of fields in the output, even if no specific fields are requested
        decrypted_entries = [OrderedDict((field, entry[field]) for field in ordered_field_names if field in entry) for entry in decrypted_entries]

    # Convert the decrypted entries to a readable format based on the `pretty` flag
    if pretty:
        if "mnemonic" in fields and deterministic:
            formatted_output = json.dumps({"entry_data":{"master_mnemonic": mnemonic, "entries": decrypted_entries}}, indent=4)
        else:            
            formatted_output = json.dumps({"entry_data":{"entries": decrypted_entries}}, indent=4)
    else:
        if "mnemonic" in fields and deterministic:
            formatted_output = json.dumps({"entry_data":{"master_mnemonic": mnemonic, "entries": decrypted_entries}})
        else:
            formatted_output = json.dumps({"entry_data":{"entries": decrypted_entries}})
    result = formatted_output
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

# Argparse Helper Functions
def sort_arguments_based_on_input(argument_names):
    """
    Overview:
        Sorts a list of CLI argument names based on their positional occurrence in sys.argv.
        Any argument not found in sys.argv is filtered out. 
        The returned list is then formatted as a comma-separated string.

    Arguments:
    - argument_names (list): A list of argument names to be sorted.
  
    Returns:
    - str: A string of sorted argument names separated by commas with 'and' added before the last argument.
  
    Note:
        This function leverages the sys.argv array, which captures the command-line arguments passed to the script.
    """
    # Filter out arguments that are not present in sys.argv
    filtered_args = [arg for arg in argument_names if arg in sys.argv]
    # Sort the filtered arguments based on their index in sys.argv
    sorted_args = sorted(filtered_args, key=lambda x: sys.argv.index(x))    
    # If there are multiple arguments, join them into a string separated by commas, adding 'and' before the last argument
    if len(sorted_args) > 1:
        return ', '.join(sorted_args[:-1]) + ', and ' + sorted_args[-1]    
    # If there is only one argument, return it as a standalone string
    elif sorted_args:
        return sorted_args[0]    
    # If no arguments are present in sys.argv, return an empty string
    else:
        return ''

def check_args(parser,args):
    """
    Overview:
        Validates combinations of CLI arguments and returns an error message via the parser
        if invalid combinations are found. Specifically, it checks for required combinations
        that involve the '-password' flag.

    Arguments:
    - parser (argparse.ArgumentParser): The argument parser object.
    - args (argparse.Namespace): The argparse namespace containing parsed arguments.
  
    Note:
        Utilizes the `sort_arguments_based_on_input` function to display arguments in the
        order in which they were passed in the command line.
    """
    # -deterministic, -2fa, and -encrypt requires -password
    if args.deterministic and args.tfa and args.encrypt and not args.password:
        sorted_args = sort_arguments_based_on_input(['-deterministic', '-2fa', '-encrypt', '-password'])
        parser.error(f"\n{sorted_args} requires the -password argument to be set.\nContext: A password is required to encrypt the wallet, enable 2-Factor Authentication, and for deterministic address generation.")

    # -2fa and -encrypt requires -password
    if args.tfa and args.encrypt and not args.password:
        sorted_args = sort_arguments_based_on_input(['-2fa', '-encrypt', '-password'])
        parser.error(f"\n{sorted_args} requires the -password argument to be set.\nContext: A password is required for encrypted wallets with 2-Factor Authentication enabled.")

    # -2fa requires both -encrypt and -password
    if args.tfa and (not args.encrypt or not args.password):
        sorted_args = sort_arguments_based_on_input(['-2fa', '-encrypt', '-password'])
        if not args.encrypt:
            context_str = "2-Factor Authentication is only supported for encrypted wallets."
        if not args.password:
            context_str = "2-Factor Authentication is only supported for encrypted wallets, which requires a password."
        # -2fa and -deterministic requires both -encrypt and -password
        if args.deterministic:
            sorted_args = sort_arguments_based_on_input(['-2fa', '-deterministic', '-encrypt', '-password'])
            if not args.password:
                context_str += " Deterministic address generation also requires a password."
        parser.error(f"\n{sorted_args} requires both the -encrypt and -password arguments to be set.\nContext: {context_str}")

    # -encrypt and -deterministic requires -password
    if args.encrypt and args.deterministic and not args.password:
        sorted_args = sort_arguments_based_on_input(['-encrypt', '-deterministic', '-password'])
        parser.error(f"\n{sorted_args} requires the -password argument to be set.\nContext: A password is required to encrypt the wallet and for deterministic address generation.")

    # -deterministic alone requires -password
    if args.deterministic and not args.password:
        sorted_args = sort_arguments_based_on_input(['-deterministic', '-password'])
        parser.error(f"\n{sorted_args} requires the -password argument to be set.\nContext: A password is required for deterministic address generation.")

    # -encrypt alone requires -password
    if args.encrypt and not args.password:
        sorted_args = sort_arguments_based_on_input(['-encrypt', '-password'])
        parser.error(f"\n{sorted_args} requires the -password argument to be set.\nContext: A password is required to encrypt the wallet.")

def process_decryptwallet_filter(args):
    """
    Overview:
        This function manages the '-filter' argument and 'filter' subparser in the 'decryptwallet' command-line interface.. 
        It is tasked with extracting and returning specified filter options, which could be based on address and/or field.
        
        - One or more addresses can be filtered.
        - Addresses can be excluded by adding a hyphen '-' to the begining of it.
        - Multiple field parameters are supported.
    
        Valid Field Parameters: id, mnemonic, private_key, public_key, address
    
        For the '-filter' Argument:
        The expected input format is: "field={id,mnemonic,private_key,public_key,address},address={ADDRESS_1, ADDRESS_2, ADDRESS_3, ...}"
            - Parameters must be enclosed within curly braces '{}'.
            - The entire filter string must be enclosed in quotation marks.
        
        For 'filter' Subparser:
        - Utilize the '-address' option to specify one or more addresses to be filtered.
        - Utilize the '-field' option to specify one or more field parameters for filtering.
    
    Arguments:
        - args (argparse.Namespace): The namespace from argparse containing all the parsed command-line arguments.
    
    Returns:
        - tuple: A tuple consisting of the filtered address, the filtered field(s), and the value of args.filter_subparser_pretty.
    """
    # Initialize address and field variables
    address = []
    field = []
    fields_to_string = ""  

    if args.filter:
        # Check if the filter argument is enclosed in quotes
        # This is necessary to ensure that the argument is parsed correctly
        filter_args = [item.replace("-filter=", "") for item in sys.argv[1:] if "-filter" in item]
        using_quotes = len(filter_args) == 1        
        # If quotes are not used, raise an error
        if not using_quotes:
            raise argparse.ArgumentTypeError("Invalid filter syntax. The -filter argument must be enclosed in quotes.")
        
        # Manually parse the args.filter string into a dictionary to check key spelling
        parsed_filter_keys = []
        for part in args.filter.split(','):
            if '=' in part:
                key, _ = part.split('=')
                parsed_filter_keys.append(key)
        
        # List of valid keys for filtering
        valid_keys = ["address", "field"]

        # Raise an error if an invalid key is found
        for key in parsed_filter_keys:
            if key not in valid_keys:
                raise argparse.ArgumentTypeError(f"Invalid filter key: '{key}'. Valid keys are {valid_keys}.")
        
        # Validate the syntax of the filter argument
        filter_str = args.filter
        valid, error = validate_filter_string(filter_str)
        if not valid:
            raise argparse.ArgumentTypeError(error)
 
        # Extract the values for 'address' and 'field' from the filter argument
        address_match = re.search(r'address=\{(.+?)\}', filter_str)
        field_match = re.search(r'field=\{(.+?)\}', filter_str)

        # Assign values to 'address' and 'field' variables
        if address_match:
            address = address_match.group(1).split(',')
        if field_match:
            field = field_match.group(1).split(',')
            fields_to_string = ", ".join(field)

    # Handle the case when the 'filter' subparser is used
    if args.filter_subparser == 'filter':
        address = args.address.split(',')
        if args.field:
            field = args.field.split(',')
            fields_to_string = ", ".join(field)

    # If no subparser is used, set pretty printing to False
    elif args.filter_subparser != 'filter':
        args.filter_subparser_pretty = False
    
    # Validate the field values against a list of valid options
    valid_fields = ["id","mnemonic", "private_key", "public_key", "address"]
    if field:
        for f in field:
            if f not in valid_fields:
                raise ValueError(f"Invalid field value: {f}. Must be one of {valid_fields}")
    
    #Remove duplicate addresses
    seen_addresses = set()
    address = [entry for entry in address if entry not in seen_addresses and not seen_addresses.add(entry)]
    address = remove_duplicates_from_address_filter(address)

    # Output the filtering criteria to the console
    if address and not field:
        print(f'\nFiltering wallet by address: "{address}"')
    if not address and field:
        print(f'\nFiltering entries by field: "{fields_to_string}"')
    if address and field:
        print(f'\nFiltering wallet by address: "{address}"')
        print(f'Filtering address entry by field: "{fields_to_string}"')
   
    # Return the filtering criteria and pretty printing option
    return address, field, args.filter_subparser_pretty

def validate_filter_string(input_string):
    """
    Validates the input string based on specific formatting rules for 'field' and 'address'.
    1. Checks basic syntax using regular expression.
    2. Checks for duplicate keys within each field set.
    3. Checks for multiple occurrences of 'address' and 'field'.
    
    Parameters:
        input_string (str): The string to be validated.
        
    Returns:
        bool: True if the string is valid, False otherwise.
        str: A message indicating why the validation failed, or 'Valid' if it succeeded.
    """
    # Basic syntax check using regex
    #pattern = re.compile(r'^(?:(field=\{[\w\d,]+\})|(address=\{[\w\d]+\}))(?:,(?!.*\1)(field=\{[\w\d,]+\}|address=\{[\w\d]+\}))?$')
    pattern = re.compile(r'^(?:(field=\{[\w\d,]+\})|(address=\{[\-\w\d,]+\}))(?:,(?!.*\1)(field=\{[\w\d,]+\}|address=\{[\-\w\d,]+\}))?$')
    match = pattern.match(input_string)
    if not match:
        return False, f"Invalid filter syntax: {input_string}"
    
    # Count occurrences of 'address' and 'field'
    address_count = 0
    field_count = 0

    # Iterate over each segment (either 'field={...}' or 'address={...}')
    for segment in re.finditer(r'(field=\{[\w\d,]+\})|(address=\{[\w\d]+\})', input_string):
        segment = segment.group()
        key, value = segment.split("=")
        # Remove braces from value
        value = value[1:-1]
        
        # Check for duplicate keys in 'field'
        if key == 'field':
            field_count += 1
            keys = value.split(",")
            duplicates = [item for item, count in Counter(keys).items() if count > 1]
            if duplicates:
                return False, f"Duplicate keys found in 'field': {', '.join(duplicates)}"

        # Count occurrences of 'address'
        if key == 'address':
            address_count += 1

    # Check for multiple occurrences of 'address' or 'field'
    if address_count > 1:
        return False, "Multiple occurrences of 'address' found"
    if field_count > 1:
        return False, "Multiple occurrences of 'field' found"
    # Check for multiple occurrences of 'address' or 'field'
    if address_count > 1 and field_count > 1:
        return False, "Multiple occurrences of 'address' and 'field' found"
                
    return True, "Valid"

def remove_duplicates_from_address_filter(address_list):
    """
    Remove duplicate addresses from the list while honoring the first occurrence of hyphenated or non-hyphenated versions.
    
    Arguments:
        address_list (list): The list of addresses, possibly containing duplicates and/or hyphenated versions.
        
    Returns:
        list: A deduplicated list of addresses.
    """
    
    # Dictionary to keep track of the first occurrence of each unhyphenated address.
    # The key is the unhyphenated address and the value is the actual address (hyphenated or not).
    seen_unhyphenated = {}
    
    # List to hold the deduplicated addresses.
    deduplicated_list = []
    
    # Iterate through the list of addresses.
    for addr in address_list:
        # Remove hyphen prefix, if any, for comparison.
        unhyphenated = addr.lstrip('-')
        
        # If this unhyphenated address hasn't been seen before, add it to both the seen dictionary and the deduplicated list.
        if unhyphenated not in seen_unhyphenated:
            seen_unhyphenated[unhyphenated] = addr
            deduplicated_list.append(addr)
        # If the unhyphenated version has been seen and the hyphenation status is the same, skip this address.
        elif seen_unhyphenated[unhyphenated].startswith('-') == addr.startswith('-'):
            continue
        # If the unhyphenated version has been seen but the hyphenation status is different, check which one appeared first.
        else:
            if address_list.index(seen_unhyphenated[unhyphenated]) > address_list.index(addr):
                # If the current address appeared first, replace the older one with this one in both the seen dictionary and deduplicated list.
                deduplicated_list.remove(seen_unhyphenated[unhyphenated])
                deduplicated_list.append(addr)
                seen_unhyphenated[unhyphenated] = addr
                
    return deduplicated_list

# Main Function
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="Manage and decrypt wallet data.")
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for generating a new wallet
    parser_generatewallet = subparsers.add_parser('generatewallet')

    parser_generatewallet.add_argument('-wallet', required=True, help="Specify the wallet filename.")
    parser_generatewallet.add_argument('-encrypt', action='store_true', help="Encrypt the new wallet.")
    parser_generatewallet.add_argument('-2fa', dest='tfa', action='store_true', help="Enables 2FA for a new encrypted wallet.")
    parser_generatewallet.add_argument('-password', help="Password used for wallet encryption and/or deterministic address generation.")
    parser_generatewallet.add_argument('-deterministic', action='store_true', help="Generates a deterministic wallet.")
    parser_generatewallet.add_argument('-backup', choices=['False', 'True'], help="Enable or disable backup of an existing wallet.")
    parser_generatewallet.add_argument('-disable-overwrite-warning', dest='disable_overwrite_warning', action='store_true', help="Disable warning when overwriting an existing wallet.")
    parser_generatewallet.add_argument('-overwrite-password', dest='overwrite_password', help="Password to overwrite an existing wallet that is encrypted.")
    
    # Subparser for generating a new address
    parser_generateaddress = subparsers.add_parser('generateaddress')
    parser_generateaddress.add_argument('-wallet', required=True, help="Specify the wallet filename.")
    parser_generateaddress.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_generateaddress.add_argument('-password', help="The password used for encryption and/or deterministic address generation of the specified wallet file.")
    
    # Subparser for decrypting the wallet
    parser_decryptwallet = subparsers.add_parser('decryptwallet')
    parser_decryptwallet.add_argument('-wallet', required=True, help="Specify the wallet filename.")
    parser_decryptwallet.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_decryptwallet.add_argument('-pretty', action='store_true', help="Print formatted json output for enhanced readability.")
    parser_decryptwallet.add_argument('-password', help="The password used for encryption of the specified wallet.")
    parser_decryptwallet.add_argument('-filter', help='Filter entries by address and/or field. Add a hyphen (-) to the beginning of an address to exclude it. Format is: -filter="address={ADDRESS_1, ADDRESS_2, ADDRESS_3, ...},field={id,mnemonic,private_key,public_key,address}". The entire filter string must be enclosed in quotation marks and parameters must be enclosed in curly braces ("\u007B\u007D").', default=None)
    
    # Subparser for filter under decryptwallet
    filter_subparser = parser_decryptwallet.add_subparsers(dest='filter_subparser', required=False)
    parser_filter = filter_subparser.add_parser('filter',help="Filter entries by address and/or field")
    parser_filter.add_argument('-address', help='One or more addresses to filter by. Add a hyphen (-) to the beginning of an address to exclude it. Format is: `address=ADDRESS_1, ADDRESS_2, ADDRESS_3,...`')
    parser_filter.add_argument('-field', help='One or more fields to filter by. Format is: `field=id,mnemonic,private_key,public_key,address`.')
    parser_filter.add_argument('-pretty', action='store_true', help="Print formatted json output for enhanced readability.", dest="filter_subparser_pretty")

    args = parser.parse_args()
    if args.command == "generatewallet":
        check_args(parser,args)        
        address = generateAddressHelper(filename=args.wallet, password=args.password, totp_code=None, new_wallet=True, encrypt=args.encrypt, use2FA=args.tfa,deterministic=args.deterministic,backup=args.backup,disable_warning=args.disable_overwrite_warning,overwrite_password=args.overwrite_password,from_cli=True)    
        if address:
            logging.info(f"Successfully generated new wallet. Address: {address}\n")

    elif args.command == "generateaddress":
        address = generateAddressHelper(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else None, new_wallet=False, encrypt=False, use2FA=False,from_cli=True)    
        if address:
            logging.info(f"Successfully generated address and stored wallet entry. Address: {address}\n")

    elif args.command == 'decryptwallet':
        address, field, args.filter_subparser_pretty = process_decryptwallet_filter(args)
        decrypted_data = decryptWalletEntries(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else "", address=address if address else None, fields=field if field else [], pretty=args.pretty or args.filter_subparser_pretty if args.pretty or args.filter_subparser_pretty else False)
        if decrypted_data:
            print(f'\nWallet Data:\n"{decrypted_data}"')
    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
    gc.collect()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\r  ")
        print("\rProcess terminated by user.")
        QRCodeUtils.close_qr_window(True)
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        gc.collect()
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        gc.collect()
        sys.exit(1)