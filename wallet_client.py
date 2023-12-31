import os
import json
import base64
import binascii
import logging
import argparse
import sys
import threading
import gc
import re
import time
from datetime import datetime

from decimal import Decimal, ROUND_DOWN
import requests
from collections import Counter, OrderedDict

# Get the absolute path of the directory containing the current script.
dir_path = os.path.dirname(os.path.realpath(__file__))

# Insert folder paths for modules
sys.path.insert(0, dir_path + "/denaro")
sys.path.insert(0, dir_path + "/denaro/wallet")
sys.path.insert(0, dir_path + "/denaro/wallet/utils")

from denaro.wallet.utils.wallet_generation_util import generate, generate_from_private_key, string_to_point, sha256
from denaro.wallet.utils.cryptographic_util import EncryptDecryptUtils, TOTP
from denaro.wallet.utils.verification_util import Verification
from denaro.wallet.utils.data_manipulation_util import DataManipulation
from denaro.wallet.utils.interface_util import QRCodeUtils, UserPrompts
from denaro.wallet.utils.transaction_utils.transaction_input import TransactionInput
from denaro.wallet.utils.transaction_utils.transaction_output import TransactionOutput
from denaro.wallet.utils.transaction_utils.transaction import Transaction

is_windows = os.name == 'nt'

if is_windows:
    import msvcrt
else:
    import termios, fcntl, readline

# Get the root logger
root_logger = logging.getLogger()

# Set the level for the root logger
root_logger.setLevel(logging.INFO if '-verbose' in sys.argv else logging.WARNING)

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
    Determines if a given segment of data appears to be encrypted.
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
    Gets a normalized file path, ensuring the directory exists.
    
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
def generate_encrypted_wallet_data(wallet_data, current_data, password, totp_secret, hmac_salt, verification_salt, stored_verifier, is_import=False):
    """Overview:
        The `generate_encrypted_wallet_data` function serves as a utility for constructing a fully encrypted representation 
        of the wallet's data. It works by individually encrypting fields like private keys or mnemonics and then organizing
        them in a predefined format. This function is vital in ensuring that sensitive wallet components remain confidential.
        
        Parameters:
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
        "id": EncryptDecryptUtils.encrypt_data(str(len(current_data["wallet_data"]["entry_data"]["entries"] if not is_import else current_data["wallet_data"]["entry_data"]["imported_entries"]) + 1), password, totp_secret, hmac_salt, verification_salt, stored_verifier),
        "private_key": EncryptDecryptUtils.encrypt_data(wallet_data['private_key'], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
    }
    
    # If the wallet is non-deterministic, encrypt the mnemonic
    if current_data["wallet_data"]["wallet_type"] == "non-deterministic" and not is_import:        
        encrypted_wallet_data["mnemonic"] = EncryptDecryptUtils.encrypt_data(wallet_data['mnemonic'], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
        del encrypted_wallet_data["private_key"]
        # Ensure a specific order for the keys
        desired_key_order = ["id", "mnemonic"]
        ordered_entry = OrderedDict((k, encrypted_wallet_data[k]) for k in desired_key_order if k in encrypted_wallet_data)
        encrypted_wallet_data = ordered_entry
    result = encrypted_wallet_data
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def generate_unencrypted_wallet_data(wallet_data, current_data, is_import=False):
    """Overview:
        Contrasting its encrypted counterpart, the `generate_unencrypted_wallet_data` function focuses on constructing 
        plaintext wallet data entries. While it doesn't encrypt data, it organizes the it in a structured manner, ensuring 
        easy storage and retrieval. This function is pivotal in scenarios where encryption isn't mandated, but structured 
        data organization is requisite.
        
        Parameters:
        - wallet_data (dict): The unencrypted wallet data.
        - current_data (dict): Existing wallet data, utilized to determine the next suitable ID for the entry.
        
        Returns:
        - dict: A structured dictionary containing the plaintext wallet data.
    """
    # Structure the data without encryption
    unencrypted_wallet_data = {
        "id": str(len(current_data["wallet_data"]["entry_data"]["entries"] if not is_import else current_data["wallet_data"]["entry_data"]["imported_entries"]) + 1),
        "private_key": wallet_data['private_key'],
        "public_key": wallet_data['public_key'],
        "address": wallet_data['address']
    }
    # For non-deterministic wallets, include the mnemonic
    if current_data["wallet_data"]["wallet_type"] == "non-deterministic" and not is_import:
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
        
        Parameters:
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
    verifier = Verification.hash_password(password, verification_salt)
    data["wallet_data"]["verifier"] = base64.b64encode(verifier).decode('utf-8')

    # If no TOTP code is provided, set it to an empty string
    if not totp_code:
        totp_code = ""

    # Handle Two-Factor Authentication (2FA) setup if enabled
    if use2FA:
        #global close_qr_window
        # Generate a secret for TOTP
        totp_secret = TOTP.generate_totp_secret(False,verification_salt)

        totp_qr_data = f'otpauth://totp/{filename}?secret={totp_secret}&issuer=Denaro Wallet Client'
        # Generate a QR code for the TOTP secret
        qr_img = QRCodeUtils.generate_qr_with_logo(totp_qr_data, "./denaro/wallet/denaro_logo.png")
        # Threading is used to show the QR window to the user while allowing input in the temrinal
        thread = threading.Thread(target=QRCodeUtils.show_qr_with_timer, args=(qr_img, filename, totp_secret,))
        thread.start()

        # Encrypt the TOTP secret for storage
        encrypted_totp_secret = EncryptDecryptUtils.encrypt_data(totp_secret, password, "", hmac_salt, verification_salt, verifier)
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
        totp_secret = TOTP.generate_totp_secret(True,verification_salt)
        encrypted_totp_secret = EncryptDecryptUtils.encrypt_data(totp_secret, password, "", hmac_salt, verification_salt, verifier)
        data["wallet_data"]["totp_secret"] = encrypted_totp_secret
        totp_secret = ""

    result = data, totp_secret, hmac_salt, verification_salt, verifier
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def handle_existing_encrypted_wallet(filename, data, password, totp_code, deterministic):
    """Overview:
        The `handle_existing_encrypted_wallet` function verifies access to an encrypted wallet by checking the provided password
        and decoding HMAC and verification salts from the wallet data. It conducts verification of the user's password against the
        stored verifier and the HMAC to ensure data integrity. If password verification fails, it updates the number of failed password
        attempts assocated with the wallet, it then logs an error for authentication failure or data corruption. For wallets with Two-Factor
        Authentication, it additionally manages TOTP verification. Upon successful verifications, it returns cryptographic components such as
        HMAC salt, verification salt, stored verifier, and TOTP secret.
    
        Parameters:
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
    password_verified, hmac_verified, stored_verifier = Verification.verify_password_and_hmac(data, password, hmac_salt, verification_salt, deterministic)

    # Based on password verification, update or reset the number of failed attempts
    data = DataManipulation.update_or_reset_attempts(data, filename, hmac_salt, password_verified, deterministic)

    if data is None:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None
    else:
        DataManipulation._save_data(filename,data)

    # Verify the password and HMAC
    password_verified, hmac_verified, stored_verifier = Verification.verify_password_and_hmac(data, password, hmac_salt, verification_salt, deterministic)

    # Fail if either the password or HMAC verification failed
    if not (password_verified and hmac_verified):
        logging.error("Authentication failed or wallet data is corrupted.")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None

    # If 2FA is enabled, handle the TOTP validation
    totp_secret, tfa_enabled = Verification.verify_totp_secret(password, data["wallet_data"]["totp_secret"], hmac_salt, verification_salt, stored_verifier)
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
        
        Parameters:
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
        EncryptDecryptUtils.encrypt_data(
            json.dumps({
                "id": EncryptDecryptUtils.encrypt_data(str(i+1), password, totp_secret, hmac_salt, verification_salt, stored_verifier), 
                "word": EncryptDecryptUtils.encrypt_data(word, password, totp_secret, hmac_salt, verification_salt, stored_verifier)
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
        
        Parameters:
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
        EncryptDecryptUtils.decrypt_data(
            json.loads(EncryptDecryptUtils.decrypt_data(encrypted_index, password, totp_secret, hmac_salt, verification_salt, stored_verifier))["word"],
            password, totp_secret, hmac_salt, verification_salt, stored_verifier
        ) for encrypted_index in encrypted_json
    ]
    result =  " ".join(decrypted_words)
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

# Wallet Orchestrator Functions
def generateAddressHelper(filename, password, totp_code=None, new_wallet=False, encrypt=False, use2FA=False, deterministic=False,backup=None,disable_warning=False,overwrite_password=None, amount=1, private_key=None, is_import=False):
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
           
        Parameters:
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
    # This handles the case if using generateaddress for a wallet that dose not exist
    if not new_wallet and not wallet_exists:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None
    
    if new_wallet:
        stored_encrypt_param = encrypt
        stored_deterministic_param = deterministic
    
    imported_entries = 0

    # Determine encryption status and wallet type for an existing wallet
    if wallet_exists or not new_wallet:
        # Convert part of the wallet data to a JSON string
        data_segment = json.dumps(data["wallet_data"])   

        # Check if the wallet data is encrypted and if a password is provided
        if is_wallet_encrypted(data_segment) and not password and not new_wallet:
            logging.error("Wallet is encrypted. A password is required to add additional addresses.")
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
        
        if "imported_entries" in data["wallet_data"]["entry_data"]:
            imported_entries = len(data["wallet_data"]["entry_data"]["imported_entries"])

        if len(data["wallet_data"]["entry_data"]["entries"]) + imported_entries > 255 and not new_wallet:
            print("Cannot proceed. Maximum wallet entries reached.")
            return None
    
    #Handle backup and overwrite for an existing wallet
    if new_wallet and wallet_exists:
        if "wallet_type" in data["wallet_data"]:
            deterministic = data["wallet_data"]["wallet_type"] == "deterministic"
        if not UserPrompts.backup_and_overwrite_helper(data, filename, overwrite_password, encrypt, backup, disable_warning, deterministic):
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return
        else:
            if '-verbose' in sys.argv:
                print()
        
    if new_wallet:
        logging.info("new_wallet is set to True.")
        encrypt = stored_encrypt_param    
        deterministic = stored_deterministic_param
    else:
        logging.info("new_wallet is set to False.")

    # Handle different scenarios based on whether the wallet is encrypted
    if encrypt:
        logging.info("encrypt is set to True.")     
        if new_wallet:
            logging.info("Handling new encrypted wallet.")
            # Handle creation of a new encrypted wallet
            data, totp_secret, hmac_salt, verification_salt, stored_verifier = handle_new_encrypted_wallet(password, totp_code, use2FA, filename, deterministic)
            if not data:
                logging.error(f"Error: Data from handle_new_encrypted_wallet is None!\nDebug: HMAC Salt: {hmac_salt}, Verification Salt: {verification_salt}, Stored Verifier: {stored_verifier}")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
        else:
            logging.info("Handling existing encrypted wallet.")
            # Handle operations on an existing encrypted wallet
            hmac_salt, verification_salt, stored_verifier, totp_secret = handle_existing_encrypted_wallet(filename, data, password, totp_code, deterministic)
            if not hmac_salt or not verification_salt or not stored_verifier:
                #logging.error(f"Error: Data from handle_existing_encrypted_wallet is None!\nDebug: HMAC Salt: {hmac_salt}, Verification Salt: {verification_salt}, Stored Verifier: {stored_verifier}")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
    else:
        logging.info("encrypt is set to False.")
    
    logging.info(f"is_import is set to {is_import}")
    
    # Check if the user is importing a wallet entry
    if not is_import:
        # If deterministic flag is set, generate addresses in a deterministic way
        if deterministic:
            logging.info("deterministic is set to True.")
            if not password:
                    logging.error("Password is required to derive the deterministic address.")
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                    return None
            if new_wallet:
                logging.info("Generating deterministic wallet data.")         
                # Generate the initial data for a new deterministic wallet
                wallet_data = generate(passphrase=password,deterministic=True)
                if encrypt:
                    logging.info("Data successfully generated for new encrypted deterministic wallet.")                   
                    logging.info("Parseing and encrypting master mnemonic.")
                    # Parse and encrypt the mnemonic words individually
                    data["wallet_data"]["entry_data"]["key_data"] = parse_and_encrypt_mnemonic(wallet_data["mnemonic"], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
                else:
                    logging.info("Data successfully generated for new unencrypted deterministic wallet.")
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
                    logging.info("Decrypting and parsing the master mnemonic.")
                    # Decrypt and parse the existing mnemonic for the deterministic wallet
                    mnemonic = decrypt_and_parse_mnemonic(data["wallet_data"]["entry_data"]["key_data"], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
                    logging.info("Master mnemonic successfully decrypted.")
                    wallet_data = []
                    entries_generated = -1
                    logging.info("Generating deterministic wallet data.")
                    for _ in range(amount):
                        if index + entries_generated < 256:
                            entries_generated += 1
                            generated_data = generate(mnemonic_phrase=mnemonic, passphrase=password, index=index+entries_generated, deterministic=True)
                            wallet_data.append(generated_data)
                        if index + len(wallet_data) >= 256:
                            print("Maximum wallet entries reached.\n")
                            break
                    logging.info(f"{entries_generated + 1} address(es) successfully generated for existing encrypted determinsitic wallet.")
                else:
                    # Use the existing mnemonic directly if it's not encrypted
                    mnemonic = data["wallet_data"]["entry_data"]["master_mnemonic"]
                    logging.info("Validating passphrase used for address derivation.")
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
                        logging.info("Passphrase validated.")
                        wallet_data = []
                        entries_generated = -1
                        logging.info("Generating deterministic wallet data.")
                        for _ in range(amount):
                            if index + entries_generated < 256:
                                entries_generated += 1
                                generated_data = generate(mnemonic_phrase=mnemonic, passphrase=password, index=index + entries_generated, deterministic=True)
                                wallet_data.append(generated_data)
                            if index + len(wallet_data) >= 256:
                                print("Maximum wallet entries reached.\n")
                                break
                        logging.info(f"{entries_generated + 1} address(es) successfully generated for existing unencrypted determinsitic wallet.")
        else:
            logging.info("deterministic is set to False")
            # For non-deterministic wallets, generate a random wallet data        
            if not new_wallet:
                wallet_data = []
                entries_generated = -1
                logging.info("Generating non-deterministic wallet data.")
                for _ in range(amount):
                    if len(data["wallet_data"]["entry_data"]["entries"]) < 256:
                        generated_data = generate()
                        wallet_data.append(generated_data)
                        entries_generated += 1
                    if len(data["wallet_data"]["entry_data"]["entries"]) + len(wallet_data) >= 256:
                        print("Maximum wallet entries reached.\n")
                        break
                if encrypt:
                    logging.info(f"{entries_generated + 1} address(es) successfully generated for existing encrypted non-determinsitic wallet.")
                else:
                    logging.info(f"{entries_generated + 1} address(es) successfully generated for existing unencrypted non-determinsitic wallet.")
            else:
                logging.info("Generating non-deterministic wallet data.")
                wallet_data = generate()
            if new_wallet and not encrypt:
                data = {
                    "wallet_data": {
                        "wallet_type": "non-deterministic",
                        "version": "0.2.2",
                        "entry_data": {
                            "entries":[]
                        }
                        
                    }
                }
                logging.info("Data successfully generated for new unencrypted non-deterministic wallet.")
            if new_wallet and encrypt:
                logging.info("Data successfully generated for new encrypted non-deterministic wallet.")
    else:
        if not new_wallet:
            # Initialize wallet_data dictionary
            wallet_data = []
            
            # Get number of wallet entries
            index = len(data["wallet_data"]["entry_data"]["entries"])
            
            # Return None if amount of wallet entries are 256 or more
            if len(data["wallet_data"]["entry_data"]["entries"]) >= 256:
                logging.error("Maximum wallet entries reached.\n")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
            
            # Validate private key using regex pattern
            private_key_pattern = r'^(0x)?[0-9a-fA-F]{64}$'
            if not re.match(private_key_pattern, private_key):
                logging.error("The private key provided is not valid.")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
            
            # Remove 0x prefix from private key if it exists 
            if private_key.startswith('0x'):
                private_key = private_key[2:]
              
            logging.info("Generating import data based on the provided private key.")

            # Generate wallet data from private key
            generated_data = generate_from_private_key(private_key_hex=private_key)

            if generated_data:
                logging.info("Data successfully generated from private key.")
            
            # Ensure imported_entries exists
            if not "imported_entries" in data["wallet_data"]["entry_data"]:
                data["wallet_data"]["entry_data"]["imported_entries"] = []

            # Append generated data to wallet_data
            wallet_data.append(generated_data)

    # Prepare data to be saved based on encryption status
    if encrypt:
        # Prepare encrypted data to be saved
        logging.info("Encrypting generated data.")        
        if new_wallet:
            encrypted_wallet_data = generate_encrypted_wallet_data(wallet_data, data, password, totp_secret, hmac_salt, verification_salt, stored_verifier)
            encrypted_data_entry = EncryptDecryptUtils.encrypt_data(json.dumps(encrypted_wallet_data), password, totp_secret, hmac_salt, verification_salt, stored_verifier)
            data["wallet_data"]["entry_data"]["entries"].append(encrypted_data_entry)
        else:
            for item in wallet_data:
                encrypted_wallet_data = generate_encrypted_wallet_data(item, data, password, totp_secret, hmac_salt, verification_salt, stored_verifier, is_import=is_import)
                encrypted_data_entry = EncryptDecryptUtils.encrypt_data(json.dumps(encrypted_wallet_data), password, totp_secret, hmac_salt, verification_salt, stored_verifier)
                if not is_import:
                    data["wallet_data"]["entry_data"]["entries"].append(encrypted_data_entry)
                else:
                    data["wallet_data"]["entry_data"]["imported_entries"].append(encrypted_data_entry)
        
        # Set HMAC message based on the encrypted wallet data
        if deterministic:
            hmac_msg = json.dumps(data["wallet_data"]["entry_data"]["entries"]).encode() + json.dumps(data["wallet_data"]["entry_data"]["key_data"]).encode()
        else:
            hmac_msg = json.dumps(data["wallet_data"]["entry_data"]["entries"]).encode()
        
        if "imported_entries" in data["wallet_data"]["entry_data"]:
            hmac_msg = json.dumps(data["wallet_data"]["entry_data"]["imported_entries"]).encode() + hmac_msg

        # Calculate HMAC for wallet's integrity verification
        computed_hmac = Verification.hmac_util(password=password,hmac_salt=hmac_salt,hmac_msg=hmac_msg,verify=False)
        data["wallet_data"]["hmac"] = base64.b64encode(computed_hmac).decode()
    else:
        # Prepare unencrypted data to be saved
        if new_wallet:
            unencrypted_data_entry = generate_unencrypted_wallet_data(wallet_data, data)
            data["wallet_data"]["entry_data"]["entries"].append(unencrypted_data_entry)       
        else:
            for item in wallet_data:
                unencrypted_data_entry = generate_unencrypted_wallet_data(item, data, is_import=is_import)
                if not is_import:
                    data["wallet_data"]["entry_data"]["entries"].append(unencrypted_data_entry)
                else:
                    data["wallet_data"]["entry_data"]["imported_entries"].append(unencrypted_data_entry)

    # Save the updated wallet data back to the file
    logging.info("Saving data to wallet file.")
    DataManipulation._save_data(filename, data)
    
    # Extract the newly generated address to be returned
    if "-verbose" in sys.argv:
        print("\n")
        print("\033[2A")
    
    # Sgie warning and other info to user
    warning = 'WARNING: Never disclose your mnemonic phrase or private key! Anyone with access to these can steal the assets held in your account.'
    if not is_import:
        if amount == 1 and new_wallet:
            result = f"Successfully generated new wallet.\n\n{warning}\n{'Master Mnemonic' if deterministic else 'Mnemonic'}: {wallet_data['mnemonic']}\nPrivate Key: 0x{wallet_data['private_key']}\nAddress #{len(data['wallet_data']['entry_data']['entries'])}: {wallet_data['address']}"
        if amount == 1 and not new_wallet:
            n ='\n'
            result = f"Successfully generated and stored wallet entry.\n\n{warning}{n+'Mnemonic: ' + wallet_data[0]['mnemonic'] if not deterministic else ''}\nPrivate Key: 0x{wallet_data[0]['private_key']}\nAddress #{len(data['wallet_data']['entry_data']['entries'])}: {wallet_data[0]['address']}"
        elif amount > 1 and not new_wallet:
            result = f"Successfully generated and stored {entries_generated + 1} wallet entries."
    else:
        result = f"Successfully imported wallet entry.\n\n{warning}\nImported Private Key #{len(data['wallet_data']['entry_data']['imported_entries'])}: 0x{wallet_data[0]['private_key']}\nAddress: {wallet_data[0]['address']}"
        print(result)
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def decryptWalletEntries(filename, password, totp_code=None, address=[], fields=[], pretty=False, show=None):
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
        input parameters for the `generate` function. The `generate` function is used to deterministically produce additional wallet
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
        
        Parameters:
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
    is_encrypted = is_wallet_encrypted(data_segment)    
    
    # Initialize a flag to check if the wallet type is deterministic
    deterministic = False

    # Check if the wallet type is present in the data and set the deterministic flag accordingly
    if "wallet_type" in data["wallet_data"]:
        deterministic = data["wallet_data"]["wallet_type"] == "deterministic"
    
    index = len(data["wallet_data"]["entry_data"]["entries"])
    
    imported_entries_length = 0
    if "imported_entries" in data["wallet_data"]["entry_data"]:
        imported_entries_length = len(data["wallet_data"]["entry_data"]["imported_entries"])

    if is_encrypted:
        # Extract necessary cryptographic salts and secrets for the encrypted wallet
        hmac_salt, verification_salt, stored_verifier, totp_secret = handle_existing_encrypted_wallet(filename, data, password, totp_code, deterministic)
        
        # Ensure none of the cryptographic values are missing
        if not hmac_salt or not verification_salt or not stored_verifier:
            #print(f"Error: Data from handle_existing_encrypted_wallet is None!\nDebug: HMAC Salt: {hmac_salt}, Verification Salt: {verification_salt}, Stored Verifier: {stored_verifier}")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
        
        # Handle warnings and messages
        if 'send' in sys.argv:
            print("\nA private key is required to send funds. \nSince a private key has not been provided, the wallet client will attempt to decrypt each entry in the wallet file until it finds the private key associated with the address specified. \nYou can use the '-private-key' argument to make this process alot faster. However, doing this is not secure and can put your funds at risk.\n")
        
        if index + imported_entries_length >= 32:
            logging.warning(f"The encrypted wallet file contains {index} entries and is quite large. Decryption {'and balance requests ' if 'balance' in sys.argv else ''}may take a while.\n")
    else:
        if index + imported_entries_length >= 32 and 'balance' in sys.argv:
            logging.warning(f"The wallet file contains {index} entries and and is quite large. Balance requests for entire wallets may take a while.\n")

    # If the wallet is deterministic, decrypt and parse the mnemonic phrase
    if deterministic:
        if is_encrypted:
            mnemonic = decrypt_and_parse_mnemonic(data["wallet_data"]["entry_data"]["key_data"], password, totp_secret, hmac_salt, verification_salt, stored_verifier)
        else:
            mnemonic = data["wallet_data"]["entry_data"]["master_mnemonic"]
        
    # List to hold decrypted wallet entries
    decrypted_entries = []

    # If no fields are specified then all fields are considered
    if fields == []:
        fields = ["mnemonic", "id", "private_key", "public_key", "address","is_import"]    
    
    entry_count = 0
    address_found = False
    is_import = False
    
    if show:
        if "imported" in show:
            if "imported_entries" in data["wallet_data"]["entry_data"]:
                index = 0
                del data["wallet_data"]["entry_data"]["entries"]
        
        if "generated" in show:
            if "imported_entries" in data["wallet_data"]["entry_data"]:
                imported_entries_length = 0
                del data["wallet_data"]["entry_data"]["imported_entries"]

    for entry_data in data["wallet_data"]["entry_data"]:        
        if entry_data != "key_data" and entry_data != "master_mnemonic":            
            for entry in data["wallet_data"]["entry_data"][entry_data]:
                if entry_data == "imported_entries":
                    is_import = True                
                if is_encrypted:
                    entry_count += 1        
                    # If wallet is encrypted, decrypt each entry in the wallet data
                    entry_with_encrypted_values = json.loads(EncryptDecryptUtils.decrypt_data(entry, password, totp_secret, hmac_salt, verification_salt, stored_verifier))            
                    fully_decrypted_entry = {}
                    for key, encrypted_value in entry_with_encrypted_values.items():
                        fully_decrypted_entry[key] = EncryptDecryptUtils.decrypt_data(encrypted_value, password, totp_secret, hmac_salt, verification_salt, stored_verifier)        
                    # Generate required data fields based on the mnemonic phrase and deterministic flag
                    generated_data = {}
                    if not is_import:
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
                    else:
                        generated_data = generate_from_private_key(private_key_hex=fully_decrypted_entry["private_key"])
                        generated_data["is_import"] = is_import
                    # Update the decrypted entry with the generated data
                    fully_decrypted_entry.update(generated_data)        
                    if 'send' in sys.argv:
                        print(f"\rDecrypting wallet entry {entry_count} of {index + imported_entries_length} | Address: {generated_data['address']}", end='')
                        if address[0] in fully_decrypted_entry['address']:
                            print("\nAddress Found.\n")
                            decrypted_entries = []
                            decrypted_entries.append(fully_decrypted_entry)
                            address_found = True
                            break
                        else:
                            decrypted_entries = []
                    else:
                        print(f"\rDecrypting wallet entry {entry_count} of {index + imported_entries_length}", end='')
                else:
                    fully_decrypted_entry = {}
                    for key, value in entry.items():
                        fully_decrypted_entry[key] = value
                    if is_import:
                        fully_decrypted_entry["is_import"] = is_import        
                decrypted_entries.append(fully_decrypted_entry)
        if 'send' in sys.argv and address_found:
            break            

    if is_encrypted and not address_found:
        print("\n")

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
        
        showed_warning = False
        # Check if there are any addresses not found for inclusion or exclusion
        if not_found_inclusion or not_found_exclusion:
            not_found_all = list(set(not_found_inclusion + not_found_exclusion))
            not_found_all.sort(key=lambda x: address.index(x) if x in address else address.index('-' + x))
            if not 'send' in sys.argv:
                logging.warning(f"The following {'address is' if len(not_found_all) == 1 else 'addresses are'} not associated with this wallet: {', '.join(not_found_all)}\n")
                showed_warning = True
            else:
                logging.error(f"The address specified is not associated with this wallet.")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return None
    
        # Error logic
        if not unique_filtered_entries:
            if not 'send' in sys.argv and not showed_warning:
                if all(addr in addresses_to_exclude for addr in all_decrypted_addresses):
                    logging.error("All of the addresses associated with the wallet have been excluded. There is nothing to return.\n")# Returning no entries.")
                else:
                    logging.error(f"{'The address specified is not' if len(address) == 1 else 'None of the addresses specified are'} associated with this wallet.\n")# Returning all wallet entries...")        
        else:
            # Sort and return unique_filtered_entries
            unique_filtered_entries.sort(key=lambda x: int(x['id']))
            decrypted_entries = unique_filtered_entries
    
    # Specify the desired order of fields for output        
    ordered_field_names = ["id", "mnemonic", "private_key", "public_key", "address", "is_import"]
        
    # If specific fields are requested, filter and order the decrypted entries based on those fields
    if fields:        
        decrypted_entries = [OrderedDict((field, entry[field]) for field in ordered_field_names if field in fields and field in entry) for entry in decrypted_entries]
    else:
        # Ensure the order of fields in the output, even if no specific fields are requested
        decrypted_entries = [OrderedDict((field, entry[field]) for field in ordered_field_names if field in entry) for entry in decrypted_entries]
    
    imported_entries = []
    for entry in decrypted_entries:
        if "is_import" in entry:
            imported_entries.append(entry)

    for entry in imported_entries:
        if entry in decrypted_entries:
            del entry["is_import"]
            decrypted_entries.remove(entry)
    
    # Convert the decrypted entries to a readable format based on the `pretty` flag
    if pretty:
        if "mnemonic" in fields and deterministic:
            formatted_output = json.dumps({"entry_data":{"master_mnemonic": mnemonic, "entries": decrypted_entries}}, indent=4)
            if len(imported_entries) > 0:
                formatted_output = json.dumps({"entry_data":{"master_mnemonic": mnemonic, "entries": decrypted_entries, "imported_entries": imported_entries}}, indent=4)
        else:            
            formatted_output = json.dumps({"entry_data":{"entries": decrypted_entries}}, indent=4)
            if len(imported_entries) > 0:
                formatted_output = json.dumps({"entry_data":{"entries": decrypted_entries, "imported_entries": imported_entries}}, indent=4)
    else:
        if "mnemonic" in fields and deterministic:
            formatted_output = json.dumps({"entry_data":{"master_mnemonic": mnemonic, "entries": decrypted_entries}})
            if len(imported_entries) > 0:
                formatted_output = json.dumps({"entry_data":{"master_mnemonic": mnemonic, "entries": decrypted_entries, "imported_entries": imported_entries}})
        else:
            formatted_output = json.dumps({"entry_data":{"entries": decrypted_entries}})
            if len(imported_entries) > 0:
                formatted_output = json.dumps({"entry_data":{"entries": decrypted_entries, "imported_entries": imported_entries}})
    
    # Convert JSON string back to dictionary
    formatted_output = json.loads(formatted_output)

    # Remove 'entries' key if empty and imported entries are only being returned
    if show == "imported" and formatted_output["entry_data"].get("entries") == []:
        del formatted_output["entry_data"]["entries"]    
    
    # Convert back to JSON string
    formatted_output = json.dumps(formatted_output, indent=4)


    result = formatted_output
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])

    if not is_encrypted and not all(addr in addresses_to_exclude for addr in all_decrypted_addresses) and not "balance" in sys.argv and not "send" in sys.argv:
        print("Wallet data does not appear to be encrypted. Returning un-encrypted data.\n")

    return result

#Transaction Functions
def validate_and_select_node(node):
    """
    Overview:
        This function is responsible for ensuring that the address of a Denaro node is valid and usable for 
        interactions with the blockchain network. It first checks if a node address is provided. If so, it
        validates the address by calling the `validate_node_address` method. If no address is provided,
        it defaults to a pre-defined, reliable node address. This function is essential for ensuring that
        subsequent blockchain operations such as transactionsor balance queries are directed to a valid node.

    Parameters:
        node (str): The node address to validate. If None, a default node address is used.

    Returns:
        str or None: The function returns the node address if the validation is successful or the default 
        node address if no address is provided. It returns None if the provided address is invalid.
    """
    if node:
        is_node_valid, node = Verification.validate_node_address(node)
        if not is_node_valid:
            node = 'https://denaro-node.gaetano.eu.org'
    else:
        node = 'https://denaro-node.gaetano.eu.org'
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not node])
    return node

def initialize_wallet(filename):
    ensure_wallet_directories_exist()
    filename = get_normalized_filepath(filename)
    data, wallet_exists = _load_data(filename, False)

    # Determine if wallet is encrypted
    encrypted = False
    if wallet_exists:
        data_segment = json.dumps(data["wallet_data"])
        encrypted = is_wallet_encrypted(data_segment)
       
    result = wallet_exists, filename, encrypted
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def checkBalance(filename, password, totp_code, address, node, to_json, to_file, show=None):
    """
    Checks the balance of cryptocurrency addresses.

    :param filename: The wallet file name.
    :param password: The password for the wallet file.
    :param totp_code: The Time-based One-Time Password for additional security.
    :param address: The cryptocurrency address or list of addresses to check.
    :param node: The node to use for balance checking.
    :param to_json: Flag to determine if output should be in JSON format.
    :return: None or JSON data.
    """
    # Select a valid node
    node = validate_and_select_node(node)
    if node is None:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None

    encrypted = False
    if filename:
        wallet_exists, filename, encrypted = initialize_wallet(filename)
        if not wallet_exists:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None

        # Error logging for encrypted wallet without a password
        if encrypted and not password:
            logging.error("Wallet is encrypted. A password is required.")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
        
        # Decrypt wallet entries
        address_data = decryptWalletEntries(filename=filename, password=password, totp_code=totp_code if totp_code else "", address=address if address else [], fields=['address','id', "is_import"], pretty=False, show=show)
        if not address_data:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
        entry_data = json.loads(address_data)['entry_data']
        total_balance = 0
        total_pending = 0
        is_import = False
        
        if show:
            if "imported" in show:
                if "imported_entries" in entry_data and "entries" in entry_data:
                    del entry_data["entries"]
            
            if "generated" in show:
                if "imported_entries" in entry_data:
                    del entry_data["imported_entries"]

        if entry_data is not None:                    
            if not to_json:
                # Print balance information
                print(f"Balance Information For: {filename}")
                print("-----------------------------------------------------------")
                for entry_feild in entry_data:
                    if entry_feild == "imported_entries":
                        is_import = True
                    for entry in entry_data[entry_feild]:
                        id = entry['id']
                        address = entry['address']
                        balance, pending_balance, is_error = get_balance_info(address, node)
                        if is_error:
                            break
                        total_balance += balance
                        total_pending += pending_balance
                        print(f'{"Imported " if is_import else ""}Address #{id}: {address}\nBalance: {balance} DNR{f" (Pending: {pending_balance} DNR)" if pending_balance != 0 else ""}\n')
                print("\033[F-----------------------------------------------------------")
                print(f'Total Balance: {total_balance} DNR')
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            
            if to_json or to_file:
                # Prepare JSON data
                balance_data = {"balance_data": {"wallet_file_path": filename, "wallet_version":"0.2.2", "addresses": [], "imported_addresses" : [], "lastUpdated": datetime.utcnow().isoformat() + "Z"}}

                if not "imported_entries" in entry_data or entry_data["imported_entries"] == []:
                    del balance_data["balance_data"]["imported_addresses"]

                if not "entries" in entry_data or entry_data["entries"] == []:
                    del balance_data["balance_data"]["addresses"]

                for entry_feild in entry_data:
                    if entry_feild == "imported_entries":
                        is_import = True                    
                    for entry in entry_data[entry_feild]:
                        address = entry['address']
                        balance, pending_balance, is_error = get_balance_info(address, node)
                        if is_error:
                            break
                        if not is_import:
                            balance_data["balance_data"]["addresses"].append({
                                "id": entry['id'],
                                "address": address,
                                "balance": {
                                    "currency" : "DNR",
                                    "amount" : str(balance)
                                }
                            })
                        else:
                            balance_data["balance_data"]["imported_addresses"].append({
                                "id": entry['id'],
                                "address": address,
                                "balance": {
                                    "currency" : "DNR",
                                    "amount" : str(balance)
                                }
                            })
                if to_json:
                    print(json.dumps(balance_data, indent=4))
                if to_file:
                    # Define the file path and name
                    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    wallet_name = os.path.splitext(os.path.basename(filename))[0]
                    balance_info_dir = os.path.join(os.path.dirname(filename), "balance_information")
                    file_directory = os.path.join(balance_info_dir, wallet_name)
                    file_name = f"{wallet_name}_balance_{timestamp}.json"
                    file_path = os.path.join(file_directory, file_name)
        
                    # Ensure balance_information directory exists
                    if not os.path.exists(balance_info_dir):
                        os.makedirs(balance_info_dir)
        
                    # Create wallet-specific directory if it doesn't exist
                    if not os.path.exists(file_directory):
                        os.makedirs(file_directory)
        
                    # Save the balance data to file
                    with open(file_path, 'w') as file:
                        json.dump(balance_data, file, indent=4)
        
                    print(f"\nBalance information saved to file: {file_path}")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        else:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None

def prepareTransaction(filename, password, totp_code, amount, sender, private_key, receiver, message, node):
    
    node = validate_and_select_node(node)
    if node is None:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None

    encrypted = False
    address_pattern = r'^[DE][1-9A-HJ-NP-Za-km-z]{44}$'
    if filename and sender and not private_key:

        #Validate wallet address using regex pattern        
        if not re.match(address_pattern, sender):
             logging.error("The wallet address provided is not valid.")
             DataManipulation.secure_delete([var for var in locals().values() if var is not None])
             return None
    
        wallet_exists, filename, encrypted = initialize_wallet(filename)
        if not wallet_exists:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None

        # If wallet is encrypted and password is not provided, log an error
        if encrypted and not password:
            logging.error("Wallet is encrypted. A password is required.")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None

        decrypted_data = decryptWalletEntries(filename=filename, password=password, totp_code=totp_code if totp_code else "", address=[sender], fields=['private_key'], pretty=False)
        if not decrypted_data is None:
            decrypted_data = json.loads(decrypted_data)
            private_key = decrypted_data['entry_data']['entries'][0]['private_key']
        
        if private_key is None:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None

    if not filename and private_key:
        # Validate private key using regex pattern
        private_key_pattern = r'^(0x)?[0-9a-fA-F]{64}$'
        if not re.match(private_key_pattern, private_key):
            logging.error("The private key provided is not valid.")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
        # Remove 0x prefix from private key if it exists 
        if private_key.startswith('0x'):
            private_key = private_key[2:]
        # Generate sending address from private key
        generated_address = generate_from_private_key(private_key_hex=private_key, fields=["address"])
        sender = generated_address['address']
    
    # Convert private key to int
    private_key = int(private_key, 16)

    # Handle message variable
    if message is None:
        message = None
    try:
        message = bytes.fromhex(message)
    except ValueError:
        message = message.encode('utf-8')
    
    #Validate receiving address using regex pattern        
    if not re.match(address_pattern, receiver):
        logging.error("The recieving address is not valid.")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None
    
    print(f"Attempting to send {amount} DNR from {sender} to {receiver}.\n")
    # Create the transaction
    result = create_transaction([private_key], sender, receiver, amount, message, node=node)
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result
    
def create_transaction(private_key, sender, receiving_address, amount, message: bytes = None, send_back_address=None, node=None):
    amount = Decimal(amount)
    inputs = []
    
    for key in private_key:
        if send_back_address is None:
            send_back_address = sender
        balance, address_inputs, is_pending, pending_transactions, is_error = get_address_info(sender, node)
        if is_error:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
        for address_input in address_inputs:
            address_input.private_key = key
        inputs.extend(address_inputs)
        if sum(input.amount for input in sorted(inputs, key=lambda item: item.amount, reverse=False)[:255]) >= amount:
            break
    
    if not inputs:
        if is_pending:
            logging.error("No spendable outputs. Please wait for pending transactions to be confirmed.")
            if pending_transactions is not None:
                print("\nTransactions awaiting confirmation:")
                count = 0
                for tx in pending_transactions:
                    count += 1
                    print(f"{count}: {tx[0]}")
        else:
            logging.error('No spendable outputs.')
            if not balance > 0:
                print("The associated address dose not have enough funds.")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None
    
    # Check if accumulated inputs are sufficient
    if sum(input.amount for input in inputs) < amount:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        print("The associated address dose not have enough funds.")
        return None

    # Select appropriate transaction inputs
    transaction_inputs = []
    for tx_input in sorted(inputs, key=lambda item: item.amount, reverse=False):
        transaction_inputs.append(tx_input)
        if sum(input.amount for input in transaction_inputs) >= amount:
            break

    # Ensure that the transaction amount is adequate
    transaction_amount = sum(input.amount for input in transaction_inputs)
    if transaction_amount < amount:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not transaction_amount])
        logging.error(f"Consolidate outputs: send {transaction_amount} Denari to yourself")
        return None
    
    # Create the transaction
    transaction = Transaction(transaction_inputs, [TransactionOutput(receiving_address, amount=amount)], message)
    if transaction_amount > amount:
        transaction.outputs.append(TransactionOutput(send_back_address, transaction_amount - amount))

    # Sign and send the transaction
    transaction.sign([private_key])
    
    # Push transaction to node
    try:
        request = requests.get(f'{node}/push_tx', {'tx_hex': transaction.hex()}, timeout=10)
        request.raise_for_status()
        response = request.json()
                
        if not response.get('ok'):
            logging.error(response.get('error'))
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None
    
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not transaction])
        return transaction
    
    except requests.RequestException as e:
        # Handles exceptions that occur during the request
        logging.error(f"Error during request to node: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None

    except ValueError as e:
        # Handles JSON decoding errors
        logging.error(f"Error decoding JSON response: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None

    except KeyError as e:
        # Handles missing keys in response data
        logging.error(f"Missing expected data in response: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None

def get_address_info(address: str, node: str):
    try:
        # Send the request to the node
        request = requests.get(f'{node}/get_address_info', {'address': address, 'transactions_count_limit': 0, 'show_pending': True})
        request.raise_for_status()

        response = request.json()

        if not response.get('ok'):
            logging.error(response.get('error'))
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None, None, None, None, True

        result = response['result']
        is_pending = False
        tx_inputs = []
        pending_spent_outputs = []

        for value in result['pending_spent_outputs']:
            pending_spent_outputs.append((value['tx_hash'], value['index']))

        for spendable_tx_input in result['spendable_outputs']:
            if (spendable_tx_input['tx_hash'], spendable_tx_input['index']) in pending_spent_outputs:
                is_pending = True
                continue

            tx_input = TransactionInput(spendable_tx_input['tx_hash'], spendable_tx_input['index'])
            tx_input.amount = Decimal(str(spendable_tx_input['amount']))
            tx_input.public_key = string_to_point(address)
            tx_inputs.append(tx_input)

        final_result = Decimal(result['balance']), tx_inputs, is_pending, pending_spent_outputs, False
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not final_result])
        return final_result

    except requests.RequestException as e:
        # Handles exceptions that occur during the request
        logging.error(f"Error during request to node: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None, True

    except ValueError as e:
        # Handles JSON decoding errors
        logging.error(f"Error decoding JSON response: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None, True

    except KeyError as e:
        # Handles missing keys in response data
        logging.error(f"Missing expected data in response: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, None, None, True

def get_balance_info(address: str, node: str):
    """
    Fetches the account data from the node and calculates the pending balance.

    :param address: The address of the account.
    :param node: The node URL to fetch data from.
    :return: The total balance and pending balance of the account.
    :raises: ConnectionError, ValueError, KeyError
    """
    try:
        # Send the request to the node
        request = requests.get(f'{node}/get_address_info', params={'address': address, 'show_pending': True})
        request.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code

        response = request.json()
        result = response.get('result')
        
        if not response.get('ok'):
            logging.error(response.get('error'))
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None, None, True
    
        # Handle potential missing 'result' key
        if result is None:
            logging.error("Missing 'result' key in response")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return None, None, True

        pending_transactions = result.get('pending_transactions', [])
        spendable_outputs = result.get('spendable_outputs', [])
        
        # Create a set of spendable transaction hashes for easy lookup
        spendable_hashes = {output['tx_hash'] for output in spendable_outputs}
        
        # Ensure the balance is a string before converting to Decimal
        total_balance = Decimal(str(result['balance']))
        pending_balance = Decimal('0')

        for transaction in pending_transactions:
            # Adjust the balance based on inputs
            for input in transaction.get('inputs', []):
                if input.get('address') == address and input.get('tx_hash') in spendable_hashes:
                    input_amount = Decimal(str(input.get('amount', '0')))
                    pending_balance -= input_amount

            # Adjust the balance based on outputs
            for output in transaction.get('outputs', []):
                if output.get('address') == address:
                    output_amount = Decimal(str(output.get('amount', '0')))
                    pending_balance += output_amount

        # Format the total balance and pending balance to remove unnecessary trailing zeros
        formatted_total_balance = total_balance.quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
        formatted_pending_balance = pending_balance.quantize(Decimal('0.000001'), rounding=ROUND_DOWN)
        
        balance_data = formatted_total_balance, formatted_pending_balance, False
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not balance_data])
        return balance_data
    
    except requests.RequestException as e:
        # Handles exceptions that occur during the request
        logging.error(f"Error during request to node: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, True

    except ValueError as e:
        # Handles JSON decoding errors
        logging.error(f"Error decoding JSON response: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, True

    except KeyError as e:
        # Handles missing keys in response data
        logging.error(f"Missing expected data in response: {e}")
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        return None, None, True

# Argparse Helper Functions
def sort_arguments_based_on_input(argument_names):
    """
    Overview:
        Sorts a list of CLI argument names based on their positional occurrence in sys.argv.
        Any argument not found in sys.argv is filtered out. The returned list is then formatted
        as a comma-separated string. This version also handles arguments with an '=' sign.

        Parameters:
        - argument_names (list): A list of argument names to be sorted.
    
        Returns:
        - str: A string of sorted argument names separated by commas with 'and' added before the last argument.
    
        Note:
            This function leverages the sys.argv array, which captures the command-line arguments passed to the script.
    """
    # Process each argument in sys.argv to extract the argument name before the '=' sign
    processed_argv = [arg.split('=')[0] for arg in sys.argv]

    # Filter out arguments that are not present in the processed sys.argv
    filtered_args = [arg for arg in argument_names if arg in processed_argv]

    # Sort the filtered arguments based on their index in the processed sys.argv
    sorted_args = sorted(filtered_args, key=lambda x: processed_argv.index(x))    

    # Join the arguments into a string with proper formatting
    if len(sorted_args) > 1:
        result = ', '.join(sorted_args[:-1]) + ', and ' + sorted_args[-1]    
    elif sorted_args:
        result = sorted_args[0]
    else:
        result = ''
    DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
    return result

def check_args(parser, args):
    """Overview:
        Validates combinations of CLI arguments and returns an error message via the parser
        if invalid combinations are found. Specifically, it checks for required combinations
        that involve the '-password' flag.

        Parameters:
        - parser (argparse.ArgumentParser): The argument parser object.
        - args (argparse.Namespace): The argparse namespace containing parsed arguments.
    
        Note:
            Utilizes the `sort_arguments_based_on_input` function to display arguments in the
            order in which they were passed in the command line.
    """
    if args.command == "generatewallet":
        # -deterministic, -2fa, and -encrypt requires -password
        if args.deterministic and args.tfa and args.encrypt and not args.password:
            sorted_args = sort_arguments_based_on_input(['-deterministic', '-2fa', '-encrypt', '-password'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} requires the -password argument to be set.\nContext: A password is required to encrypt the wallet, enable 2-Factor Authentication, and for deterministic address generation.")
    
        # -2fa and -encrypt requires -password
        if args.tfa and args.encrypt and not args.password:
            sorted_args = sort_arguments_based_on_input(['-2fa', '-encrypt', '-password'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} requires the -password argument to be set.\nContext: A password is required for encrypted wallets with 2-Factor Authentication enabled.")
    
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

            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args and var is not context_str])
            parser.error(f"{sorted_args} requires both the -encrypt and -password arguments to be set.\nContext: {context_str}")
    
        # -encrypt and -deterministic requires -password
        if args.encrypt and args.deterministic and not args.password:
            sorted_args = sort_arguments_based_on_input(['-encrypt', '-deterministic', '-password'])
            parser.error(f"{sorted_args} requires the -password argument to be set.\nContext: A password is required to encrypt the wallet and for deterministic address generation.")
    
        # -deterministic alone requires -password
        if args.deterministic and not args.password:
            sorted_args = sort_arguments_based_on_input(['-deterministic', '-password'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} requires the -password argument to be set.\nContext: A password is required for deterministic address generation.")
    
        # -encrypt alone requires -password
        if args.encrypt and not args.password:
            sorted_args = sort_arguments_based_on_input(['-encrypt', '-password'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} requires the -password argument to be set.\nContext: A password is required to encrypt the wallet.")

    if args.command == "send":
        # -wallet and -private-key cannot be used together
        if args.wallet and args.private_key:
            sorted_args = sort_arguments_based_on_input(['-wallet', '-private-key'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} cannot be used together.\nContext: The script automatically retrieves the private key of the specified address from the wallet file. The -private-key arguemnt is unnessesary in this instance.")
        
        # -wallet requires -address
        if args.wallet and not args.sender:
            sorted_args = sort_arguments_based_on_input(['-wallet', '-address'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} requires the -address argument to be set.\nContext: An address that is associated with the wallet file must be specified.")
        
        # -address requires -wallet
        if args.sender and not args.wallet:
            sorted_args = sort_arguments_based_on_input(['-address', '-wallet'])
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not sorted_args])
            parser.error(f"{sorted_args} requires the -wallet argument to be set.\nContext: A wallet file must be specified in order to use the given address. The address should also be associated with the wallet file.")

def process_decryptwallet_filter(args):
    """Overview:
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
    
        Parameters:
            - args (argparse.Namespace): The namespace from argparse containing all the parsed command-line arguments.
        
        Returns:
            - tuple: A tuple consisting of the filtered address, the filtered field(s), and the value of args.filter_subparser_pretty.
    """
    # Initialize address and field variables
    addresses = []
    field = []
    fields_to_string = ""  
    filter_subparser_pretty = False
    filter_subparser_show = None
    if not args.command == 'balance':
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
                addresses = address_match.group(1).split(',')
            if field_match:
                field = field_match.group(1).split(',')
                fields_to_string = ", ".join(field)        
        
        # Handle the case when the 'filter' subparser is used
        if args.filter_subparser == 'filter':
            filter_subparser_pretty = args.filter_subparser_pretty
            filter_subparser_show = args.filter_subparser_show
            if args.address:
                addresses = args.address.split(',')
            if args.field:
                field = args.field.split(',')
                fields_to_string = ", ".join(field)
    
        # If no subparser is used, set pretty printing to False
        elif args.filter_subparser != 'filter':
            args.filter_subparser_pretty = False
            args.filter_subparser_show = None
        # Validate the field values against a list of valid options
        valid_fields = ["id","mnemonic", "private_key", "public_key", "address"]
        if field:
            for f in field:
                if f not in valid_fields:
                    raise ValueError(f"Invalid field value: {f}. Must be one of {valid_fields}")
    else:
        if args.address:
            addresses = args.address.split(',')
    
    #Remove duplicate addresses
    seen_addresses = set()
    addresses = [entry for entry in addresses if entry not in seen_addresses and not seen_addresses.add(entry)]
    addresses = remove_duplicates_from_address_filter(addresses)
    
    #Validate addresses using regex pattern
    address_pattern = r'^-?[DE][1-9A-HJ-NP-Za-km-z]{44}$'
    valid_addresses = [addr for addr in addresses if re.match(address_pattern, addr)]
    invalid_addresses = [addr for addr in addresses if addr not in valid_addresses]
    if len(invalid_addresses) >= 1:
        print(f"Warning: The following {'address is' if len(invalid_addresses) == 1 else 'addresses are'} not valid: {invalid_addresses}")
        if not len(valid_addresses) >=1:
            print()
    addresses = valid_addresses

    # Output the filtering criteria to the console
    if addresses and not field:
        print(f'Filtering wallet by address: "{addresses}"\n')
    if not addresses and field:
        print(f'Filtering entries by field: "{fields_to_string}"\n')
    if addresses and field:
        print(f'Filtering wallet by address: "{addresses}"\n')
        print(f'Filtering address entry by field: "{fields_to_string}"\n')
    # Return the filtering criteria and pretty printing option
    return addresses, field, filter_subparser_pretty, filter_subparser_show

def validate_filter_string(input_string):
    """Overview:
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
    """Overview:
        Remove duplicate addresses from the list while honoring the first occurrence of hyphenated or non-hyphenated versions.
        
        Parameters:
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
    # Verbose parser for shared arguments
    verbose_parser = argparse.ArgumentParser(add_help=False)
    verbose_parser.add_argument('-verbose', action='store_true', help='Enables info and debug messages.')
    
    #Node URL parser 
    denaro_node = argparse.ArgumentParser(add_help=False)
    denaro_node.add_argument('-node', type=str, help="Specifies the URL or IP address of a Denaro node.")

    # Create the parser
    parser = argparse.ArgumentParser(description="Manage wallet data.")
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for generating a new wallet
    parser_generatewallet = subparsers.add_parser('generatewallet', parents=[verbose_parser])
    parser_generatewallet.add_argument('-wallet', required=True, help="Specifies the wallet filename. A filepath can be specified before the filename, if not then the default './wallets/' filepath will be used.")
    parser_generatewallet.add_argument('-encrypt', action='store_true', help="Encrypt the new wallet.")
    parser_generatewallet.add_argument('-2fa', dest='tfa', action='store_true', help="Enables 2FA for a new encrypted wallet.")
    parser_generatewallet.add_argument('-password', help="Password used for wallet encryption and/or deterministic address generation.")
    parser_generatewallet.add_argument('-deterministic', action='store_true', help="Generates a deterministic wallet.")
    parser_generatewallet.add_argument('-backup', choices=['False', 'True'], help="Enable or disable backup of an existing wallet.")
    parser_generatewallet.add_argument('-disable-overwrite-warning', dest='disable_overwrite_warning', action='store_true', help="Disable warning when overwriting an existing wallet.")
    parser_generatewallet.add_argument('-overwrite-password', dest='overwrite_password', help="Password to overwrite an existing wallet that is encrypted.")
    
    # Subparser for generating a new address
    parser_generateaddress = subparsers.add_parser('generateaddress', parents=[verbose_parser])
    parser_generateaddress.add_argument('-wallet', required=True, help="Specifies the wallet filename. A filepath can be specified before the filename, if not then the default './wallets/' filepath will be used.")
    parser_generateaddress.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_generateaddress.add_argument('-password', help="The password used for encryption and/or deterministic address generation of the specified wallet file.")
    parser_generateaddress.add_argument('-amount', type=int, help="Specifies the amount of addresses to generate.")

    # Subparser for decrypting the wallet
    parser_decryptwallet = subparsers.add_parser('decryptwallet', parents=[verbose_parser])
    parser_decryptwallet.add_argument('-wallet', required=True, help="Specifies the wallet filename. A filepath can be specified before the filename, if not then the default './wallets/' filepath will be used.")
    parser_decryptwallet.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_decryptwallet.add_argument('-pretty', action='store_true', help="Prints formatted JSON output for enhanced readability.")
    parser_decryptwallet.add_argument('-password', help="The password used for encryption of the specified wallet.")
    parser_decryptwallet.add_argument('-filter', help='Filter entries by address and/or field. Add a hyphen (-) to the beginning of an address to exclude it. Format is: -filter="address={ADDRESS_1, ADDRESS_2, ADDRESS_3, ...},field={id,mnemonic,private_key,public_key,address}". The entire filter string must be enclosed in quotation marks and parameters must be enclosed in curly braces ("\u007B\u007D").', default=None)
    
    # Subparser for filter under decryptwallet
    filter_subparser = parser_decryptwallet.add_subparsers(dest='filter_subparser', required=False)
    parser_filter = filter_subparser.add_parser('filter', parents=[verbose_parser], help="Filter entries by address and/or field")
    parser_filter.add_argument('-address', help='One or more addresses to filter by. Add a hyphen (-) to the beginning of an address to exclude it. Format is: `address=ADDRESS_1, ADDRESS_2, ADDRESS_3,...`')
    parser_filter.add_argument('-field', help='One or more fields to filter by. Format is: `field=id,mnemonic,private_key,public_key,address`.')
    parser_filter.add_argument('-show', choices=['generated', 'imported'], dest="filter_subparser_show", help="Filters information based on entry origin. Use 'generated' to retrieve only the information of wallet entries that have been internally generated. Use 'imported' to retrieve only the information of wallet entries that have been imported.")    
    parser_filter.add_argument('-pretty', action='store_true', dest="filter_subparser_pretty", help="Prints formatted JSON output for enhanced readability.")
         
    # Subparser for importing wallet data based on a private key
    parser_import = subparsers.add_parser('import', parents=[verbose_parser])
    parser_import.add_argument('-wallet', required=True, help="Specifies the wallet filename. A filepath can be specified before the filename, if not then the default './wallets/' filepath will be used.")
    parser_import.add_argument('-password', help="The password used for encryption of the specified wallet.")
    parser_import.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_import.add_argument('-private-key', dest='private_key', required=True, help="Specifies the private key to import.")
    
    # Subparser for sending a transaction
    parser_send = subparsers.add_parser('send', parents=[verbose_parser, denaro_node])
    parser_send.add_argument('-amount', required=True, help="The amount of Denaro to send.")    
    
    # Subparser to specify the wallet file and address to send from. The private key of an address can also be specified.
    send_from_subparser = parser_send.add_subparsers(dest='transaction_send_from_subparser', required=True)
    parser_send_from = send_from_subparser.add_parser('from', parents=[verbose_parser, denaro_node])
    parser_send_from.add_argument('-wallet', help="Specifies the wallet filename. A filepath can be specified before the filename, if not then the default './wallets/' filepath will be used.")
    parser_send_from.add_argument('-password', help="The password used for encryption of the specified wallet.")
    parser_send_from.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_send_from.add_argument('-address', dest='sender', help="Wallet address to send from.")
    parser_send_from.add_argument('-private-key', dest='private_key', help="Specifies the private key associated with the address to send from. Not required if using a wallet file.")
    
    # Subparser to specify the receiving address and optional transaction message.
    parser_send_to_subparser = parser_send_from.add_subparsers(dest='transaction_send_to_subparser', required=True)
    parser_send_to = parser_send_to_subparser.add_parser('to', parents=[verbose_parser, denaro_node])
    parser_send_to.add_argument('receiver', help="The receiveing address.")
    parser_send_to.add_argument('-message', default="", help="Optional transaction message.")
    
    # Subparser for checking balance
    parser_balance = subparsers.add_parser('balance', parents=[verbose_parser, denaro_node])
    parser_balance.add_argument('-wallet', required=True, help="Specifies the wallet filename. A filepath can be specified before the filename, if not then the default './wallets/' filepath will be used.")
    parser_balance.add_argument('-password', help="The password used for encryption of the specified wallet.")
    parser_balance.add_argument('-2fa-code', dest='tfacode', type=str, required=False, help="Two-Factor Authentication code for 2FA enabled wallets.")
    parser_balance.add_argument('-address', help="Specifies the address to get the balance of.")
    parser_balance.add_argument('-json', action='store_true', help="Prints the output of the blance information in JSON format.")
    parser_balance.add_argument('-to-file', dest='to_file', action='store_true', help="Saves the output of the balance information to a file. The resulting file will be in JSON format and named as '[WalletName]_balance_[Timestamp].json' and stored in '/[WalletDirectory]/balance_information/[WalletName]/'. Example for './wallets/PersonalWallet.json': './wallets/balance_information/PersonalWallet/PersonalWallet_balance_2023-12-20_17-09-26.json'.")
    parser_balance.add_argument('-show', choices=['generated', 'imported'], help="Filters balance information based on entry origin. Use 'generated' to retrieve only the balance information of wallet entries that have been internally generated. Use 'imported' to retrieve only the balance information of wallet entries that have been imported.")    
    args = parser.parse_args()


    if args.command == "generatewallet":
        check_args(parser, args)        
        address = generateAddressHelper(filename=args.wallet, password=args.password, totp_code=None, new_wallet=True, encrypt=args.encrypt, use2FA=args.tfa, deterministic=args.deterministic, backup=args.backup, disable_warning=args.disable_overwrite_warning, overwrite_password=args.overwrite_password)    
        if address:
            print(address)

    elif args.command == "generateaddress":
        address = generateAddressHelper(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else None, new_wallet=False, encrypt=False, use2FA=False, amount=args.amount if args.amount else 1)    
        if address:
            print(address)

    elif args.command == 'decryptwallet':
        address, field, args.filter_subparser_pretty, args.filter_subparser_show = process_decryptwallet_filter(args)
        decrypted_data = decryptWalletEntries(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else "", address=address if address else None, fields=field if field else [], pretty=args.pretty or args.filter_subparser_pretty if args.pretty or args.filter_subparser_pretty else False, show=args.filter_subparser_show if args.filter_subparser_show else None)
        if decrypted_data:
            print(f'Wallet Data:\n"{decrypted_data}"')

    elif args.command == 'send':
        check_args(parser, args)
        transaction = prepareTransaction(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else "", amount=args.amount, sender=args.sender if args.sender else None, private_key=args.private_key if args.private_key else None, receiver=args.receiver, message=args.message, node=args.node)
        if transaction:
            print(f'Transaction successfully pushed to node. \nTransaction hash: {sha256(transaction.hex())}')
            print(f'\nDenaro Explorer link: http://explorer.denaro.is/transaction/{sha256(transaction.hex())}')
    
    elif args.command == 'balance':
        address, _, _, _ = process_decryptwallet_filter(args)
        checkBalance(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else "", address=address if args.address else None, node=args.node, to_json=args.json, to_file=args.to_file, show=args.show)
    
    elif args.command == 'import':
        generateAddressHelper(filename=args.wallet, password=args.password, totp_code=args.tfacode if args.tfacode else None, new_wallet=False, encrypt=False, use2FA=False, private_key=args.private_key, is_import=True)

    DataManipulation.secure_delete([var for var in locals().values() if var is not None])

if __name__ == "__main__":
    exit_code = 1
    try:
        main()
        exit_code = 0 
    except KeyboardInterrupt:
        print("\r  ")
        print("\rProcess terminated by user.")
        QRCodeUtils.close_qr_window(True)
        exit_code = 1
    #except Exception as e:
    #    logging.error(f"{e}")
    #    exit_code = 1    
    finally:
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        gc.collect()
        sys.exit(exit_code)