import os
import logging
import base64
import hashlib
import random
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
import hmac as hmac_module
import pyotp
import ctypes
import json
import time
import sys
from filelock import Timeout, FileLock

# Global variables
FAILED_ATTEMPTS = 0
MAX_ATTEMPTS = 5
DIFFICULTY = 3

class EncryptionUtils:
    """
    Handles encryption and decryption tasks.
    """
    @staticmethod
    def aes_gcm_encrypt(data, key, nonce):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        result = ciphertext, tag
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

    @staticmethod
    def aes_gcm_decrypt(ciphertext, tag, key, nonce):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        result = cipher.decrypt_and_verify(ciphertext, tag)
        return result

    @staticmethod
    def chacha20_poly1305_encrypt(data, key):
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        result = cipher.nonce, ciphertext, tag
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

    @staticmethod
    def chacha20_poly1305_decrypt(nonce, ciphertext, tag, decryption_key):
        """
        Decrypt data using ChaCha20-Poly1305.
        """
        cipher = ChaCha20_Poly1305.new(key=decryption_key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not decrypted_data])
            return decrypted_data
        except ValueError:
            logging.error("ChaCha20-Poly1305 tag verification failed. Data might be corrupted or tampered with.")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("ChaCha20-Poly1305 tag verification failed. Data might be corrupted or tampered with.")

class ProofOfWork:
    """
    Handles proof-of-work generation and validation.
    """
    @staticmethod
    def generate_proof(challenge):
        proof = 0
        target = "1" * DIFFICULTY
        while not hashlib.sha256(challenge + str(proof).encode()).hexdigest().startswith(target):
            proof += 1
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not proof])
        return proof

    @staticmethod
    def is_proof_valid(proof, challenge):
        result = hashlib.sha256(challenge + str(proof).encode()).hexdigest().startswith("1" * DIFFICULTY)
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

class DataManipulation:
    """
    Handles data scrambling and descrambling.
    """
    dot_count = 0
    iteration_count = 0

    @staticmethod
    def scramble(data, seed):
        if isinstance(seed, int):
            seed = seed.to_bytes((seed.bit_length() + 7) // 8, 'big')
        random.seed(hashlib.sha256(seed).digest())
        indices = list(range(len(data)))
        random.shuffle(indices)
        scrambled_data = bytearray(len(data))
        for i, j in enumerate(indices):
            scrambled_data[j] = data[i]
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not scrambled_data])
        return scrambled_data

    @staticmethod
    def descramble(scrambled_data, seed):
        if isinstance(seed, int):
            seed = seed.to_bytes((seed.bit_length() + 7) // 8, 'big')
        random.seed(hashlib.sha256(seed).digest())
        indices = list(range(len(scrambled_data)))
        random.shuffle(indices)
        data = bytearray(len(scrambled_data))
        for i, j in enumerate(indices):
            data[i] = scrambled_data[j]
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not data])
        return data

    @staticmethod
    def update_or_reset_attempts(data, filename, hmac_salt, password_verified, deterministic):
        """
        Updates or resets failed login attempts based on whether the password was verified.
        
        Arguments:
        - data: The wallet data
        - hmac_salt: The HMAC salt
        - password_verified: Boolean indicating if the password is verified
        - filename: The name of the wallet file
        - deterministic: Boolean indicating if the wallet is deterministic
        """
        # Determine the appropriate function to update or reset attempts
        update_or_reset = CryptoWallet.update_failed_attempts if not password_verified else CryptoWallet.reset_failed_attempts
    
        # Define keys to update or reset based on deterministic flag
        key_list = [["entry_data", "entries"]]
        if deterministic:
            key_list.append(["entry_data", "key_data"])
        key_list.append(["totp_secret"])
    
        # Update or reset the attempts for each key in the wallet data
        for key in key_list:
            # Initialize target_data as the root dictionary
            target_data = data["wallet_data"]
            for k in key:
                # Navigate through nested keys
                target_data = target_data.get(k, {})
            
            # Convert to list if target_data is not a list
            if not isinstance(target_data, list):
                target_data = [target_data]
            
            # Convert each entry to string
            target_data = [str(entry) for entry in target_data]
            
            # Update or reset attempts
            updated_data, attempts_left = update_or_reset(target_data, hmac_salt)
            
            # Save the updated data back into the original data structure
            if len(key) == 1:
                data["wallet_data"][key[0]] = updated_data
            else:
                data["wallet_data"][key[0]][key[1]] = updated_data
        
        data["wallet_data"]["totp_secret"] = data["wallet_data"]["totp_secret"][0]
        if not password_verified:
            if attempts_left:
                print(f"\nPassword Attempts Left: {attempts_left}")
            if attempts_left <= 5 and attempts_left > 3 and attempts_left != 0:
                logging.warning(f"Password attempts left are approaching 0, after which any existing wallet data will be ERASED AND POTENTIALLY UNRECOVERABLE!!")
            if attempts_left <= 3 and attempts_left != 0:
                logging.critical(f"PASSWORD ATTEMPTS LEFT ARE APPROACHING 0, AFTER WHICH ANY EXISTING WALLET DATA WILL BE ERASED AND POTENTIALLY UNRECOVERABLE!!")
            if attempts_left == 0:
                print(f"\nPassword Attempts Left: {attempts_left}")
                DataManipulation.delete_wallet(filename, data)
                print("Wallet data has been permanetly erased.")
                time.sleep(0.5)
                data = None
        
        # Securely delete sensitive variables
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not data])
        return data
    
    @staticmethod
    def secure_delete(var):
        """Overview:
            This function aims to securely delete a variable by overwriting its memory footprint with zeros, thus ensuring
            that sensitive data does not linger in memory. By employing both native Python techniques and lower-level memory
            operations, it ensures that sensitive data remnants are minimized, reducing exposure to potential threats.
            
            Arguments:
            - var (various types): The variable which needs to be securely deleted and its memory overwritten.
            
            Returns:
            - None: This function works by side-effect, modifying memory directly.
        """
        try:
            # Attempt to get the memory size of the variable using ctypes
            var_size = ctypes.sizeof(var)
            # Create a byte array of zeros with the size of the variable
            zeros = (ctypes.c_byte * var_size)()
            # Retrieve the memory address of the variable
            var_address = id(var)
            # Overwrite the variable's memory location with zeros
            ctypes.memmove(var_address, zeros, var_size)
        except TypeError:
            # Handle different types of variables
            if isinstance(var, (str, bytes)):
                # For immutable types, reassigning is the only way, but it's not 100% secure
                var = '0' * len(var)
            elif isinstance(var, list):
                # For lists, we can zero out each element
                for i in range(len(var)):
                    var[i] = 0
            elif isinstance(var, dict):
                # For dictionaries, set each value to zero
                for key in var:
                    var[key] = 0
            else:
                # For other unsupported types, just reassign to zero
                var = 0
        finally:
            # Explicitly delete the variable reference
            del var
    
    @staticmethod
    def _save_data(filename, data):
        """
        Persistently stores wallet data to a specified file.
        """
        try:
            with open(filename, 'w') as f:
                if data:
                    json.dump(data, f, indent=4)
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                else: 
                    f = data
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        except Exception as e:
            logging.error(f"Error saving data to file: {str(e)}")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
    
    @staticmethod
    def overwrite_with_pattern(file, pattern, file_size):
        """Overview:
            This function is designed for secure file overwriting. It methodically replaces the content
            of a file with a given pattern. It continuously writes the pattern to the file, ensuring complete
            coverage of the original data. The function also includes progress logging and strict data integrity
            measures, like buffer flushing and disk state synchronization.
    
            Parameters:
            - file: A binary-write-mode file object.
            - pattern: Byte string used as the overwrite pattern.
            - file_size: Total size of the file to be overwritten, in bytes.
        """
        try:
            file.seek(0)  # Start at the beginning of the file
            bytes_written = 0

            # Update interval for printing progress, can be adjusted for efficiency
            update_interval = max(1, file_size // 1)

            while bytes_written < file_size:
                write_size = min(file_size - bytes_written, len(pattern))
                file.write(pattern[:write_size])
                bytes_written += write_size

                # Update progress at intervals
                if bytes_written % update_interval == 0 or bytes_written == file_size:
                    DataManipulation.dot_count += 1
                    if DataManipulation.dot_count >= 4:
                        DataManipulation.dot_count = 0
                        DataManipulation.iteration_count += 1
                        if DataManipulation.iteration_count > 4:
                            DataManipulation.iteration_count = 1
                    sys.stdout.write("\r" + " " * 50)  # Clear with 50 spaces
                    sys.stdout.write("\rWallet Annihilation in progress" + "." * DataManipulation.iteration_count)
                    sys.stdout.flush()

            file.flush()
            os.fsync(file.fileno())
        except IOError as e:
            print()
            logging.error(f"IOError during file overwrite: {e}")
        except Exception as e:
            print()
            logging.error(f"Unexpected error during file overwrite: {e}")
    
    @staticmethod
    def DoD_5220_22_M_wipe(file, file_size):
        """Overview:
            Implements the DoD 5220.22-M wiping standard, a recognized method for secure file erasure.
            This function executes multiple overwrite passes, using a mix of zero bytes, one bytes, and
            random data. Each pass serves to further obfuscate the underlying data, aligning with the
            standard's specifications for secure deletion.
    
            Parameters:
            - file: A file object to be overwritten.
            - file_size: The size of the file in bytes, guiding the overwrite extent.
        """
        try:
        #print("Using: DoD_5220_22_M_wipe")
            for i in range(1, 7):
                # Pass 1, 4, 5: Overwrite with 0x00
                if i in [1, 4, 5]:
                    DataManipulation.overwrite_with_pattern(file, b'\x00' * file_size, file_size)
    
                # Pass 2, 6: Overwrite with 0xFF
                if i in [2, 6]:
                    DataManipulation.overwrite_with_pattern(file, b'\xFF' * file_size, file_size)
    
                # Pass 3, 7: Overwrite with random data
                if i in [3, 7]:
                    random_bytes = bytearray(random.getrandbits(8) for _ in range(file_size))
                    DataManipulation.overwrite_with_pattern(file, random_bytes * file_size, file_size)
                    DataManipulation.overwrite_with_pattern(file, os.urandom(64), file_size)
        except Exception as e:
            print()
            logging.error(f"Error during DoD 5220.22-M Wipe: {e}")

    @staticmethod
    def Schneier_wipe(file, file_size):
        """Overview:
            Adheres to the Schneier wiping protocol, a multi-pass data destruction method. The first two
            passes use fixed byte patterns (0x00 and 0xFF), followed by subsequent passes that introduce
            random data. This sequence is designed to thoroughly scramble the data, enhancing security and
            reducing the possibility of data recovery.
    
            Parameters:
            - file: The file object for wiping.
            - file_size: Size of the file, dictating the wiping process scope.
        """
        try:
            for i in range(1, 7):
                if i in [1]:
                    # First pass: overwrite with 0x00
                    DataManipulation.overwrite_with_pattern(file, b'\x00' * file_size, file_size)
                if i in [2]:
                    # Second pass: overwrite with 0xFF
                    DataManipulation.overwrite_with_pattern(file, b'\xFF' * file_size, file_size)
                if i in [3, 4, 5, 6, 7]:
                    # Additional passed: overwrite with random data
                    random_bytes = bytearray(random.getrandbits(8) for _ in range(file_size))
                    DataManipulation.overwrite_with_pattern(file, random_bytes * file_size, file_size)
                    DataManipulation.overwrite_with_pattern(file, os.urandom(64), file_size)
        except Exception as e:
            print()
            logging.error(f"Error during Schneier Wipe: {e}")

    @staticmethod
    def Gutmann_wipe(file, file_size):
        """Overview:
            Executes the Gutmann wiping method, known for its extensive pattern use. It cycles through
            35 different patterns, blending predefined and random patterns to overwrite data. This method
            is comprehensive, aiming to address various data remanence possibilities and ensuring a high
            level of data sanitization.
    
            Parameters:
            - file: Target file object for data wiping.
            - file_size: Determines the quantity of data to be overwritten.
        """
        try:
            #print("Gutmann_wipe")
            for i in range(1, 35):
                if i in [1, 2, 3, 4, 32, 33, 34, 35]:
                    pattern = bytearray(random.getrandbits(8) for _ in range(file_size)) * file_size
                else:
                    patterns = [
                        # Passes 5-6
                        b"\x55\x55\x55", b"\xAA\xAA\xAA",
                        # Passes 7-9
                        b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
                        # Passes 10-25
                        b"\x00\x00\x00", b"\x11\x11\x11", b"\x22\x22\x22", b"\x33\x33\x33",
                        b"\x44\x44\x44", b"\x55\x55\x55", b"\x66\x66\x66", b"\x77\x77\x77",
                        b"\x88\x88\x88", b"\x99\x99\x99", b"\xAA\xAA\xAA", b"\xBB\xBB\xBB",
                        b"\xCC\xCC\xCC", b"\xDD\xDD\xDD", b"\xEE\xEE\xEE", b"\xFF\xFF\xFF",
                        # Passes 26-28
                        b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
                        # Passes 29-31
                        b"\x6D\xB6\xDB", b"\xB6\xDB\x6D", b"\xDB\x6D\xB6",
                    ]
                    pattern = patterns[i - 5]
    
                # Calculate repeat_count and the remainder
                pattern_length = len(pattern)
                repeat_count = file_size // pattern_length
                remainder = file_size % pattern_length
        
                # Create the final pattern
                final_pattern = pattern * repeat_count + pattern[:remainder]
                # Overwrite with the final pattern
                DataManipulation.overwrite_with_pattern(file, final_pattern, file_size)
        except Exception as e:
            print()
            logging.error(f"Error during Gutmann Wipe: {e}")
    
    @staticmethod
    def wallet_annihilation(filename, file, data, file_size):
        """Overview:
            This function first encrypts the wallet data, adding a layer of security, and then proceeds
            to a comprehensive wiping process. It utilizes a combination of the DoD 5220.22-M, Schneier, 
            and Gutmann methods to ensure thorough overwriting and scrambling of the file data. The 
            encryption step is crucial as it secures the data before the wiping begins, making any 
            potential recovery attempts even more challenging. The sequence of wiping techniques aims 
            to achieve a high degree of certainty that the data cannot be recovered.
    
            Parameters:
            - filename: The name of the file to be wiped.
            - file: File object representing the wallet file.
            - data: The wallet data to be encrypted and then wiped.
            - file_size: The total size of the file, guiding the scope of wiping.
        """     
        try:
            # Encryption with SHA3-512 hashes is 100% overkill but we need to ensure that the wallet data is unrecoverable
            hmac_salt = hashlib.sha3_512().hexdigest()
            verification_salt = hashlib.sha3_512().hexdigest()
            password = hashlib.sha3_512().hexdigest()
            verifier = VerificationUtils.hash_password(password, verification_salt)
            totp_secret = TOTP_Utils.generate_totp_secret(True, bytes(verification_salt,'utf-8'))               
            encrypted_data = CryptoWallet.encrypt_data(str(data), password, totp_secret, hmac_salt, verification_salt, verifier)
            DataManipulation._save_data(filename, encrypted_data)
            time.sleep(0.5)
            
            random_bytes = bytearray(random.getrandbits(8) for _ in range(file_size))
            DataManipulation.overwrite_with_pattern(file, random_bytes * file_size, file_size)
            time.sleep(0.1)

            DataManipulation.DoD_5220_22_M_wipe(file, file_size)
            time.sleep(0.1)

            DataManipulation.Schneier_wipe(file, file_size)
            time.sleep(0.1)

            DataManipulation.Gutmann_wipe(file, file_size)
        except Exception as e:
            print()
            logging.error(f"Error during Wallet Annihilation: {e}")

    @staticmethod
    def delete_wallet(file_path, data, passes=2):
        """Overview:
            This is the main function for securely deleting wallet files. It locks the file to prevent
            concurrent access, then executing the 'wallet_annihilation' method, which combines multiple
            advanced wiping techniques, for each pass specified. The function ensures that the wallet
            file is not just deleted, but it's data is irrecoverably destroyed in the event of too
            many failed password attempts, or overwrite.
    
            Parameters:
            - file_path: The path to the wallet file.
            - data: Data used in the annihilation process.
            - passes: The number of annihilation cycles to execute.
        """
        if not os.path.exists(file_path):
            raise ValueError("File does not exist")
        
        lock = FileLock(file_path+".lock")
        try:
            with lock:
                with open(file_path, "r+b") as file:
                    file_size = os.path.getsize(file.name)
                    if file_size == 0:
                        raise ValueError("File is empty")
                    
                    for _ in range(passes):
                        DataManipulation.wallet_annihilation(file_path, file, data, file_size)
                        file.flush()
                        os.fsync(file.fileno())
                with open(file_path, "w+b") as file:
                    file.truncate(0)
            lock.release()
        except IOError as e:
            print()
            logging.error(f"IOError during file overwrite: {e}")
        except ValueError as e:
            print()
            logging.error(f"ValueError in file handling: {e}")
        except Exception as e:
            print()
            logging.error(f"Unexpected error occurred: {e}")
        finally:
            lock.release()
        try:
            time.sleep(0.5)
            os.remove(file_path)
            if os.path.exists(file_path+".lock"):
                os.remove(file_path+".lock")
            sys.stdout.write("\rWallet Annihilation in progress....")
            print()
        except OSError as e:
            print()
            logging.error(f"Error while removing file: {e}")

class VerificationUtils:
    """
    Handles data verification.
    """
    @staticmethod
    def hash_password(password, salt):        
        """
        Generate a cryptographic hash of the password using PBKDF2 and then Scrypt.
        """
        # First layer of hashing using PBKDF2
        salt_bytes = salt
        if not isinstance(salt, bytes):
            salt_bytes = bytes(salt, 'utf-8')
        pbkdf2_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)

        # Second layer of hashing using Scrypt
        result = scrypt(pbkdf2_hash, salt=salt, key_len=32, N=2**14, r=8, p=1)
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

    @staticmethod
    def verify_password(stored_password_hash, provided_password, salt):
        """
        Compares the provided password with the stored hash.
        """
        # Generate hash of the provided password
        verifier = VerificationUtils.hash_password(provided_password, salt)
        # Securely compare the generated hash with the stored hash
        is_verified = hmac_module.compare_digest(verifier, stored_password_hash)

        # Nullify verifier if not verified
        if not is_verified:
            verifier = None
        result = is_verified, verifier
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result
    
    @staticmethod
    def hmac_util(password=None,hmac_salt=None,stored_hmac=None, hmac_msg=None, verify=False):
        """
        Handle HMAC generation and verification.
        """
        # Generate HMAC key using Scrypt
        hmac_key = scrypt(password.encode(), salt=hmac_salt, key_len=32, N=2**14, r=8, p=1)
        # Generate HMAC of the message
        computed_hmac = hmac_module.new(hmac_key, hmac_msg, hashlib.sha256).digest()
        # If in verify mode, securely compare the computed HMAC with the stored HMAC
        if verify:
            result = hmac_module.compare_digest(computed_hmac, stored_hmac)
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result
        else:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not computed_hmac])
            return computed_hmac

    @staticmethod
    def verify_password_and_hmac(data, password, hmac_salt, verification_salt, deterministic):
        """
        Verifies the given password and HMAC.
        
        Arguments:
        - data: The wallet data
        - password: The user's password
        - hmac_salt: The HMAC salt
        
        Returns:
        - A tuple of booleans indicating if the password and HMAC are verified
        """
        # Decode and verify the stored password verifier
        stored_verifier = base64.b64decode(data["wallet_data"]["verifier"].encode('utf-8'))
        password_verified, _ = VerificationUtils.verify_password(stored_verifier, password, verification_salt)
        
        # Prepare and verify the HMAC message
        hmac_msg = json.dumps(data["wallet_data"]["entry_data"]["entries"]).encode()
        if deterministic:
            hmac_msg += json.dumps(data["wallet_data"]["entry_data"]["key_data"]).encode()
        stored_hmac = base64.b64decode(data["wallet_data"]["hmac"].encode('utf-8'))
        hmac_verified = VerificationUtils.hmac_util(password=password, hmac_salt=hmac_salt, stored_hmac=stored_hmac, hmac_msg=hmac_msg, verify=True)
        result = password_verified, hmac_verified, stored_verifier
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result
    
    @staticmethod
    def verify_totp_secret(password,totp_secret,hmac_salt,verification_salt,stored_verifier):
        """
        Validates the given Two-Factor Authentication secret token
        """
        # Decrypt the stored TOTP secret to handle 2FA
        decrypted_totp_secret = CryptoWallet.decrypt_data(totp_secret, password, "", hmac_salt, verification_salt, stored_verifier)
        # Generate a predictable TOTP secret to check against
        predictable_totp_secret = TOTP_Utils.generate_totp_secret(True,verification_salt)
        # If the decrypted TOTP doesn't match the predictable one, handle 2FA validation
        if decrypted_totp_secret != predictable_totp_secret:
            result = decrypted_totp_secret, True
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result
        else:
            result = "", False
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result

    @staticmethod
    def validate_totp_code(secret, code):
        """
        Validates the given Two-Factor Authentication code using the provided secret.
        """
        totp = pyotp.TOTP(secret)
        result = totp.verify(code)
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

class TOTP_Utils:    
    @staticmethod
    def generate_totp_secret(predictable, verification_salt):
        """
        Generate a new TOTP secret.
        """
        if not predictable:
            result = pyotp.random_base32()
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result
        else:
            result = hashlib.sha256(verification_salt).hexdigest()[:16]
            DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result
    
    @staticmethod
    def generate_totp_code(secret):
        """
        Generate a Two-Factor Authentication code using the given secret.
        """
        totp = pyotp.TOTP(secret)
        result = totp.now()
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

class CryptoWallet:
    @staticmethod
    def encrypt_data(data, password, totp_secret, hmac_salt, verification_salt, stored_password_hash):
        # 1. Password Verification
        # Verify the provided password against the stored hash and salt
        password_verified, verifier = VerificationUtils.verify_password(stored_password_hash, password, verification_salt)
        if not password_verified and not verifier:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("Authentication failed or wallet data is corrupted.")
            raise ValueError("Authentication failed or wallet data is corrupted.")
        
        # 2. AES-GCM Layer Encryption
        # Generate a random 16-byte challenge for AES
        aes_challenge_portion = os.urandom(16)
        # Generate a proof-of-work based on the challenge
        aes_challenge_portion_proof = ProofOfWork.generate_proof(aes_challenge_portion)
        # Scramble the challenge based on the proof-of-work
        scrambled_aes_challenge_portion = DataManipulation.scramble(aes_challenge_portion, aes_challenge_portion_proof)
        # Generate a proof-of-work based on the scrambled challenge
        aes_proof = ProofOfWork.generate_proof(scrambled_aes_challenge_portion)
        
        # Create a commitment by hashing the proof
        aes_commitment = hashlib.sha256(str(aes_proof).encode()).digest()
        # Convert the commitment to a hexadecimal string
        aes_commitment_hex = aes_commitment.hex()

        # Scramble all the parameters to be used for key derivation
        scrambled_parameters = [DataManipulation.scramble(param.encode() if isinstance(param, str) else param, aes_proof) for param in [password, totp_secret, aes_commitment_hex, hmac_salt, verifier, verification_salt]]
    
        # Derive AES encryption key using Scrypt
        aes_encryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)
        # Generate a random nonce for AES encryption
        aes_nonce = os.urandom(16)
        
        # Scramble and encrypt the data
        scrambled_data = DataManipulation.scramble(data.encode(), aes_proof)
        aes_ct_bytes, aes_tag = EncryptionUtils.aes_gcm_encrypt(scrambled_data, aes_encryption_key, aes_nonce)

        # Scramble the ciphertext and tag
        scrambled_aes_ct_bytes = DataManipulation.scramble(aes_ct_bytes, aes_proof)
        scrambled_aes_tag = DataManipulation.scramble(aes_tag, aes_proof)

        # Compute HMAC for AES layer
        hmac_1 = VerificationUtils.hmac_util(password=scrambled_parameters[0].decode(), hmac_salt=scrambled_parameters[3], hmac_msg=aes_nonce + scrambled_aes_ct_bytes + scrambled_aes_tag, verify=False)

        # 3. ChaCha20-Poly1305 Layer Encryption
        # Generate a random 16-byte challenge for ChaCha20
        chacha_challenge_portion = os.urandom(16)
        # Generate a proof-of-work based on the challenge
        chacha_challenge_portion_proof = ProofOfWork.generate_proof(chacha_challenge_portion)
        # Scramble the challenge based on the proof-of-work
        scrambled_chacha_challenge_portion = DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
        # Generate a proof-of-work based on the scrambled challenge
        chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)
        
        # Create a commitment by hashing the proof
        chacha_commitment = hashlib.sha256(str(chacha_proof).encode()).digest()
        # Convert the commitment to a hexadecimal string
        chacha_commitment_hex = chacha_commitment.hex()
        
        # Scramble all the parameters to be used for key derivation
        scrambled_parameters = [DataManipulation.scramble(param.encode() if isinstance(param, str) else param, chacha_proof) for param in [password, totp_secret, chacha_commitment_hex, hmac_salt, verifier, verification_salt]]

        # Derive ChaCha20 encryption key using Scrypt
        chacha_encryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)
        # Encrypt the data using ChaCha20-Poly1305
        chacha_nonce, chacha_ct_bytes, chacha_tag = EncryptionUtils.chacha20_poly1305_encrypt(aes_challenge_portion + aes_nonce + scrambled_aes_ct_bytes + scrambled_aes_tag + hmac_1, chacha_encryption_key)

        # Scramble the ciphertext and tag
        scrambled_chacha_ct_bytes = DataManipulation.scramble(chacha_ct_bytes, chacha_proof)
        scrambled_chacha_tag = DataManipulation.scramble(chacha_tag, chacha_proof)

        # Compute HMAC for ChaCha20 layer
        hmac_2 = VerificationUtils.hmac_util(password=chacha_commitment_hex, hmac_salt=scrambled_parameters[3], hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag, verify=False)
        
        failed_attempts = 0
        failed_attempts_bytes = failed_attempts.to_bytes(4, byteorder='big')
        #print(chacha_proof)
        #print(DataManipulation.scramble(chacha_challenge_portion + chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag + hmac_2, failed_attempts_bytes))
        # Base64 encode the final encrypted data for easier storage and transmission
        result = base64.b64encode(DataManipulation.scramble(chacha_challenge_portion + chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag + hmac_2, failed_attempts_bytes)).decode('utf-8')

        # 4. Cleanup and return
        # Securely delete sensitive variables
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
                
        return result

    @staticmethod
    def decrypt_data(encrypted_data, password, totp_secret, hmac_salt, verification_salt, stored_password_hash):
        global FAILED_ATTEMPTS, MAX_ATTEMPTS, DIFFICULTY  # Global variables for failed attempts and PoW difficulty
       
        # 1. Base64 Decoding
        # Decode the base64 encoded encrypted data
        data = base64.b64decode(encrypted_data.encode('utf-8'))

        # 2. Password Verification        
        # Verify the provided password against the stored hash and salt
        password_verified, verifier = VerificationUtils.verify_password(stored_password_hash, password, verification_salt)
        if not password_verified and not verifier:
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("Authentication failed or wallet data is corrupted.")
            raise ValueError("Authentication failed or wallet data is corrupted.")
        else:
            failed_attempts = 0
            failed_attempts_bytes = failed_attempts.to_bytes(4, byteorder='big')
            data = DataManipulation.descramble(data,failed_attempts_bytes)

        # 3. ChaCha20-Poly1305 Layer Decryption
        # Update the extraction logic to account for the 4 bytes of failed_attempts
        chacha_challenge_portion = data[:16]
        chacha_nonce = data[16:28]
        scrambled_chacha_ct_bytes = data[28:-48]
        scrambled_chacha_tag = data[-48:-32]
        stored_chacha_hmac = data[-32:]        
        
        # Generate a proof-of-work based on the challenge
        chacha_challenge_portion_proof = ProofOfWork.generate_proof(chacha_challenge_portion)
        
        #Check if ChaCha challenge proof is valid
        if not ProofOfWork.is_proof_valid(chacha_challenge_portion_proof, chacha_challenge_portion):
            FAILED_ATTEMPTS += 1
            if FAILED_ATTEMPTS >= MAX_ATTEMPTS:
                #del encrypted_data  # Replace with your secure delete function
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid ChaCha Challenge proof. Try again.")
        
        # Scramble the challenge based on the proof-of-work
        scrambled_chacha_challenge_portion = DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
        # Generate another proof-of-work based on the scrambled challenge
        chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)

        #Check if ChaCha scrambled challenge proof is valid
        if not ProofOfWork.is_proof_valid(chacha_proof, scrambled_chacha_challenge_portion):
            FAILED_ATTEMPTS += 1
            if FAILED_ATTEMPTS >= MAX_ATTEMPTS:
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                #del encrypted_data  # Replace with your secure delete function
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid ChaCha proof. Try again.")
        
        # Compute commitment and convert it to hex
        chacha_commitment_hex = hashlib.sha256(str(chacha_proof).encode()).hexdigest()

        # Scramble all parameters for key derivation
        scrambled_parameters = [DataManipulation.scramble(param.encode() if isinstance(param, str) else param, chacha_proof) for param in [password, totp_secret, chacha_commitment_hex, hmac_salt, verifier, verification_salt]]

        # Verify HMAC for ChaCha layer data
        if not VerificationUtils.hmac_util(password=chacha_commitment_hex,hmac_salt=scrambled_parameters[3],stored_hmac=stored_chacha_hmac,hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag,verify=True):
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("ChaCha layer data integrity check failed. Wallet data might be corrupted or tampered with.")
            raise ValueError("ChaCha layer data integrity check failed. Wallet data might be corrupted or tampered with.")
                
        # Derive decryption key using Scrypt
        chacha_decryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)

        # Descramble ChaCha ciphertext and the tag
        chacha_ct_bytes = DataManipulation.descramble(scrambled_chacha_ct_bytes, chacha_proof)
        chacha_tag = DataManipulation.descramble(scrambled_chacha_tag, chacha_proof)
        
        # Decrypt the data using ChaCha20-Poly1305
        chacha_decrypted_data = EncryptionUtils.chacha20_poly1305_decrypt(chacha_nonce, chacha_ct_bytes, chacha_tag, chacha_decryption_key)

        # 4. AES-GCM Layer Decryption
        # Extract AES-related portions from the decrypted data
        aes_challenge_portion = chacha_decrypted_data[:16]
        chacha_decrypted_data = chacha_decrypted_data[16:]
        aes_nonce = chacha_decrypted_data[:16]
        scrambled_aes_tag = chacha_decrypted_data[-48:-32]
        stored_aes_hmac = chacha_decrypted_data[-32:]
        scrambled_aes_ct_bytes = chacha_decrypted_data[16:-48]
        
        # Generate a proof-of-work for AES
        aes_challenge_portion_proof = ProofOfWork.generate_proof(aes_challenge_portion)

        #Check if AES challenge proof is valid
        if not ProofOfWork.is_proof_valid(aes_challenge_portion_proof, aes_challenge_portion):
            FAILED_ATTEMPTS += 1
            if FAILED_ATTEMPTS >= MAX_ATTEMPTS:
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                #del encrypted_data  # Replace with your secure delete function
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid AES Challenge proof. Try again.")
        
        # Scramble the AES challenge based on the proof-of-work
        scrambled_aes_challenge_portion = DataManipulation.scramble(aes_challenge_portion, aes_challenge_portion_proof)
        # Generate another proof-of-work based on the scrambled challenge
        aes_proof = ProofOfWork.generate_proof(scrambled_aes_challenge_portion)

        #Check if AES scrambled challenge proof is valid
        if not ProofOfWork.is_proof_valid(aes_proof, scrambled_aes_challenge_portion):
            FAILED_ATTEMPTS += 1
            if FAILED_ATTEMPTS >= MAX_ATTEMPTS:
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                #del encrypted_data  # Replace with your secure delete function
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid AES proof. Try again.")
        
        # Compute commitment and convert it to hex
        aes_commitment_hex = hashlib.sha256(str(aes_proof).encode()).hexdigest()

        # Scramble all parameters for key derivation
        scrambled_parameters = [DataManipulation.scramble(param.encode() if isinstance(param, str) else param, aes_proof) for param in [password, totp_secret, aes_commitment_hex, hmac_salt, verifier, verification_salt]]
        
        # Verify HMAC for AES layer data
        if not VerificationUtils.hmac_util(password=scrambled_parameters[0].decode(),hmac_salt=scrambled_parameters[3],stored_hmac=stored_aes_hmac,hmac_msg=aes_nonce + scrambled_aes_ct_bytes + scrambled_aes_tag,verify=True):
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("AES layer data integrity check failed. Wallet data might be corrupted or tampered with.")
            raise ValueError("AES layer data integrity check failed. Wallet data might be corrupted or tampered with.")
        
        # Derive decryption key using Scrypt
        aes_decryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)
        
        # Descramble the AES ciphertext and tag
        aes_ct_bytes = DataManipulation.descramble(scrambled_aes_ct_bytes, aes_proof)
        aes_tag = DataManipulation.descramble(scrambled_aes_tag,aes_proof)

        # Decrypt the data using AES-GCM
        decrypted_data = EncryptionUtils.aes_gcm_decrypt(aes_ct_bytes, aes_tag, aes_decryption_key, aes_nonce)
        
        # Descramble the decrypted data
        decrypted_data = DataManipulation.descramble(decrypted_data, aes_proof)

        result = decrypted_data.decode('utf-8')
                                                     
        # 5. Cleanup and return
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result      
    
    @staticmethod
    def update_failed_attempts(encrypted_data,hmac_salt):
        #encrypted_data = encrypted_data["wallet_data"]["entry_data"]["entries"]
        updated_data = []

        #print(f"encrypted_data: {encrypted_data}")
        for encrypted_entry in encrypted_data:
            #print(f"encrypted_entry: {encrypted_entry}")
            data = base64.b64decode(encrypted_entry.encode('utf-8'))
            for n in range(10):
                descrambled_data = DataManipulation.descramble(data,n.to_bytes(4, byteorder='big'))
                chacha_challenge_portion = descrambled_data[:16]
                chacha_nonce = descrambled_data[16:28]
                scrambled_chacha_ct_bytes = descrambled_data[28:-48]
                scrambled_chacha_tag = descrambled_data[-48:-32]
                stored_chacha_hmac = descrambled_data[-32:]    
                chacha_challenge_portion_proof = ProofOfWork.generate_proof(chacha_challenge_portion)
                scrambled_chacha_challenge_portion = DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
                chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)
                # Create a commitment by hashing the proof
                chacha_commitment = hashlib.sha256(str(chacha_proof).encode()).digest()
                # Convert the commitment to a hexadecimal string
                chacha_commitment_hex = chacha_commitment.hex()
                #print(chacha_proof)             
                if VerificationUtils.hmac_util(password=chacha_commitment_hex,hmac_salt=DataManipulation.scramble(hmac_salt,chacha_proof),stored_hmac=stored_chacha_hmac,hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag,verify=True):
                    number_of_attempts = n
                    break
            number_of_attempts += + 1
            attempts_left = 10 - number_of_attempts            
            rescrambled_data = DataManipulation.scramble(descrambled_data,number_of_attempts.to_bytes(4, byteorder='big'))
            #print(rescrambled_data)
            updated_encrypted_data_base64 = base64.b64encode(rescrambled_data).decode('utf-8')
            updated_data.append(updated_encrypted_data_base64)
            encrypted_data = updated_data
        result = encrypted_data, attempts_left
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result
    
    @staticmethod
    def reset_failed_attempts(encrypted_data,hmac_salt):
        #encrypted_data = encrypted_data["wallet_data"]["entry_data"]["entries"]
        updated_data = []
        #print(encrypted_data)
        for encrypted_entry in encrypted_data:
            #print(encrypted_entry)
            data = base64.b64decode(encrypted_entry.encode('utf-8'))
            
            for n in range(10):
                descrambled_data = DataManipulation.descramble(data,n.to_bytes(4, byteorder='big'))
                chacha_challenge_portion = descrambled_data[:16]
                chacha_nonce = descrambled_data[16:28]
                scrambled_chacha_ct_bytes = descrambled_data[28:-48]
                scrambled_chacha_tag = descrambled_data[-48:-32]
                stored_chacha_hmac = descrambled_data[-32:]    
                chacha_challenge_portion_proof = ProofOfWork.generate_proof(chacha_challenge_portion)
                scrambled_chacha_challenge_portion = DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
                chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)
                # Create a commitment by hashing the proof
                chacha_commitment = hashlib.sha256(str(chacha_proof).encode()).digest()
                # Convert the commitment to a hexadecimal string
                chacha_commitment_hex = chacha_commitment.hex()
                #print(chacha_proof)             
                if VerificationUtils.hmac_util(password=chacha_commitment_hex,hmac_salt=DataManipulation.scramble(hmac_salt,chacha_proof),stored_hmac=stored_chacha_hmac,hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag,verify=True):
                    number_of_attempts = n
                    break
            number_of_attempts = 0
            rescrambled_data = DataManipulation.scramble(descrambled_data,number_of_attempts.to_bytes(4, byteorder='big'))
            updated_encrypted_data_base64 = base64.b64encode(rescrambled_data).decode('utf-8')
            updated_data.append(updated_encrypted_data_base64)
            encrypted_data = updated_data
        result = encrypted_data, None
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result