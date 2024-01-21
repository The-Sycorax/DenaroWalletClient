import os
import sys
import logging
import hashlib
import random
import time
import ctypes
import json
import shutil
import datetime
from filelock import FileLock
import cryptographic_util
import verification_util

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
        update_or_reset = cryptographic_util.EncryptDecryptUtils.update_failed_attempts if not password_verified else cryptographic_util.EncryptDecryptUtils.reset_failed_attempts
    
        # Define keys to update or reset based on deterministic flag
        key_list = [["entry_data", "entries"],["totp_secret"]]
        if "imported_entries" in data["wallet_data"]["entry_data"]:
            key_list.append(["entry_data", "imported_entries"])
        #key_list.append(["entry_data", "imported_entries"])

        if deterministic:
            key_list.append(["entry_data", "key_data"])
            
        #key_list.append(["totp_secret"])
    
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
    def backup_wallet(filename, directory):
        # Construct the backup filename
        base_filename = os.path.basename(filename)
        backup_name, _ = os.path.splitext(base_filename)
        #backup_path = os.path.join("./wallets/wallet_backups", f"{backup_name}_backup_{datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y-%m-%d_%H-%M-%S')}") + ".json"
        backup_path = os.path.join("./wallets/wallet_backups" if not directory else directory, f"{backup_name}_backup_{datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y-%m-%d_%H-%M-%S')}") + ".json"
        try:
            # Create the backup
            shutil.copy(filename, backup_path)
            print(f"Backup created at: {backup_path}")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return True
        except Exception as e:
            logging.error(f" Could not create backup: {e}\n")
            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            return

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
            verifier = verification_util.Verification.hash_password(password, verification_salt)
            totp_secret = cryptographic_util.TOTP.generate_totp_secret(True, bytes(verification_salt,'utf-8'))               
            encrypted_data = cryptographic_util.EncryptDecryptUtils.encrypt_data(str(data), password, totp_secret, hmac_salt, verification_salt, verifier)
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
    def delete_wallet(file_path, data, passes=1):
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