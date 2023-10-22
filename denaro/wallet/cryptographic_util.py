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
    def update_or_reset_attempts(data, hmac_salt, password_verified, deterministic):
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
    
        if attempts_left:
            print(f"\nPassword Attempts Left: {attempts_left}")
        if attempts_left == 0:
            print(f"\nPassword Attempts Left: {attempts_left}")
            print("Wallet data permanetly erased...")
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

class VerificationUtils:
    
    @staticmethod
    def hash_password(password, salt):        
        """
        Generate a cryptographic hash of the password using PBKDF2 and then Scrypt.
        """
        # First layer of hashing using PBKDF2
        pbkdf2_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
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