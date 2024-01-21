import os
import hashlib
import pyotp
from Crypto.Cipher import AES, ChaCha20_Poly1305
import logging
import base64
import data_manipulation_util
import verification_util

# Global variables
FAILED_ATTEMPTS = 0
MAX_ATTEMPTS = 5
DIFFICULTY = 3

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
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not proof])
        return proof

    @staticmethod
    def is_proof_valid(proof, challenge):
        result = hashlib.sha256(challenge + str(proof).encode()).hexdigest().startswith("1" * DIFFICULTY)
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

class TOTP:    
    @staticmethod
    def generate_totp_secret(predictable, verification_salt):
        """
        Generate a new TOTP secret.
        """
        if not predictable:
            result = pyotp.random_base32()
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result
        else:
            result = hashlib.sha256(verification_salt).hexdigest()[:16]
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
            return result
    
    @staticmethod
    def generate_totp_code(secret):
        """
        Generate a Two-Factor Authentication code using the given secret.
        """
        totp = pyotp.TOTP(secret)
        result = totp.now()
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result

class EncryptDecryptUtils:
    """
    Handles encryption and decryption tasks.
    """
    @staticmethod
    def aes_gcm_encrypt(data, key, nonce):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        result = ciphertext, tag
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
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
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
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
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not decrypted_data])
            return decrypted_data
        except ValueError:
            logging.error("ChaCha20-Poly1305 tag verification failed. Data might be corrupted or tampered with.")
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("ChaCha20-Poly1305 tag verification failed. Data might be corrupted or tampered with.")
        
    @staticmethod
    def encrypt_data(data, password, totp_secret, hmac_salt, verification_salt, stored_password_hash):
        # 1. Password Verification
        # Verify the provided password against the stored hash and salt
        password_verified, verifier = verification_util.Verification.verify_password(stored_password_hash, password, verification_salt)
        if not password_verified and not verifier:
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("Authentication failed or wallet data is corrupted.")
            raise ValueError("Authentication failed or wallet data is corrupted.")
        
        # 2. AES-GCM Layer Encryption
        # Generate a random 16-byte challenge for AES
        aes_challenge_portion = os.urandom(16)
        # Generate a proof-of-work based on the challenge
        aes_challenge_portion_proof = ProofOfWork.generate_proof(aes_challenge_portion)
        # Scramble the challenge based on the proof-of-work
        scrambled_aes_challenge_portion = data_manipulation_util.DataManipulation.scramble(aes_challenge_portion, aes_challenge_portion_proof)
        # Generate a proof-of-work based on the scrambled challenge
        aes_proof = ProofOfWork.generate_proof(scrambled_aes_challenge_portion)
        
        # Create a commitment by hashing the proof
        aes_commitment = hashlib.sha256(str(aes_proof).encode()).digest()
        # Convert the commitment to a hexadecimal string
        aes_commitment_hex = aes_commitment.hex()

        # Scramble all the parameters to be used for key derivation
        scrambled_parameters = [data_manipulation_util.DataManipulation.scramble(param.encode() if isinstance(param, str) else param, aes_proof) for param in [password, totp_secret, aes_commitment_hex, hmac_salt, verifier, verification_salt]]
    
        # Derive AES encryption key using Scrypt
        aes_encryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)
        # Generate a random nonce for AES encryption
        aes_nonce = os.urandom(16)
        
        # Scramble and encrypt the data
        scrambled_data = data_manipulation_util.DataManipulation.scramble(data.encode(), aes_proof)
        aes_ct_bytes, aes_tag = EncryptDecryptUtils.aes_gcm_encrypt(scrambled_data, aes_encryption_key, aes_nonce)

        # Scramble the ciphertext and tag
        scrambled_aes_ct_bytes = data_manipulation_util.DataManipulation.scramble(aes_ct_bytes, aes_proof)
        scrambled_aes_tag = data_manipulation_util.DataManipulation.scramble(aes_tag, aes_proof)

        # Compute HMAC for AES layer
        hmac_1 = verification_util.Verification.hmac_util(password=scrambled_parameters[0].decode(), hmac_salt=scrambled_parameters[3], hmac_msg=aes_nonce + scrambled_aes_ct_bytes + scrambled_aes_tag, verify=False)

        # 3. ChaCha20-Poly1305 Layer Encryption
        # Generate a random 16-byte challenge for ChaCha20
        chacha_challenge_portion = os.urandom(16)
        # Generate a proof-of-work based on the challenge
        chacha_challenge_portion_proof = ProofOfWork.generate_proof(chacha_challenge_portion)
        # Scramble the challenge based on the proof-of-work
        scrambled_chacha_challenge_portion = data_manipulation_util.DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
        # Generate a proof-of-work based on the scrambled challenge
        chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)
        
        # Create a commitment by hashing the proof
        chacha_commitment = hashlib.sha256(str(chacha_proof).encode()).digest()
        # Convert the commitment to a hexadecimal string
        chacha_commitment_hex = chacha_commitment.hex()
        
        # Scramble all the parameters to be used for key derivation
        scrambled_parameters = [data_manipulation_util.DataManipulation.scramble(param.encode() if isinstance(param, str) else param, chacha_proof) for param in [password, totp_secret, chacha_commitment_hex, hmac_salt, verifier, verification_salt]]

        # Derive ChaCha20 encryption key using Scrypt
        chacha_encryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)
        # Encrypt the data using ChaCha20-Poly1305
        chacha_nonce, chacha_ct_bytes, chacha_tag = EncryptDecryptUtils.chacha20_poly1305_encrypt(aes_challenge_portion + aes_nonce + scrambled_aes_ct_bytes + scrambled_aes_tag + hmac_1, chacha_encryption_key)

        # Scramble the ciphertext and tag
        scrambled_chacha_ct_bytes = data_manipulation_util.DataManipulation.scramble(chacha_ct_bytes, chacha_proof)
        scrambled_chacha_tag = data_manipulation_util.DataManipulation.scramble(chacha_tag, chacha_proof)

        # Compute HMAC for ChaCha20 layer
        hmac_2 = verification_util.Verification.hmac_util(password=chacha_commitment_hex, hmac_salt=scrambled_parameters[3], hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag, verify=False)
        
        failed_attempts = 0
        failed_attempts_bytes = failed_attempts.to_bytes(4, byteorder='big')
        #print(chacha_proof)
        #print(data_manipulation_util.DataManipulation.scramble(chacha_challenge_portion + chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag + hmac_2, failed_attempts_bytes))
        # Base64 encode the final encrypted data for easier storage and transmission
        result = base64.b64encode(data_manipulation_util.DataManipulation.scramble(chacha_challenge_portion + chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag + hmac_2, failed_attempts_bytes)).decode('utf-8')

        # 4. Cleanup and return
        # Securely delete sensitive variables
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
                
        return result

    @staticmethod
    def decrypt_data(encrypted_data, password, totp_secret, hmac_salt, verification_salt, stored_password_hash):
        global FAILED_ATTEMPTS, MAX_ATTEMPTS, DIFFICULTY  # Global variables for failed attempts and PoW difficulty
       
        # 1. Base64 Decoding
        # Decode the base64 encoded encrypted data
        data = base64.b64decode(encrypted_data.encode('utf-8'))

        # 2. Password Verification        
        # Verify the provided password against the stored hash and salt
        password_verified, verifier = verification_util.Verification.verify_password(stored_password_hash, password, verification_salt)
        if not password_verified and not verifier:
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("Authentication failed or wallet data is corrupted.")
            raise ValueError("Authentication failed or wallet data is corrupted.")
        else:
            failed_attempts = 0
            failed_attempts_bytes = failed_attempts.to_bytes(4, byteorder='big')
            data = data_manipulation_util.DataManipulation.descramble(data,failed_attempts_bytes)

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
                data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid ChaCha Challenge proof. Try again.")
        
        # Scramble the challenge based on the proof-of-work
        scrambled_chacha_challenge_portion = data_manipulation_util.DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
        # Generate another proof-of-work based on the scrambled challenge
        chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)

        #Check if ChaCha scrambled challenge proof is valid
        if not ProofOfWork.is_proof_valid(chacha_proof, scrambled_chacha_challenge_portion):
            FAILED_ATTEMPTS += 1
            if FAILED_ATTEMPTS >= MAX_ATTEMPTS:
                data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                #del encrypted_data  # Replace with your secure delete function
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid ChaCha proof. Try again.")
        
        # Compute commitment and convert it to hex
        chacha_commitment_hex = hashlib.sha256(str(chacha_proof).encode()).hexdigest()

        # Scramble all parameters for key derivation
        scrambled_parameters = [data_manipulation_util.DataManipulation.scramble(param.encode() if isinstance(param, str) else param, chacha_proof) for param in [password, totp_secret, chacha_commitment_hex, hmac_salt, verifier, verification_salt]]

        # Verify HMAC for ChaCha layer data
        if not verification_util.Verification.hmac_util(password=chacha_commitment_hex,hmac_salt=scrambled_parameters[3],stored_hmac=stored_chacha_hmac,hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag,verify=True):
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("ChaCha layer data integrity check failed. Wallet data might be corrupted or tampered with.")
            raise ValueError("ChaCha layer data integrity check failed. Wallet data might be corrupted or tampered with.")
                
        # Derive decryption key using Scrypt
        chacha_decryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)

        # Descramble ChaCha ciphertext and the tag
        chacha_ct_bytes = data_manipulation_util.DataManipulation.descramble(scrambled_chacha_ct_bytes, chacha_proof)
        chacha_tag = data_manipulation_util.DataManipulation.descramble(scrambled_chacha_tag, chacha_proof)
        
        # Decrypt the data using ChaCha20-Poly1305
        chacha_decrypted_data = EncryptDecryptUtils.chacha20_poly1305_decrypt(chacha_nonce, chacha_ct_bytes, chacha_tag, chacha_decryption_key)

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
                data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                #del encrypted_data  # Replace with your secure delete function
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid AES Challenge proof. Try again.")
        
        # Scramble the AES challenge based on the proof-of-work
        scrambled_aes_challenge_portion = data_manipulation_util.DataManipulation.scramble(aes_challenge_portion, aes_challenge_portion_proof)
        # Generate another proof-of-work based on the scrambled challenge
        aes_proof = ProofOfWork.generate_proof(scrambled_aes_challenge_portion)

        #Check if AES scrambled challenge proof is valid
        if not ProofOfWork.is_proof_valid(aes_proof, scrambled_aes_challenge_portion):
            FAILED_ATTEMPTS += 1
            if FAILED_ATTEMPTS >= MAX_ATTEMPTS:
                data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                #del encrypted_data  # Replace with your secure delete function
                raise ValueError("Too many failed attempts. Data deleted.")
            DIFFICULTY += 1
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            raise ValueError("Invalid AES proof. Try again.")
        
        # Compute commitment and convert it to hex
        aes_commitment_hex = hashlib.sha256(str(aes_proof).encode()).hexdigest()

        # Scramble all parameters for key derivation
        scrambled_parameters = [data_manipulation_util.DataManipulation.scramble(param.encode() if isinstance(param, str) else param, aes_proof) for param in [password, totp_secret, aes_commitment_hex, hmac_salt, verifier, verification_salt]]
        
        # Verify HMAC for AES layer data
        if not verification_util.Verification.hmac_util(password=scrambled_parameters[0].decode(),hmac_salt=scrambled_parameters[3],stored_hmac=stored_aes_hmac,hmac_msg=aes_nonce + scrambled_aes_ct_bytes + scrambled_aes_tag,verify=True):
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
            logging.error("AES layer data integrity check failed. Wallet data might be corrupted or tampered with.")
            raise ValueError("AES layer data integrity check failed. Wallet data might be corrupted or tampered with.")
        
        # Derive decryption key using Scrypt
        aes_decryption_key = hashlib.scrypt(b''.join(scrambled_parameters), salt=scrambled_parameters[-1], n=2**14, r=8, p=1, dklen=32)
        
        # Descramble the AES ciphertext and tag
        aes_ct_bytes = data_manipulation_util.DataManipulation.descramble(scrambled_aes_ct_bytes, aes_proof)
        aes_tag = data_manipulation_util.DataManipulation.descramble(scrambled_aes_tag,aes_proof)

        # Decrypt the data using AES-GCM
        decrypted_data = EncryptDecryptUtils.aes_gcm_decrypt(aes_ct_bytes, aes_tag, aes_decryption_key, aes_nonce)
        
        # Descramble the decrypted data
        decrypted_data = data_manipulation_util.DataManipulation.descramble(decrypted_data, aes_proof)

        result = decrypted_data.decode('utf-8')
                                                     
        # 5. Cleanup and return
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result      
    
    @staticmethod
    def get_failed_attempts(data, hmac_salt):
        """
        Overview:
            This method is designed to ascertain the number of unsuccessful password attempts encoded within encrypted data. 
            It sequentially descrambles the data using varying nonce values derived from the range 1-10, extracts several 
            cryptographic segments (like ChaCha20 components and HMAC), and engages in a proof-of-work challenge-response cycle. 
            This cycle includes scrambling and descrambling, along with HMAC verification using the provided salt. 
            The loop terminates upon successful HMAC validation, reflecting the correct attempt count.
    
        Parameters:
            - data (bytes): The encrypted data containing encoded information about password attempt failures.
            - hmac_salt (bytes): The cryptographic salt utilized in the HMAC verification process for enhanced security.
    
        Returns:
            Tuple (bytes, int): 
                A tuple comprising the descrambled data and the determined number of failed password attempts.
        """        
        # Loop between 1-10 to get amount of failed password attempts
        number_of_attempts = 0
        for n in range(10):
            # Descrample Data
            descrambled_data = data_manipulation_util.DataManipulation.descramble(data,n.to_bytes(4, byteorder='big'))            
            # Extract cryptographic data
            chacha_challenge_portion = descrambled_data[:16]
            chacha_nonce = descrambled_data[16:28]
            scrambled_chacha_ct_bytes = descrambled_data[28:-48]
            scrambled_chacha_tag = descrambled_data[-48:-32]
            stored_chacha_hmac = descrambled_data[-32:]
            # Handle proof of work
            chacha_challenge_portion_proof = ProofOfWork.generate_proof(chacha_challenge_portion)
            scrambled_chacha_challenge_portion = data_manipulation_util.DataManipulation.scramble(chacha_challenge_portion, chacha_challenge_portion_proof)
            chacha_proof = ProofOfWork.generate_proof(scrambled_chacha_challenge_portion)
            # Create a commitment by hashing the proof
            chacha_commitment = hashlib.sha256(str(chacha_proof).encode()).digest()
            # Convert the commitment to a hexadecimal string
            chacha_commitment_hex = chacha_commitment.hex()
            # Verify HMAC of data within loop iteration
            if verification_util.Verification.hmac_util(password=chacha_commitment_hex,hmac_salt=data_manipulation_util.DataManipulation.scramble(hmac_salt,chacha_proof),stored_hmac=stored_chacha_hmac,hmac_msg=chacha_nonce + scrambled_chacha_ct_bytes + scrambled_chacha_tag,verify=True):
                # If the HMAC is verified, set number_of_attempts to n and break loop
                number_of_attempts = n
                break
        # Return the nessessary data
        return descrambled_data, number_of_attempts
    
    @staticmethod
    def update_failed_attempts(encrypted_data, hmac_salt):
        """
        Overview:
            This method updates the count of failed password attempts for each encrypted data entry. It iterates through
            a list of encrypted entries, decodes them from base64, and employs 'get_failed_attempts' to retrieve the current
            count of failed attempts. Each count is then incremented, signifying an additional failed attempt. The data is then
            rescrambled with the incremented count and re-encoded in base64. Afterwhich, the nessessary data is updated and returned.
    
        Parameters:
            - encrypted_data (list of strings): A collection of base64 encoded strings representing encrypted data entries.
            - hmac_salt (bytes): The cryptographic salt used in HMAC operations for data authentication.
    
        Returns:
            Tuple (list of strings, int): 
                The updated list of encrypted data entries in base64 format with revised attempt counts, 
                alongside the remaining number of attempts before breach protocol activation.
        """
        #encrypted_data = encrypted_data["wallet_data"]["entry_data"]["entries"]
        updated_data = []
        #print(f"encrypted_data: {encrypted_data}")
        for encrypted_entry in encrypted_data:
            #print(f"encrypted_entry: {encrypted_entry}")
            data = base64.b64decode(encrypted_entry.encode('utf-8'))
            descrambled_data, number_of_attempts = EncryptDecryptUtils.get_failed_attempts(data, hmac_salt)
            number_of_attempts += + 1
            attempts_left = 10 - number_of_attempts            
            rescrambled_data = data_manipulation_util.DataManipulation.scramble(descrambled_data, number_of_attempts.to_bytes(4, byteorder='big'))
            #print(rescrambled_data)
            updated_encrypted_data_base64 = base64.b64encode(rescrambled_data).decode('utf-8')
            updated_data.append(updated_encrypted_data_base64)
            encrypted_data = updated_data
        result = encrypted_data, attempts_left
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result
    
    @staticmethod
    def reset_failed_attempts(encrypted_data, hmac_salt):
        """
        Overview:
            This method resets the failed password attempt count for each entry in a set of encrypted data. 
            By utilizing 'get_failed_attempts', it fetches the current attempt count, then resets this to zero, 
            reflecting a revalidated access. The data is then rescrambled with the new count and re-encoded in base64.
            Afterwhich, the nessessary data is updated and returned.
        
        Parameters:
            - encrypted_data (list of strings): A series of base64 encoded strings that represent encrypted data entries.
            - hmac_salt (bytes): Salt used in HMAC for ensuring data authenticity and integrity.
    
        Returns:
            Tuple (list of strings, NoneType): 
                A list of updated encrypted entries with reset attempt counts, encoded in base64, 
                and a None value, signifying no secondary return value.
        """
        #encrypted_data = encrypted_data["wallet_data"]["entry_data"]["entries"]
        updated_data = []
        #print(encrypted_data)
        for encrypted_entry in encrypted_data:
            #print(encrypted_entry)
            data = base64.b64decode(encrypted_entry.encode('utf-8'))
            descrambled_data, number_of_attempts = EncryptDecryptUtils.get_failed_attempts(data, hmac_salt)
            number_of_attempts = 0
            rescrambled_data = data_manipulation_util.DataManipulation.scramble(descrambled_data,number_of_attempts.to_bytes(4, byteorder='big'))
            updated_encrypted_data_base64 = base64.b64encode(rescrambled_data).decode('utf-8')
            updated_data.append(updated_encrypted_data_base64)
            encrypted_data = updated_data
        result = encrypted_data, None
        data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
        return result