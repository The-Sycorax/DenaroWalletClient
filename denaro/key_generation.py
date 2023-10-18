# Importing required standard libraries
import hashlib
import json
import logging
import sys
from enum import Enum
from math import ceil
from datetime import datetime, timezone
from typing import Union

# Importing third-party libraries
import base58
from fastecdsa import keys, curve
from fastecdsa.point import Point
from fastecdsa.util import mod_sqrt
import mnemonic
from bitcoinlib.keys import HDKey, Key
from icecream import ic
import binascii

# Custom print function definition
_print = print  # Saving the original print function for later use

# Constants
ENDIAN = 'little'  # Defining byte order as little-endian
CURVE = curve.P256  # Defining the elliptic curve for ECDSA

# Logging Configuration
# Set logging level based on command-line arguments
logging.basicConfig(level=logging.INFO if '--nologs' not in sys.argv else logging.WARNING)

def log(s):
    """
    Log the provided message using the logging library.
    
    Parameters:
        s (str): Message to log
    """
    logging.getLogger('denaro').info(s)  # Logging the message under the 'denaro' namespace

# Configure Icecream for custom logging
ic.configureOutput(outputFunction=log)  # Redirecting icecream output to custom log function

def get_json(obj):
    """
    Convert an object to its JSON representation and then back to a dictionary.
    
    Parameters:
        obj: Object to convert. Can be a dictionary, list, or custom object.
        
    Returns:
        dict: Object as a dictionary.
    """
    # Convert object to JSON and then deserialize it to dictionary
    return json.loads(json.dumps(obj, default=lambda o: getattr(o, 'as_dict', getattr(o, '__dict__', str(o)))))

def timestamp():
    """
    Get the current UTC timestamp.
    
    Returns:
        int: Current timestamp in UTC timezone.
    """
    # Getting current time, setting it to UTC and returning its timestamp
    return int(datetime.now(timezone.utc).replace(tzinfo=timezone.utc).timestamp())

def sha256(message: Union[str, bytes]):
    """
    Compute the SHA-256 hash of the given message.
    
    Parameters:
        message (Union[str, bytes]): Message to hash. Can be a string or bytes.
        
    Returns:
        str: SHA-256 hash in hexadecimal format.
    """
    # If the message is a string, convert it to bytes
    if isinstance(message, str):
        message = bytes.fromhex(message)
    # Calculate SHA-256 hash and return it as a hexadecimal string
    return hashlib.sha256(message).hexdigest()

def byte_length(i: int):
    """
    Calculate the byte length of an integer.
    
    Parameters:
        i (int): Integer whose byte length is to be calculated.
        
    Returns:
        int: Byte length of the integer.
    """
    # Calculate byte length using bit length and ceiling function
    return ceil(i.bit_length() / 8.0)

def normalize_block(block) -> dict:
    """
    Normalize a block by trimming spaces and converting timestamps.
    
    Parameters:
        block (dict): Block data to normalize.
        
    Returns:
        dict: Normalized block data.
    """
    # Create a copy of the block dictionary
    block = dict(block)
    # Remove leading and trailing spaces from the 'address' field
    block['address'] = block['address'].strip(' ')
    # Convert and normalize the 'timestamp' field to UTC timestamp
    block['timestamp'] = int(block['timestamp'].replace(tzinfo=timezone.utc).timestamp())
    return block

def x_to_y(x: int, is_odd: bool = False):
    """
    Given the x-coordinate, compute the y-coordinate on the elliptic curve.
    
    Parameters:
        x (int): x-coordinate on the elliptic curve.
        is_odd (bool, optional): Whether the y-coordinate should be odd. Defaults to False.
        
    Returns:
        int: Computed y-coordinate based on the x-coordinate.
    """
    # Elliptic curve parameters
    a, b, p = CURVE.a, CURVE.b, CURVE.p
    # Compute y^2 using the curve equation
    y2 = x ** 3 + a * x + b
    # Compute the square root of y^2 modulo p
    y_res, y_mod = mod_sqrt(y2, p)
    # Return either y_res or y_mod based on whether y should be odd
    return y_res if y_res % 2 == is_odd else y_mod

class AddressFormat(Enum):
    """
    Enumeration to represent different address formats.
    """
    FULL_HEX = 'hex'  # Full hexadecimal format
    COMPRESSED = 'compressed'  # Compressed format

def bytes_to_point(point_bytes: bytes) -> Point:
    """
    Convert bytes to an ECDSA point.
    
    Parameters:
        point_bytes (bytes): Bytes to convert.
        
    Returns:
        Point: Converted ECDSA point.
    """
    # If the byte length is 64, it's a full point (x and y coordinates)
    if len(point_bytes) == 64:
        x, y = int.from_bytes(point_bytes[:32], ENDIAN), int.from_bytes(point_bytes[32:], ENDIAN)  # Extract x and y from bytes
        return Point(x, y, CURVE)  # Return as Point object
    # If the byte length is 33, it's a compressed point
    elif len(point_bytes) == 33:
        specifier = point_bytes[0]  # First byte is the specifier for odd/even y-coordinate
        x = int.from_bytes(point_bytes[1:], ENDIAN)  # Extract x from the bytes
        return Point(x, x_to_y(x, specifier == 43))  # Compute y and return as Point object
    else:
        # Unsupported byte length
        raise NotImplementedError()

def bytes_to_string(point_bytes: bytes) -> str:
    """
    Convert point bytes to its string representation based on its format (full or compressed).
    
    Parameters:
        point_bytes (bytes): Bytes representing the point.
        
    Returns:
        str: String representation of the point.
    """
    point = bytes_to_point(point_bytes)  # Convert bytes to ECDSA point
    # Determine the address format based on byte length
    if len(point_bytes) == 64:
        address_format = AddressFormat.FULL_HEX  # Full hexadecimal format
    elif len(point_bytes) == 33:
        address_format = AddressFormat.COMPRESSED  # Compressed format
    else:
        # Unsupported byte length
        raise NotImplementedError()
    return point_to_string(point, address_format)  # Convert point to string based on the determined format

def point_to_bytes(point: Point, address_format: AddressFormat = AddressFormat.FULL_HEX) -> bytes:
    """
    Convert an ECDSA point to bytes based on the address format.
    
    Parameters:
        point (Point): ECDSA point to convert.
        address_format (AddressFormat, optional): Format to use for the conversion. Defaults to AddressFormat.FULL_HEX.
        
    Returns:
        bytes: Point in byte format.
    """
    # If full hexadecimal format is chosen
    if address_format is AddressFormat.FULL_HEX:
        return point.x.to_bytes(32, byteorder=ENDIAN) + point.y.to_bytes(32, byteorder=ENDIAN)
    # If compressed format is chosen
    elif address_format is AddressFormat.COMPRESSED:
        return string_to_bytes(point_to_string(point, AddressFormat.COMPRESSED))
    else:
        # Raise an exception for unsupported formats
        raise NotImplementedError()
    
def point_to_string(point: Point, address_format: AddressFormat = AddressFormat.COMPRESSED) -> str:
    """
    Convert an ECDSA point to its string representation.
    
    Parameters:
        point (Point): ECDSA point to convert.
        address_format (AddressFormat, optional): The format to use for the conversion. Defaults to AddressFormat.COMPRESSED.
        
    Returns:
        str: String representation of the point.
    """
    x, y = point.x, point.y  # Extract x and y coordinates from the point
    # For full hexadecimal format
    if address_format is AddressFormat.FULL_HEX:
        point_bytes = point_to_bytes(point)  # Convert point to bytes
        return point_bytes.hex()  # Convert bytes to hexadecimal string
    # For compressed format
    elif address_format is AddressFormat.COMPRESSED:
        # Convert point to Base58 string
        address = base58.b58encode((42 if y % 2 == 0 else 43).to_bytes(1, ENDIAN) + x.to_bytes(32, ENDIAN))
        return address if isinstance(address, str) else address.decode('utf-8')  # Ensure the result is a string
    else:
        # Unsupported format
        raise NotImplementedError()

def string_to_bytes(string: str) -> bytes:
    """
    Convert a string to bytes. The function handles both hexadecimal and Base58 encoded strings.
    
    Parameters:
        string (str): The string to convert.
        
    Returns:
        bytes: The converted bytes.
    """
    try:
        # Try to convert from hexadecimal to bytes
        point_bytes = bytes.fromhex(string)
    except ValueError:
        # If not hexadecimal, assume it's Base58 and decode it
        point_bytes = base58.b58decode(string)
    return point_bytes

def string_to_point(string: str):
    """
    Convert a string to an ECDSA point. The function handles both hexadecimal and Base58 encoded strings.
    
    Parameters:
        string (str): The string to convert.
        
    Returns:
        Point: The converted ECDSA point.
    """
    # Convert the string to bytes and then to an ECDSA point
    return bytes_to_point(string_to_bytes(string))

def hex_to_point(x_hex: str, y_hex: str, curve_obj):
    """
    Convert hexadecimal coordinates to an ECDSA point.
    
    Parameters:
        x_hex (str): Hexadecimal x-coordinate.
        y_hex (str): Hexadecimal y-coordinate.
        curve_obj: Elliptic curve object.
        
    Returns:
        Point: The converted ECDSA point.
    """
    x_int = int(x_hex, 16)  # Convert x from hex to integer
    y_int = int(y_hex, 16)  # Convert y from hex to integer
    return Point(x_int, y_int, curve_obj)  # Create and return the ECDSA point

def private_to_public_key_fastecdsa(private_key_hex):
    """
    Convert a private key in hexadecimal format to a public key and its compressed representation.
    
    Parameters:
        private_key_hex (str): Private key in hexadecimal format.
        
    Returns:
        tuple: A tuple containing the ECDSA point representing the public key and its compressed hexadecimal representation.
    """
    # Convert the hexadecimal private key to an integer
    private_key_int = int(private_key_hex, 16)
    
    # Use fastecdsa's keys.get_public_key function to calculate the public point corresponding to the private key
    public_point = keys.get_public_key(private_key_int, curve.P256)
    
    # Determine the prefix for the compressed public key ('02' for even y-coordinates and '03' for odd)
    prefix = '02' if public_point.y % 2 == 0 else '03'
    
    # Create the compressed public key by concatenating the prefix and the x-coordinate in hexadecimal format
    compressed_public_key = prefix + format(public_point.x, '064x')
    
    # Return the public point and its compressed representation
    return public_point, compressed_public_key

def generate(mnemonic_phrase=None, passphrase=None, index=0, deterministic=False, fields=None):
    """
    Generate cryptographic keys and addresses.
    
    Parameters:
        mnemonic_phrase (str, optional): Mnemonic phrase for generating seed. If not provided, one is generated.
        passphrase (str, optional): Optional passphrase for the mnemonic.
        index (int, optional): Index for deriving deterministic child keys.
        deterministic (bool, optional): Whether to generate deterministic keys. Defaults to False.
        fields (list, optional): List of fields to include in the result. Defaults to None.
        
    Returns:
        dict: Dictionary containing the generated information.
    """
    # Generate a 12-word mnemonic if not provided
    if not mnemonic_phrase:
        mnemonic_phrase = mnemonic.Mnemonic("english").generate()
    # Set passphrase to empty if not provided
    if not passphrase:
        passphrase = ""
    # Generate seed from mnemonic
    seed = mnemonic.Mnemonic.to_seed(mnemonic_phrase, passphrase)
    # Generate BIP32 root key from seed
    root_key = HDKey.from_seed(seed)
    result = {}  # Dictionary to store the result
    
    # Deterministic key generation
    if deterministic:
        child_key = root_key.subkey_for_path(f"m/0/{index}")  # Derive child key
        private_key_hex = child_key.private_hex  # Get private key in hexadecimal
        public_key_point, public_key_hex = private_to_public_key_fastecdsa(private_key_hex)  # Get public key
        address = point_to_string(public_key_point)  # Get address
        
        # Define default fields if not specified
        if fields is None:
            fields = ["mnemonic", "id", "private_key", "public_key", "address"]
        
        # Populate result based on specified fields
        if "mnemonic" in fields:
            result["mnemonic"] = mnemonic_phrase
        if "id" in fields:
            result["id"] = index
        if "private_key" in fields:
            result["private_key"] = private_key_hex
        if "public_key" in fields:
            result["public_key"] = public_key_hex
        if "address" in fields:
            result["address"] = address
    else:
        # Non-deterministic key generation
        private_key_hex = root_key.private_hex  # Get private key in hexadecimal
        public_key_point, public_key_hex = private_to_public_key_fastecdsa(private_key_hex)  # Get public key
        address = point_to_string(public_key_point)  # Get address
        
        # Define default fields if not specified
        if fields is None:
            fields = ["mnemonic", "private_key", "public_key", "address"]
        
        # Populate result based on specified fields
        if "mnemonic" in fields:
            result["mnemonic"] = mnemonic_phrase
        if "private_key" in fields:
            result["private_key"] = private_key_hex
        if "public_key" in fields:
            result["public_key"] = public_key_hex
        if "address" in fields:
            result["address"] = address
    
    return result  # Return the generated information as a dictionary