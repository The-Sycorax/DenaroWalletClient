import qrcode
from PIL import Image, ImageDraw
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import CircleModuleDrawer
from qrcode.image.styles.colormasks import SolidFillColorMask
import os
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = "hide"
import pygame
import pygame.freetype
import logging
import getpass
import shutil
import datetime
import time
import threading
import select
import sys
import base64
from cryptographic_util import VerificationUtils, DataManipulation

close_qr_window = False

is_windows = os.name == 'nt'

if is_windows:
    import msvcrt
else:
    import termios, fcntl

# QRCode utility class
class QRCodeUtils:  

    @staticmethod
    def generate_qr_with_logo(data, logo_path):
        """
        Overview: 
        Generates a custom QR code of the TOTP secret token with Denaro's logo in the center.
        The generated QR code is meant to be scanned by a Authenticator app. 

        Arguments:
        - data (str): The data to encode in the QR code.
        - logo_path (str): The path to the logo image file.
        
        Returns:
        - PIL.Image: The generated QR code image.
        """
        # Initialize QR Code with high error correction
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)  
        qr.add_data(data)  
        
        # Create a styled QR code image
        qr_img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=CircleModuleDrawer(radius_ratio=1.5),
            color_mask=SolidFillColorMask(back_color=(255, 255, 255))
        )  
        
        # Define color palette for gradient
        palette = [(51, 76, 154), (51, 76, 154), (14, 117, 165),
                   (83, 134, 162), (83, 134, 162), (14, 117, 165), (51, 76, 154), (51, 76, 154)]
        
        # Apply gradient based on the color pallette
        gradient_img = Image.new("RGB", qr_img.size, (255, 255, 255))  
        gradient_img = QRCodeUtils.generate_qr_gradient(gradient_img, palette)  
        
        # Create a mask for the gradient
        mask = qr_img.convert("L")  
        threshold = 200  
        mask = mask.point(lambda p: p < threshold and 255)  
        
        # Apply gradient to the QR code
        qr_img = Image.composite(gradient_img, qr_img, mask)  
        
        # Load, resize and place the logo
        logo_img = Image.open(logo_path)
        basewidth = min(qr_img.size[0] // 4, logo_img.size[0])  
        wpercent = (basewidth / float(logo_img.size[0]))  
        hsize = int((float(logo_img.size[1]) * float(wpercent)))  
        logo_img = logo_img.resize((basewidth, hsize))  
        
        # Calculate logo position
        logo_pos = ((qr_img.size[0] - logo_img.size[0]) //
                    2, (qr_img.size[1] - logo_img.size[1]) // 2)  
        
        # Paste the logo onto the QR code
        qr_img.paste(logo_img, logo_pos, logo_img)  
        
        # Return the final QR code image with the logo
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not qr_img])
        return qr_img  

    @staticmethod
    def generate_qr_gradient(image, palette):
        """
        Overview: Generates a gradient image based on a color palette.

        Arguments:
        - image (PIL.Image): The image to apply the gradient on.
        - palette (list): List of RGB tuples for the gradient.
        
        Returns:
        - PIL.Image: The image with gradient applied.
        """
        # Initialize the drawing object
        draw = ImageDraw.Draw(image)  
        
        # Get image dimensions
        width, height = image.size  
        
        # Calculate the last index of the palette
        max_index = len(palette) - 1  
        
        # Draw the gradient line by line
        for x in range(width):  
            blended_color = [
                int((palette[min(int(x / width * max_index), max_index - 1)][i] * (1 - (x / width * max_index - int(x / width * max_index))) +
                     palette[min(int(x / width * max_index) + 1, max_index)][i] * (x / width * max_index - int(x / width * max_index))))
                for i in range(3)
            ]
            draw.line([(x, 0), (x, height)], tuple(blended_color))  
        
        # Return the image with gradient applied
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not image])
        return image  

    @staticmethod
    def show_qr_with_timer(qr_image, filename, totp_secret):
        """
        Overview: Displays the QR code in a window with a timer.
        
        Arguments:
        - qr_image (PIL.Image): The QR code image to display.
        - filename (str): The filename for the caption.
        - totp_secret (str): The TOTP secret to display.
        
        Returns: None
        """
        # Initialize pygame
        global close_qr_window  
        close_qr_window = False  
        pygame.init()  
        
        # Set the initial dimensions of the window
        size = 500  
        screen = pygame.display.set_mode((size, size), pygame.RESIZABLE)  
        pygame.display.set_caption(f'2FA QR Code for {filename}')  
        
        # Initialize timer and clock
        countdown = 60  
        clock = pygame.time.Clock()  
        
        # Define the activation message
        activation_message = (
            "To enable Two-Factor Authentication (2FA) for this wallet, scan the QR code with an authenticator app,"
            " then provide the one-time code in the terminal.")  
        reveal_secret = False  
        
        # Define constants for resizing and text
        BASE_SIZE = 500  
        BASE_QR_WIDTH = BASE_SIZE - 125  
        BASE_FONT_SIZE = 24  
        BASE_SMALL_FONT_SIZE = 22  
        
        # Initialize time variables
        time_elapsed = 0 # Used to track time elapsed for countdown
        resize_delay = 0 # Used to introduce a delay for resizing the window

        # Main loop for displaying the window
        while countdown > 0 and not close_qr_window:
            dt = clock.tick(60) / 1000.0 # Delta time in seconds
            time_elapsed += dt # Increment elapsed time by delta time

            # If a second or more has passed reset elapsed time
            if time_elapsed >= 1:  
                countdown -= 1  
                time_elapsed = 0
            
            # Fill the screen with a white background
            screen.fill((255, 255, 255)) 

            # For loop for event handling
            for event in pygame.event.get():
                # Fill the screen again within the for loop
                screen.fill((255, 255, 255))
                # Capture window close event
                if event.type == pygame.QUIT:  
                    pygame.quit()
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                    return
                # Capture window resize event
                elif event.type == pygame.VIDEORESIZE:  
                    resize_delay = 0.5
                # Ensure button_rect maintains the correct size
                button_rect = pygame.Rect(size - int(220 * size / BASE_SIZE), int(10 * size / BASE_SIZE), int(200 * size / BASE_SIZE), int(25 * size / BASE_SIZE))  
                # Capture mouse click event
                if event.type == pygame.MOUSEBUTTONDOWN:  
                    if button_rect.collidepoint(event.pos):  
                        reveal_secret = not reveal_secret

            # Handle window resizing
            if resize_delay > 0:  
                resize_delay -= dt  
                if resize_delay <= 0:  
                    size = min(pygame.display.get_window_size())  
                    screen = pygame.display.set_mode((size, size), pygame.RESIZABLE)  
                    resize_delay = 0  
            
            # Calculate scale factor for resizing
            scale_factor = size / BASE_SIZE  
            
            # Resize and display the QR code image
            qr_width = int(BASE_QR_WIDTH * scale_factor)  
            resized_surface = pygame.transform.scale(pygame.image.frombuffer(qr_image.convert("RGB").tobytes(), qr_image.size, 'RGB'), (qr_width, qr_width))  
            screen.blit(resized_surface, ((size - qr_width) // 2, int(40 * scale_factor)))  
            
            # Draw and display the "Reveal 2FA Token" button
            button_color = (100, 200, 100)  
            pygame.draw.rect(screen, button_color, button_rect)  
            font_button = pygame.font.SysFont(None, int(BASE_FONT_SIZE * scale_factor))  
            btn_text = "Reveal 2FA Token" if not reveal_secret else "Hide 2FA Token"  
            text_surf = font_button.render(btn_text, True, (0, 0, 0))  
            text_rect = text_surf.get_rect(center=button_rect.center)  
            screen.blit(text_surf, text_rect)  
            
            # Display the countdown timer
            font = pygame.font.SysFont(None, int(BASE_FONT_SIZE * scale_factor))  
            countdown_text = font.render(f"Closing window in: {countdown}s", True, (255, 0, 0))  
            screen.blit(countdown_text, (int(10 * scale_factor), int(10 * scale_factor)))  
            
            # Display the TOTP secret if the "Reveal" button was clicked
            font_secret = pygame.font.SysFont(None, int(BASE_FONT_SIZE * scale_factor))  
            secret_text_surf = font_secret.render(totp_secret, True, (0, 0, 255))  
            secret_text_rect = secret_text_surf.get_rect(center=(size // 2, qr_width + int(35 * scale_factor)))  
            if reveal_secret:  
                screen.blit(secret_text_surf, secret_text_rect)  
            
            # Display the activation message
            activation_message_start_y = secret_text_rect.bottom + int(20 * scale_factor)  
            font_small = pygame.font.SysFont(None, int(BASE_SMALL_FONT_SIZE * scale_factor))  
            wrapped_text = QRCodeUtils.wrap_text(
                activation_message, font_small, size - int(40 * scale_factor))  
            for idx, line in enumerate(wrapped_text):  
                text_line = font_small.render(line, True, (50, 50, 50))  
                text_line_pos = text_line.get_rect(center=(size // 2, activation_message_start_y + idx * int(25 * scale_factor)))  
                screen.blit(text_line, text_line_pos)  
            
            # Update the display
            pygame.display.flip()

        # Quit pygame when the countdown reaches zero or the window is closed
        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
        pygame.quit()

    @staticmethod
    def wrap_text(text, font, max_width):
        """
        Overview: Wraps text to fit within a given width.
        
        Arguments:
        - text (str): The text to wrap.
        - font (pygame.font.Font): The font used for measuring the text size.
        - max_width (int): The maximum width for the text.

        Returns:
        - list: The wrapped lines of text.
        """
        # Split text into words
        words = text.split(' ')          
        # Initialize list for wrapped lines
        lines = []        
        # Create lines with words that fit within max_width
        while words:  
            line = ''  
            while words and font.size(line + ' ' + words[0])[0] <= max_width:  
                line = (line + ' ' + words.pop(0)).strip()  
            lines.append(line)  
        # Return the wrapped lines
        DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not lines])
        return lines 
    
    def close_qr_window(value):
        global close_qr_window
        close_qr_window = value

class UserPrompts:
    
    @staticmethod
    def get_backup_preference(backup=None):
        """
        Overview:
        Asks the user whether they would like to back up an existing wallet.

        Arguments:
        - backup (str, optional): Default answer for the prompt. If not provided, input is taken from user.

        Returns:
        - bool: True if the user wants to back up the wallet, False otherwise.
        """
        # Loop until a valid input is received
        while True:
            # Prompt the user for backup preference or use the provided default
            backup_wallet = backup or input("WARNING: Wallet already exists. Do you want to back it up? (y/n)? ")
            # Normalize the input and check for valid options
            if backup_wallet.strip().lower() in ['y', 'n']:
                return backup_wallet.strip().lower() == 'y'
            elif backup_wallet.strip().lower() == "/q":
                #return False
                return backup_wallet
            else:
                print("Invalid input.")

    @staticmethod
    def get_overwrite_preference(disable_warning=False):
        """
        Overview:
        Asks the user for permission to overwrite an existing wallet.

        Arguments:
        - disable_warning (bool): If True, bypasses the warning and returns True.

        Returns:
        - bool: True if the user allows overwriting, False otherwise.
        """
        # Check if warnings are disabled
        if not disable_warning:
            while True:
                # Display a critical warning message
                print("\nCRITICAL WARNING: You have chosen not to back up the existing wallet.")
                # Prompt for user confirmation
                overwrite_wallet = input("Proceeding will PERMANENTLY OVERWRITE the existing wallet. Continue? (y/n)? ")
                if overwrite_wallet.strip().lower() in ['y', 'n']:
                    return overwrite_wallet.strip().lower() == 'y'
                elif overwrite_wallet.strip().lower() == "/q":
                    return overwrite_wallet
                else:
                    print("Invalid input.")
        else:
            return True

    @staticmethod
    def get_password(password=None, from_cli=False):
        """
        Overview:
        Prompts the user for a password and its confirmation.

        Arguments:
        - password (str, optional): Default password. If provided, no prompt will be displayed.
        - from_cli (bool): Flag indicating if the password is being set from the command line.

        Returns:
        - str: The password entered by the user.
        """
        # Loop until passwords match
        while True:
            # If password is not provided or not being set from CLI
            if not from_cli and not password or from_cli and not password:
                print()
                # Prompt for password
                password_input = getpass.getpass("Enter wallet password: ")
                # Prompt for password confirmation
                password_confirm = getpass.getpass("Confirm password: ")
            else:
                print()
                # Use the provided password or prompt for it
                password_input = password or getpass.getpass("Enter wallet password: ")
                password_confirm = password_input
            # Check if the passwords match
            if password_input == password_confirm:
                DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not password_input])
                return password_input
            else:
                print("Passwords do not match. Please try again.")
    
    @staticmethod
    def user_input_listener(stop_event):
        """
        Overview:
        Listens for user input and sets a global variable when input is received.

        Arguments:
        - stop_event (threading.Event): Event to stop listening for input.
        """
        global user_input_received
        # Wait for a keypress
        UserPrompts.get_input(stop_event)
        # Set the global flag indicating that input was received
        user_input_received = True

    @staticmethod
    def get_input(stop_event):
        """
        Overview:
        Waits for a single keypress from the user.

        Arguments:
        - stop_event (threading.Event): Event to stop waiting for input.

        Returns:
        - str: The key pressed by the user, or None if the stop event is set.
        """
        # Loop until the stop event is set
        while not stop_event.is_set():
            # Check if the operating system is Windows
            if is_windows:
                if msvcrt.kbhit():
                    return msvcrt.getch().decode('utf-8')
            else:
                # Save the current terminal settings
                fd = sys.stdin.fileno()
                oldterm = termios.tcgetattr(fd)
                newattr = termios.tcgetattr(fd)
                newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSANOW, newattr)

                try:
                    # Check for available input
                    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                        return sys.stdin.read(1)
                except Exception:
                    pass
                finally:
                    # Restore the terminal settings
                    termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
            # Sleep briefly to avoid busy-waiting
            time.sleep(0.1)

    @staticmethod
    def wait_for_input(timeout):
        """
        Overview:
        Waits for user input for a specified time before proceeding.

        Arguments:
        - timeout (int): The number of seconds to wait for user input.

        Returns:
        - bool: True if no input is received within the timeout, False otherwise.
        """
        try:
            # Initialize global variable
            global user_input_received
            user_input_received = False

            # Create a threading event to stop listening for input
            stop_event = threading.Event()

            # Start a new thread to listen for user input
            user_input_thread = threading.Thread(target=UserPrompts.user_input_listener, args=(stop_event,))
            user_input_thread.start()

            # Initialize timing variables
            start_time = time.time()
            last_second_passed = None

            # Loop until timeout
            while time.time() - start_time < timeout:
                # Check for user input
                if user_input_received:
                    print(f"\rExisting wallet data will be erased in {time_remaining} seconds. Press any key to cancel operation... ")
                    print('Operation canceled.')
                    stop_event.set()
                    return False                
                # Countdown logic
                seconds_passed = int(time.time() - start_time)
                if last_second_passed != seconds_passed:
                    last_second_passed = seconds_passed
                    time_remaining = timeout - seconds_passed
                    print(f"\rExisting wallet data will be erased in {time_remaining} seconds. Press any key to cancel operation...", end='')
                time.sleep(0.1)
            # Stop listening for input
            stop_event.set()
            return True
        
        # Handle exit on keyboard interrupt
        except KeyboardInterrupt:
            print(f"\rExisting wallet data will be erased in {time_remaining} seconds. Press any key to cancel operation...    ")
            print('Operation canceled. Process terminated by user.')
            stop_event.set()
            sys.exit(1)  

    @staticmethod
    def backup_and_overwrite_helper(data, filename, password, encrypt, backup, disable_warning, from_cli, deterministic):
        """
        Overview:
        Handles the logic for backing up and overwriting wallet data.

        Args:
        - data (dict): The wallet data.
        - filename (str): The name of the file to backup or overwrite.
        - password (str): The user's password.
        - encrypt (bool): Whether to encrypt the backup.
        - backup (str): User's preference for backing up.
        - disable_warning (bool): Whether to display warnings.
        - from_cli (bool): Whether the operation is initiated from the command line interface.

        Returns:
        - bool: True if successful, False or None otherwise.
        """
        # Initialize verification variables
        password_verified = False
        hmac_verified = False

        # Convert CLI boolean values to 'y' or 'n'
        if from_cli:
            if backup == "True":
                backup = "y"
            if backup == "False":
                backup = "n"

        # Handle the backup preference
        perform_backup = UserPrompts.get_backup_preference(backup)
        if perform_backup in ['/q']:
            return
        if perform_backup:
            # Construct the backup filename
            base_filename = os.path.basename(filename)
            backup_name, _ = os.path.splitext(base_filename)
            backup_path = os.path.join("./wallets/wallet_backups", f"{backup_name}_backup_{datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y-%m-%d_%H-%M-%S_%p')}") + ".json"
            try:
                # Create the backup
                shutil.copy(filename, backup_path)
                print(f"Backup created at {backup_path}\n")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return True

            except Exception as e:
                logging.error(f" Could not create backup: {e}\n")
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return
        else:
            # Handle the overwrite preference
            perform_overwrite = UserPrompts.get_overwrite_preference(disable_warning)
            if perform_overwrite in ['/q']:
                return
            if perform_overwrite:
                # Print messages based on the CLI boolean values
                if disable_warning:
                    if backup == "n":
                        print("Wallet not backed up.")
                    print("Overwrite warning disabled.")

                if password and encrypt:
                    print("Overwrite password provided.")

                    # Verify the password and HMAC to prevent brute force
                    password_verified, hmac_verified, _ = VerificationUtils.verify_password_and_hmac(data, password, base64.b64decode(data["wallet_data"]["hmac_salt"]), base64.b64decode(data["wallet_data"]["verification_salt"]), deterministic)
                    
                    # Based on password verification, update or reset the number of failed attempts
                    data = DataManipulation.update_or_reset_attempts(data, base64.b64decode(data["wallet_data"]["hmac_salt"]), password_verified, deterministic)
                    DataManipulation._save_data(filename,data)
                    
                    # Check if there is still wallet data verify the password and HMAC again
                    if data:
                        password_verified, hmac_verified, _ = VerificationUtils.verify_password_and_hmac(data, password, base64.b64decode(data["wallet_data"]["hmac_salt"]), base64.b64decode(data["wallet_data"]["verification_salt"]), deterministic)
                    # Handle error if the password and HMAC verification failed
                    if not (password_verified and hmac_verified):
                        logging.error("Authentication failed or wallet data is corrupted.")

                # If the wallet is encrypted and the password and hmac have not yet been varified then enter while loop
                if encrypt and not (password_verified and hmac_verified) and data:
                    while True:
                        # Prompt user for password
                        password_input = UserPrompts.get_password(password=password if password and (password_verified and hmac_verified) else None,from_cli=True)
                        # Verify the password and HMAC
                        password_verified, hmac_verified, _ = VerificationUtils.verify_password_and_hmac(data, password_input, base64.b64decode(data["wallet_data"]["hmac_salt"]), base64.b64decode(data["wallet_data"]["verification_salt"]), deterministic)
    
                        # Based on password verification, update or reset the number of failed attempts
                        data = DataManipulation.update_or_reset_attempts(data, base64.b64decode(data["wallet_data"]["hmac_salt"]), password_verified, deterministic)
                        DataManipulation._save_data(filename,data)
                        
                        # If wallet data has not erased yet verify the password and HMAC again
                        if data:
                            password_verified, hmac_verified, _ = VerificationUtils.verify_password_and_hmac(data, password_input, base64.b64decode(data["wallet_data"]["hmac_salt"]), base64.b64decode(data["wallet_data"]["verification_salt"]), deterministic)
                        
                        # Handle error if the password and HMAC verification failed
                        if data and not (password_verified and hmac_verified):
                            logging.error("Authentication failed or wallet data is corrupted.")
                       
                        # Handle error if wallet data was erased then continue
                        elif not data:
                            logging.error("Authentication failed or wallet data is corrupted.")
                            break                        
                        # If the password and HMAC verification passed then continue
                        else:
                            break

                # Check data was not erased due to failed password attempts 
                if data:
                    print()
                    # Call wait_for_input and allow up to 5 seconds for the user to cancel overwrite operation
                    if not UserPrompts.wait_for_input(timeout=5):
                        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                        return
                    # If no input is recieved within 5 seconds then continue
                    else:
                        print()
                        try:
                            # Overwrite wallet with empty data
                            with open(filename, 'w') as file:
                                file.write("")
                                print("\nWallet data permanetly erased.")
                        except Exception as e:
                            logging.error(f" Could not write to file: {e}")
                            DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                            return
                        DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                        return True
                else:
                    print()
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                    return True
            else:
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                return
    
    @staticmethod
    def handle_2fa_validation(data, totp_code=None):
        """
        Overview:
        Handles Two-Factor Authentication (2FA) validation.

        Arguments:
        - data (dict): Data used for 2FA.
        - totp_code (str, optional): Time-based One-Time Password (TOTP) code.

        Returns:
        - dict: A dictionary containing validation results and TOTP secret, or False if validation fails.
        """

        # Loop until the user provides the correct Two-Factor Authentication code or decides to exit
        while True:
            # Check if a TOTP code was already provided
            if not totp_code:
                # Get TOTP code from user input
                totp_code = input("Please enter the Two-Factor Authentication code from your autthenticator app (or type '/q' to exit the script): ")
                # Exit if the user chooses to quit
                if totp_code.lower() == '/q':
                    logging.info("User exited before providing a valid Two-Factor Authentication code.\n")
                    DataManipulation.secure_delete([var for var in locals().values() if var is not None])
                    return False
                # Check if the totp_code is provided
                if not totp_code:
                    logging.error("No Two-Factor Authentication code provided. Please enter a valid Two-Factor Authentication code.\n")
                    continue
                # Validate that the TOTP code is a 6-digit integer
                try:
                    int(totp_code)
                    if len(totp_code) != 6:
                        logging.error("Two-Factor Authentication code should contain 6 digits. Please try again.\n")
                        totp_code = None
                        continue
                except ValueError:
                    logging.error("Two-Factor Authentication code should be an integer. Please try again.\n")
                    totp_code = None
                    continue
            # Validate the TOTP code using utility method
            if VerificationUtils.validate_totp_code(data, totp_code):
                result = {"valid": True, "totp_secret": data}
                DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not result])
                return result
            else:
                logging.error("Authentication failed. Please try again.\n")
                # Reset TOTP code and continue the loop
                totp_code = None
                DataManipulation.secure_delete([var for var in locals().values() if var is not None])