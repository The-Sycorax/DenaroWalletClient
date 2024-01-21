import logging
import qrcode
from PIL import Image, ImageDraw, ImageFont
import data_manipulation_util

class PaperWalletGenerator:
    @staticmethod
    def generate_qr_code(data):
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=0,
            )
            qr.add_data(data)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not qr_image])
            return qr_image
        except Exception as e:
            logging.error(f"Error in generating QR code: {e}")
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])


    @staticmethod
    def overlay_qr_code(private_key_qr, public_address_qr, private_key, address, file_type):
        try:
            # Load background image
            background_image_path = './denaro/wallet/paper_wallet_front.png'
            background_image = Image.open(background_image_path)

            # Resize QR codes
            private_key_qr = private_key_qr.resize((474, 474), Image.LANCZOS)
            public_address_qr = public_address_qr.resize((474, 474), Image.LANCZOS)

            # Convert to RGBA if necessary
            if background_image.mode != 'RGBA':
                background_image = background_image.convert('RGBA')

            # Font settings (using default font)
            font = ImageFont.load_default()
            text_color = (0, 0, 0)  # Black color

            # Function to draw and scale up rotated text
            def draw_scaled_rotated_text(image, text, position, angle, font, fill, scale_factor):
                # Create a new image for the text
                text_image = Image.new('RGBA', (1000, 20), (0, 0, 0, 0))  # Create large enough image for the text
                text_draw = ImageDraw.Draw(text_image)
                text_draw.text((0, 0), text, font=font, fill=fill)

                # Scale up the text image
                scaled_text_image = text_image.resize((int(text_image.width * scale_factor), int(text_image.height * scale_factor)), Image.NEAREST)

                # Rotate the scaled text image
                rotated_text_image = scaled_text_image.rotate(angle, expand=1)

                # Calculate the new position
                text_image_x, text_image_y = position
                position = (text_image_x, text_image_y - rotated_text_image.size[1] // 2)

                # Paste the text image onto the original image
                image.paste(rotated_text_image, position, rotated_text_image)

            # Position and rotation settings
            pk_text_pos = (133 + 474 + 10, 472 + 460)  # Adjust as needed
            addr_text_pos = (3083 + 474 + 10, 472 + 510)  # Adjust as needed
            angle = -90
            scale_factor = 1.35  # Adjust scale factor as needed for size

            # Draw scaled and rotated text for private key and address
            draw_scaled_rotated_text(background_image, private_key, pk_text_pos, angle, font, text_color, scale_factor)
            draw_scaled_rotated_text(background_image, address, addr_text_pos, angle, font, text_color, scale_factor)

            # Paste QR codes
            background_image.paste(private_key_qr, (133, 262), private_key_qr if private_key_qr.mode == 'RGBA' else None)
            background_image.paste(public_address_qr, (3083, 263), public_address_qr if public_address_qr.mode == 'RGBA' else None)
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None and var is not background_image])
            return background_image
        except Exception as e:
            logging.error(f"Error in overlaying QR code: {e}")
            data_manipulation_util.DataManipulation.secure_delete([var for var in locals().values() if var is not None])
    