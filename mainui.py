import tkinter as tk
from tkinter import ttk
import subprocess
import os
import json
import re
import tkinter.font as tkFont


def load_wallets():
    wallet_dir = "./wallets"  # Update this path to your wallet directory
    wallet_files = [f for f in os.listdir(wallet_dir) if f.endswith('.json')]
    wallet_dropdown['values'] = wallet_files
    print("Wallets loaded.")

def display_addresses():
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_dir = "./wallets"  # Update this path to your wallet directory
        wallet_path = os.path.join(wallet_dir, selected_wallet_file)

        # Clear the current address frames
        for widget in address_frame.winfo_children():
            widget.destroy()

        # Load and display addresses from the selected wallet file
        with open(wallet_path, 'r') as file:
            wallet_data = json.load(file)
            entries = wallet_data["wallet_data"]["entry_data"]["entries"]

        for entry in entries:
            if 'address' in entry:
                address = entry["address"]
        
                # Create and pack the address label centered
                address_label = ttk.Label(address_frame, text=address, style='TLabel')
                address_label.pack(side="left", anchor="center")
        
                # Create and pack the balance label, initially with a placeholder text
                balance_label = ttk.Label(address_frame, text="Balance: Loading...", style='TLabel')
                balance_label.pack(side="left", anchor="center")
                address_labels[address] = balance_label

def refresh_balance():
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_name = selected_wallet_file.replace('.json', '')
        # Fetch balance for the entire wallet
        result = subprocess.run(["python3", "wallet_client.py", "balance", "-wallet", wallet_name], capture_output=True, text=True)
        output = result.stdout.strip()

        # Parse and update individual balances
        for address, balance_label in address_labels.items():
            balance_search = re.search(f"Address #\\d+: {address}\s+Balance: (.+?)\s", output)
            if balance_search:
                balance = balance_search.group(1)
                balance_label.config(text=f"Balance: {balance}")

        # Update total balance
        total_balance_search = re.search("Total Balance: (.+)", output)
        if total_balance_search:
            total_balance.set(f"Total Balance: {total_balance_search.group(1)}")

def send_transaction():
    amount = amount_entry.get()
    receiver_address = receiver_address_entry.get()
    selected_wallet_file = wallet_dropdown.get()

    if selected_wallet_file and amount and receiver_address:
        wallet_name = selected_wallet_file.replace('.json', '')

        # Here, you need to specify which address you are sending from. 
        # This example uses the first address in the wallet. Adjust as needed.
        wallet_dir = "./wallets"
        wallet_path = os.path.join(wallet_dir, selected_wallet_file)
        with open(wallet_path, 'r') as file:
            wallet_data = json.load(file)
            sending_address = wallet_data["wallet_data"]["entry_data"]["entries"][0]["address"]
        
        command = ["python3", "wallet_client.py", "send", "-amount", amount, "from", "-wallet", wallet_name, "-address", sending_address, "to", receiver_address]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            transaction_output_label.config(text=result.stdout)
        except subprocess.CalledProcessError as e:
            transaction_output_label.config(text=f"Error: {e.output}")

# Function to show send transaction fields


def generate_wallet():
    wallet_name = wallet_name_entry.get()
    password = password_entry.get()

    command = ["python3", "wallet_client.py", "generatewallet", "-wallet", wallet_name]
    if password:
        command.extend(["-password", password])

    if wallet_name:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print("Wallet generated:", result.stdout)
        except subprocess.CalledProcessError as e:
            print("Error in generating wallet:", e.output)


# Flags to control the visibility of frames
is_generate_wallet_frame_open = False
is_send_transaction_frame_open = False

def show_generate_wallet_fields():
    global is_generate_wallet_frame_open
    if not is_generate_wallet_frame_open:
        generate_wallet_frame.pack()
        wallet_name_label.pack(side="top")
        wallet_name_entry.pack(side="top")
        password_label.pack(side="top")
        password_entry.pack(side="top")
        confirm_generate_button.pack(side="top")
        is_generate_wallet_frame_open = True
    else:
        generate_wallet_frame.pack_forget()
        is_generate_wallet_frame_open = False

def show_send_transaction_fields():
    global is_send_transaction_frame_open
    if not is_send_transaction_frame_open:
        send_transaction_frame.pack()
        amount_label.pack(side="top")
        amount_entry.pack(side="top")
        receiver_address_label.pack(side="top")
        receiver_address_entry.pack(side="top")
        confirm_send_button.pack(side="top")
        transaction_output_label.pack(side="top")
        is_send_transaction_frame_open = True
    else:
        send_transaction_frame.pack_forget()
        is_send_transaction_frame_open = False




# Initialize the main window
window_width = 1003  # replace with the width of the window in the screenshot
window_height = 499  # replace with the height of the window in the screenshot

# Initialize the main window
root = tk.Tk()
root.title("Denaro Core v1.0.0")



# Set the window size
root.geometry(f"{window_width}x{window_height}")

# Prevent the window from being resized
root.resizable(False, False)

DARK_BG = "#2B2B2B"
LIGHT_TEXT = "#0077CC"
ACCENT_COLOR = "#4BA3C7"
BUTTON_BG = "#333333"
ENTRY_BG = "#484848"
PAD_X = 10
PAD_Y = 5


logo_image = tk.PhotoImage(file="des.png")  # Replace with your logo's file path
logo_image = logo_image.subsample(7, 7)  # Adjust the subsampling factor to resize

# Create a label for the logo and place it in the top left corner
logo_label = tk.Label(root, image=logo_image, bg=DARK_BG)
logo_label.place(x=0, y=0)


# Configure the default style
style = ttk.Style(root)
style.theme_use('clam')

style.configure('TButton', background=BUTTON_BG, foreground=LIGHT_TEXT)
style.map('TButton', background=[('active', ACCENT_COLOR)], foreground=[('active', LIGHT_TEXT)])

style.configure('TLabel', background=DARK_BG, foreground=LIGHT_TEXT)
style.configure('TEntry', background=ENTRY_BG, foreground=LIGHT_TEXT)
style.configure('TCombobox', fieldbackground=ENTRY_BG, foreground=LIGHT_TEXT)



# Configure root window's background
root.configure(bg=DARK_BG)

# Dropdown for wallet file selection
wallet_dropdown = ttk.Combobox(root, state="readonly")
wallet_dropdown.pack(padx=PAD_X, pady=PAD_Y)

# Button to load wallets
load_button = ttk.Button(root, text="Load Wallets", command=load_wallets)
load_button.pack(padx=PAD_X, pady=PAD_Y)

# Frame to display addresses and balances
address_frame = tk.Frame(root, bg=DARK_BG)
address_frame.pack(padx=PAD_X, pady=PAD_Y)

# Dictionary to store balance labels
address_labels = {}

# Button to display addresses
display_button = ttk.Button(root, text="Display Addresses", command=display_addresses)
display_button.pack(padx=PAD_X, pady=PAD_Y)

# Button to refresh balance
refresh_button = ttk.Button(root, text="Refresh Balance", command=refresh_balance)
refresh_button.pack(padx=PAD_X, pady=PAD_Y)

# Label for total balance
total_balance = tk.StringVar()
total_balance_label = ttk.Label(root, textvariable=total_balance, justify=tk.RIGHT)
total_balance_label.pack(side="bottom", anchor="e", padx=PAD_X, pady=PAD_Y)

# Send Transaction Frame (initially not packed)
# Send Transaction Frame widgets
send_transaction_frame = tk.Frame(root, bg=DARK_BG)
amount_label = ttk.Label(send_transaction_frame, text="Amount:")
amount_entry = ttk.Entry(send_transaction_frame)
receiver_address_label = ttk.Label(send_transaction_frame, text="Receiver Address:")
receiver_address_entry = ttk.Entry(send_transaction_frame)
confirm_send_button = ttk.Button(send_transaction_frame, text="Confirm", command=send_transaction)
transaction_output_label = ttk.Label(send_transaction_frame)

# Generate Wallet Frame widgets
generate_wallet_frame = tk.Frame(root, bg=DARK_BG)
wallet_name_label = ttk.Label(generate_wallet_frame, text="Wallet Name:")
wallet_name_entry = ttk.Entry(generate_wallet_frame)
password_label = ttk.Label(generate_wallet_frame, text="Password (optional):")
password_entry = ttk.Entry(generate_wallet_frame, show="*")
confirm_generate_button = ttk.Button(generate_wallet_frame, text="Confirm", command=generate_wallet)



# Send button
send_button = ttk.Button(root, text="Send", command=show_send_transaction_fields)
send_button.pack(padx=PAD_X, pady=PAD_Y)
generate_wallet_button = ttk.Button(root, text="Generate Wallet", command=show_generate_wallet_fields)
generate_wallet_button.pack(padx=PAD_X, pady=PAD_Y)
# Start the GUI loop
root.mainloop()
