import tkinter as tk
from tkinter import ttk
import subprocess
import os
import json
import re
import tkinter.font as tkFont
from tkinter import simpledialog, messagebox
import threading
from tkinter import PhotoImage



# Modified load_wallets function to start thread


def update_wallet_dropdown(values):
    wallet_dropdown['values'] = values

def load_wallets_thread():
    wallet_dir = "./wallets"  # Update this path to your wallet directory
    wallet_files = [f for f in os.listdir(wallet_dir) if f.endswith('.json')]

    # Use a helper function to update the dropdown in the main thread
    root.after(0, lambda: update_wallet_dropdown(wallet_files))
    root.after(0, lambda: print("Wallets loaded."))

    if wallet_files:
        root.after(0, lambda: wallet_dropdown.set(wallet_files[0]))
        root.after(0, display_addresses)

    root.after(0, loading_popup.destroy)  # Close the popup



def load_wallets():
    wallet_dir = "./wallets"  # Update this path to your wallet directory
    wallet_files = [f for f in os.listdir(wallet_dir) if f.endswith('.json')]
    wallet_dropdown['values'] = wallet_files
    print("Wallets loaded.")
    if wallet_files:  # If there are wallet files, automatically display the first one
        wallet_dropdown.set(wallet_files[0])  # Set the dropdown to show the first wallet file
        display_addresses() 

def display_addresses(*args):
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_dir = "./wallets"  # Update this path to your wallet directory
        wallet_path = os.path.join(wallet_dir, selected_wallet_file)

        # Clear the current address list
        for i in address_list.get_children():
            address_list.delete(i)

        # Load addresses from the selected wallet file
        with open(wallet_path, 'r') as file:
            wallet_data = json.load(file)
            normal_entries = wallet_data.get("wallet_data", {}).get("entry_data", {}).get("entries", [])
            imported_entries = wallet_data.get("wallet_data", {}).get("entry_data", {}).get("imported_entries", [])

        for entry in normal_entries + imported_entries:
            if 'address' in entry:
                address = entry["address"]
                address_list.insert("", "end", values=(address, "Balance: Loading..."))
        
        refresh_balance()  # Refresh balance for new addresses




def refresh_balance():
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_name = selected_wallet_file.replace('.json', '')
        # Fetch balance for the entire wallet
        result = subprocess.run(["python3", "wallet_client.py", "balance", "-wallet", wallet_name], capture_output=True, text=True)
        output = result.stdout.strip()

        # Update balance in the address list
        for child in address_list.get_children():
            address = address_list.item(child)["values"][0]  # Address is in the first column
            balance_search = re.search(f"Address #\\d+: {address}\s+Balance: (.+?)\s", output)
            if balance_search:
                balance = balance_search.group(1)
                # Update the balance in the second column
                address_list.item(child, values=(address, f"Balance: {balance}"))

        # Update total balance
        total_balance_search = re.search("Total Balance: (.+)", output)
        if total_balance_search:
            total_balance.set(f"Total Balance: {total_balance_search.group(1)}")





def send_transaction():
    selected_wallet_file = wallet_dropdown.get()
    wallet_name = selected_wallet_file.replace('.json', '')

    if not selected_wallet_file:
        messagebox.showerror("Error", "No wallet selected.")
        return

    # Get the selected address from the dropdown
    sending_address = sending_address_dropdown.get()

    # Get the amount and receiver address from the entries
    amount = amount_entry.get()
    receiver_address = recipient_address_entry.get()

    if not amount or not receiver_address:
        messagebox.showwarning("Warning", "Please fill all fields.")
        return

    command = [
    "python3", "wallet_client.py", "send", "-amount", amount, "from",
    "-wallet", wallet_name, "-address", sending_address, 
    "to", receiver_address
]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        messagebox.showinfo("Success", "Transaction sent:\n" + result.stdout)
    except subprocess.CalledProcessError as e:
        error_message = f"Transaction failed:\nStdout: {e.stdout}\nStderr: {e.stderr}"
        messagebox.showerror("Error", error_message)
        print(error_message)



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
is_generate_addresses_frame_open = False




def show_generate_wallet_fields():
    global is_generate_wallet_frame_open
    if not is_generate_wallet_frame_open:
        # Pack the frame and its components
        wallet_name_label.pack(side="top", fill='x')
        wallet_name_entry.pack(side="top", fill='x')
        password_label.pack(side="top", fill='x')
        password_entry.pack(side="top", fill='x')
        confirm_generate_button.pack(side="top", fill='x')

        # Pack the frame right after the generate wallet button
        generate_wallet_frame.pack(padx=PAD_X, pady=PAD_Y, after=generate_wallet_button)
        is_generate_wallet_frame_open = True
    else:
        # Unpack the frame and its components
        wallet_name_label.pack_forget()
        wallet_name_entry.pack_forget()
        password_label.pack_forget()
        password_entry.pack_forget()
        confirm_generate_button.pack_forget()

        generate_wallet_frame.pack_forget()
        is_generate_wallet_frame_open = False






def show_send_transaction_fields():
    global is_send_transaction_frame_open
    if not is_send_transaction_frame_open:
        send_transaction_frame.pack(expand=True, fill="both")
        amount_label.pack(side="top")
        amount_entry.pack(side="top")
        receiver_address_label.pack(side="top")
        receiver_address_entry.pack(side="top")
        confirm_send_button.pack(side="top")
        transaction_output_label.pack(side="top")
        is_send_transaction_frame_open = False


        is_send_transaction_frame_open = True
    else:
        send_transaction_frame.pack_forget()
        is_send_transaction_frame_open = False


def populate_address_dropdown():
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_dir = "./wallets"  # Update this path to your wallet directory
        wallet_path = os.path.join(wallet_dir, selected_wallet_file)

        addresses = []
        with open(wallet_path, 'r') as file:
            wallet_data = json.load(file)
            entries = wallet_data.get("wallet_data", {}).get("entry_data", {}).get("entries", [])
            addresses = [entry["address"] for entry in entries if 'address' in entry]

        return addresses


def generate_addresses():
    selected_wallet_file = wallet_dropdown.get()
    wallet_name = selected_wallet_file.replace('.json', '')
    password = password_entry.get()
    tfacode = tfacode_entry.get()

    # Retrieve the amount and validate it
    amount_str = generate_amount_entry.get().strip()
    print("Amount Entered:", amount_str)

    try:
        # Ensure that the amount_str is a valid integer
        amount = int(amount_str)  # Convert it to an integer
    except ValueError:
        # Handle the case where the amount_str is not a valid integer
        generation_output_label.config(text="Error: Invalid amount. Please enter a valid integer.")
        return


    if selected_wallet_file:
        # Convert the amount_str to an integer and back to a string
        amount_str = str(int(amount_str))

        command = ["python3", "wallet_client.py", "generateaddress", "-wallet", wallet_name, "-amount", amount_str]
        if password:
            command.extend(["-password", password])
        if tfacode:
            command.extend(["-2fa-code", tfacode])

        try:
            # Print the command for debugging purposes
            print("Command:", " ".join(command))
            
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            generation_output_label.config(text="Addresses generated successfully:\n" + result.stdout)
        except subprocess.CalledProcessError as e:
            error_message = f"Command failed:\nStdout: {e.stdout}\nStderr: {e.stderr}"
            generation_output_label.config(text=error_message)
            print(error_message)



def open_import_private_key_dialog():
    # Prompt for wallet name if it's not already selected
    wallet_name = wallet_dropdown.get()
    if not wallet_name:
        wallet_name = simpledialog.askstring("Input", "Enter wallet name:", parent=root)
        if not wallet_name:
            messagebox.showwarning("Warning", "No wallet name provided.")
            return

    # Prompt for the private key
    private_key = simpledialog.askstring("Input", "Enter private key:", parent=root)
    if private_key:
        import_private_key(wallet_name, private_key)
    else:
        messagebox.showwarning("Warning", "No private key provided.")

def import_private_key(wallet_name, private_key):
    try:
        command = ["python3", "wallet_client.py", "import", "-wallet", wallet_name, "-private-key", private_key]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        messagebox.showinfo("Success", "Private key imported:\n" + result.stdout)
    except subprocess.CalledProcessError as e:
        error_message = f"Import failed:\nStdout: {e.stdout}\nStderr: {e.stderr}"
        messagebox.showerror("Error", error_message)
        print(error_message)











# Initialize the main window
root = tk.Tk()
root.title("Denaro Core v1.0.0")
window_width = 1003
window_height = 499
root.geometry(f"{window_width}x{window_height}")
root.resizable(False, False)

# Configure styles
DARK_BG = "#2B2B2B"
LIGHT_TEXT = "#0077CC"
ACCENT_COLOR = "#4BA3C7"
BUTTON_BG = "#333333"  # Background color for buttons and now for the window
ENTRY_BG = "#484848"
PAD_X = 10
PAD_Y = 5

style = ttk.Style(root)
style.theme_use('clam')
style.configure('Treeview', background=BUTTON_BG, fieldbackground=BUTTON_BG, foreground=LIGHT_TEXT)
style.configure('TFrame', background=BUTTON_BG)
style.configure('TButton', background=BUTTON_BG, foreground=LIGHT_TEXT)
style.map('TButton', background=[('active', ACCENT_COLOR)], foreground=[('active', LIGHT_TEXT)])
style.configure('TLabel', background=BUTTON_BG, foreground=LIGHT_TEXT)
style.configure('TEntry', background=ENTRY_BG, foreground=LIGHT_TEXT)
style.configure('TCombobox', fieldbackground=ENTRY_BG, foreground=LIGHT_TEXT)
style.configure('Treeview', background=BUTTON_BG, fieldbackground=BUTTON_BG)
style.map('Treeview', background=[('selected', ACCENT_COLOR)])
root.configure(bg=BUTTON_BG)



# Create the tab control
tab_control = ttk.Notebook(root)
tab1 = ttk.Frame(tab_control, style='TFrame')
tab2 = ttk.Frame(tab_control, style='TFrame')
tab3 = ttk.Frame(tab_control, style='TFrame')
tab_control.add(tab1, text='Wallet Operations')
tab_control.add(tab2, text='Generate Options')
tab_control.add(tab3, text='Wallet Settings')
tab_control.pack(expand=1, fill="both")


# Dropdown for wallet file selection
wallet_dropdown = ttk.Combobox(root, state="readonly")
wallet_dropdown.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)
wallet_dropdown.bind('<<ComboboxSelected>>', display_addresses)

# Button to load wallets
load_button = ttk.Button(root, text="Load Wallets", command=load_wallets)
load_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)
#send_button = ttk.Button(root, text="Send", command=send_transaction)
#send_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)

# Frame to display addresses and balances
address_frame = tk.Frame(root, bg=DARK_BG)
address_frame.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)

# Dictionary to store balance labels
address_labels = {}

# Button to display addresses
columns = ('Address', 'Balance')
address_list = ttk.Treeview(tab1, columns=columns, show='headings')
address_list.heading('Address', text='Address')
address_list.heading('Balance', text='Balance')
address_list.pack(side="left", fill="both", expand=True)

# Add a scrollbar for the address list
scrollbar = ttk.Scrollbar(tab1, orient=tk.VERTICAL, command=address_list.yview)
scrollbar.pack(side="right", fill="y")
address_list.configure(yscrollcommand=scrollbar.set)

# Button to refresh balance
refresh_button = ttk.Button(root, text="Refresh Balance", command=refresh_balance)
#refresh_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)

# Label for total balance
total_balance = tk.StringVar()
total_balance_label = ttk.Label(root, textvariable=total_balance, justify=tk.RIGHT)
total_balance_label.pack(side="bottom", anchor="e", padx=PAD_X, pady=PAD_Y, in_=tab1)

# Send Transaction Frame (initially not packed)
# Send Transaction Frame widgets


# Generate Wallet Frame widgets
generate_wallet_frame = tk.Frame(root, bg=DARK_BG)
wallet_name_label = ttk.Label(generate_wallet_frame, text="Wallet Name:")
wallet_name_entry = ttk.Entry(generate_wallet_frame)
password_label = ttk.Label(generate_wallet_frame, text="Password (optional):")
password_entry = ttk.Entry(generate_wallet_frame, show="*")
confirm_generate_button = ttk.Button(generate_wallet_frame, text="Confirm", command=generate_wallet)

# Generate Addresses Frame widgets
generate_addresses_frame = tk.Frame(root, bg=DARK_BG)
generate_amount_label = ttk.Label(generate_addresses_frame, text="Amount for Addresses:")
generate_amount_entry = ttk.Entry(generate_addresses_frame)
password_label = ttk.Label(generate_addresses_frame, text="Password (optional):")
password_entry = ttk.Entry(generate_addresses_frame, show="*")
tfacode_label = ttk.Label(generate_addresses_frame, text="2FA Code (optional):")
tfacode_entry = ttk.Entry(generate_addresses_frame)
confirm_generate_addresses_button = ttk.Button(generate_addresses_frame, text="Confirm", command=generate_addresses)
generation_output_label = ttk.Label(generate_addresses_frame)

# Positioning the Generate Addresses Frame widgets
generate_amount_label.pack(side="top")
generate_amount_entry.pack(side="top")
password_label.pack(side="top")
password_entry.pack(side="top")
tfacode_label.pack(side="top")
tfacode_entry.pack(side="top")
confirm_generate_addresses_button.pack(side="top")
generation_output_label.pack(side="top")


send_transaction_frame = tk.Frame(tab1, bg=DARK_BG)  # Place it inside tab1

sending_address_label = ttk.Label(send_transaction_frame, text="From Address:")
sending_address_dropdown = ttk.Combobox(send_transaction_frame, state="readonly")
recipient_address_label = ttk.Label(send_transaction_frame, text="To Address:")
recipient_address_entry = ttk.Entry(send_transaction_frame)
amount_label = ttk.Label(send_transaction_frame, text="Amount:")
amount_entry = ttk.Entry(send_transaction_frame)
confirm_send_button = ttk.Button(send_transaction_frame, text="Confirm", command=send_transaction)


def toggle_generate_addresses_frame():
    global is_generate_addresses_frame_open
    if not is_generate_addresses_frame_open:
        # Pack the frame and its components
        generate_addresses_frame.pack(padx=PAD_X, pady=PAD_Y, in_=tab2)

        # Pack each component inside the frame
        generate_amount_label.pack(side="top")
        generate_amount_entry.pack(side="top")
        password_label.pack(side="top")
        password_entry.pack(side="top")
        tfacode_label.pack(side="top")
        tfacode_entry.pack(side="top")
        confirm_generate_addresses_button.pack(side="top")
        generation_output_label.pack(side="top")

        is_generate_addresses_frame_open = True
    else:
        # Unpack the frame and its components
        generate_addresses_frame.pack_forget()
        generate_amount_label.pack(side="top")
        generate_amount_entry.pack(side="top")
        password_label.pack_forget()
        password_entry.pack_forget()
        tfacode_label.pack_forget()
        tfacode_entry.pack_forget()
        confirm_generate_addresses_button.pack_forget()
        generation_output_label.pack_forget()

        is_generate_addresses_frame_open = False


    
def open_send_transaction():
    global is_send_transaction_frame_open
    if not is_send_transaction_frame_open:
            # Pack the frame and its components
        sending_address_label.pack(side="top", fill='x')
        sending_address_dropdown.pack(side="top", fill='x')
        recipient_address_label.pack(side="top", fill='x')
        recipient_address_entry.pack(side="top", fill='x')
        amount_label.pack(side="top", fill='x')
        amount_entry.pack(side="top", fill='x')
        confirm_send_button.pack(side="top", fill='x')
        addresses = populate_address_dropdown()
        sending_address_dropdown['values'] = addresses
        if addresses:
            sending_address_dropdown.set(addresses[0])
    
        # Pack the frame and its components
        send_transaction_frame.pack(padx=PAD_X, pady=PAD_Y, after=send_button)
        is_send_transaction_frame_open = True
    else:
        send_transaction_frame.pack_forget()
        is_send_transaction_frame_open = False


# Send button
send_button = ttk.Button(root, text="Send", command=open_send_transaction)
send_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)
generate_wallet_button = ttk.Button(root, text="Generate Wallet", command=show_generate_wallet_fields)
generate_wallet_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab2)
generate_addresses_button = ttk.Button(root, text="Generate Addresses", command=toggle_generate_addresses_frame)
generate_addresses_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab2)
import_private_key_button = ttk.Button(tab3, text="Import Private Key", command=open_import_private_key_dialog)
import_private_key_button.pack(padx=PAD_X, pady=PAD_Y)

# Start the GUI loop
root.mainloop()
