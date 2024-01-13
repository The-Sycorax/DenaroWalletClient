import tkinter as tk
from tkinter import ttk
import subprocess
import os
import json
import re
import tkinter.font as tkFont
from tkinter import simpledialog, messagebox
import threading
from tkinter import PhotoImage, Label
import ast
import re
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

# Modified load_wallets function to start thread
first_click = True
wallets_loaded = False
# Global variable to store the password of the currently opened encrypted wallet
wallet_password = None

def on_load_button_click():
    global first_click
    if first_click:
        load_wallets()
        load_button.config(text="Refresh")
        first_click = False
    else:
        refresh_wallets()

def refresh_wallets():
    threading.Thread(target=load_wallets_thread, daemon=True).start()


def update_wallet_dropdown(values):
    wallet_dropdown['values'] = values

def load_wallets():
    threading.Thread(target=load_wallets_thread, daemon=True).start()

def load_wallets_thread():
    global wallets_loaded

    wallet_dir = "./wallets"
    wallet_files = [f for f in os.listdir(wallet_dir) if f.endswith('.json')]

    # Use a helper function to update the dropdown in the main thread
    root.after(0, lambda: update_wallet_dropdown(wallet_files))
    root.after(0, lambda: print("Wallets loaded."))

    if wallet_files:
        root.after(0, lambda: wallet_dropdown.set(wallet_files[0]))
        root.after(0, display_addresses)

    #root.after(0, loading_popup.destroy)  # Close the popup

    # Update button text to "Refresh" only once
    if not wallets_loaded:
        root.after(0, lambda: load_button.config(text="Refresh"))
        wallets_loaded = True


def is_wallet_encrypted(wallet_path):
    try:
        with open(wallet_path, 'r') as file:
            wallet_data = json.load(file)
            return 'hmac' in wallet_data.get("wallet_data", {}) and 'verifier' in wallet_data.get("wallet_data", {})
    except json.JSONDecodeError:
        return False 
        
def load_wallet_data(wallet_path):
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


def decrypt_wallet(wallet_name, password, two_factor_code=None):
    global wallet_password
    wallet_password = password
    command = ["python3", "wallet_client.py", "decryptwallet", "-wallet", wallet_name, "-password", password]

    # Add 2FA code to command if provided
    if two_factor_code:
        command.extend(["-2fa-code", two_factor_code])

    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=5)
        output = result.stdout.strip()


        # Check if the output contains wallet data
        if "Wallet Data:" in output:
            try:
                # Extract the JSON part from the output
                json_data_start = output.index("{")
                json_data_end = output.rindex("}") + 1
                json_data_str = output[json_data_start:json_data_end]
                json_data = json.loads(json_data_str)
                update_address_list_with_decrypted_data(json_data)
                messagebox.showinfo("Success", "Wallet decrypted successfully.")
            except (ValueError, json.JSONDecodeError) as e:
                messagebox.showerror("Error", f"Failed to parse wallet data: {e}")
        else:
            messagebox.showerror("Error", "Wrong password.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Decryption failed:\nStdout: {e.stdout}\nStderr: {e.stderr}")
    except subprocess.TimeoutExpired:
        messagebox.showerror("Error", "Operation timed out. 2FA code may be needed.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Decryption failed:\nStdout: {e.stdout}\nStderr: {e.stderr}")
        
def update_address_list_with_decrypted_data(wallet_data):
    # Clear the current address list
    for i in address_list.get_children():
        address_list.delete(i)

    # Initialize a list to store addresses for the sending address dropdown
    sending_addresses = []

    # Extract and display addresses from the decrypted wallet data
    entries = wallet_data.get("entry_data", {}).get("entries", [])
    for entry in entries:
        if 'address' in entry:
            address = entry["address"]
            address_list.insert("", "end", values=(address, "Balance: Loading..."))
            sending_addresses.append(address)

    refresh_balance()  # Refresh balance for new addresses

    # Update sending address dropdown
    sending_address_dropdown['values'] = sending_addresses
    if sending_addresses:
        sending_address_dropdown.set(sending_addresses[0])


def load_wallets():
    wallet_dir = "./wallets"  # Update this path to your wallet directory
    wallet_files = [f for f in os.listdir(wallet_dir) if f.endswith('.json')]
    wallet_dropdown['values'] = wallet_files
    print("Wallets loaded.")
    if wallet_files:  # If there are wallet files, automatically display the first one
        wallet_dropdown.set(wallet_files[0])  # Set the dropdown to show the first wallet file
        display_addresses() 

def display_addresses(*args):
    global wallet_password
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_dir = "./wallets"
        wallet_path = os.path.join(wallet_dir, selected_wallet_file)

        # Check if the wallet is encrypted
        if is_wallet_encrypted(wallet_path):
            # Create a new dialog for password and 2FA code
            dialog = tk.Toplevel(root)
            dialog.title("Decrypt Wallet")

            tk.Label(dialog, text="Enter wallet password:").pack()
            password_entry = ttk.Entry(dialog, show="*")
            password_entry.pack()

            tk.Label(dialog, text="Enter 2FA code (if applicable):").pack()
            two_fa_entry = ttk.Entry(dialog)
            two_fa_entry.pack()

            def on_confirm():
                password = password_entry.get()
                two_fa_code = two_fa_entry.get() if two_fa_entry.get() else None
                dialog.destroy()
                if password:
                    decrypt_wallet(selected_wallet_file, password, two_fa_code)
                else:
                    messagebox.showwarning("Warning", "No password provided. Cannot access encrypted wallet.")

            confirm_button = ttk.Button(dialog, text="Confirm", command=on_confirm)
            confirm_button.pack()

            dialog.mainloop()

        else:
            wallet_password = None  # Clear the password when switching to a non-encrypted wallet
            load_wallet_data(wallet_path)





def refresh_balance():
    threading.Thread(target=refresh_balance_thread, daemon=True).start()

def refresh_balance_thread():
    global wallet_password
    selected_wallet_file = wallet_dropdown.get()
    if selected_wallet_file:
        wallet_name = selected_wallet_file.replace('.json', '')

        addresses = []
        for child in address_list.get_children():
            address = address_list.item(child)["values"][0]
            addresses.append(address)

        # Function to fetch balance for an address
        def fetch_balance(address):
            command = [
                "python3", "wallet_client.py", "balance", "-wallet", wallet_name, 
                "-address", address
            ]
            if wallet_password:
                command.extend(["-password", wallet_password])

            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                output = result.stdout.strip()
            except subprocess.CalledProcessError as e:
                print(f"Error fetching balance for {address}: {e.stderr.strip()}")
                return address, "Error"

            balance_search = re.search(r"Balance: (.+?)\s", output)
            if balance_search:
                balance = balance_search.group(1)
                return address, balance
            else:
                return address, "Balance not found"

        # Using ThreadPoolExecutor for parallel processing
        total_balance_value = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_address = {executor.submit(fetch_balance, address): address for address in addresses}
            for future in as_completed(future_to_address):
                address = future_to_address[future]
                address, balance = future.result()  # Unpack the tuple
                if balance not in ["Error", "Balance not found"]:
                    root.after(0, lambda addr=address, bal=balance: update_address_balance(addr, bal))
                    try:
                        balance_amount = float(balance.replace(' DNR', ''))
                        total_balance_value += balance_amount
                    except ValueError:
                        pass

        # Update total balance
        root.after(0, lambda: total_balance.set(f"Total Balance: {total_balance_value} DNR"))

def update_address_balance(address, balance):
    for child in address_list.get_children():
        if address_list.item(child)["values"][0] == address:
            address_list.item(child, values=(address, f"Balance: {balance}"))





def send_transaction():
    global wallet_password  # Use the global password variable

    selected_wallet_file = wallet_dropdown.get()
    wallet_name = selected_wallet_file.replace('.json', '')

    if not selected_wallet_file:
        messagebox.showerror("Error", "No wallet selected.")
        return

    sending_address = sending_address_dropdown.get()
    amount = amount_entry.get()
    receiver_address = recipient_address_entry.get()

    if not amount or not receiver_address:
        messagebox.showwarning("Warning", "Please fill all fields.")
        return

    # Constructing the command according to the specified format
    command = [
        "python3", "wallet_client.py", "send", "-amount", amount, "from", 
        "-wallet=" + wallet_name
    ]

    # Check if wallet is encrypted and ask for 2FA if needed
    if is_wallet_encrypted(os.path.join("./wallets", selected_wallet_file)):
        if wallet_password:
            command.append("-password=" + wallet_password)

        # Ask for 2FA code
        tfacode = simpledialog.askstring("2FA Code", "Enter 2FA code (if applicable):", show="*")
        if tfacode:
            command.append("-2fa-code=" + tfacode)

    # Append the address and recipient
    command.extend(["-address", sending_address, "to", receiver_address])

    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=5)
        output = result.stdout.strip()
        messagebox.showinfo("Transaction Status", f"Transaction sent:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Transaction failed:\n{e.stderr}")
    except subprocess.TimeoutExpired:
        messagebox.showerror("Error", "Operation timed out. 2FA code may be needed.")



# Function to show send transaction fields


def generate_wallet():
    wallet_name = wallet_name_entry.get()
    password = generate_wallet_password_entry.get()  # Use the renamed widget

    # Base command for generating a wallet
    command = ["python3", "wallet_client.py", "generatewallet", "-wallet", wallet_name]

    # Check if a password is provided and append it to the command
    if password.strip():
        command.extend(["-password", password, "-encrypt"])

    # Debug: Print the command for verification
    print("Executing command:", " ".join(command))

    # Execute the command
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        messagebox.showinfo("Success", "Wallet generated:\n" + result.stdout)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", "Error in generating wallet:\n" + str(e))







# Flags to control the visibility of frames
is_generate_wallet_frame_open = False
is_send_transaction_frame_open = False
is_generate_addresses_frame_open = False




def show_generate_wallet_fields():
    global is_generate_wallet_frame_open
    if not is_generate_wallet_frame_open:
        # Pack the frame below the generate wallet button
        generate_wallet_frame.pack(padx=PAD_X, pady=PAD_Y, in_=tab2)  # Make sure it's packed in the correct tab or parent
        is_generate_wallet_frame_open = True
    else:
        # Unpack the frame
        generate_wallet_frame.pack_forget()
        is_generate_wallet_frame_open = False


def generate_2fa_wallet():
    wallet_name = wallet_name_entry.get()
    password = generate_wallet_password_entry.get()

    if not wallet_name:
        messagebox.showerror("Error", "Please enter a wallet name.")
        return
    if not password:
        messagebox.showwarning("Warning", "Password is required for generating a 2FA wallet.")
        return
    command = ["python3", "wallet_client.py", "generatewallet", "-wallet", wallet_name, "-password", password, "-encrypt", "-2fa"]

    try:
        result = subprocess.Popen(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Create a new window for 2FA code input
        two_fa_window = tk.Toplevel(root)
        two_fa_window.title("2FA Authentication")
        two_fa_label = ttk.Label(two_fa_window, text="Enter the 2FA code from your authenticator app:")
        two_fa_label.pack()
        two_fa_entry = ttk.Entry(two_fa_window)
        two_fa_entry.pack()

        def confirm_2fa():
            two_fa_code = two_fa_entry.get()
            two_fa_window.destroy()

            # Send 2FA code to subprocess and capture output
            output, error = result.communicate(two_fa_code + '\n')
            final_output = (output or "") + (error or "")
            messagebox.showinfo("2FA Wallet Generation Output", final_output)

        confirm_button = ttk.Button(two_fa_window, text="Confirm", command=confirm_2fa)
        confirm_button.pack()

    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate 2FA wallet: {str(e)}")


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
    try:
        # Ensure that the amount_str is a valid integer
        amount = int(amount_str)
    except ValueError:
        generation_output_label.config(text="Error: Invalid amount. Please enter a valid integer.")
        return

    if selected_wallet_file:
        command = ["python3", "wallet_client.py", "generateaddress", "-wallet", wallet_name, "-amount", str(amount)]
        if password:
            command.extend(["-password", password])
        if tfacode:
            command.extend(["-2fa-code", tfacode])

        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=5)
            output = result.stdout.strip()

            # Check for empty or error output
            if not output or result.returncode != 0:
                error_message = "Error occurred: " + (result.stderr or "No addresses generated. Check password or other details.")
                generation_output_label.config(text=error_message)
            else:
                generation_output_label.config(text="Addresses generated successfully:\n" + output)
        except subprocess.TimeoutExpired:
            #messagebox.showerror("Operation Failed", "Operation failed: Invalid 2FA might be the cause.\nPlease try again.")
            generation_output_label.config(text="Operation timed out. Check 2FA and try again.")





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




def on_treeview_select(event):
    selected_items = address_list.selection()
    if selected_items:  # Check if anything is selected
        item = address_list.item(selected_items[0])  # Assuming single selection
        address = item['values'][0]  # Get the address from the first column
        root.clipboard_clear()  # Clear the clipboard
        root.clipboard_append(address)  # Append the address to the clipboard
        root.update()  # Now it stays on the clipboard after the window is closed
        messagebox.showinfo("Info", f"Address {address} copied to clipboard.")




def backup_wallet():
    backup_info_text.configure(state="normal")  # Enable editing to modify text
    backup_info_text.delete('1.0', tk.END)  # Clear existing text

    selected_wallet_file = backup_wallet_dropdown.get()
    if selected_wallet_file:
        wallet_path = os.path.join("./wallets", selected_wallet_file)

        if is_wallet_encrypted(wallet_path):
            password = simpledialog.askstring("Password", "Enter wallet password:", show="*")
            tfacode = None  # Initialize tfacode to None
            if password:
                tfacode = simpledialog.askstring("2FA Code", "Enter 2FA code (if applicable):", show="*")
                try:
                    command = ["python3", "wallet_client.py", "decryptwallet", "-wallet", selected_wallet_file, "-password", password]
                    if tfacode:
                        command.extend(["-2fa-code", tfacode])

                    result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    
                    if "Password Attempts Left" in result.stdout:
                        messagebox.showerror("Error", "Incorrect password. Please try again.")
                    else:
                        json_data_match = re.search(r'"entry_data":\s*\{.*\}\n\s*\}', result.stdout, re.DOTALL)
                        if json_data_match:
                            json_data_str = '{' + json_data_match.group(0)
                            try:
                                wallet_data = json.loads(json_data_str)
                                display_wallet_data(wallet_data)
                            except json.JSONDecodeError as e:
                                backup_info_text.insert(tk.END, "Failed to parse wallet data.")
                        else:
                            backup_info_text.insert(tk.END, "Failed to find wallet data in the output.")
                except subprocess.TimeoutExpired:
                    messagebox.showerror("Error", "Failed to decrypt wallet: 2FA code might be the reason.")
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", "Error in decrypting wallet:\n" + str(e))
                finally:
                    backup_info_text.configure(state="disabled")
            else:
                messagebox.showwarning("Warning", "No password provided. Cannot access encrypted wallet.")
                backup_info_text.configure(state="disabled")
        else:
            # For non-encrypted wallets
            try:
                with open(wallet_path, 'r') as file:
                    wallet_data = json.load(file)
                    display_wallet_data(wallet_data)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read wallet data: {e}")
    else:
        messagebox.showwarning("Warning", "No wallet selected for backup.")
        backup_info_text.configure(state="disabled")  # Ensure text is read-only if no wallet selected


def display_wallet_data(wallet_data):
    """ Display wallet data in the backup info text widget. """
    backup_info_text.configure(state="normal")  # Enable editing to modify text
    backup_info_text.delete('1.0', tk.END)  # Clear existing text

    try:
        # Determine the structure based on whether the data is from an encrypted wallet or not
        entries = wallet_data.get("entry_data", {}).get("entries", []) if "entry_data" in wallet_data else wallet_data.get("wallet_data", {}).get("entry_data", {}).get("entries", [])
        
        for entry in entries:
            backup_info = f"ID: {entry.get('id', 'N/A')}\n"
            backup_info += f"Private Key: {entry.get('private_key', 'N/A')}\n"
            backup_info += f"Public Key: {entry.get('public_key', 'N/A')}\n"
            backup_info += f"Address: {entry.get('address', 'N/A')}\n\n"
            backup_info_text.insert(tk.END, backup_info)
    except Exception as e:
        backup_info_text.insert(tk.END, f"Error processing wallet data: {e}")

    backup_info_text.configure(state="disabled")





# Initialize the main window
root = tk.Tk()
root.title("Denaro Wallet")
window_width = 1200
window_height = 699
root.geometry(f"{window_width}x{window_height}")
root.resizable(False, False)

top_frame = tk.Frame(root, bg='white')  # Set the background color as needed
top_frame.pack(side='top', fill='x')

# Load and resize the logo image
logo_path = "des.png"  # Update this to your logo file path
logo_image = PhotoImage(file=logo_path)
logo_image = logo_image.subsample(8, 8)  # Adjust as needed

# Create a label for the logo in the top frame
logo_label = tk.Label(top_frame, image=logo_image, bg='white')
logo_label.grid(row=0, column=0, padx=5, pady=5)

text_label = tk.Label(top_frame, text="v1.0.1", bg='white', fg='blue', font=('Helvetica', 22, 'bold'))
text_label.grid(row=0, column=1, padx=6, pady=6)


top_frame.columnconfigure(1, weight=10)  # Give more weight to the center column
top_frame.columnconfigure(2, weight=1)
# Configure styles
# Configure styles for light mode
DARK_BG = "#FFFFFF"
LIGHT_BG = "#FFFFFF"  # White background
DARK_TEXT = "#000000"  # Black text
ACCENT_COLOR = "#0077CC"  # Blue for accent
ENTRY_BG = "#F0F0F0"  # Light grey for entry fields
BUTTON_BG = "#E0E0E0"  # Light grey for buttons
LIGHT_TEXT = "#0077CC"
PAD_X = 10
PAD_Y = 5



def clear_treeview_selection(event):
    # Clear the selection in the address_list Treeview
    address_list.selection_remove(address_list.selection())

# Bind the clear_treeview_selection function to a mouse click event on the root window


# Additionally, if you have other frames or widgets where you also want to clear the selection when clicked, bind them as well
top_frame.bind("<Button-1>", clear_treeview_selection)

style = ttk.Style(root)
style.theme_use('clam')
style.configure("Treeview",
                background=BUTTON_BG,  # Background color of the Treeview
                fieldbackground=BUTTON_BG,  # Background color of the fields
                foreground=DARK_TEXT,  # Text color
                rowheight=25,  # Height of each row, adjust as per requirement
                font=('Helvetica', 12, 'bold'))  # Font style and size for content

style.configure('TFrame', background=LIGHT_BG)
style.configure('TButton', background=BUTTON_BG, foreground=DARK_TEXT)
style.map('TButton', background=[('active', ACCENT_COLOR)], foreground=[('active', DARK_TEXT)])
style.configure('TLabel', background=LIGHT_BG, foreground=DARK_TEXT)
style.configure('TEntry', background=ENTRY_BG, foreground=DARK_TEXT)
style.configure('TCombobox', fieldbackground=ENTRY_BG, foreground=DARK_TEXT)
style.configure("Treeview.Heading",
                background="white",  # Background color of the headings
                foreground="blue",  # Text color of the headings
                font=('Helvetica', 14, 'bold'))  # Font style and size for headings

style.map('Treeview', background=[('selected', ACCENT_COLOR)])  # Background color when a row is selected
style.configure("Treeview.Heading", background="white", foreground="blue", font=('Helvetica', 10, 'bold'))
root.configure(bg=BUTTON_BG)



# Create the tab control
tab_control = ttk.Notebook(root)
tab1 = ttk.Frame(tab_control, style='TFrame')
tab2 = ttk.Frame(tab_control, style='TFrame')
tab3 = ttk.Frame(tab_control, style='TFrame')
tab4 = ttk.Frame(tab_control, style='TFrame')
tab_control.add(tab1, text='Wallet Operations')
tab_control.add(tab2, text='Generate Options')
tab_control.add(tab3, text='Wallet Settings')
tab_control.add(tab4, text='FAQ')

tab_control.pack(expand=1, fill="both")


# Dropdown for wallet file selection
wallet_dropdown = ttk.Combobox(root, state="readonly")
wallet_dropdown.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)
wallet_dropdown.bind('<<ComboboxSelected>>', display_addresses)

# Button to load wallets
load_button = ttk.Button(root, text="Load Wallets", command=on_load_button_click)
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
address_list = ttk.Treeview(tab1, columns=columns, show='headings', style="Treeview")
address_list.heading('Address', text='Address')
address_list.heading('Balance', text='Balance')
address_list.pack(side="left", fill="both", expand=True)
address_list.bind('<<TreeviewSelect>>', on_treeview_select)

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



# Generate Wallet Frame widgets
# ... [previous code] ...

# Generate Wallet Frame widgets
# Generate Wallet Frame widgets
generate_wallet_frame = tk.Frame(root, bg=DARK_BG)
wallet_name_label = ttk.Label(generate_wallet_frame, text="Wallet Name:")
wallet_name_entry = ttk.Entry(generate_wallet_frame)
generate_wallet_password_label = ttk.Label(generate_wallet_frame, text="Password (optional):")
generate_wallet_password_entry = ttk.Entry(generate_wallet_frame, show="*")

# Regular wallet generation button
confirm_generate_button = ttk.Button(generate_wallet_frame, text="Confirm", command=generate_wallet)

# 2FA wallet generation button
generate_2fa_wallet_button = ttk.Button(generate_wallet_frame, text="Generate 2FA Wallet", command=generate_2fa_wallet)

# Packing widgets within generate_wallet_frame
wallet_name_label.pack(side="top", fill='x')
wallet_name_entry.pack(side="top", fill='x')
generate_wallet_password_label.pack(side="top", fill='x')
generate_wallet_password_entry.pack(side="top", fill='x')

# Create a frame for buttons to align them horizontally
buttons_frame = tk.Frame(generate_wallet_frame, bg=DARK_BG)
buttons_frame.pack(side="top", fill='x', pady=(5, 0))

confirm_generate_button.pack(side="left", padx=(0, 5))
generate_2fa_wallet_button.pack(side="left")



# ... [rest of your code] ...




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


backup_wallet_frame = tk.Frame(tab3, bg=DARK_BG)
backup_wallet_label = ttk.Label(backup_wallet_frame, text="Never share your keys")
backup_wallet_dropdown = ttk.Combobox(backup_wallet_frame, state="readonly", values=[f for f in os.listdir("./wallets") if f.endswith('.json')])
backup_wallet_button = ttk.Button(backup_wallet_frame, text="Reveal", command=backup_wallet)

# Create a Text widget with a Scrollbar for displaying backup information
backup_info_text = tk.Text(backup_wallet_frame, height=10, width=50)
backup_info_scroll = ttk.Scrollbar(backup_wallet_frame, command=backup_info_text.yview)
backup_info_text.configure(yscrollcommand=backup_info_scroll.set)

# Positioning the Backup Wallet Frame widgets
backup_wallet_label.pack(side="top", fill='x')
backup_wallet_dropdown.pack(side="top", fill='x')
backup_wallet_button.pack(side="top", fill='x')
backup_info_text.pack(side="left", fill='both', expand=True)
backup_info_scroll.pack(side="right", fill='y')
backup_wallet_frame.pack(padx=PAD_X, pady=PAD_Y)

# Send button
send_button = ttk.Button(root, text="Send", command=open_send_transaction)
send_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab1)
generate_wallet_button = ttk.Button(root, text="Generate Wallet", command=show_generate_wallet_fields)
generate_wallet_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab2)  # Adjust the placement as needed


generate_addresses_button = ttk.Button(root, text="Generate Addresses", command=toggle_generate_addresses_frame)
generate_addresses_button.pack(padx=PAD_X, pady=PAD_Y, in_=tab2)
import_private_key_button = ttk.Button(tab3, text="Import Private Key", command=open_import_private_key_dialog)
import_private_key_button.pack(padx=PAD_X, pady=PAD_Y)


# FAQ content Text widget
faq_text = tk.Text(tab4, wrap='word', state='normal', height=25)
faq_text.pack(padx=PAD_X, pady=PAD_Y, fill='both', expand=True)


def open_link(url):
    webbrowser.open_new(url)

# Insert FAQ content
# New FAQ content
new_faq_content = """
***Introducing Denaro

A unique Python-based cryptocurrency offering fast, secure transactions with a blockchain capable of handling 40 transactions per second. With a focus on decentralization and efficiency, Denaro is reshaping digital finance and flexibility.  Join the excitement at our exclusive Denaro-token-powered Telegram casino! Play, win, and be part of a new era of crypto gaming.

**Casino bot: [https://t.me/DenaroCasinoBot?start=rezeilo

**Casino Community: [https://t.me/EmojiBetting]

**Website: [https://denaro.is/]

**Explorer: [https://explorer.denaro.is/]

**DVM (Denaro Virtual Machine) is a layer built on top of Denaro Blockchain, which uses transaction messages to communicate with the VM: [https://github.com/denaro-coin/dvm]

**Miner: [https://github.com/geiccobs/denaro-cuda-miner]

****Wallet:

Our wallet will allow you to send and receive Denaro coin on Denaro chain, facilitate the use of your private keys and enhance the security of your funds and wallets. Keep in mind that you should not share your keys with any third parties or even Denaro devs as they will never ask you to do so. If there is any trouble or bugs encountered while using our wallet please report to the Telegram group: [t.me/DenaroGroup](https://t.me/DenaroGroup)
"""
faq_text.insert('end', new_faq_content)


# Making 'website' clickable


# Start the GUI loop
root.mainloop()
