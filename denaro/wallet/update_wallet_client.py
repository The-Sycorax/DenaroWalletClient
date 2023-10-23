import requests
import json
from hashlib import sha1
from pathlib import Path
import os
import shutil
from datetime import datetime

class Repository:

    def __init__(self, repo_owner, repo_name, branch='main', local_dir='.', data_file='github_data.json'):
        """
        Initializes the Repository object by setting various attributes such as the repository owner, name, and branch. 
        The function also establishes URLs for GitHub API operations like fetching tree data and obtaining the latest commit's SHA-1 hash. 
        
        It configures the local directory and initializes a JSON file for saving repository data. If this data file doesn't exist, the function 
        creates it with an empty JSON object.
        
        Parameters:
        - repo_owner: The owner of the GitHub repository (str).
        - repo_name: The name of the GitHub repository (str).
        - branch: The branch of the GitHub repository to work with (str). The default is 'main'.
        - local_dir: The local directory where files from the GitHub repository will be saved (str). The default is the current directory.
        - data_file: The name of the JSON file used to save repository data (str). The default is 'github_data.json'.
        """
        # Set the local directory as a Path object for easier manipulation
        self.local_dir = Path(local_dir)
        
        # Set the data file for saving state
        self.data_file = self.local_dir / data_file
        
        # Initialize an empty JSON file if it doesn't exist
        if not self.data_file.exists():
            self.data_file.write_text("{}")
        
        # Raise an exception if the local directory doesn't exist
        if not self.local_dir.exists():
            raise FileNotFoundError("{} does not exist".format(local_dir))
        
        # Store repo owner, repo name, and branch information
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.branch = branch
        
        # URLs for various API operations
        self.urls = {
            'tree': f'https://api.github.com/repos/{repo_owner}/{repo_name}/git/trees/{branch}?recursive=1',  # URL for repo tree
            'download': f'https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{branch}/',  # URL for raw content
            'last_commit_sha': f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/HEAD/branches-where-head",  # URL for last commit SHA
        }
        
        # Load saved data for comparison in future operations
        with self.data_file.open(mode='r') as f:
            self.saved_data = json.load(f)

    def get_tree_data(self):
        """
        This function fetches the tree data of the GitHub repository using the GitHub API. 
        The function filters out all types except 'blob,' which represents files, and returns
        this filtered data as a dictionary.
        
        Returns:
        - dict: A dictionary where keys are relative file paths in the GitHub repository, and values are the metadata about each file.
        """
        # Initialize an empty dictionary to hold tree data
        result = dict()
        
        # Get the URL for the tree API
        tree_url = self.urls['tree']        
        
        # Fetch the tree data
        tree_data = json.loads(requests.get(tree_url).content)
        
        # Loop through the tree data to filter out only files ('blob' type)
        for item in tree_data['tree']:
            if item['type'] == 'blob':
                # Add each file to the result dictionary
                result[item['path']] = item 
                        
        # Replace the original tree data with filtered data
        tree_data['tree'] = result
        
        # Return the filtered tree data
        return tree_data

    def download_files(self, paths, max_download_size=float('inf')):
        """
        This function downloads the specified files from the GitHub repository to the local directory. 
        The function constructs download URLs based on the file paths and fetches the files. If a file's size 
        exceeds the maximum download size, the function skips that file.
        
        Parameters:

        - paths: A list of relative file paths in the GitHub repository to be downloaded.
        - max_download_size: The maximum allowed size of files to download, in bytes (float). The default is infinity.
        """
        # Loop through each path in the list of paths to download
        for p in paths:
            # Generate the URL for downloading the file
            download_url = self.urls['download'] + p                        
            # Fetch the size of the file
            file_size_bytes = int(requests.head(download_url).headers['Content-Length'])
            
            # Convert the size to a human-readable format
            file_size = file_size_bytes
            file_size_str = "Bytes"
            # Convert bytes to KB if size > 1024 bytes
            if file_size > 1024: 
                file_size_str = "KB"
                file_size /= 1024
            # Convert KB to MB if size > 1024 KB
            if file_size > 1024: 
                file_size_str = "MB"
                file_size /= 1024
            # Format the file size string
            file_size_str = f"{file_size:.2f} {file_size_str}" 
            
            # Check if the file size is within the maximum allowed download size
            if file_size_bytes > max_download_size:
                print("Skipping {} ({})".format(p, file_size_str))
                continue
            
            print("Downloading {} ({})...".format(p, file_size_str), end="\t")
            
            # Ensure the directory for the file exists, create it otherwise
            if not (self.local_dir / p).parent.exists():
                (self.local_dir / p).parent.mkdir(parents=True)
            
            # Download the file and save it locally
            with (self.local_dir / p).open(mode='wb') as f:
                # Fetch the file as a stream
                response = requests.get(download_url, stream=True)
                # Check for successful response
                if response.status_code != 200: 
                    # Print an error message if the download failed
                    print("[ERROR]")
                    continue
                # Iterate through the file stream
                for chunk in response.iter_content(chunk_size=1024):
                    # If the chunk is not empty then write to file
                    if chunk:
                        f.write(chunk)
                        
            # Indicate successful download
            print("[OK]")
    
    def backup_local_files(self):
        """
        Creates a backup of existing files and folders in the current local directory, excluding the 'env' and 'old_versions' folders. 
        The backup is saved in a timestamped folder within a directory named `old_versions`.
        """
        # Create a directory for old versions if it doesn't exist
        os.makedirs("old_versions", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        # Create a backup folder name based on the timestamp
        backup_folder = f"old_versions/backup_{timestamp}"        
        # Create the backup folder
        os.makedirs(backup_folder, exist_ok=True)

        # Loop through each item in the current directory for backup
        for item in os.listdir("."):
             # Exclude certain directories
            if item not in ["env","old_versions"]:
                # Source path for the item
                src_path = os.path.join(".", item)
                # Destination path for the item
                dest_path = os.path.join(backup_folder, item)                
                # Check if the item is a directory or a file and copy accordingly
                if os.path.isdir(src_path):
                    # Copy directory
                    shutil.copytree(src_path, dest_path)
                else:
                    # Copy file
                    shutil.copy2(src_path, dest_path)  

        # Indicate where the backup is saved
        print(f'Backup saved to: {backup_folder}\n')

    def get_head_sha(self, timeout=5):
        """
        This function fetches the SHA-1 hash of the latest commit in the specified branch of the GitHub repository. 
        The function makes a request to the GitHub API to fetch this hash and returns it.
        
        Parameters:
        - timeout: The time, in seconds, to wait for the HTTP request to complete (int). The default is 5 seconds.
        
        Returns:
        - str: The SHA-1 hash of the latest commit or None if the information could not be fetched.
        """
        # Fetch the last commit SHA
        response = requests.get(self.urls['last_commit_sha'], timeout=timeout)
        # Check for successful response
        if response.status_code == 200:
            # Parse the response content
            branches = json.loads(response.content)

            # Loop through each branch in the response
            for b in branches:
                # Check if the branch matches the specified branch
                if b['name'] == self.branch:
                    # Return the SHA of the last commit
                    return b['commit']['sha']
                                
        # Return None if the SHA could not be fetched
        return None

    @staticmethod
    def calc_sha(data):
        """
        This function calculates the SHA-1 hash of the provided data, which can be either a file path, a Path object, or raw byte data. 
        If a file path or Path object is provided, the function reads the file into bytes and then calculates its SHA-1 hash.
        
        Parameters:
        - data (str/Path/bytes): The data to calculate the SHA-1 hash.
        
        Returns:
        - str: The SHA-1 hash of the input data.
        """
        # Check if the data is a string (file path)
        if type(data) is str:
            # Convert the string to a Path object
            data = Path(data)
            
        # Check if the data is a Path object
        if isinstance(data, Path):
            # Read the file into bytes
            data = data.read_bytes()
            
        # Calculate and return the SHA-1 hash
        return sha1(f"blob {len(data)}\0".encode() + data).hexdigest()

    def auto_update(self, max_download_size=float('inf')):
        """
        This funciton checks for updates in the GitHub repository by fetching the latest tree data and comparing it with the local files. 
        Based on user input, the function updates the local directory by downloading any new or changed files from the GitHub repository.
        
        Parameters:
        - max_download_size: The maximum allowed size of files to download, in bytes (float). The default is infinity.
        
        Returns:
        - bool: True if updates were performed; False otherwise.
        """
        # Fetch the latest tree data from GitHub
        tree_data = self.get_tree_data()
        # Initialize an empty list for files to download
        to_download = []
        
        # Loop through each file in the tree data to check if it needs to be downloaded
        for path, data in tree_data['tree'].items():
            # If the file doesn't exist locally then add it to the download list
            if not (self.local_dir / path).exists(): 
                to_download.append(path) 
            else:
                # Calculate the local SHA-1 hash of the file
                local_sha = self.calc_sha(self.local_dir / path)
                # Compare the local SHA-1 hash with the repository SHA-1 hash
                if local_sha != data['sha']:
                    # Add the file to the download list if the hashes don't match
                    to_download.append(path)
        
        # Check if there are any files to download
        if len(to_download) > 0:
            # Prompt the user for update and backup
            update, backup = Repository.prompt_for_update()
            # If the user wants to backup local files then perform backup
            if backup:
                self.backup_local_files()
            # Check if the user wants to update local files then perform update
            if update:
                self.download_files(to_download, max_download_size) 
                print("\nFinished updating.")
                print("Please run wallet client again.")
                # Save the latest SHA-1 hash
                self.saved_data['sha'] = tree_data['sha']
                 # Write the saved data to the data file
                self.data_file.write_text(json.dumps(self.saved_data))
                # Set the updated flag to True
                updated = True
            else:
                # Set the updated flag to False if the user declines to update
                updated = False
        else:
            # Indicate that the client is up to date
            print("Wallet client is up to date")
             # Save the latest SHA-1 hash
            self.saved_data['sha'] = tree_data['sha']
            # Write the saved data to the data file
            self.data_file.write_text(json.dumps(self.saved_data))
            # Set the updated flag to False
            updated = False
                    
        # Return the updated flag
        return updated

    @staticmethod
    def prompt_for_update():
        """
        Presents a prompt to the user, asking if they want to update the local directory and if they want to create a backup of it. 
        This function returns the user's choices as a tuple of two boolean values.
        
        Returns:
        - tuple: A tuple containing two boolean values. The first boolean indicates whether to update, and the second indicates whether to create a backup.
        """
        # Indicate that an update is available
        print("An Update is Available.\n")
        while True:
            # Ask the user if they want to update walet client
            prompt_for_update = input("Would you like to update the wallet client? (y/n): ")
            if prompt_for_update.lower() == 'y':
                while True:
                    # Ask the user if they want to backup their current verison of wallet client
                    prompt_for_backup = input("Would you like to backup your current version? (y/n): ")
                    if prompt_for_backup.lower() == 'y': 
                         # Return flags for update and backup
                        return True, True
                    # Check if the user declines to backup
                    elif prompt_for_backup.lower() == 'n': 
                        print()
                        # Return flags for update and no backup
                        return True, False
                    else:
                        # Indicate invalid input for backup choice
                        print("Invalid choice. Please enter 'y' or 'n'.") 
                        print()
            # Check if the user declines to update
            elif prompt_for_update.lower() == 'n':
                # Return flags for no update and no backup
                return False, False
            else:
                # Indicate invalid input for update choice
                print("Invalid choice. Please enter 'y' or 'n'.")
                print()
    
    def check_for_updates(self, timeout=5):
        """
        Checks for updates in the GitHub repository by comparing the SHA-1 hash of the latest commit against a locally stored value.
        If no local SHA-1 hash is stored, the function assumes that an update check has not been performed before and proceeds to call 'auto_update'.
        
        If a local SHA-1 hash is stored, the function compares this hash with the SHA-1 hash of the latest commit in the GitHub repository. 
        If the hashes do not match, the function triggers an update by calling 'auto_update'.
        
        Parameters:
        - timeout: The time, in seconds, to wait for the HTTP request to fetch the latest commit's SHA-1 hash (int). The default is 5 seconds.
        
        Returns:
        - bool: True if updates were available and performed; False otherwise.
        """
        # Check if the SHA-1 hash is not in the saved data
        if "sha" not in self.saved_data:
             # Indicate that an update may be available
            print("Update may be available for wallet client. Checking...")            
            # Perform the automatic update and return appropiate flags
            if Repository.auto_update(self):
                return True
            else:
                return False            
        # Compare the latest SHA-1 hash with the saved SHA-1 hash
        elif self.get_head_sha(timeout) != self.saved_data['sha']:
            # Indicate that an update may be available
            print("Update may be available for wallet client. Checking...")            
            # Perform the automatic update and return appropiate flags
            if Repository.auto_update(self):
                return True
            else:
                return False        
        else:
            # Return False if no update is available
            return False