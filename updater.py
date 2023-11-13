import requests
import json
import argparse
import base64
import os
import math
import hashlib
import logging
import shutil
from datetime import datetime

# Get the root logger
root_logger = logging.getLogger()

# Set the level for the root logger
root_logger.setLevel(logging.INFO)

# Create a handler with the desired format
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)

# Clear any existing handlers from the root logger and add our handler
root_logger.handlers = []
root_logger.addHandler(handler)

def fetch_from_github_api(url):
    """
    Fetches data from the GitHub API at the specified URL.

    If the request is successful, it returns the JSON response and any pagination links.
    In case of a request failure, it logs the error and returns None for both the JSON response and the links.

    Parameters:
    - url (str): The GitHub API endpoint URL to fetch data from.

    Returns:
    - tuple: A tuple containing the JSON response (dict) and the pagination links (dict), or (None, {}) on failure.
    """
    try:
        response = requests.get(url)  # Sends an HTTP GET request to the GitHub API
        response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code
        return json.loads(response.text), response.links  # Parses the JSON response text and returns it with pagination links
    except requests.RequestException as e:
        logging.error(f"Failed to fetch from GitHub API: {e}")  # Logs any exception that occurs during the HTTP request
        return None, {}  # Returns None and an empty dictionary if an exception occurs
    
def fetch_tree_from_sha(owner, repo, commit_sha):
    """
    Fetches the tree associated with a specific commit SHA from the GitHub repository.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.
    - commit_sha (str): The SHA of the commit.

    Returns:
    - dict: A dictionary representing the tree of files from the commit, or None on failure.
    """
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"  # Constructs the URL to fetch the tree
    result, _ = fetch_from_github_api(tree_url)  # Calls fetch_from_github_api() to get the tree data
    return result  # Returns the result, which is either the tree as a dictionary or None

def fetch_commit_sha_from_tag(owner, repo, tag):
    """
    Fetches the commit SHA for a given tag from the GitHub repository.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.
    - tag (str): The tag name to fetch the commit SHA for.

    Returns:
    - str: The commit SHA associated with the tag, or None on failure.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{tag}"  # Constructs the URL to fetch the commit SHA from the tag
    data, _ = fetch_from_github_api(url)  # Calls fetch_from_github_api() to get the commit SHA data
    return data['object']['sha'] if data else None  # Extracts the commit SHA from the response, returns None if the request failed

def fetch_latest_commit_sha(owner, repo):
    """
    Fetches the latest commit SHA from the 'main' branch of a GitHub repository.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.

    Returns:
    - str: The latest commit SHA, or None on failure.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/main"  # Constructs the URL to fetch the latest commit from the 'main' branch
    data, _ = fetch_from_github_api(url)  # Calls fetch_from_github_api() to get the latest commit data
    return data['sha'] if data else None  # Extracts the commit SHA from the response, returns None if the request failed

def fetch_releases(owner, repo, prerelease=None, get_all=False):
    """
    Fetches a list of releases from the GitHub repository.
    Can filter for prereleases and optionally fetch all releases across all pages.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.
    - prerelease (bool): If set, filters the releases for prerelease status.
    - get_all (bool): If True, fetches all releases across all pages.

    Returns:
    - list: A list of tuples containing the tag name and commit SHA for each release, or an empty list on failure.
    """
    releases = []
    if get_all:
        page = 1  # Starts from the first page
        while True:
            url = f"https://api.github.com/repos/{owner}/{repo}/releases?page={page}&per_page=100"  # URL for paginated releases
            page_releases, links = fetch_from_github_api(url)  # Calls fetch_from_github_api() to get releases data for the page
            if page_releases:
                # Filters and stores releases with the matching prerelease status
                filtered_releases = [
                    (release['tag_name'], fetch_commit_sha_from_tag(owner, repo, release['tag_name']))
                    for release in page_releases if prerelease is None or release['prerelease'] == prerelease
                ]
                releases.extend(filtered_releases)  # Adds the filtered releases to the main list
                if 'next' in links:
                    page += 1  # Increments the page counter if there's a 'next' page
                else:
                    break  # Breaks the loop if there are no more pages
            else:
                break  # Breaks the loop if no releases are found for the page
    else:
        # Constructs the appropriate URL based on whether we're fetching the latest release or a specific prerelease
        if prerelease is None:
            url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        else:
            url = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=1"

        single_release_data, _ = fetch_from_github_api(url)  # Calls fetch_from_github_api() to get release data
        if single_release_data:
            # Handles the case where a list is returned by 'per_page' parameter
            if isinstance(single_release_data, list):
                single_release_data = single_release_data[0] if single_release_data else None
            # If release matches the prerelease filter, it stores the tag and commit SHA
            if single_release_data and (prerelease is None or single_release_data['prerelease'] == prerelease):
                tag_name = single_release_data['tag_name']
                commit_sha = fetch_commit_sha_from_tag(owner, repo, tag_name)
                return tag_name, commit_sha

    return releases if get_all else (None, None)  # Returns the list of releases or (None, None) if not get_all

def verify_version(owner, repo, version, prerelease_flag):
    """
    Verifies if a specific version tag exists in the GitHub repository and matches a prerelease flag.
    If the specified version is found and the prerelease status matches the flag, it returns the corresponding commit SHA.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.
    - version (str): The version tag to verify.
    - prerelease_flag (bool): The flag indicating whether to match prereleases or not.

    Returns:
    - str: The commit SHA for the specified version if found and matches the prerelease flag, None otherwise.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100"  # Constructs the URL for fetching releases
    releases, _ = fetch_from_github_api(url)  # Calls fetch_from_github_api() to get the releases data
    if releases:
        for release in releases:
            # Checks if the release matches the specified version and prerelease status
            if release['tag_name'] == version and release['prerelease'] == prerelease_flag:
                return fetch_commit_sha_from_tag(owner, repo, version)  # Returns the commit SHA if a match is found
    return None  # Returns None if no matching release is found

def is_downgrade(current_commit_sha, target_commit_sha, releases):
    """
    Determines if a change from the current commit SHA to the target commit SHA represents a downgrade
    by comparing their positions in the list of releases.

    Parameters:
    - current_commit_sha (str): The commit SHA of the current version.
    - target_commit_sha (str): The commit SHA of the target version to compare.
    - releases (list): A list of tuples containing release tags and their corresponding commit SHAs.

    Returns:
    - bool: True if the change represents a downgrade, False otherwise.
    """
    # Finds the index of the current and target commit SHAs in the list of releases
    current_index = next((index for index, (_, sha) in enumerate(releases) if sha == current_commit_sha), None)
    target_index = next((index for index, (_, sha) in enumerate(releases) if sha == target_commit_sha), None)
    
    # Compares the indices to determine if the target commit SHA comes after the current one, which indicates a downgrade
    if current_index is not None and target_index is not None and target_index > current_index:
        return True  # Returns True if the target version is older than the current version
    return False  # Returns False if it is not a downgrade or if indices are not found

def extract_path_and_url(json_data):
    """
    Extracts 'path' and 'url' information from JSON data representing a tree of files from the GitHub repository.

    Parameters:
    - json_data (dict): A dictionary representing JSON data from a GitHub tree API response.

    Returns:
    - dict: A dictionary mapping file paths to a sub-dictionary containing 'path' and 'url' information.
    """
    # Initialize an empty dictionary to store the result
    result = {}
    # Iterate through each key-value pair in the JSON data
    for key, value in json_data.items():
        # Check if the current value is a dictionary
        if isinstance(value, dict):
            # Extract the 'path' and 'url' fields from the dictionary
            path = value.get('path', None)
            url = value.get('url', None)
            # Check if both 'path' and 'url' exist
            if path is not None and url is not None:
                # Store the 'path' and 'url' in the result dictionary
                result[key] = {'path': path, 'url': url}
    return result

def fetch_and_decode_content(extracted_data):
    """
    Fetches and decodes the content of files from their URLs provided in the extracted data.

    Parameters:
    - extracted_data (dict): A dictionary containing 'path' and 'url' for each file.

    Returns:
    - dict: A dictionary mapping file paths to their decoded content.
    """
    # Initialize an empty dictionary to store the decoded content
    decoded_content = {}
    # Iterate through each key-value pair in the extracted_data dictionary
    for key, value in extracted_data.items():
        # Extract the 'path' and 'url' for each file
        path = value['path']
        url = value['url']
        # Fetch the file content from GitHub
        response = requests.get(url)
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response to get the base64 encoded content
            json_data = response.json()
            content_base64 = json_data.get('content', '')
            # Decode the base64 content to bytes
            content_bytes = base64.b64decode(content_base64)
            # Store the bytes content in the decoded_content dictionary
            decoded_content[path] = content_bytes
    # Return the decoded content
    return decoded_content

def convert_size(size_bytes):
    """
    Convert a given size in bytes to a string that represents the size in Bytes, KB, MB, or GB.

    Parameters:
    - size_bytes (int): The size in bytes

    Returns:
    - str: A string that represents the size in a more readable format
    """
    # Check if the size is zero
    if size_bytes == 0:
        return "0B"
    # Define the size units
    size_name = ("Bytes", "KB", "MB", "GB")
    # Calculate the index to use for the size unit
    i = int(math.floor(math.log(size_bytes, 1024)))
    # Calculate the size in the chosen unit
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    # Return the size as a string
    return f"{s} {size_name[i]}"

def calculate_sha1(file_path):
    """
    Calculate the SHA1 hash of a file in a manner consistent with GitHub.

    Parameters:
    - file_path (str): The path to the file

    Returns:
    - str: The SHA1 hash of the file content
    """
    # Initialize the SHA1 hash object
    sha1 = hashlib.sha1()
    # Read the file content
    with open(file_path, 'rb') as f:
        content = f.read()
    # GitHub includes the "blob" string and file size in bytes in the SHA calculation
    header = f'blob {len(content)}\0'
    # Update the SHA1 hash object with the header and the content
    sha1.update(header.encode('utf-8'))
    sha1.update(content)
    # Return the hexadecimal representation of the SHA1 hash
    return sha1.hexdigest()

def save_content_to_files(decoded_content, sha_map, root_dir='.'):
    """
    Saves the decoded content to files on the local filesystem. It also cleans up files that
    are not present in the decoded content, with exceptions for specific directories and files.

    Parameters:
    - decoded_content (dict): A dictionary mapping file paths to their decoded content.
    - sha_map (dict): A dictionary mapping file paths to their SHA1 hash values.
    - root_dir (str): The root directory where files will be saved.

    Notes:
    This function will remove files that are not in the decoded_content and are not part of the keep_files set.
    It will also create any necessary directories and write the content to the files.
    """
    files_downloaded = False  # Flag to track if any files were downloaded
    # Defines directories and files to exclude from cleanup
    exclude_dirs = {'wallets', 'env', '.git','old_versions', 'testing'}
    keep_files = {'update_config.json','updater.py'}

    os.makedirs(root_dir, exist_ok=True)  # Ensures the root directory exists
    
    updated_paths = set(decoded_content.keys())  # Gets all paths that are about to be updated or checked
    
    for root, dirs, files in os.walk(root_dir, topdown=True):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]  # Excludes certain directories from traversal
        for name in files:
            file_path = os.path.join(root, name)  # Constructs the full file path
            relative_path = os.path.relpath(file_path, root_dir)  # Gets the relative path for comparison
            if os.path.basename(file_path) in keep_files:
                continue  # Skips files that should be kept
            if relative_path not in updated_paths:
                os.remove(file_path)  # Removes files not in the update list

    for path, content in decoded_content.items():
        full_path = os.path.join(root_dir, path)  # Constructs the full path to where the file will be saved
        os.makedirs(os.path.dirname(full_path), exist_ok=True)  # Creates any directories in the path
        size = len(content)
        readable_size = convert_size(size)  # Converts the size to a human-readable format
        if os.path.exists(full_path):
            existing_sha1 = calculate_sha1(full_path)  # Calculates the SHA1 for the existing file
            if existing_sha1 == sha_map.get(path):
                continue  # Skips the file if the SHA1 matches (no change)
        try:
            print(f"Downloading: {path} | Size: {readable_size}...", end='')
            with open(full_path, 'wb') as f:
                f.write(content)  # Writes the decoded content to the file
            print("[OK]")
            files_downloaded = True  # Sets the flag to True since a file was downloaded
        except Exception as e:
            print(f"[Error] - {e}")  # Prints any error that occurs during file writing

    if files_downloaded:
        print() 

def backup_local_files():
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
                # Copies directories
                shutil.copytree(src_path, dest_path)
            else:
                # Copies files
                shutil.copy2(src_path, dest_path)  
    logging.info(f"Backup created at '{backup_folder}'")
    print()

def perform_update(owner, repo, commit_sha, msg):
    """
    Executes the update process by fetching the file tree from a specific commit SHA and saving the new files locally.
    Before the update, it offers to back up the current version. After fetching the tree, it processes and saves the files.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.
    - commit_sha (str): The commit SHA to update from.
    - msg (str): A message to log before performing the update.

    Notes:
    This function integrates multiple steps such as backup, tree fetching, content extraction, decoding, and file saving.
    It also handles error checking and logging throughout the process.
    """
    # Show comfirmation prompt to back up current files before updating
    if confirmation_prompt("Would you like to backup your current version? (y/n): "):
        backup_local_files()

    logging.info(msg)  # Logs the message passed to the function
    print()
    
    # Fetches the file tree from the specified commit SHA
    tree = fetch_tree_from_sha(owner, repo, commit_sha)
    if not tree:
        print("Failed to fetch the tree.")
        exit(1)  # Exits the script if the tree could not be fetched
    
    result, sha_map = {}, {}
    # Processes the file tree, extracting paths and SHA values
    for item in tree['tree']:
        if item['type'] == 'blob':  # Filters for blob items, which represent files
            result[item['path']] = item  # Maps file paths to their metadata
            sha_map[item['path']] = item['sha']  # Maps file paths to their SHA values

    # Extracts URLs and paths from the tree's blobs
    extracted_data = extract_path_and_url(result)
    # Fetches and decodes the content from the GitHub blobs
    decoded_content = fetch_and_decode_content(extracted_data)
    # Saves the decoded content to local files
    save_content_to_files(decoded_content, sha_map)

def read_config(disable_err_msg = False,config_path='update_config.json'):
    """
    Reads the configuration from a JSON file.

    Parameters:
    - config_path (str): The path to the configuration file. Defaults to 'update_config.json'.

    Returns:
    - dict: The configuration as a dictionary, or None if the file is not found or contains invalid JSON.
    """
    try:
        with open(config_path, 'r') as config_file:
            return json.load(config_file)  # Loads and returns the configuration as a dictionary
    except FileNotFoundError:
        if not disable_err_msg:
            logging.error(" Config file not found. Please initialize the configuration using 'setconfig'.")
        return None  # Returns None if the configuration file is not found
    except json.JSONDecodeError:
        logging.error(" Config file contains invalid JSON.")
        return None  # Returns None if the JSON is invalid

def write_config(config, config_path='update_config.json'):
    """
    Writes the given configuration to a JSON file.

    Parameters:
    - config (dict): The configuration to write.
    - config_path (str): The path to the configuration file. Defaults to 'update_config.json'.

    Returns:
    - bool: True if the configuration was written successfully, False otherwise.
    """
    try:
        with open(config_path, 'w') as config_file:
            json.dump(config, config_file, indent=4)  # Writes the configuration to the file with indentation
        return True  # Returns True if the operation was successful
    except Exception as e:
        logging.error(f"Failed to write config: {e}")
        return False  # Returns False if any exception occurred during file writing

def check_for_update(owner, repo, stored_commit_sha, prerelease_flag, is_dev):
    """
    Checks if an update is available by comparing the stored commit SHA with the latest commit SHA from GitHub.

    Parameters:
    - owner (str): The owner of the GitHub repository.
    - repo (str): The name of the GitHub repository.
    - stored_commit_sha (str): The commit SHA stored in the configuration file.
    - prerelease_flag (bool): Flag indicating whether to check for pre-releases or stable releases.
    - is_dev (bool): Flag indicating if the development channel should be used.

    Returns:
    - tuple: A tuple containing a boolean indicating if an update is available and the latest commit SHA.
    """
    if not is_dev:
        # Fetches the latest stable or prerelease commit SHA
        _, latest_commit_sha = fetch_releases(owner, repo, prerelease=prerelease_flag, get_all=False)
    else:
        # Fetches the latest commit SHA from the 'main' branch for the development channel
        latest_commit_sha = fetch_latest_commit_sha(owner, repo)
    
    # Checks if the fetched commit SHA tree can be retrieved, if not, the script exits
    if not fetch_tree_from_sha(owner, repo, latest_commit_sha):
        exit(1)
    
    # Compares the stored commit SHA with the latest fetched commit SHA to determine update availability
    if latest_commit_sha and stored_commit_sha != latest_commit_sha:
        return True, latest_commit_sha  # Returns True and the latest commit SHA if an update is available
    return False, stored_commit_sha  # Returns False and the stored commit SHA otherwise

def confirmation_prompt(msg):
    """
    Displays a prompt message and awaits user input for confirmation.

    Parameters:
    - msg (str): The prompt message to display to the user.

    Returns:
    - bool: True if the user confirms ('y'), False if the user declines ('n') or quits ('/q').
    """
    print()
    while True:
        confirmation = input(msg)  # Displays the prompt and awaits input
        if confirmation.strip().lower() in ['y', 'n']:
            return confirmation.strip().lower() == 'y'  # Returns True if 'y', False if 'n'
        elif confirmation.strip().lower() == "/q":
            exit(0)  # Additional handling if '/q' is entered
        else:
            print("Invalid input.\n")  # Informs the user of invalid input and repeats the prompt

def main():
    """
    This is the main function of the script. It parses command-line arguments to determine the operation mode,
    such as updating, downgrading, or setting the configuration for the wallet client update process.
    Based on the selected command and options, it carries out the necessary actions.
    """
    # Assign GitHub repository owner and name to variables.
    owner, repo = "The-Sycorax", "DenaroWalletClient"

    # Initialize the argument parser for command-line interface with a description.
    parser = argparse.ArgumentParser(description="Update the DenaroWalletClient based on configuration or manually.")
    # Create subparsers for the main parser to handle different commands.
    subparsers = parser.add_subparsers(dest='command')

    # Add a sub-parser for the 'update' command to the main parser.
    parser_update = subparsers.add_parser('update')
    # Add subparsers for the 'update' command for further subcommands.
    update_subparsers = parser_update.add_subparsers(dest='update_command')

    # Add a 'manual' sub-parser under the 'update' sub-parser.
    parser_manual = update_subparsers.add_parser('manual')
    # Add arguments for the 'manual' update sub-command to specify the update channel and version.
    parser_manual.add_argument("-channel", required=True, help="Update channel (stable/beta/dev).", choices=['stable', 'beta', 'dev'])
    parser_manual.add_argument("-version", help="Specifies the version to update to.")

    # Add an 'auto' sub-parser under the 'update' sub-parser.
    parser_auto = update_subparsers.add_parser('auto')
    # Add an option to the 'auto' sub-command to disable the confirmation prompt.
    parser_auto.add_argument("-disable-prompt", dest='disable_prompt', action='store_true', help="Disables confirmation prompt when performing an automatic update.")

    # Add a sub-parser for the 'downgrade' command to the main parser.
    parser_downgrade = subparsers.add_parser('downgrade')
    # Add arguments for the 'downgrade' command to specify the update channel and version.
    parser_downgrade.add_argument("-channel", help="Update channel (stable/beta).", choices=['stable', 'beta'])
    parser_downgrade.add_argument("-version", required=True, help="Specifies the version to downgrade to.")
    # Add an option to the 'downgrade' command to disable the confirmation prompt.
    parser_downgrade.add_argument("-disable-prompt", dest='disable_prompt', action='store_true', help="Disables confirmation prompt when performing a downgrade.")

    # Add a sub-parser for 'setconfig' command to update the configuration.
    parser_setconfig = subparsers.add_parser('setconfig')
    # Add an argument for the 'setconfig' command to specify the default update channel.
    parser_setconfig.add_argument("-channel", required=True, help="Set default channel to update from (stable/beta/dev).", choices=['stable', 'beta', 'dev'])

    # Parse the arguments passed to the command line.
    args = parser.parse_args()

    # Execute the appropriate action based on the command provided.
    if args.command == 'setconfig':
        disable_err_msg = True
        # Read existing configuration from a file or create a new one if it doesn't exist.
        config = read_config(disable_err_msg = True) or {}
        # Update the configuration dictionary with the channel specified in the command line argument.
        config['channel'] = args.channel
        # Write the updated configuration back to the file.
        if write_config(config):
            # Log the information that the update channel has been set.
            logging.info(f" Update channel set to {args.channel}. Run an auto update to use this channel.")

    elif args.command == 'update':
        # Execute the update process if the 'update' command is provided.
        if args.update_command == 'manual':
            # For manual update, read the existing configuration or create a new one.
            config = read_config() or {}
            # Determine whether the update channel is a beta release.
            prerelease_flag = args.channel == 'beta'
            # Log the chosen update channel.
            logging.info(f"Update channel set to {args.channel}.")

            if args.channel == 'dev':
                # If the dev channel is chosen, fetch the latest commit SHA.
                logging.info(" Fetching the latest commit on the dev channel.")
                commit_sha = fetch_latest_commit_sha(owner, repo)
                # Check if fetching the latest commit SHA was successful.
                if not commit_sha:
                    # Log an error and exit if fetching the commit SHA failed.
                    logging.error(" Failed to fetch the latest commit for the 'dev' channel.")
                    exit(1)
                elif commit_sha == config.get('commit_sha'):
                    # If the current version is the same as the specified, log the information and exit.
                    logging.info(f" The wallet client is already at the latest dev version.")
                    exit(0)
                # No need to check for downgrades in the dev channel, update to the latest commit.
                msg = " Updating wallet client to the latest commit."
                perform_update(owner, repo, commit_sha, msg)
            else:
                # For stable or beta channels, fetch all releases to check for downgrades.
                all_releases = fetch_releases(owner, repo, prerelease_flag, get_all=True)
                
                if args.version:
                    # If a specific version is provided, log the action of fetching it.
                    logging.info(f" Fetching version: {args.version}")
                    # Verify if the provided version exists and fetch its commit SHA.
                    commit_sha = verify_version(owner, repo, args.version, prerelease_flag)
                    # Check if fetching the commit SHA was successful.
                    if not commit_sha:
                        # Log an error and exit if the specified version is not found.
                        logging.error(f"Version '{args.version}' not found.")
                        exit(1)
                    elif commit_sha == config.get('commit_sha'):
                        # If the current version is the same as the specified, log the information and exit.
                        logging.info(f" The wallet client is already at version {args.version}.")
                        exit(0)
                    
                    # Check if attempting to downgrade.
                    if is_downgrade(config.get('commit_sha'), commit_sha, all_releases):
                        # Log an error and exit if a downgrade is attempted without using the 'downgrade' command.
                        logging.error(f" The version specified is lower than one currently in use. Please use the 'downgrade' argument if you wish to use an older version.")
                        exit(1)

                    # Fetch the file tree for the specified commit SHA.
                    if not fetch_tree_from_sha(owner, repo, commit_sha):
                        # Exit if fetching the file tree failed.
                        exit(1)
                    else:
                        # If the tree is fetched successfully, perform the update.
                        msg = f" Updating wallet client to version {args.version}."
                        perform_update(owner, repo, commit_sha, msg)
                else:
                    # If no version is specified, fetch the latest release for the specified channel.
                    logging.info(f" Fetching the latest '{args.channel}' release.")
                    _, commit_sha = fetch_releases(owner, repo, prerelease=prerelease_flag, get_all=False)
                    # Check if the current commit SHA matches the latest commit SHA.
                    if commit_sha == config.get('commit_sha'):
                        # Log the information that the client is already at the latest version and exit.
                        logging.info(f"The wallet client is already at the latest {args.channel} release.")
                        exit(0)
                    
                    # Fetch the file tree for the latest commit SHA.
                    if not fetch_tree_from_sha(owner, repo, commit_sha):
                        # Exit if fetching the file tree failed.
                        exit(1)
                    else:
                        # If the tree is fetched successfully, perform the update.
                        msg = f" Updating wallet client to the latest {args.channel} release."
                        perform_update(owner, repo, commit_sha, msg)

            # After a successful manual update, update the commit SHA in the configuration.
            config['commit_sha'] = commit_sha
            # Write the updated configuration back to the file.
            write_config(config)       

        elif args.update_command == 'auto':
            # For the automatic update process, read the existing configuration.
            config = read_config()
            # Exit if the configuration file does not exist or cannot be read.
            if config is None:
                exit(1)

            # Check if the update channel is set and valid in the configuration.
            if 'channel' not in config or config['channel'] not in ['stable', 'beta', 'dev']:
                # Log an error and exit if the update channel is not set or invalid.
                logging.error(" Update channel is not set or invalid in the config file. Please set a valid channel using 'setconfig'.")
                exit(1)

            # Retrieve the update channel from the configuration.
            channel = config.get('channel')
            # Determine whether the update channel is a beta release.
            prerelease_flag = channel == 'beta'
            # Determine whether the update is for the development channel.
            is_dev = channel == 'dev'
            # Check if the commit SHA is present in the configuration.
            if 'commit_sha' not in config:
                # Log the update channel set in the configuration.
                logging.info(f" Update channel set to: '{channel}' in the config file.")
                # Fetch the latest release or commit SHA based on the update channel.
                logging.info(f" Fetching the latest '{channel}' release.")
                if not is_dev:
                    _, latest_commit_sha = fetch_releases(owner, repo, prerelease=prerelease_flag, get_all=False)
                else:
                    latest_commit_sha = fetch_latest_commit_sha(owner, repo)
                # Exit if fetching the file tree for the latest commit SHA failed.
                if not fetch_tree_from_sha(owner, repo, latest_commit_sha):
                    exit(1)
                else:
                    # If the tree is fetched successfully, perform the update.
                    msg = f" Updating wallet client to the latest {channel} release."
                    perform_update(owner, repo, latest_commit_sha, msg)
                    # Update the commit SHA in the configuration with the latest one after update.
                    config['commit_sha'] = latest_commit_sha
                    # Write the new configuration back to the configuration file.
                    write_config(config)
            else:
                # If commit SHA exists in the configuration, log the current update channel.
                logging.info(f" Update channel set to: '{channel}' in the config file.")
                # Fetch the latest release for the current update channel.
                logging.info(f" Fetching the latest '{channel}' release.")
                # Retrieve the stored commit SHA from the configuration.
                stored_commit_sha = config['commit_sha']
                # Check if there is an update available by comparing the stored commit SHA with the latest commit SHA.
                is_update_available, latest_commit_sha = check_for_update(owner, repo, stored_commit_sha, prerelease_flag, is_dev)

                # If an update is available, proceed with the update process.
                if is_update_available:
                    # Initialize the confirmation flag for the automatic update.
                    auto_update_confirmed = False
                    # If the prompt is not disabled, ask the user for confirmation to update.
                    if not args.disable_prompt:
                        if confirmation_prompt("An update for the wallet client is available. Would you like to continue? [y/n]:"):
                            auto_update_confirmed = True
                    else:
                        # If the prompt is disabled, set the confirmation flag to True directly.
                        auto_update_confirmed = True
                    
                    # If the update is confirmed, either by the user or because the prompt was disabled, perform the update.
                    if auto_update_confirmed:
                        # Log the action of updating the wallet client to the latest release.
                        msg = f" Updating wallet client to the latest {channel} release."
                        # Perform the update with the latest commit SHA.
                        perform_update(owner, repo, latest_commit_sha, msg)
                        # Update the commit SHA in the configuration with the latest one after update.
                        config['commit_sha'] = latest_commit_sha
                        # Write the new configuration back to the configuration file.
                        write_config(config)
                    else:
                        # If the update is canceled by the user, log the cancellation.
                        logging.info(" Update canceled by the user.")
                else:
                    # If no update is needed, log that the current version is already up to date.
                    logging.info(f" No update needed. You already have the latest {channel} release.")

    elif args.command == 'downgrade':
        # If the 'downgrade' command is provided, read the existing configuration or create a new one.
        config = read_config() or {}
        # If the channel is not specified in the arguments, use the one from the configuration.
        if not args.channel:
            logging.info(" -channel is not set. Using the update channel specified in the config file.")
            # Check if the channel in the configuration is valid.
            if 'channel' in config and config['channel'] in ['stable', 'beta']:
                channel = config['channel']
                logging.info(f" Update channel set to: '{channel}'")
            else:
                # If the channel is not set or invalid, log an error and exit.
                logging.error(" Update channel is not set or invalid in the config file. Please set a valid channel using 'setconfig'.")
                exit(1)
        else:
            # If the channel is specified in the arguments, use that one.
            channel = args.channel
            logging.info(f" Update channel set to: '{channel}'")
        
        # If no channel is determined, log an error and exit.
        if not channel:
            logging.error(" Update channel is not set. Please use the -channel option or set a valid channel using 'setconfig'.")
            exit(1)

        # Determine if the specified channel is a prerelease.
        prerelease_flag = (channel == 'beta')
    
        # Fetch all releases for the given owner and repo.
        all_releases = fetch_releases(owner, repo, prerelease_flag, get_all=True)
        # Verify the specified version for the downgrade and fetch its commit SHA.
        target_commit_sha = verify_version(owner, repo, args.version, prerelease_flag)
        # If the target commit SHA is not fetched, exit.
        if not fetch_tree_from_sha(owner, repo, target_commit_sha):
            exit(1)
        else:
            # If the commit SHA is fetched, check if it matches the stored commit SHA.
            if not target_commit_sha:
                logging.error(f"Version '{args.version}' not found.")
                exit(1)
            elif target_commit_sha == config.get('commit_sha'):
                logging.info(f" The wallet client is already at version {args.version}.")
                exit(0)
            # Check if the specified version is indeed older than the current version.
            if not is_downgrade(config.get('commit_sha'), target_commit_sha, all_releases):
                logging.error(f" The version specified is higher than one currently in use. Please use the 'update' argument if you wish to use a newer version.")
                exit(1)
            else:
                # If the specified version is older, confirm with the user if the prompt is not disabled.
                downgrade_confirmed = False
                if not args.disable_prompt:
                    msg = f"You are attempting to downgrade to version {args.version}. Are you sure you want to continue? [y/n]: "
                    if confirmation_prompt(msg):
                        downgrade_confirmed = True
                else:
                    # If the prompt is disabled, set the confirmation flag to True directly.
                    downgrade_confirmed = True
                # If the downgrade is confirmed, proceed with the process.
                if downgrade_confirmed:
                    # Log the action of downgrading to the specified version.
                    msg = f" Downgrading to version {args.version}."
                    # Perform the downgrade with the target commit SHA.
                    perform_update(owner, repo, target_commit_sha, msg)
                    # Update the commit SHA in the configuration with the target one after downgrade.
                    config['commit_sha'] = target_commit_sha
                    # Write the new configuration back to the configuration file.
                    write_config(config)
                else:
                    # If the downgrade is canceled by the user, log the cancellation.
                    logging.info(" Downgrade canceled by the user.")    
    else:
        # If no command is provided, or an unrecognized one is given, print the help message.
        parser.print_help()

if __name__ == "__main__":
    main()  # Execute the main function.