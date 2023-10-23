import requests
import json
from hashlib import sha1
from pathlib import Path
import os
import shutil
from datetime import datetime

class Repository:
    def __init__(self, repo_owner, repo_name, branch='main', local_dir='.', data_file='github_data.json'):
        self.local_dir = Path(local_dir)
        self.data_file = self.local_dir / data_file
        if not self.data_file.exists():
            self.data_file.write_text("{}")
        if not self.local_dir.exists():
            raise FileNotFoundError("{} does not exist".format(local_dir))
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.branch = branch
        self.urls = {
            'tree': f'https://api.github.com/repos/{repo_owner}/{repo_name}/git/trees/{branch}?recursive=1',
            'download': f'https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{branch}/',
            'last_commit_sha': f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/HEAD/branches-where-head",
        }
        with self.data_file.open(mode='r') as f:
            self.saved_data = json.load(f)

    def get_tree_data(self):
        result = dict()
        tree_url = self.urls['tree']
        tree_data = json.loads(requests.get(tree_url).content)
        for item in tree_data['tree']:
            if item['type'] == 'blob':
                result[item['path']] = item
        tree_data['tree'] = result
        return tree_data

    def download_files(self, paths, max_download_size=float('inf')):
        for p in paths:
            download_url = self.urls['download'] + p
            file_size_bytes = int(requests.head(download_url).headers['Content-Length'])
            file_size = file_size_bytes
            file_size_str = "Bytes"
            if file_size > 1024:
                file_size_str = "KB"
                file_size /= 1024
            if file_size > 1024:
                file_size_str = "MB"
                file_size /= 1024
            file_size_str = f"{file_size:.2f} {file_size_str}"
            if file_size_bytes > max_download_size:
                print("Skipping {} ({})".format(p, file_size_str))
                continue
            print("Downloading {} ({})...".format(p, file_size_str), end="\t")
            if not (self.local_dir / p).parent.exists():
                (self.local_dir / p).parent.mkdir(parents=True)
            with (self.local_dir / p).open(mode='wb') as f:
                response = requests.get(download_url, stream=True)
                if response.status_code != 200:
                    print("[ERROR]")
                    continue
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            print("[OK]")
    
    def backup_local_files(self):
        # Create a backup folder with a timestamp
        os.makedirs("old_versions", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_folder = f"old_versions/backup_{timestamp}"
        # Create the specific backup folder
        os.makedirs(backup_folder, exist_ok=True)
         # Backup all files and folders except 'master.zip' and 'temp_folder'
        for item in os.listdir("."):
            if item not in ["env","old_versions"]:
                src_path = os.path.join(".", item)
                dest_path = os.path.join(backup_folder, item)
                if os.path.isdir(src_path):
                    shutil.copytree(src_path, dest_path)
                else:
                    shutil.copy2(src_path, dest_path)
        print(f'Backup saved to: {backup_folder}\n')

    def get_head_sha(self, timeout=5):
        response = requests.get(self.urls['last_commit_sha'], timeout=timeout)
        if response.status_code == 200:
            branches = json.loads(response.content)
            for b in branches:
                if b['name'] == self.branch:
                    return b['commit']['sha']
        return None

    @staticmethod
    def calc_sha(data):
        if type(data) is str:
            data = Path(data)
        if isinstance(data, Path):
            data = data.read_bytes()
        return sha1(f"blob {len(data)}\0".encode() + data).hexdigest()

    def auto_update(self, max_download_size=float('inf')):
        tree_data = self.get_tree_data()
        to_download = []
        for path, data in tree_data['tree'].items():
            if not (self.local_dir / path).exists():
                to_download.append(path)
            else:
                local_sha = self.calc_sha(self.local_dir / path)
                if local_sha != data['sha']:
                    to_download.append(path)
        if len(to_download) > 0:
            update, backup = Repository.prompt_for_update()
            if backup:
                self.backup_local_files()                
            if update:
                self.download_files(to_download, max_download_size)
                print("\nFinished updating")
                print("Please run wallet client again.")
                updated = True
            else:
                updated = False              
        else:
            print("Wallet client is up to date")
            updated = False
        self.saved_data['sha'] = tree_data['sha']
        self.data_file.write_text(json.dumps(self.saved_data))            
        return updated

    def prompt_for_update():
        print("An Update is Available")            
        while True:
            prompt_for_update = input("Would you like to update the wallet client? (y/n): ")
            if prompt_for_update.lower() == 'y':
                while True:
                    prompt_for_backup = input("Would you like to backup your current version? (y/n): ")
                    if prompt_for_backup.lower() == 'y':
                        print()
                        return True, True
                    elif prompt_for_backup.lower() == 'n':
                        return True, False
                    else:
                        print("Invalid choice. Please enter 'y' or 'n'.")
                        print()
            elif prompt_for_update.lower() == 'n':
                return False, False
            else:
                print("Invalid choice. Please enter 'y' or 'n'.")
                print()
    
    def check_for_updates(self, timeout=5):
        if "sha" not in self.saved_data:
            if Repository.auto_update(self):
                return True
            else: 
                return False
        elif self.get_head_sha(timeout) != self.saved_data['sha']:
            if Repository.auto_update(self):
                return True
            else: 
                return False
        else:
            if Repository.auto_update(self):
                return True
            else: 
                return False