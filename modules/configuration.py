"""
 __author__ = "Mohammed Shehab"
 __copyright__ = "Copyright (c) 2024 Mohammed Shehab"
 __credits__ = ["Mohammed Shehab", "Safwan Omari", "Yaser Jararweh"]
 __license__ = "MIT License"
 __version__ = "1.0.0"
 __maintainer__ = "Mohammed Shehab"
 __email__ = "shihab@live.cn"
 __status__ = "Development"
"""

import json
import os
from git import Repo


def load_configuration(config_file="config.json"):
    default_config = {
        "project_name": "impala",
        "code_repository_path": "C:/Users/Shehab/Downloads/impala",
        "repo_url": "https://github.com/apache/impala.git",
        "repository_branch": "main",    # trunk, master
        "file_ext_to_parse": ["cpp", "c", "h", "hpp"],
        "num_workers": 1,
        "nvd_api_key": "ADD_YOUR_NVD_API_KEY"
    }

    if not os.path.exists(config_file):
        print(f"Configuration file {config_file} not found. Using default configuration.")
        return default_config
    print(f"Loading configuration from {config_file}.")
    with open(config_file, "r") as f:
        return json.load(f)

# Load configuration
config = load_configuration(config_file="./config.json")

# Access configuration variables
project_name = config["project_name"]
code_repository_path = config["code_repository_path"]
file_ext_to_parse = config["file_ext_to_parse"]
num_workers = config["num_workers"]
repository_branch = config.get("repository_branch", "main")
repo_url = config.get("repo_url", f"https://github.com/apache/impala.git")

# Todo: remove the default NVD API key
nvd_api_key = config.get("nvd_api_key", "ADD_YOUR_NVD_API_KEY")

print("Checking if the code repository exists...")
if not os.path.isdir(code_repository_path):
    print(f"Code repository not found at {code_repository_path}. Cloning from {repo_url}...")
    try:
        Repo.clone_from(url=repo_url, to_path=code_repository_path)
        print("Code repository cloned successfully.")
    except Exception as e:
        print(f"Error cloning repository: {e}")
        exit(4)