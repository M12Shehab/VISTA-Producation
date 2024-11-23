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

import os
import json


class DataHandler:
    def __init__(self, base_dir="."):
        """
        Initializes the DataHandler with a base directory where files will be saved or loaded.
        """
        self.base_dir = base_dir

    def save_to_json(self, keyword, data, process_type="vulnerabilities"):
        """
        Saves data to a JSON file within a directory named after the keyword.

        Parameters:
            keyword (str): The directory and file prefix.
            data (dict or list): Data to save in JSON format.
            process_type (str): A suffix to specify the type of data (e.g., 'vulnerabilities').
        """
        dir_name = os.path.join(self.base_dir, keyword)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)

        file_path = os.path.join(dir_name, f"{keyword}_{process_type}.json")
        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)

        print(f"Data saved to {file_path}")

    def load_json(self, keyword, process_type="vulnerabilities"):
        """
        Loads data from a JSON file in the specified directory.

        Parameters:
            keyword (str): The directory and file prefix.
            process_type (str): A suffix specifying the type of data (e.g., 'vulnerabilities').

        Returns:
            dict or list: The loaded JSON data.
        """
        file_path = os.path.join(self.base_dir, keyword, f"{keyword}_{process_type}.json")
        try:
            with open(file_path, 'r') as json_file:
                data = json.load(json_file)
            return data
        except FileNotFoundError:
            return None
