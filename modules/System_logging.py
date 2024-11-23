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

import logging
import os

from modules.configuration import project_name

log_folder = '../logger'
os.makedirs(log_folder, exist_ok=True)

# Define the log file name based on the project name
log_file = os.path.join(log_folder, f'log_{project_name}.log')


def setup_project_logger(project_name):
    # Create the logger folder if it doesn't exist
    os.makedirs(log_folder, exist_ok=True)

    # Define the log file name based on the project name
    log_file = os.path.join(log_folder, f'log_{project_name}.log')

    # Create a custom logger for the project
    logger = logging.getLogger(project_name)
    logger.setLevel(logging.DEBUG)  # Set level to DEBUG to capture all messages

    # Create a file handler to write logs to the project-specific log file
    file_handler = logging.FileHandler(log_file, mode='w')
    file_handler.setLevel(logging.DEBUG)

    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Add the file handler to the custom logger
    logger.addHandler(file_handler)

    # Prevent the logger from propagating messages to the root logger
    logger.propagate = False

    return logger

