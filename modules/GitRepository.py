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
from pygit2 import Repository, GIT_SORT_TOPOLOGICAL, GIT_SORT_REVERSE


class GitRepository:
    def __init__(self, repo_path, branch_name):
        self.repo_path = repo_path
        self.branch_name = branch_name
        self.repo = self._initialize_repository()
        self.commits = self._load_commits()

    def _initialize_repository(self):
        if not os.path.exists(self.repo_path):
            raise FileNotFoundError(f"Repository not found at {self.repo_path}")
        return Repository(self.repo_path)

    def _load_commits(self):
        branch = f"refs/tags/{self.branch_name}"
        head = self.repo.references.get(branch)
        if head is None:
            branch = f"refs/heads/{self.branch_name}"
            head = self.repo.references.get(branch)
        if head is None:
            raise ValueError("Please check the branch name!")
        commits = list(self.repo.walk(head.target, GIT_SORT_TOPOLOGICAL | GIT_SORT_REVERSE))
        print(f"+++ {len(commits)} commits loaded from branch '{self.branch_name}'")
        return commits
