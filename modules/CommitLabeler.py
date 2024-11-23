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

from typing_extensions import List

from modules.szz_versions.ma_szz import MASZZ
from modules.configuration import code_repository_path, file_ext_to_parse
from modules.System_logging import setup_project_logger

log = setup_project_logger("CommitLabeler")


class CommitLabeler:
    def __init__(self, project_name: str, repo_url: str, commits: List, linked_commits: List):
        """
        :param project_name: The name of the project
        :param repo_url: the GitHub repository url
        :param commits: list
        of commits information
        :param linked_commits: list of commits linked to vulnerabilities. Usually these
        commits are the ones that fix the vulnerabilities. And we need to trace back to find the commits that
        introduced the vulnerability
        """
        if not project_name or not repo_url or not commits or not linked_commits:
            log.error("Wrong initialization: One of the parameters is empty")
            raise ValueError("Wrong initialization: One of the parameters is empty")
        self.project_name = project_name
        self.repo_url = repo_url
        self.commits = commits
        self.linked_commits = linked_commits
        self.ma_szz = MASZZ(project_name, repo_url=repo_url, repos_dir=code_repository_path, use_temp_dir=False)

    def label_data_szz(self):
        vulnerable_intro = []
        log.info("Labeling data using MA-SZZ algorithm")
        print("Labeling data using MA-SZZ algorithm")
        if self.project_name != "test_repo_path":
            for id, commit in enumerate(self.linked_commits):
                impacted_files, fixed_commit = self.ma_szz.get_impacted_files(commit['commit'], file_ext_to_parse=file_ext_to_parse)
                bug_introducing_commits = self.ma_szz.find_bic(commit['commit'], impacted_files)

                for bic in bug_introducing_commits:
                    vulnerable_intro.append({
                        "bug_pattern": commit['cve_id'],
                        "hash_fix": commit['commit']['hash'],
                        "hash_introduced": bic.hexsha,
                        "fixing_time": commit['commit']['commit_time'],
                        "vulnerable_time": bic.committed_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                        "severity": commit['severity']
                    })
                if id % 10 == 0:
                    log.info(f"Processed {id + 1} commits out of {len(self.linked_commits)}")
                    print(f"Processed {id + 1} commits out of {len(self.linked_commits)}")
        return vulnerable_intro