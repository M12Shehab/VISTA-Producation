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

from pydriller import Repository
from modules.configuration import file_ext_to_parse, project_name
from modules.System_logging import setup_project_logger

log = setup_project_logger(project_name)


class CommitLoader:
    def __init__(self, repo_path, branch="trunk"):
        self.repo_path = repo_path
        self.branch = branch

    def load_commits(self, test_mode=False):
        repo = Repository(self.repo_path, only_in_branch=self.branch, only_no_merge=True)
        commits = []

        if self.repo_path != "test_repo_path":
            for i, commit in enumerate(repo.traverse_commits()):
                if test_mode and len(commits) >= 100:
                    break
                # Basic commit information
                commit_info = {
                    'hash': commit.hash,
                    'msg': commit.msg,
                    'author': commit.author.name,
                    'author_date': commit.author_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'commit_time': commit.committer_date.strftime('%Y-%m-%d %H:%M:%S')

                }

                # Only process modified files if they exist and are needed
                files = []
                if commit.modified_files:
                    for modified_file in commit.modified_files:
                        if modified_file.old_path and modified_file.filename.split('.')[-1] in file_ext_to_parse and modified_file.source_code:
                            # Only add necessary data to minimize memory usage
                            files.append({
                                'filename': modified_file.filename,
                                'old_path': modified_file.old_path,
                                'new_path': modified_file.new_path,
                                'change_type': modified_file.change_type.name,
                                'added':[item for item in modified_file.diff_parsed['added'] if item[1] != ''],
                                'deleted': [item for item in modified_file.diff_parsed['deleted'] if item[1] != ''],
                                'source_code': modified_file.source_code[:4096]  # Limit to first 4KB or as needed
                            })
                commit_info['files'] = files
                commit_info['has_files'] = True if len(files) > 0 else False
                commits.append(commit_info)
                # Log progress every 100 commits instead of each one
                if i % 100 == 0:
                    log.info(f"Processed {i + 1} commits...")

        log.info(f"Total commits loaded: {len(commits)}")

        return commits
