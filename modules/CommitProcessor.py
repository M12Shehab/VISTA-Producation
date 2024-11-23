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

import threading

from datetime import datetime
import pandas as pd

from modules.VulnerabilityScanner import VulnerabilityScanner
from modules.GitRepository import GitRepository


class CommitProcessor:
    def __init__(self, repository: GitRepository, scanner: VulnerabilityScanner, chunk_size=1000):
        self.repository = repository
        self.scanner = scanner
        self.chunk_size = chunk_size
        self.commit_labels = list()
        self.threads = []
        self.completed_threads = 0
        self.lock = threading.Lock()

    def export_to_csv(self, data, file_path, columns):
        df = pd.DataFrame(data.items(), columns=columns)
        df.to_csv(f'./CSV/{file_path}.csv', index=False, header=True)

    def process_commit_chunk(self, commits, thread_id):
        for commit in commits:
            self._process_single_commit(commit)
        print(f"Thread {thread_id} processed {len(commits)} commits.")

    def _process_single_commit(self, commit):
        commit_id = commit.hex
        previous_commit = commit.parents[0] if commit.parents else None
        if not previous_commit:
            return

        try:
            diff = self.repository.repo.diff(previous_commit, commit)
            vulnerabilities = {}
            for patch in diff:
                if patch.delta.is_binary:
                    continue
                file_path = patch.delta.new_file.path
                # check if the file extension is in the list of extensions to parse
                if file_path.split('.')[-1] in self.scanner.file_ext_to_parse:
                # if file_path.endswith('.c'):
                    issues, output = self.scanner.scan_file(file_path)
                    for issue in issues:
                        line = self.scanner.process_issue(output, issue)
                        if issue in self.scanner.vulnerabilities_info:
                            self.scanner.vulnerabilities_info[issue] += 1
                        else:
                            self.scanner.vulnerabilities_info[issue] = 1
                        if issue not in vulnerabilities:
                            vulnerabilities[issue] = [line]
                        else:
                            vulnerabilities[issue].append(line)
            if len(vulnerabilities) > 0:
                self.lock.acquire()
                readable_time = datetime.fromtimestamp(commit.commit_time).strftime('%Y-%m-%d %H:%M:%S')
                commit_result = {"hash_introduced": commit_id,
                                 "vulnerable_time": readable_time,
                                 "vulnerabilities": vulnerabilities}
                self.commit_labels.append(commit_result)
                self.lock.release()
            # self.commit_labels[commit_id] = vulnerabilities
        except Exception as e:
            print(f"Failed to process commit {commit_id}: {e}")

    def process_all_commits(self):
        chunked_commits = [self.repository.commits[i:i + self.chunk_size] for i in
                           range(0, len(self.repository.commits), self.chunk_size)]
        for i, chunk in enumerate(chunked_commits):
            thread = threading.Thread(target=self.process_commit_chunk, args=(chunk, i + 1))
            self.threads.append(thread)
            thread.start()
        for thread in self.threads:
            thread.join()
        print("All commits processed.")

    # def get_results(self):
    #     return self.commit_labels#, self.scanner.vulnerabilities_info
