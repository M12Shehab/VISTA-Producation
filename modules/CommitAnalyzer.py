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


import spacy
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import os

from modules.System_logging import setup_project_logger
from modules.configuration import project_name

log = setup_project_logger(project_name)


class CommitAnalyzer:
    def __init__(self, cve_data, sem_threshold=0.75, syn_threshold=0.50, Debug=False, version="advanced"):
        """
        :param cve_data: List of dictionaries containing CVE information
        :param sem_threshold: the semantic similarity threshold, range [0, 1], default is 0.75
        :param syn_threshold: the syntactic similarity threshold, range [0, 1], default is 0.5
        """
        self.cve_data = cve_data
        self.syn_threshold = syn_threshold
        self.sem_threshold = sem_threshold
        self.nlp = None
        self.Debug = Debug
        self.version = version
        # try to load the spacy model
        try:
            self.nlp = spacy.load("en_core_web_lg")
        except Exception as e:
            log.error(f"Error loading spacy model: {e}")

            # if the model is not found, download it
            print("Downloading spacy model...")
            log.info("Downloading spacy model...")
            os.system("python -m spacy download en_core_web_lg")
            try:
                log.info("Loading spacy model after failure...")
                self.nlp = spacy.load("en_core_web_lg")
                log.info("Spacy model loaded successfully")
            except Exception as e:
                log.error(f"Error after loading spacy model: {e}")
                raise Exception(f"Error loading spacy model: {e}")

    def analyze_commits(self, commits_info, num_workers=4):
        chunk_size = (len(commits_info) + num_workers - 1) // num_workers
        commit_chunks = [commits_info[i * chunk_size:(i + 1) * chunk_size] for i in range(num_workers)]
        all_linked_commits = []

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(self.process_commit_chunk, chunk, idx): chunk for idx, chunk in enumerate(commit_chunks)
            }
            for future in as_completed(futures):
                all_linked_commits.extend(future.result())

        return all_linked_commits

    def process_commit_chunk(self, commits, thread_id):
        """
        Each thread processes a chunk of commits
        :param commits: part of commits to process
        :param thread_id: thread id to keep track the progress
        :return: the fixed commits linked to vulnerabilities
        """
        linked_commits = []
        log.info(f"Thread {thread_id} started processing {len(commits)} commits")
        print(f"Thread {thread_id} started processing {len(commits)} commits")
        for idx, commit in enumerate(commits):
            if self.version == "advanced":
                is_vulnerable, severity, cve_id, sem_similarity, syn_similarity = self.check_vulnerability(commit)
                if is_vulnerable:
                    linked_commits.append({
                        'commit': commit,
                        'severity': severity,
                        'cve_id': cve_id,
                        'sem_similarity': sem_similarity,
                        'syn_similarity': syn_similarity
                    })
            else: # Run only V-SZZ
                is_vulnerable, severity, cve_id, commit_msg, keyword = self.check_vulnerability_szz(commit)
                if is_vulnerable:
                    linked_commits.append({
                        'commit': commit,
                        'severity': severity,
                        'cve_id': cve_id,
                        'commit_msg': commit_msg,
                        'keyword': keyword
                    })

            if idx % 100 == 0:
                log.info(f"Thread {thread_id} processed {idx + 1} commits out of {len(commits)}")
                print(f"Thread {thread_id} processed {idx + 1} commits out of {len(commits)}")
        log.info(f"Thread {thread_id} linked {len(linked_commits)} commits")
        print(f"Thread {thread_id} linked {len(linked_commits)} commits")
        return linked_commits

    def check_vulnerability(self, commit):
        for cve in self.cve_data:
            cve_id = cve['CVE_ID']
            description = cve['Description']
            severity = cve['Severity']

            if cve_id in commit['msg']:
                return True, severity, cve_id, 1.0, 1.0

            token1 = self.nlp(description)
            token2 = self.nlp(commit['msg'])
            sem_similarity = token1.similarity(token2)
            syn_similarity = SequenceMatcher(None, description, commit['msg']).ratio()
            if self.Debug:
                print(f"DEBUG: Semantic similarity: {sem_similarity}, syntactic similarity {syn_similarity}")
            if sem_similarity >= self.sem_threshold and syn_similarity >= self.syn_threshold:
                return True, severity, cve_id, sem_similarity, syn_similarity

            for modified_file in commit.get('modified_files', []):
                if cve_id in modified_file.get('source_code', ''):
                    return True, severity, cve_id, sem_similarity, syn_similarity
            if self.version == "hybrid":
                keywords = ['fix', 'vulnerability', 'security', 'patch','flaw', 'cve']

                #Check if the commit message contains any of the keywords
                for keyword in keywords:
                    if keyword in commit['msg'].lower():
                        return True, severity, cve_id, commit['msg'], keyword

        return False, None, None, 0.0, 0.0

    def check_vulnerability_szz(self, commit):
        for cve in self.cve_data:
            cve_id = cve['CVE_ID']
            description = cve['Description']
            severity = cve['Severity']
            keywords = ['fix', 'vulnerability', 'security', 'patch','flaw', 'cve']
            if cve_id in commit['msg']:
                return True, severity, cve_id, commit['msg'], f'Find CVE ID: {cve_id}'

            # Check if the commit message contains any of the keywords
            for keyword in keywords:
                if keyword in commit['msg'].lower():
                    return True, severity, cve_id, commit['msg'], keyword

        return False, None, None, None, None
