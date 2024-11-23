"""
__author__ = "Author Name"
 __copyright__ = "Copyright (c) 2024 Author Name"
 __credits__ = ["Contributor1", "Contributor2"]
 __license__ = "MIT License"
 __version__ = "1.0.0"
 __maintainer__ = "Author Name"
 __email__ = "author.email@example.com"
 __status__ = "Development"
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.CommitAnalyzer import CommitAnalyzer


class TestCommitAnalyzer(unittest.TestCase):
    def setUp(self):
        # Sample CVE data
        self.cve_data = [
            {'CVE_ID': 'CVE-124', 'Description': 'Sample vulnerability description', 'Severity': 'High'}
        ]
        # Initialize CommitAnalyzer instance
        self.analyzer = CommitAnalyzer(self.cve_data, sem_threshold=0.75, syn_threshold=0.50)

    @patch('spacy.load')
    def test_spacy_model_load_success(self, mock_spacy_load):
        # Test successful loading of the Spacy model
        mock_spacy_load.return_value = MagicMock()
        analyzer = CommitAnalyzer(self.cve_data)
        self.assertIsNotNone(analyzer.nlp)

    @patch('spacy.load', side_effect=Exception("Model loading error"))
    @patch('os.system')
    def test_spacy_model_load_failure_and_download(self, mock_os_system, mock_spacy_load):
        # Test fallback when loading Spacy model fails, triggering download
        with self.assertRaises(Exception):
            CommitAnalyzer(self.cve_data)

        mock_os_system.assert_called_once_with("python -m spacy download en_core_web_lg")

    @patch.object(CommitAnalyzer, 'process_commit_chunk', return_value=[{'commit': {'msg': 'Test commit'}, 'severity': 'High', 'cve_id': 'CVE-1234'}])
    def test_analyze_commits(self, mock_process_commit_chunk):
        # Sample commit data
        commits_info = [{'msg': 'Fix CVE-1234 vulnerability'}]
        linked_commits = self.analyzer.analyze_commits(commits_info, num_workers=2)
        self.assertEqual(len(linked_commits), 2)
        self.assertEqual(linked_commits[0]['commit']['msg'], 'Test commit')
        mock_process_commit_chunk.assert_called()

    @patch('spacy.load')
    def test_check_vulnerability_cve_in_commit_msg(self, mock_spacy_load):
        # Mock Spacy NLP object and test for direct CVE_ID match
        mock_spacy_load.return_value = MagicMock()
        commit = {'msg': 'Fix CVE-1234 vulnerability', 'modified_files': []}
        is_vulnerable, severity, cve_id, sem_similarity, syn_similarity = self.analyzer.check_vulnerability(commit)
        self.assertTrue(is_vulnerable)
        self.assertEqual(severity, 'High')
        self.assertEqual(cve_id, 'CVE-1234')

    @patch('spacy.load')
    def test_check_vulnerability_semantic_similarity(self, mock_spacy_load):
        # Mock Spacy NLP similarity for semantic similarity threshold check
        mock_spacy = MagicMock()
        mock_spacy.similarity.return_value = 0.8  # Above threshold
        mock_spacy_load.return_value = mock_spacy
        commit = {'msg': 'This commit addresses vulnerability in the system', 'modified_files': []}

        is_vulnerable, severity, cve_id, sem_similarity, syn_similarity = self.analyzer.check_vulnerability(commit)
        self.assertFalse(is_vulnerable)
        self.assertEqual(severity, None)
        self.assertEqual(cve_id, None)

    @patch('spacy.load')
    def test_check_vulnerability_syntactic_similarity(self, mock_spacy_load):
        # Mock for syntactic similarity threshold
        mock_spacy_load.return_value = MagicMock()
        commit = {'msg': 'Security issue similar to sample vulnerability', 'modified_files': []}

        with patch('difflib.SequenceMatcher.ratio', return_value=0.6):  # Above threshold
            is_vulnerable, severity, cve_id, sem_similarity, syn_similarity = self.analyzer.check_vulnerability(commit)
            self.assertFalse(is_vulnerable)
            self.assertEqual(severity, None)
            self.assertEqual(cve_id, None)

    @patch('spacy.load')
    def test_no_vulnerability_found(self, mock_spacy_load):
        # Test when no vulnerability is detected in commit
        mock_spacy = MagicMock()
        mock_spacy.similarity.return_value = 0.4  # Below threshold
        mock_spacy_load.return_value = mock_spacy
        commit = {'msg': 'No CVE found in this message', 'modified_files': []}

        is_vulnerable, severity, cve_id, sem_similarity, syn_similarity, = self.analyzer.check_vulnerability(commit)
        self.assertFalse(is_vulnerable)
        self.assertIsNone(severity)
        self.assertIsNone(cve_id)

if __name__ == '__main__':
    unittest.main()
