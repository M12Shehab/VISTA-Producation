#  """
#  __author__ = "Author Name"
#  __copyright__ = "Copyright (c) 2024 Author Name"
#  __credits__ = ["Contributor1", "Contributor2"]
#  __license__ = "MIT License"
#  __version__ = "1.0.0"
#  __maintainer__ = "Author Name"
#  __email__ = "author.email@example.com"
#  __status__ = "Development"
#  """
#
import unittest
from modules.CommitLoader import CommitLoader


class TestCommitLoader(unittest.TestCase):
    def setUp(self):
        self.loader = CommitLoader(repo_path="test_repo_path", branch="main")

    def test_load_commits(self):
        # Mock the Repository and its behavior
        commits = self.loader.load_commits(test_mode=True)
        self.assertIsInstance(commits, list)
        if commits:
            self.assertIn('hash', commits[0])
            self.assertIn('msg', commits[0])
            self.assertIn('modified_files', commits[0])


if __name__ == '__main__':
    unittest.main()
