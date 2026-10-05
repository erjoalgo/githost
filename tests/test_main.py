"""Tests for the command-line entry point."""

import sys
import unittest
from unittest import mock

from githost import githost


class AliasTest(unittest.TestCase):
    """Check the two-letter aliases select the right service."""

    def test_aliases(self):
        for alias, service in [("gh", githost.Github), ("gl", githost.Gitlab),
                               ("bb", githost.Bitbucket)]:
            argv = ["githost", alias, "-u", "alice", "repo-list"]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(service, "list_repos") as list_repos:
                githost.main()
            list_repos.assert_called_once()


if __name__ == "__main__":
    unittest.main()
