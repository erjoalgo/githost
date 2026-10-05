"""Tests for caching credentials in the authinfo file."""

import io
import os
import tempfile
import unittest
from unittest import mock

from githost import githost


class AuthinfoTest(unittest.TestCase):
    """Check the token is written to authinfo only when the user agrees."""

    def prompt_password(self, answer):
        """Prompt for a token, answer the write prompt, return the authinfo contents."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        service = githost.Github(githost.Auth(user="alice", passwd=None, authinfo=authinfo))
        with mock.patch("getpass.getpass", return_value="tok"), \
             mock.patch("builtins.input", return_value=answer), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(service.password(), "tok")
        if not os.path.exists(authinfo):
            return None
        with open(authinfo) as fh:
            return fh.read()

    def test_yes_writes_token(self):
        self.assertEqual(self.prompt_password("0"),
                         "machine api.github.com login alice password tok\n")

    def test_no_does_not_write_token(self):
        self.assertIsNone(self.prompt_password("1"))


if __name__ == "__main__":
    unittest.main()
