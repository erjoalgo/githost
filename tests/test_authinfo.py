"""Tests for caching credentials in the authinfo file."""

import io
import os
import tempfile
import unittest
from unittest import mock

import requests

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
             mock.patch("sys.stdin.isatty", return_value=True), \
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

    def test_without_a_terminal_exits_instead_of_prompting(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        with open(authinfo, "w") as fh:
            fh.write("machine api.github.com login alice password tok\n")
        service = githost.Github(githost.Auth(user="claude", passwd=None, authinfo=authinfo))
        with mock.patch("sys.stdin.isatty", return_value=False), \
             mock.patch("getpass.getpass") as getpass:
            with self.assertRaises(SystemExit) as ctx:
                service.password()
        getpass.assert_not_called()
        self.assertIn("login claude at api.github.com", str(ctx.exception.code))

    def test_no_does_not_write_token(self):
        self.assertIsNone(self.prompt_password("1"))


class WriteAuthinfoTest(unittest.TestCase):
    """Check writing a token replaces the login's line instead of adding another."""

    def write(self, contents, user):
        """Write token new-tok for user into an authinfo holding contents, return the result."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        with open(authinfo, "w") as fh:
            fh.write(contents)
        service = githost.Github(githost.Auth(user=user, passwd="new-tok", authinfo=authinfo))
        service.write_authinfo(authinfo)
        with open(authinfo) as fh:
            return fh.read()

    def test_replaces_the_login_line(self):
        self.assertEqual(
            self.write("machine x login a password p\n"
                       "machine api.github.com login alice password old-tok\n"
                       "machine api.github.com login bob password bob-tok\n", "alice"),
            "machine x login a password p\n"
            "machine api.github.com login alice password new-tok\n"
            "machine api.github.com login bob password bob-tok\n")

    def test_appends_a_new_login(self):
        self.assertEqual(
            self.write("machine x login a password p", "alice"),
            "machine x login a password p\n"
            "machine api.github.com login alice password new-tok\n")


class ReadAuthinfoTest(unittest.TestCase):
    """Check which authinfo line is used when several match the host."""

    def read(self, user):
        """Returns (user, passwd) read from an authinfo with two logins for the host."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        with open(authinfo, "w") as fh:
            fh.write("machine localhost login claude password claude-tok\n"
                     "machine localhost login alice password alice-tok\n")
        service = githost.Forgejo(githost.Auth(user=user, passwd=None, authinfo=authinfo))
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            service.read_authinfo()
        return service.auth.user, service.auth.passwd

    def test_without_username_uses_first_line(self):
        self.assertEqual(self.read(None), ("claude", "claude-tok"))

    def test_username_selects_its_line(self):
        self.assertEqual(self.read("alice"), ("alice", "alice-tok"))

    def test_username_without_a_line_is_not_replaced(self):
        self.assertEqual(self.read("bob"), ("bob", None))


class RejectedTokenTest(unittest.TestCase):
    """Check a rejected token can be replaced and the request retried."""

    def send(self, isatty, answer="0"):
        """POST through a service whose stored token gets a 401.

        Returns (tokens sent, authinfo contents)."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        with open(authinfo, "w") as fh:
            fh.write("machine api.github.com login alice password old-tok\n")
        service = githost.Github(githost.Auth(user=None, passwd=None, authinfo=authinfo))
        sent = []

        def send(_session, prepared):
            token = prepared.headers["Authorization"]
            sent.append(token)
            resp = requests.Response()
            resp.status_code = 401 if len(sent) == 1 else 200
            resp._content = b"{}"
            return resp

        with mock.patch("requests.Session.send", send), \
             mock.patch("sys.stdin.isatty", return_value=isatty), \
             mock.patch("getpass.getpass", return_value="new-tok"), \
             mock.patch("builtins.input", return_value=answer), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            try:
                service.req_send(requests.Request("POST", "/user/keys", json={}))
            except requests.HTTPError:
                pass
        with open(authinfo) as fh:
            return sent, fh.read()

    def test_new_token_is_saved_and_retried(self):
        sent, contents = self.send(isatty=True)
        self.assertEqual(len(sent), 2)
        self.assertNotEqual(sent[0], sent[1])
        self.assertEqual(contents, "machine api.github.com login alice password new-tok\n")

    def test_declining_keeps_the_token(self):
        sent, contents = self.send(isatty=True, answer="1")
        self.assertEqual(len(sent), 1)
        self.assertEqual(contents, "machine api.github.com login alice password old-tok\n")

    def test_without_a_terminal_does_not_prompt(self):
        sent, _ = self.send(isatty=False)
        self.assertEqual(len(sent), 1)


if __name__ == "__main__":
    unittest.main()
