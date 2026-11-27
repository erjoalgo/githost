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

    def send(self, isatty, answer="0", token_works=False):
        """POST through a service whose stored token gets a 401 on it.

        With token_works, the token still works on /user. Returns
        ((url, Authorization header) of each request sent, authinfo contents)."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        with open(authinfo, "w") as fh:
            fh.write("machine api.github.com login alice password old-tok\n")
        service = githost.Github(githost.Auth(user=None, passwd=None, authinfo=authinfo))
        sent = []

        def send(_session, prepared):
            sent.append((prepared.url, prepared.headers["Authorization"]))
            old_token = sent[0][1]
            resp = requests.Response()
            if prepared.headers["Authorization"] != old_token:
                resp.status_code = 200
            elif token_works and prepared.url.endswith("/user"):
                resp.status_code = 200
            else:
                resp.status_code = 401
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
        self.assertEqual([url for url, _ in sent],
                         ["https://api.github.com/user/keys", "https://api.github.com/user",
                          "https://api.github.com/user/keys"])
        self.assertNotEqual(sent[0][1], sent[2][1])
        self.assertEqual(contents, "machine api.github.com login alice password new-tok\n")

    def test_declining_keeps_the_token(self):
        sent, contents = self.send(isatty=True, answer="1")
        self.assertEqual(len(sent), 2)
        self.assertEqual(contents, "machine api.github.com login alice password old-tok\n")

    def test_working_token_is_not_replaced(self):
        sent, contents = self.send(isatty=True, token_works=True)
        self.assertEqual(len(sent), 2)
        self.assertEqual(contents, "machine api.github.com login alice password old-tok\n")

    def test_without_a_terminal_does_not_prompt(self):
        sent, _ = self.send(isatty=False)
        self.assertEqual(len(sent), 1)


class RemoveAuthinfoTest(unittest.TestCase):
    """Check only the rejected login's line is removed, and only when it's unambiguous."""

    def remove(self, contents, user, passwd):
        """Remove user's rejected token passwd at localhost; return the authinfo contents."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        authinfo = os.path.join(tmpdir.name, "authinfo")
        with open(authinfo, "w") as fh:
            fh.write(contents)
        service = githost.Forgejo(githost.Auth(user=user, passwd=passwd, authinfo=authinfo))
        service.remove_authinfo()
        with open(authinfo) as fh:
            return fh.read()

    def test_keeps_other_logins_on_the_host(self):
        self.assertEqual(
            self.remove("machine localhost login ealfonso password e-tok\n"
                        "machine localhost login claude password c-tok\n", "claude", "c-tok"),
            "machine localhost login ealfonso password e-tok\n")

    def test_login_without_a_line_is_left_alone(self):
        contents = "machine localhost login ealfonso password e-tok\n"
        with self.assertLogs(githost.logger, "WARNING"):
            self.assertEqual(self.remove(contents, "claude", "typed-tok"), contents)

    def test_several_lines_for_the_login_exit(self):
        with self.assertRaises(SystemExit):
            self.remove("machine localhost login claude password c-tok\n"
                        "machine localhost login claude password other-tok\n", "claude", "c-tok")

    def test_line_with_another_token_exits(self):
        with self.assertRaises(SystemExit):
            self.remove("machine localhost login claude password other-tok\n", "claude", "c-tok")


if __name__ == "__main__":
    unittest.main()
