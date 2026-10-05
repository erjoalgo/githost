"""Tests for the gitlab service."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import requests

from githost import githost


def fake_response(data, status=200):
    """Build a requests.Response carrying the given json data."""
    resp = requests.Response()
    resp.status_code = status
    resp._content = json.dumps(data).encode()
    return resp


class GitlabTest(unittest.TestCase):
    """Check that gitlab requests hit the right endpoints with token auth."""

    def setUp(self):
        auth = githost.Auth(user="alice", passwd="glpat-test", authinfo=None)
        self.service = githost.Gitlab(auth)
        patcher = mock.patch.object(requests.Session, "send")
        self.send = patcher.start()
        self.addCleanup(patcher.stop)
        self.send.return_value = fake_response({})

    def sent(self):
        """Returns the single prepared request that was sent."""
        self.assertEqual(self.send.call_count, 1)
        return self.send.call_args[0][0]

    def test_auth_uses_private_token_header_not_basic_auth(self):
        self.service.list_repos()
        req = self.sent()
        self.assertEqual(req.headers["PRIVATE-TOKEN"], "glpat-test")
        self.assertNotIn("Authorization", req.headers)

    def test_list_repos(self):
        self.service.list_repos()
        req = self.sent()
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url, "https://gitlab.com/api/v4/projects?owned=true")

    def test_post_key(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as fh:
            fh.write("ssh-ed25519 AAAA test@host\n")
        self.addCleanup(os.remove, fh.name)
        self.service.post_key(pubkey_path=fh.name, pubkey_label="label")
        req = self.sent()
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url, "https://gitlab.com/api/v4/user/keys")
        self.assertEqual(json.loads(req.body),
                         {"key": "ssh-ed25519 AAAA test@host", "title": "label"})

    @mock.patch("subprocess.run")
    @mock.patch("subprocess.check_output")
    def test_repo_create_adds_remote_from_response(self, check_output, run):
        del check_output
        ssh_url = "git@gitlab.example.com:alice/proj.git"
        self.send.return_value = fake_response({"ssh_url_to_repo": ssh_url}, 201)
        self.service.base = "https://gitlab.example.com/api/v4"
        self.service.repo_create(repo_name="proj", description="desc")
        req = self.sent()
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url, "https://gitlab.example.com/api/v4/projects")
        self.assertEqual(json.loads(req.body),
                         {"name": "proj", "description": "desc",
                          "visibility": "private"})
        run.assert_called_once_with(["git", "remote", "add", "gitlab", ssh_url],
                                    check=True)

    def test_token_url_follows_base_url(self):
        self.service.base = "https://gitlab.example.com/api/v4"
        self.assertEqual(
            self.service.token_url(),
            "https://gitlab.example.com/-/user_settings/personal_access_tokens")

    def test_main_base_url_flag_sets_instance_base(self):
        argv = ["githost", "gitlab", "-u", "alice",
                "-b", "https://gitlab.example.com/api/v4/", "repo-list"]
        bases = []
        orig = githost.Gitlab.list_repos

        def record(gitlab, **kwargs):
            del kwargs
            bases.append(gitlab.base)
        githost.Gitlab.list_repos = record
        self.addCleanup(setattr, githost.Gitlab, "list_repos", orig)
        with mock.patch.object(sys, "argv", argv):
            githost.main()
        self.assertEqual(bases, ["https://gitlab.example.com/api/v4"])


if __name__ == "__main__":
    unittest.main()
