"""Tests for the forgejo service."""

import json
import os
import tempfile
import unittest
from unittest import mock

import requests

from githost import githost
from test_gitlab import fake_response

API = "http://localhost:3123/api/v1"


class ForgejoTest(unittest.TestCase):
    """Check that forgejo requests hit the right endpoints with token auth."""

    def setUp(self):
        auth = githost.Auth(user="alice", passwd="fj-token", authinfo=None)
        self.service = githost.Forgejo(auth)
        patcher = mock.patch.object(requests.Session, "send")
        self.send = patcher.start()
        self.addCleanup(patcher.stop)
        self.send.return_value = fake_response([])

    def sent(self):
        """Returns the prepared requests that were sent."""
        return [call[0][0] for call in self.send.call_args_list]

    def test_auth_uses_token_header_not_basic_auth(self):
        self.service.list_repos()
        req, = self.sent()
        self.assertEqual(req.headers["Authorization"], "token fj-token")

    def test_web_url(self):
        self.assertEqual(self.service.web_url(), "http://localhost:3123")
        self.service.base = "https://fj.example.com/api/v1"
        self.assertEqual(self.service.web_url(), "https://fj.example.com")

    def test_get_all_follows_link_header(self):
        page2 = f"{API}/user/repos?limit=50&page=2"
        self.send.side_effect = [
            fake_response([{"id": 1}], headers={"Link": f'<{page2}>; rel="next"'}),
            fake_response([{"id": 2}])]
        self.assertEqual(self.service.get_all("/user/repos"), [{"id": 1}, {"id": 2}])
        first, second = self.sent()
        self.assertEqual(first.url, f"{API}/user/repos?limit=50")
        self.assertEqual(second.url, page2)

    def test_post_key(self):
        self.send.return_value = fake_response({})
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as fh:
            fh.write("ssh-ed25519 AAAA test@host\n")
        self.addCleanup(os.remove, fh.name)
        self.service.post_key(pubkey_path=fh.name, pubkey_label="label")
        req, = self.sent()
        self.assertEqual((req.method, req.url), ("POST", f"{API}/user/keys"))
        self.assertEqual(json.loads(req.body),
                         {"key": "ssh-ed25519 AAAA test@host", "title": "label"})

    @mock.patch("subprocess.run")
    @mock.patch("subprocess.check_output")
    def test_repo_create_adds_remote_from_response(self, check_output, run):
        del check_output
        self.send.return_value = fake_response(
            {"clone_url": "http://localhost:3123/alice/proj.git",
             "html_url": "http://localhost:3123/alice/proj"})
        self.service.repo_create(repo_name="proj", description="desc")
        req, = self.sent()
        self.assertEqual((req.method, req.url), ("POST", f"{API}/user/repos"))
        self.assertEqual(json.loads(req.body),
                         {"name": "proj", "description": "desc", "private": True})
        run.assert_called_once_with(
            ["git", "remote", "add", "forgejo", "http://localhost:3123/alice/proj.git"],
            check=True)
