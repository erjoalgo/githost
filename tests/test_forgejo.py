"""Tests for the forgejo service."""

import io
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


REMOTES = {"remote": "origin\nforgejo\n",
           "remote get-url forgejo": "http://localhost:3123/alice/proj.git\n",
           "remote get-url origin": "git@github.com:alice/proj.git\n",
           "rev-parse --abbrev-ref HEAD": "feature\n",
           "log -1 --format=%B feature": "Add feature\n\nBecause.\n"}


def fake_git(cmd, **kwargs):
    del kwargs
    return REMOTES[" ".join(cmd[1:])]


@mock.patch("subprocess.check_output", side_effect=fake_git)
class ForgejoPullRequestTest(unittest.TestCase):
    """Check the pull request commands."""

    def setUp(self):
        auth = githost.Auth(user="alice", passwd="fj-token", authinfo=None)
        self.service = githost.Forgejo(auth)
        patcher = mock.patch.object(requests.Session, "send")
        self.send = patcher.start()
        self.addCleanup(patcher.stop)

    def sent(self):
        return [call[0][0] for call in self.send.call_args_list]

    def test_repo_path_prefers_forgejo_remote(self, check_output):
        del check_output
        self.assertEqual(self.service.repo_path(), "alice/proj")

    def test_repo_path_rejects_remote_on_other_host(self, check_output):
        del check_output
        with self.assertRaises(SystemExit):
            self.service.repo_path("origin")

    def test_pr_list(self, check_output):
        del check_output
        self.send.return_value = fake_response([
            {"number": 3, "state": "closed", "merged": True, "draft": False,
             "updated_at": "2026-11-17T20:00:00Z", "html_url": "http://x/pulls/3",
             "head": {"ref": "feature"}, "title": "Add feature"}])
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_list(state="all")
        req, = self.sent()
        self.assertEqual(req.url,
                         f"{API}/repos/alice/proj/pulls?state=all&sort=recentupdate&limit=50")
        self.assertEqual(out.getvalue(),
                         "#3\tmerged\t2026-11-17\thttp://x/pulls/3\tfeature\tAdd feature\n")

    @mock.patch.object(githost, "interactive_edit", side_effect=lambda text: text)
    def test_pr_create_defaults(self, edit, check_output):
        del edit, check_output
        self.send.side_effect = [fake_response({"default_branch": "master"}),
                                 fake_response({"html_url": "http://x/pulls/4"})]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_create()
        get, post = self.sent()
        self.assertEqual(get.url, f"{API}/repos/alice/proj")
        self.assertEqual((post.method, post.url), ("POST", f"{API}/repos/alice/proj/pulls"))
        self.assertEqual(json.loads(post.body),
                         {"head": "feature", "base": "master",
                          "title": "Add feature", "body": "Because."})
        self.assertEqual(out.getvalue(), "http://x/pulls/4\n")

    def test_pr_create_explicit_args_skip_lookups(self, check_output):
        del check_output
        self.send.return_value = fake_response({"html_url": "http://x/pulls/5"})
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.pr_create(source_branch="b", target_branch="main",
                                   title="T", description="D")
        post, = self.sent()
        self.assertEqual(json.loads(post.body),
                         {"head": "b", "base": "main", "title": "T", "body": "D"})
