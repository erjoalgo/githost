"""Tests for the gitlab service."""

import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import requests

from githost import githost


def fake_response(data, status=200, headers=None):
    """Build a requests.Response carrying the given json data."""
    resp = requests.Response()
    resp.status_code = status
    resp._content = json.dumps(data).encode()
    resp.headers.update(headers or {})
    return resp


def fake_git(outputs):
    """Fake subprocess.check_output answering git commands from a dict."""
    def check_output(cmd, **kwargs):
        del kwargs
        return outputs[" ".join(cmd[1:])]
    return check_output


REMOTES = {"remote": "origin\n",
           "remote get-url origin": "git@gitlab.com:grp/sub/proj.git\n"}
PROJECT_URL = "https://gitlab.com/api/v4/projects/grp%2Fsub%2Fproj"


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


class ParseRemoteUrlTest(unittest.TestCase):
    """Check host and project path are extracted from all git remote url forms."""

    def test_url_forms(self):
        for url in ["git@gitlab.com:grp/sub/proj.git",
                    "ssh://git@gitlab.com:2222/grp/sub/proj.git",
                    "https://gitlab.com/grp/sub/proj.git",
                    "https://gitlab.com/grp/sub/proj/",
                    "gitlab.com:grp/sub/proj"]:
            self.assertEqual(githost.parse_remote_url(url),
                             ("gitlab.com", "grp/sub/proj"), url)


class GitlabProjectTest(unittest.TestCase):
    """Check the merge request and branch commands."""

    def setUp(self):
        auth = githost.Auth(user="alice", passwd="glpat-test", authinfo=None)
        self.service = githost.Gitlab(auth)
        patcher = mock.patch.object(requests.Session, "send")
        self.send = patcher.start()
        self.addCleanup(patcher.stop)
        self.git_outputs = dict(REMOTES)
        patcher = mock.patch("subprocess.check_output",
                             side_effect=fake_git(self.git_outputs))
        patcher.start()
        self.addCleanup(patcher.stop)

    def output_of(self, fn, **kwargs):
        """Returns what fn printed."""
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            fn(**kwargs)
        return out.getvalue()

    def test_project_id_prefers_gitlab_remote(self):
        self.git_outputs["remote"] = "origin\ngitlab\n"
        self.git_outputs["remote get-url gitlab"] = "git@gitlab.com:me/other.git"
        self.assertEqual(self.service.project_id(), "me%2Fother")

    def test_project_id_explicit_remote(self):
        self.git_outputs["remote get-url upstream"] = "https://gitlab.com/up/proj.git"
        self.assertEqual(self.service.project_id("upstream"), "up%2Fproj")

    def test_project_id_rejects_remote_on_other_host(self):
        self.git_outputs["remote get-url origin"] = "https://github.com/me/proj"
        with self.assertRaises(SystemExit) as ctx:
            self.service.project_id()
        self.assertIn("remote origin is on github.com, not gitlab.com", str(ctx.exception))
        self.send.assert_not_called()

    def test_project_id_self_hosted(self):
        self.service.base = "https://gitlab.example.com/api/v4"
        self.git_outputs["remote get-url origin"] = "git@gitlab.example.com:grp/proj.git"
        self.assertEqual(self.service.project_id(), "grp%2Fproj")

    def test_get_all_follows_pages(self):
        self.send.side_effect = [
            fake_response([{"n": 1}], headers={"X-Next-Page": "2"}),
            fake_response([{"n": 2}], headers={"X-Next-Page": ""})]
        self.assertEqual(self.service.get_all("/things"), [{"n": 1}, {"n": 2}])
        urls = [call[0][0].url for call in self.send.call_args_list]
        self.assertEqual(urls, [
            "https://gitlab.com/api/v4/things?per_page=100&page=1",
            "https://gitlab.com/api/v4/things?per_page=100&page=2"])

    def test_mr_list(self):
        self.send.return_value = fake_response([{
            "iid": 7, "source_branch": "feat", "target_branch": "main",
            "author": {"username": "bob"}, "draft": True, "title": "Add feat",
            "web_url": "https://gitlab.com/grp/sub/proj/-/merge_requests/7"}])
        out = self.output_of(self.service.mr_list)
        self.assertEqual(
            out, "!7\tfeat -> main\tbob\t[draft] Add feat"
            "\thttps://gitlab.com/grp/sub/proj/-/merge_requests/7\n")
        self.assertEqual(self.send.call_args[0][0].url,
                         PROJECT_URL + "/merge_requests?state=opened&per_page=100&page=1")

if __name__ == "__main__":
    unittest.main()
