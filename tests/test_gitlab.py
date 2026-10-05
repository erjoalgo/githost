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

    def test_mr_list_mrs_then_branches_without_mr(self):
        # no git repo needed: any git call would raise KeyError
        self.git_outputs.clear()

        def mr(project_id, path, iid, source, title, draft=False):
            return {"source_project_id": project_id, "source_branch": source,
                    "iid": iid, "draft": draft, "title": title,
                    "updated_at": f"2026-09-{iid:02}T10:00:00.000Z",
                    "web_url": f"https://gitlab.com/{path}/-/merge_requests/{iid}"}

        def push(project_id, ref, ref_type="branch"):
            return {"project_id": project_id,
                    "push_data": {"ref": ref, "ref_type": ref_type}}

        def branch(path, name):
            return {"commit": {"title": f"wip on {name}",
                               "committed_date": "2026-10-01T09:00:00.000+02:00"},
                    "web_url": f"https://gitlab.com/{path}/-/tree/{name}"}
        mrs = "/merge_requests?state={}&scope=created_by_me&per_page=100&page=1"
        responses = {
            mrs.format("opened"): [mr(1, "grp/one", 7, "open-mr", "Add feat", draft=True)],
            mrs.format("merged"): [mr(1, "grp/one", 5, "merged-mr", "Fix bug")],
            "/events?action=pushed&per_page=100&page=1": [
                push(1, "feat"), push(1, "open-mr"), push(1, "merged-mr"),
                push(1, "deleted"), push(1, "main"), push(1, "v1.0", ref_type="tag"),
                push(2, "no-access"), push(1, "feat"), push(3, "me/wip")],
            "/projects/1": {"path_with_namespace": "grp/one", "default_branch": "main"},
            "/projects/3": {"path_with_namespace": "grp/three", "default_branch": "main"},
            "/projects/1/repository/branches/feat": branch("grp/one", "feat"),
            "/projects/1/repository/branches/open-mr": branch("grp/one", "open-mr"),
            "/projects/1/repository/branches/merged-mr": branch("grp/one", "merged-mr"),
            "/projects/3/repository/branches/me%2Fwip": branch("grp/three", "me/wip"),
            # skipped as the default branch, though it exists
            "/projects/1/repository/branches/main": branch("grp/one", "main"),
            # a tag push, so skipped even though a branch of the same name exists
            "/projects/1/repository/branches/v1.0": branch("grp/one", "v1.0"),
        }

        def send(req):
            path = req.url[len("https://gitlab.com/api/v4"):]
            if path in responses:
                return fake_response(responses[path])
            return fake_response({"message": "404 Not Found"}, 404)
        self.send.side_effect = send

        out = self.output_of(self.service.mr_list)
        self.assertEqual(out.splitlines(), [
            "!7\topened\t2026-09-07\thttps://gitlab.com/grp/one/-/merge_requests/7"
            "\topen-mr\t[draft] Add feat",
            "!5\tmerged\t2026-09-05\thttps://gitlab.com/grp/one/-/merge_requests/5"
            "\tmerged-mr\tFix bug",
            "null\t-\t2026-10-01\thttps://gitlab.com/grp/one/-/tree/feat"
            "\tfeat\twip on feat",
            "null\t-\t2026-10-01\thttps://gitlab.com/grp/three/-/tree/me/wip"
            "\tme/wip\twip on me/wip"])
        urls = [call[0][0].url for call in self.send.call_args_list]
        self.assertEqual(urls.count("https://gitlab.com/api/v4/projects/1"), 1)

    @mock.patch.object(githost, "interactive_edit",
                       return_value="Add feat\n\nLonger\nexplanation\n")
    def test_mr_create_defaults(self, edit):
        self.git_outputs["rev-parse --abbrev-ref HEAD"] = "feat\n"
        self.git_outputs["log -1 --format=%B feat"] = "commit msg\n"
        self.send.side_effect = [
            fake_response({"default_branch": "main"}),
            fake_response({"web_url": "https://gitlab.com/mr/1"}, 201)]
        out = self.output_of(self.service.mr_create)
        edit.assert_called_once_with("commit msg")
        get, post = [call[0][0] for call in self.send.call_args_list]
        self.assertEqual(get.url, PROJECT_URL)
        self.assertEqual(post.method, "POST")
        self.assertEqual(post.url, PROJECT_URL + "/merge_requests")
        self.assertEqual(json.loads(post.body),
                         {"source_branch": "feat", "target_branch": "main",
                          "title": "Add feat", "description": "Longer\nexplanation"})
        self.assertEqual(out, "https://gitlab.com/mr/1\n")

    def test_mr_create_explicit_args_skip_lookups(self):
        self.send.return_value = fake_response({"web_url": "u"}, 201)
        self.output_of(self.service.mr_create, source_branch="feat",
                       target_branch="dev", title="T", description="D")
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(json.loads(self.send.call_args[0][0].body),
                         {"source_branch": "feat", "target_branch": "dev",
                          "title": "T", "description": "D"})

    def test_mr_list_unsupported_for_github(self):
        argv = ["githost", "github", "ls-mr"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err, \
             self.assertRaises(SystemExit):
            githost.main()
        self.assertIn("mr_list is not supported for github", err.getvalue())


if __name__ == "__main__":
    unittest.main()
