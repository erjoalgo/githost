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
           "rev-parse HEAD": "abc123\n",
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

    def test_collaborator_add(self, check_output):
        del check_output
        self.send.side_effect = [fake_response(None, status=204),
                                 fake_response(None, status=204)]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.collaborator_add(["claude", "bob"], permission="read")
        claude, bob = self.sent()
        self.assertEqual((claude.method, claude.url),
                         ("PUT", f"{API}/repos/alice/proj/collaborators/claude"))
        self.assertEqual(json.loads(claude.body), {"permission": "read"})
        self.assertEqual(bob.url, f"{API}/repos/alice/proj/collaborators/bob")
        self.assertEqual(out.getvalue(), "claude: read\nbob: read\n")

    def test_branch_protect_creates_rule(self, check_output):
        del check_output
        self.send.side_effect = [fake_response({"login": "alice"}),
                                 fake_response({"message": "not found"}, status=404),
                                 fake_response({})]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.branch_protect("master")
        user, get, post = self.sent()
        self.assertEqual(user.url, f"{API}/user")
        self.assertEqual(get.url, f"{API}/repos/alice/proj/branch_protections/master")
        self.assertEqual((post.method, post.url),
                         ("POST", f"{API}/repos/alice/proj/branch_protections"))
        self.assertEqual(json.loads(post.body),
                         {"rule_name": "master",
                          "enable_push": True,
                          "enable_push_whitelist": True,
                          "push_whitelist_usernames": ["alice"],
                          "enable_merge_whitelist": True,
                          "merge_whitelist_usernames": ["alice"]})
        self.assertEqual(out.getvalue(), "master: only alice can push or merge\n")

    def test_branch_protect_updates_existing_rule(self, check_output):
        del check_output
        self.send.side_effect = [fake_response({"login": "alice"}),
                                 fake_response({"rule_name": "release/1"}),
                                 fake_response({})]
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.branch_protect("release/1")
        user, get, patch = self.sent()
        rule = f"{API}/repos/alice/proj/branch_protections/release%2F1"
        self.assertEqual(get.url, rule)
        self.assertEqual((patch.method, patch.url), ("PATCH", rule))
        self.assertNotIn("rule_name", json.loads(patch.body))

    @mock.patch("subprocess.run")
    def test_repo_publish_existing_remote(self, run, check_output):
        del check_output
        run.return_value = mock.Mock(returncode=0)
        self.send.side_effect = [fake_response(None, status=204),
                                 fake_response({"login": "alice"}),
                                 fake_response({"message": "not found"}, status=404),
                                 fake_response({})]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.repo_publish("proj", collaborator=["claude"])
        put, user, get, post = self.sent()
        self.assertEqual(put.url, f"{API}/repos/alice/proj/collaborators/claude")
        self.assertEqual(json.loads(post.body)["rule_name"], "main")
        verify, push = run.call_args_list
        self.assertEqual(verify[0][0][-1], "refs/heads/main")
        self.assertEqual(push[0][0][-3:], ["push", "forgejo", "main"])
        self.assertIn("credential.helper=", push[0][0])
        self.assertEqual(push[1]["env"]["GFJ_TOKEN"], "fj-token")
        self.assertIn("not creating the repo", out.getvalue())

    @mock.patch("subprocess.run")
    def test_repo_publish_falls_back_to_master(self, run, check_output):
        del check_output
        run.side_effect = [mock.Mock(returncode=1), mock.Mock(returncode=0),
                           mock.Mock(returncode=0)]
        self.send.side_effect = [fake_response({"login": "alice"}),
                                 fake_response({"rule_name": "master"}),
                                 fake_response({})]
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.repo_publish("proj")
        self.assertEqual(run.call_args_list[2][0][0][-1], "master")
        user, get, patch = self.sent()
        self.assertEqual(patch.method, "PATCH")

    @mock.patch("subprocess.run", return_value=mock.Mock(returncode=1))
    def test_repo_publish_without_branch_exits_before_any_request(self, run, check_output):
        del run, check_output
        with self.assertRaises(SystemExit):
            self.service.repo_publish("proj", branch="nope")
        self.assertEqual(self.sent(), [])

    def test_pr_create_explicit_args_skip_lookups(self, check_output):
        del check_output
        self.send.return_value = fake_response({"html_url": "http://x/pulls/5"})
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.pr_create(source_branch="b", target_branch="main",
                                   title="T", description="D")
        post, = self.sent()
        self.assertEqual(json.loads(post.body),
                         {"head": "b", "base": "main", "title": "T", "body": "D"})

    def test_pr_show_defaults_to_current_branch_and_prints_feedback(self, check_output):
        del check_output
        user = {"login": "bob"}
        self.send.side_effect = [
            fake_response([{"number": 7, "head": {"ref": "feature", "sha": "old"}}]),
            fake_response({"title": "Add feature", "state": "open", "merged": False,
                           "html_url": "http://x/pulls/7", "body": "Why.",
                           "head": {"ref": "feature"}, "base": {"ref": "master"}}),
            fake_response([{"id": 1, "user": user, "created_at": "t1", "body": "LGTM?"}]),
            fake_response([
                {"id": 2, "user": user, "state": "REQUEST_CHANGES", "stale": False,
                 "submitted_at": "t2", "body": "A few things.", "comments_count": 2},
                {"id": 3, "user": user, "state": "COMMENT", "stale": False,
                 "submitted_at": "t3", "body": "", "comments_count": 0}]),
            fake_response([
                {"id": 10, "path": "a.py", "position": 12, "original_position": 0,
                 "diff_hunk": "@@ -1 +1 @@\n-x\n+y", "body": "rename y", "resolver": None},
                {"id": 11, "path": "b.py", "position": 0, "original_position": 4,
                 "diff_hunk": "", "body": "old", "resolver": {"login": "alice"}}]),
        ]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_show()
        urls = [req.url for req in self.sent()]
        self.assertEqual(urls, [
            f"{API}/repos/alice/proj/pulls?state=open&limit=50",
            f"{API}/repos/alice/proj/pulls/7",
            f"{API}/repos/alice/proj/issues/7/comments?limit=50",
            f"{API}/repos/alice/proj/pulls/7/reviews?limit=50",
            f"{API}/repos/alice/proj/pulls/7/reviews/2/comments"])
        self.assertEqual(out.getvalue(), """\
#7 open: Add feature
http://x/pulls/7
feature -> master

Why.

--- comment 1 by bob at t1
LGTM?

--- review 2 by bob, REQUEST_CHANGES, at t2
A few things.

  > comment 10 on a.py:12
    @@ -1 +1 @@
    -x
    +y
  rename y

  > comment 11 on b.py:4 (resolved by alice, outdated)
  old
""")

    def test_pr_number_without_open_pr_exits(self, check_output):
        del check_output
        self.send.return_value = fake_response([])
        with self.assertRaises(SystemExit):
            self.service.pr_number("alice/proj", None)

    def test_pr_number_matches_head_commit_on_detached_head(self, check_output):
        del check_output
        REMOTES["rev-parse --abbrev-ref HEAD"] = "HEAD\n"
        self.addCleanup(REMOTES.__setitem__, "rev-parse --abbrev-ref HEAD", "feature\n")
        self.send.return_value = fake_response([
            {"number": 1, "head": {"ref": "other", "sha": "zzz"}},
            {"number": 2, "head": {"ref": "feature", "sha": "abc123"}}])
        self.assertEqual(self.service.pr_number("alice/proj", None), 2)

    def test_pr_number_ignores_same_branch_name_from_a_fork(self, check_output):
        del check_output
        self.send.return_value = fake_response([
            {"number": 1, "head": {"ref": "feature", "sha": "x",
                                   "repo": {"full_name": "mallory/proj"}}},
            {"number": 2, "head": {"ref": "feature", "sha": "y",
                                   "repo": {"full_name": "alice/proj"}}}])
        self.assertEqual(self.service.pr_number("alice/proj", None), 2)

    def test_pr_number_ambiguous_exits(self, check_output):
        del check_output
        self.send.return_value = fake_response([
            {"number": 1, "head": {"ref": "feature", "sha": "x"}},
            {"number": 2, "head": {"ref": "other", "sha": "abc123"}}])
        with self.assertRaises(SystemExit) as ctx:
            self.service.pr_number("alice/proj", None)
        self.assertIn("#1, #2", ctx.exception.code)

    def test_pr_comment_reply_quotes_inline_comment(self, check_output):
        del check_output
        self.send.side_effect = [
            fake_response([]),  # issue comments
            fake_response([{"id": 2, "comments_count": 1}]),
            fake_response([{"id": 10, "path": "a.py", "position": 12,
                            "user": {"login": "bob"}, "body": "rename y\nplease"}]),
            fake_response({"html_url": "http://x/pulls/7#issuecomment-11"})]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_comment(number=7, message="Done.", reply_to=10)
        post = self.sent()[-1]
        self.assertEqual((post.method, post.url),
                         ("POST", f"{API}/repos/alice/proj/issues/7/comments"))
        self.assertEqual(json.loads(post.body)["body"],
                         "Re: bob's comment 10 on `a.py:12`:\n> rename y\n> please\n\nDone.")
        self.assertEqual(out.getvalue(), "http://x/pulls/7#issuecomment-11\n")

    def test_pr_comment_reply_to_unknown_comment_exits(self, check_output):
        del check_output
        self.send.side_effect = [fake_response([]), fake_response([])]
        with self.assertRaises(SystemExit) as ctx:
            self.service.pr_comment(number=7, message="x", reply_to=99)
        self.assertEqual(ctx.exception.code, "no comment 99 on PR #7")

    def test_pr_edit_appends_to_description(self, check_output):
        del check_output
        self.send.side_effect = [
            fake_response({"body": "What changed.\n"}),
            fake_response({"html_url": "http://x/pulls/7"})]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_edit(number=7, append_description="Update: retargeted.")
        get, patch = self.sent()
        self.assertEqual((get.method, get.url), ("GET", f"{API}/repos/alice/proj/pulls/7"))
        self.assertEqual((patch.method, patch.url),
                         ("PATCH", f"{API}/repos/alice/proj/pulls/7"))
        self.assertEqual(json.loads(patch.body),
                         {"body": "What changed.\n\nUpdate: retargeted."})
        self.assertEqual(out.getvalue(), "http://x/pulls/7\n")

    def test_pr_edit_title_and_target_leave_description(self, check_output):
        del check_output
        self.send.return_value = fake_response({"html_url": "http://x/pulls/7"})
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.pr_edit(number=7, title="New", target_branch="main")
        patch, = self.sent()
        self.assertEqual(json.loads(patch.body), {"title": "New", "base": "main"})

    @mock.patch.object(githost, "interactive_edit", return_value="Edited.\n")
    def test_pr_edit_without_changes_opens_editor(self, edit, check_output):
        del check_output
        self.send.side_effect = [
            fake_response({"body": "Old."}),
            fake_response({"html_url": "http://x/pulls/7"})]
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.pr_edit(number=7)
        edit.assert_called_once_with("Old.")
        self.assertEqual(json.loads(self.sent()[-1].body), {"body": "Edited."})

    def test_pr_close_comments_then_closes(self, check_output):
        del check_output
        self.send.side_effect = [
            fake_response({"html_url": "http://x/pulls/7#issuecomment-1"}),
            fake_response({"html_url": "http://x/pulls/7"})]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_close(number=7, message="Superseded by #8.")
        comment, patch = self.sent()
        self.assertEqual((comment.method, comment.url),
                         ("POST", f"{API}/repos/alice/proj/issues/7/comments"))
        self.assertEqual(json.loads(comment.body), {"body": "Superseded by #8."})
        self.assertEqual((patch.method, patch.url),
                         ("PATCH", f"{API}/repos/alice/proj/pulls/7"))
        self.assertEqual(json.loads(patch.body), {"state": "closed"})
        self.assertEqual(out.getvalue(), "http://x/pulls/7\n")

    def test_pr_close_without_message_only_closes(self, check_output):
        del check_output
        self.send.return_value = fake_response({"html_url": "http://x/pulls/7"})
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.service.pr_close(number=7)
        patch, = self.sent()
        self.assertEqual(json.loads(patch.body), {"state": "closed"})

    @mock.patch("time.sleep")
    def test_pr_wait_returns_on_feedback_newer_than_our_last_comment(self, sleep, check_output):
        del check_output
        pr = {"state": "open", "created_at": "2026-01-01T00:00:00Z"}
        ours = {"id": 5, "user": {"login": "alice"}, "body": "Re: bob's comment 4:\n> old\n\nDone.",
                "created_at": "2026-01-02T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z"}
        old = {"id": 4, "user": {"login": "bob"}, "body": "old",
               "created_at": "2026-01-01T12:00:00Z", "updated_at": "2026-01-01T12:00:00Z"}
        review = {"id": 9, "user": {"login": "bob"}, "state": "REQUEST_CHANGES",
                  "submitted_at": "2026-01-03T00:00:00Z", "updated_at": "2026-01-03T00:00:00Z"}
        pending = dict(review, id=10, state="PENDING")
        self.send.side_effect = [
            fake_response({"login": "alice"}),
            fake_response(pr),
            fake_response([old, ours]), fake_response([pending]),  # nothing new
            fake_response(pr),
            fake_response([old, ours]), fake_response([review, pending]),
        ]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_wait(number=7, interval=5)
        sleep.assert_called_once_with(5)
        self.assertEqual(out.getvalue(),
                         "#7: review:9 (REQUEST_CHANGES) by bob at 2026-01-03T00:00:00+00:00\n"
                         "to wait for more: wait-pr 7 --since review:9\n")

    @mock.patch("time.sleep")
    def test_pr_wait_since_skips_older_feedback(self, sleep, check_output):
        del check_output
        approval = {"id": 9, "user": {"login": "bob"}, "state": "APPROVED",
                    "submitted_at": "2026-01-03T00:00:00Z", "updated_at": "2026-01-03T00:00:00Z"}
        comment = {"id": 11, "user": {"login": "bob"}, "body": "nit",
                   "created_at": "2026-01-04T00:00:00Z", "updated_at": "2026-01-04T00:00:00Z"}
        pr = {"state": "open", "created_at": "2026-01-01T00:00:00Z"}
        self.send.side_effect = [
            fake_response({"login": "alice"}),
            fake_response(pr),
            fake_response([]), fake_response([approval]),
            fake_response(pr),
            fake_response([comment]), fake_response([approval]),
        ]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_wait(number=7, since="review:9")
        sleep.assert_called_once()
        self.assertTrue(out.getvalue().startswith("#7: comment:11 by bob"))

    @mock.patch("time.sleep")
    def test_pr_wait_since_none_and_no_activity_of_ours_count_all_feedback(
            self, sleep, check_output):
        del sleep, check_output
        old = {"id": 4, "user": {"login": "bob"}, "body": "old",
               "created_at": "2026-01-01T12:00:00Z", "updated_at": "2026-01-01T12:00:00Z"}
        pr = {"state": "open", "created_at": "2026-01-02T00:00:00Z"}
        for since in ("none", None):
            self.send.side_effect = [fake_response({"login": "alice"}), fake_response(pr),
                                     fake_response([old]), fake_response([])]
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                self.service.pr_wait(number=7, since=since)
            self.assertTrue(out.getvalue().startswith("#7: comment:4 by bob"), since)

    def test_pr_wait_reports_unreplied_comments_older_than_ours(self, check_output):
        del check_output
        def comment(id_, login, body, time):
            return {"id": id_, "user": {"login": login}, "body": body,
                    "created_at": time, "updated_at": time}
        # edited after the reply: still replied, as replies name the id
        answered = comment(1, "bob", "rename x and z", "2026-01-01T00:03:00Z")
        missed = comment(2, "bob", "and y", "2026-01-01T00:01:00Z")
        ours = comment(3, "alice", "Re: bob's comment 1:\n> rename x\n\nDone.",
                       "2026-01-01T00:02:00Z")
        review = {"id": 9, "user": {"login": "bob"}, "state": "COMMENT", "comments_count": 2,
                  "submitted_at": "2026-01-01T00:00:30Z", "updated_at": "2026-01-01T00:00:30Z"}
        inline = dict(comment(10, "bob", "typo", "2026-01-01T00:00:30Z"),
                      path="a.py", position=12)
        resolved = dict(comment(11, "bob", "style", "2026-01-01T00:00:30Z"),
                        path="a.py", position=3, resolver={"login": "bob"})
        self.send.side_effect = [
            fake_response({"login": "alice"}),
            fake_response({"state": "open", "created_at": "2026-01-01T00:00:00Z"}),
            fake_response([answered, missed, ours]), fake_response([review]),
            fake_response([inline, resolved]),
        ]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_wait(number=7)
        self.assertEqual(out.getvalue(),
                         "#7: comment:1 by bob at 2026-01-01T00:03:00+00:00\n"
                         "#7: unreplied comment 2 by bob\n"
                         "#7: unreplied comment 10 by bob on a.py:12\n"
                         "to wait for more: wait-pr 7 --since comment:1\n")
        self.assertEqual(self.sent()[-1].url,
                         f"{API}/repos/alice/proj/pulls/7/reviews/9/comments")

    def test_pr_wait_unknown_since_event_exits(self, check_output):
        del check_output
        self.send.side_effect = [fake_response({"login": "alice"}),
                                 fake_response({"state": "open", "created_at": "2026-01-01T00:00:00Z"}),
                                 fake_response([]), fake_response([])]
        with self.assertRaises(SystemExit) as ctx:
            self.service.pr_wait(number=7, since="review:99")
        self.assertIn("no event review:99", ctx.exception.code)

    @mock.patch("time.sleep")
    def test_pr_wait_retries_network_errors(self, sleep, check_output):
        del check_output
        self.send.side_effect = [
            fake_response({"login": "alice"}),
            requests.ConnectionError("Connection reset by peer"),
            fake_response({"state": "open", "created_at": "2026-01-01T00:00:00Z"}),
            requests.Timeout("timed out"),
            fake_response({"state": "closed", "merged": True}),
        ]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.service.pr_wait(number=7, interval=5)
        self.assertEqual(sleep.call_args_list, [mock.call(5), mock.call(5)])
        self.assertEqual(err.getvalue(),
                         "#7: Connection reset by peer; retrying in 5s\n"
                         "#7: timed out; retrying in 5s\n")
        self.assertEqual(out.getvalue(), "#7 is merged\n")

    @mock.patch("time.sleep")
    def test_pr_wait_returns_when_merged(self, sleep, check_output):
        del check_output
        self.send.side_effect = [
            fake_response({"login": "alice"}),
            fake_response({"state": "open", "created_at": "2026-01-01T00:00:00Z"}),
            fake_response([]), fake_response([]),
            fake_response({"state": "closed", "merged": True}),
        ]
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.service.pr_wait(number=7)
        sleep.assert_called_once()
        self.assertEqual(out.getvalue(), "#7 is merged\n")
