`pip install githost`

`githost -h`

Post the local ssh public key at `~/.ssh/id_rsa.pub` to github.

`githost github add-key`

Each service also has a two-letter alias: `gh` (github), `gl` (gitlab),
`bb` (bitbucket) and `fj` (forgejo), e.g. `githost gh add-key`, and its own
command with the service already selected: `ggh`, `ggl`, `gbb` and `gfj`, e.g.
`ggl ls-mr`.

Use github's API to list the existing repositories in JSON format:

`githost github ls-repo`

```
[
    ...
    {
        "id": 149032817,
        "name": "emacs-buttons",
        "full_name": "erjoalgo/emacs-buttons",
        "private": false,
        "owner": {
            "login": "erjoalgo",
            "id": 5349288,
            "node_id": "MDQ6VXNlcjUzNDkyODg=",
            "avatar_url": "https://avatars.githubusercontent.com/u/5349288?v=4",
            "gravatar_id": "",
            "url": "https://api.github.com/users/erjoalgo",
            ...
    },
    ...
]
```



Publish the local git repo at the current directory to github:

`githost github create-repo`


`ls` is short for `ls-repo`. The old command names `key-post`, `repo-list` and
`repo-create` still work.


If required authentication is missing or invalid at any time, the tool will
prompt and walk the user through how to obtain the appropriate github, gitlab or bitbucket API tokens,
and provide the option to cache those tokens locally.

### GitLab

The same commands work with `gitlab` in place of `github`, using a personal
access token with the `api` scope:

`githost gitlab add-key`

`githost gitlab ls-repo`

`githost gitlab create-repo`

For a self-hosted GitLab instance, pass its API base url:

`githost gitlab -b https://gitlab.example.com/api/v4 ls-repo`

`githost gitlab ls-mr` lists your open and merged merge requests across all
projects, then the branches you pushed to that have neither, with `null` in the
first column. Default branches and deleted branches are skipped. Columns: MR,
state, last modified date, url, branch, title.

Inside a clone of a GitLab project (the `gitlab` remote is used if present,
otherwise `origin`; override with `-R REMOTE`):

`githost gitlab create-mr` opens a merge request from the current branch, which
must already be pushed, into the default branch. The last commit message is
opened in `$EDITOR` to become the title (first line) and description, unless
`--title` is given.

## Forgejo

The forgejo service defaults to a private instance at `http://localhost:3123`;
pass `-b https://forgejo.example.com/api/v1` for another one. It authenticates
with an access token (Settings → Applications), stored in `~/.authinfo` under
the API host, e.g. `machine localhost login alice password <token>`.
With several logins for one host, `-u` picks the line; it defaults to
`$GITHOST_USER`, else the first line for the host. E.g. to have your shells act
as you while an agent's shells use its own account:
`[ -n "$CLAUDECODE" ] || export GITHOST_USER=${GITHOST_USER:-alice}`.

Create a repo for the current directory and add it as the `forgejo` remote:

`gfj create-repo -d "description"`

Add users as collaborators on the current directory's repo (`-p` for the
permission, default write), and protect a branch so only you can push to it or
merge. Both work on new and existing repos and are safe to re-run. Run them as
the repo's owner, protecting a branch after it's pushed:

`gfj -u alice add-collaborator claude`

`gfj -u alice protect-branch main`

`protect-branch` sets a Forgejo branch protection rule on that branch with push
and merge allowlists holding only you: collaborators can still push other
branches and open pull requests into it, but only you can push to it or merge
those pull requests.

`publish-repo` does all of it for the current directory's repo: creates it
(skipped if the `forgejo` remote exists), adds the `-c` collaborators, pushes
`main` (else `master`, or `--branch`) with your token, and protects it. It's
safe to re-run:

`gfj -u alice publish-repo -c claude -d "description"`

Open a pull request for the current, already-pushed branch (the title and
description default to the last commit message), and list the repo's PRs:

`gfj create-pr`

`gfj ls-pr -s all`

Show a pull request with all its feedback: comments, reviews, and inline
review comments with their file, line and diff context (defaults to the PR
for the current branch):

`gfj show-pr [NUMBER]`

Comment on a pull request. `-r` quotes the comment being answered, with its
file:line for inline review comments (ids are shown by `show-pr`):

`gfj comment-pr -r 42 -m "Fixed in the latest commit."`

Wait for new feedback on a pull request: blocks until someone else comments or
submits a review after your own last comment, or the PR is closed or merged,
then prints what arrived and how to resume after it (`--since review:ID`, for feedback
that needed no reply). It polls the API every 30 seconds (`-i` to change):

`gfj wait-pr [NUMBER]`
