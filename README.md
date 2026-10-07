`pip install githost`

`githost -h`

Post the local ssh public key at `~/.ssh/id_rsa.pub` to github.

`githost github key-post`

Each service also has a two-letter alias: `gh` (github), `gl` (gitlab) and
`bb` (bitbucket), e.g. `githost gh key-post`, and its own command with the
service already selected: `gh-gh`, `gh-gl` and `gh-bb`, e.g.
`gh-gl ls-mr`.

Use github's API to list the existing repositories in JSON format:

`githost github repo-list`

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

`githost github repo-create`


If required authentication is missing or invalid at any time, the tool will
prompt and walk the user through how to obtain the appropriate github, gitlab or bitbucket API tokens,
and provide the option to cache those tokens locally.

### GitLab

The same commands work with `gitlab` in place of `github`, using a personal
access token with the `api` scope:

`githost gitlab key-post`

`githost gitlab repo-list`

`githost gitlab repo-create`

For a self-hosted GitLab instance, pass its API base url:

`githost gitlab -b https://gitlab.example.com/api/v4 repo-list`

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
