`pip install githost`

`githost -h`

Post the local ssh public key at `~/.ssh/id_rsa.pub` to github.

`githost github add-key`

Each service also has a two-letter alias: `gh` (github), `gl` (gitlab) and
`bb` (bitbucket), e.g. `githost gh add-key`, and its own command with the
service already selected: `ggh`, `ggl` and `gbb`, e.g.
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
