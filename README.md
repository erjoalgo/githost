`pip install githost`

`githost -h`

Post the local ssh public key at `~/.ssh/id_rsa.pub` to github.

`githost github key-post`

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
prompt and walk the user through how to obtain the appropriate github or bitbucket API tokens.