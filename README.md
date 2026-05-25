: pip install githost
: githost -h

Post the local ssh public key to github.

: githost github key-post

List the existing repositories
: githost github repo-list

Publish the local git repo at the current directory to github:
: githost github repo-create


If required authentication is missing or invalid at any time, the tool will
prompt and walk the user through how to obtain the appropriate github or bitbucket API tokens.