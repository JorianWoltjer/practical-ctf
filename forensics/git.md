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

### Directory Listing

When you visit the `.git` directory on the website, and you can see a list of files relating to git, you know that directory listing is on. This makes it really easy to download everything at once recursively and then examine the repository on your own machine.&#x20;

```shell-session
$ wget -r http://example.com/.git
```

### Git-dumper

When a website disables directory listing, but the `.git` directory can still be found with something like `.git/HEAD`, you might be able to use [git-dumper](https://github.com/arthaud/git-dumper) on it to extract all the files without having the need for directory listing. This tool understands the Git file structure and can find all the related files:

{% embed url="https://github.com/arthaud/git-dumper" %}
A tool to dump a git repository to your local machine, without needing directory listing
{% endembed %}

```shell-session
$ pip install git-dumper
$ git-dumper http://example.com/.git git
```

## Git tricks

If you're running a git repository, you might want to do some more complicated actions. This is a collection of some of these actions as commands to quickly copy and paste.&#x20;

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
