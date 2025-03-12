---
description: Query structured data through an API and perform mutations with authorization
---

# GraphQL

## Enumeration

[GraphQL](https://graphql.org/) is an alternative to a REST API, it automatically exposes all data through one endpoint and lets the client query whatever they need. It is also possible to _write_ data. fully replacing the need for regular API endpoints. Of course, this should be guarded by authorization checks to ensure you cannot read data you're not supposed to.

While using an application with GraphQL, the client-side JavaScript code will make fetches to a `/graphql` endpoint. Note that it may be in a subdirectory or renamed, but you should find it in your request history after browsing some data.

### Introspection

When having found such an endpoint, you want to get the "documentation" to understand what kind of queries you can write. There is a built-in feature called _introspection_ where you send a special kind of query, which the server recognizes and returns documentation. Not all servers have this enabled, but if it is, this will make your life much easier.

Below is an example request to check if a GraphQL endpoint has introspection enabled:

```http
POST /graphql HTTP/2
Host: example.com
Content-Type: application/json

{"query": "query { __schema { types { name } } }"}
```

As you can see, a `query` parameter is set to a string version of the query in the body. All introspection queries use the `__schema` key, and here we request the names of all types. A successful response would be something like the following:

<pre class="language-json"><code class="lang-json">{
  "data": {
    "__schema": {
      "types": [
        {"name": "Boolean"},
<strong>        {"name": "CustomType1"},
</strong>        {"name": "Float"},
        {"name": "ID"},
        {"name": "Int"},
        {"name": "Query"},
<strong>        {"name": "SomeOtherCustomType"},
</strong>        {"name": "String"},
        {"name": "StringQueryOperatorInput"},
        {"name": "__Directive"},
        ...
</code></pre>

Instead of exploring these manually ([which you can](https://portswigger.net/web-security/graphql#exploiting-unsanitized-arguments#discovering-schema-information)), tools exist that send these introspection queries to build a schema. You can then read the schema and write queries with auto-completion.

If you're lucky, your target has a URL like `/graphiql` or responds to `GET /graphql` with a playground where you can test the API. However, in more hardened environments this is often not the case. You can however use a regular tool like [Apollo Sandbox](https://www.apollographql.com/docs/apollo-server/v2/testing/graphql-playground) with a URL pointing to your target to send and receive data from there, while having a nice UI.

To aid in this, I created a simple wrapper where you can specify your own URL. You can open this in an empty browser profile with web security disabled to allow CORS without the target having to configure it. Apollo Sandbox allows you to add custom required headers and you can copy over the cookies from your regular authenticated session on your target.

{% embed url="https://github.com/JorianWoltjer/graphiql-always" %}
Interact with any GraphQL endpoint using a nice UI
{% endembed %}

With an introspection response, you can let the following tool generate all possible queries to play around with if you don't want to manually write these queries (although Apollo Sandbox can help with this too):

{% embed url="https://github.com/doyensec/GQLSpection" %}
Generate all possible queries from an introspection
{% endembed %}

### Guessing Schema with Hints

There are reasons for GraphQL APIs to disable introspection, in this case the tool above won't be able to auto-complete queries or fields. What you can do instead is try to fuzz for the right keywords. Often these APIs still give _suggestions_ on your queries if a name is not recognized. With a good wordlist you can often recover a large portion of the API with this method.

The following tool implements this:

{% embed url="https://github.com/nikitastupin/clairvoyance" %}
Fuzz GraphQL APIs to find names and build a schema
{% endembed %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ clairvoyance --help
</strong>usage: clairvoyance [-h] [-v] [-i &#x3C;file>] [-o &#x3C;file>] [-d &#x3C;string>] [-H &#x3C;header>] [-c &#x3C;int>] [-w &#x3C;file>] [-wv] [-x &#x3C;string>] [-k]
                    [-m &#x3C;int>] [-b &#x3C;int>] [-p {slow,fast}] [--progress]
                    url

positional arguments:
  url

options:
  -h, --help            show this help message and exit
  -v, --verbose
  -i &#x3C;file>, --input-schema &#x3C;file>
                        Input file containing JSON schema which will be supplemented with obtained information
  -o &#x3C;file>, --output &#x3C;file>
                        Output file containing JSON schema (default to stdout)
  -d &#x3C;string>, --document &#x3C;string>
                        Start with this document (default query { FUZZ })
  -H &#x3C;header>, --header &#x3C;header>
  -c &#x3C;int>, --concurrent-requests &#x3C;int>
                        Number of concurrent requests to send to the server
  -w &#x3C;file>, --wordlist &#x3C;file>
                        This wordlist will be used for all brute force effots (fields, arguments and so on)
  -wv, --validate       Validate the wordlist items match name Regex
  -x &#x3C;string>, --proxy &#x3C;string>
                        Define a proxy to use for all requests. For more info, read
                        https://docs.aiohttp.org/en/stable/client_advanced.html?highlight=proxy
  -k, --no-ssl          Disable SSL verification
  -m &#x3C;int>, --max-retries &#x3C;int>
                        How many retries should be made when a request fails
  -b &#x3C;int>, --backoff &#x3C;int>
                        Exponential backoff factor. Delay will be calculated as: `0.5 * backoff**retries` seconds.
  -p {slow,fast}, --profile {slow,fast}
                        Select a speed profile. fast mod will set lot of workers to provide you quick result but if the server as
                        some rate limit you may want to use slow mod.
  --progress            Enable progress bar
</code></pre>

After running the tool and receiving an output `schema.json` file, you can upload this to _GraphiQL Explorer_ together with your endpoint to receive auto-completion and view the schema while querying.

For better results, it is recommended to create a **custom wordlist** from as much information as you can find from your target. This can be as simple as running a `\w+` regex over the text to find and extract all unique words that may potentially be query names or fields. Use the `-w` option to provide it to clairvoyance.

Note that while looking at the target's JavaScript files, you can already often find some GraphQL queries stored in there as it is always the browser that requests them. Search for keywords like `query` or `mutation` .

## Features

The basic concepts of GraphQL are explained in the tutorial below:

{% embed url="https://www.howtographql.com/basics/2-core-concepts/" %}
Explaining how the GraphQL concepts relate to each other
{% endembed %}

In summary, you have [_types_ with _fields_](https://graphql.org/learn/schema/). You can [_query_](https://graphql.org/learn/queries/) these types for exactly the fields that you require, or call specific _mutations_ that have server-side logic implemented for them.

### Arguments & Variables

Fields can also have arguments, these are common for filtering results. In your query you fill in these arguments with values.

Queries can also contain arguments, and you can leave these generic to fill them with a separate `variables` parameter. In a request, this looks like:

{% code title="Query with $name variable" %}
```graphql
query ExampleQuery($name: String!) {
  someQuery(arg: $name) {
    id
  }
}
```
{% endcode %}

<pre class="language-http" data-title="Request"><code class="lang-http">POST /graphql HTTP/2
Host: example.com
Content-Type: application/json

<strong>{"query":"query ExampleQuery(...", "variables": {"name": "value"}}
</strong></code></pre>

This is a common pattern for applications because the query can be cached, but only the variable data is unique.

### Mutations

The server can implement functions to handle changes in data, which you can call from GraphQL. These [mutations](https://graphql.org/learn/mutations/) often also use variables as explained above, and have a very similar structure to queries:

{% code title="Mutation with $name variable" %}
```graphql
mutation ExampleMutation($name: String!) { 
  createUser(name: $name) {
    id
    name
  }
}
```
{% endcode %}

{% code title="Request" %}
```http
POST /graphql HTTP/2
Host: example.com
Content-Type: application/json

{"query":"mutation ExampleMutation(...", "variables": {"name": "value"}}
```
{% endcode %}

The variables will be substituted in the query and the server will perform whatever logic it has implemented. The fields `id` and `name` specified inside the function call will be returned after it is done.

You can run multiple mutations in series by providing multiple [_aliases_](https://graphql.org/learn/queries/#aliases) for different functions calls:

{% code title="Multiple mutations" %}
```graphql
mutation { 
  firstUser: deleteUser(id: "42")
  secondUser: deleteUser(id: "1337")
}
```
{% endcode %}

More information about the HTTP requirements for a standard server endpoint can be found in the documentation below:

{% embed url="https://graphql.org/learn/serving-over-http/" %}
Specification on how servers should behave over HTTP
{% endembed %}

### WebSockets

Instead of HTTP, there is also a common library that adds communication via WebSockets:

{% embed url="https://github.com/enisdenjo/graphql-ws" %}

The structure and handlers of this are slightly different from the regular HTTP API, so you may see different behavior like one allowing introspection while the other does not.

The [WebSocket protocol](https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md) is very similar, apart from some protocol changes, queries are the exact same. Below is an example _client_ that queries another server over WebSockets:

```html
<script type="module">
import { createClient } from 'https://cdn.jsdelivr.net/npm/graphql-ws@6.0.4/+esm'

const client = createClient({
  url: "ws://localhost:4000/graphql",
});
console.log("Client connected", client);

(async () => {
  const query = client.iterate({
    query: "{ hello }",
  });

  const { value } = await query.next();
  console.log(value); // { hello: "world" }
})().catch((e) => console.error(e.message));
</script>
```

## Attacks

### Data Leak & IDOR

One common mistake in GraphQL is accidentally exposing too many properties. \
**You should enumerate all fields for every object in every query**. Developers may unintentionally expose properties that should be internal, like a password hash, reset token or 2FA secret.&#x20;

You can use [#introspection](graphql.md#introspection "mention") to get an exhaustive list, or fuzz with [#guessing-schema-with-hints](graphql.md#guessing-schema-with-hints "mention").

Your own user and another user are two very different types. You should be able to see almost all properties of your user, but only a few minimal ones of other users. A naive implementation may just return all properties for all users, potentially exposing too much information if you can get a reference to another user.

Additionally, protections may be set on certain _queries_ rather than _fields_. This has the effect that maybe directly requesting something you are not authorized to won't work, but if you indirectly access the field through some other reference it may still be allowed.

This combines well with Insecure Direct Object Reference (IDOR) vulnerabilities if you need to specify an identifier of some kind in a query/mutation argument.

Lastly, it is good to know that a **mutation returns data**. This is often the object you mutated, but may also expose too many properties. The following syntax gets properties of the result of a mutation:

{% code title="Return data from mutation" %}
```graphql
mutation {
  sendMessage(user_id: 1337, message: "Hi!") {
    user {
      password_hash
    }
  }
}
```
{% endcode %}

### Batching

In a single GraphQL request, you can send multiple queries and/or mutations. If they have the same name, you can differentiate them using an _alias_ which is a `name:` prefix. This can be useful for bypassing per-request rate limiting because a single request may contain many actions.\
Below is an example for brute-forcing a login form, only the alias that was successful will return a valid token in the response:

{% code title="Batch with aliases" %}
```graphql
mutation  {
  a: login(username: "admin", password: "admin")
  b: login(username: "admin", password: "123456")
  c: login(username: "admin", password: "password")
}
```
{% endcode %}

### CSRF

[cross-site-request-forgery-csrf.md](../client-side/cross-site-request-forgery-csrf.md "mention") is a technique where you send a request from an attacker's site straight to the target site, which will be automatically authenticated by the browser adding cookies.

Because GraphQL mutations happen via a simple POST request to a `/graphql` endpoint, implementations of it may also be vulnerable. It is crucial to check if **only cookies provide authentication**, no need for headers. And if so, check the `SameSite=` attribute of the cookie. See the dedicated CSRF page for details on what cases are exploitable and how.

By default, the query and variables are sent with a `Content-Type: application/json` header. This is not directly allowed to be set in a cross-origin request, and the browser will first send a _Preflight_ request. If the response to this OPTIONS request says that it may use the JSON content type, only then will the real `fetch()` request you set up be sent.\
There are ways around this by confusing the content type reader, especially if `SameSite=None` or empty by providing alternative headers and a cleverly set up body.

GraphQL also uses a POST request which causes `SameSite=Lax` cookies not to be sent, even in a top-level form navigation. It may however be possible to change the method to GET and write the `query` parameter in the URL, such as:

```url
GET /graphql?query=mutation%20{...
```

#### WebSocket Hijacking

If the server uses [#websockets](graphql.md#websockets "mention") and only requires `SameSite=None` or empty cookies to authenticate, you can connect with it cross-site. The best thing is that CORS doesn't apply here, you can always **read the response**!

Note that if cookies are `SameSite=Strict`, they will still be sent from subdomains, an XSS or takeover would be enough to compromise the main site in such a case.

All you have to do is connect with the WebSocket, send it a query that will be authenticated as the signed-in victim, and then read the response ([more info](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)).

#### XS-Search via Timing

If you are able to perform CSRF, but there aren't any interesting mutations, you may still get lucky if there are **queries that search private data**. These are inherently vulnerable to a [XS-Leaks](https://xsleaks.dev/docs/attacks/xs-search/) where you send a request from the attacker's site using `fetch()`, and then measure the time it took to resolve the request. The timing can be amplified by [#batching](graphql.md#batching "mention") to slowly leak the data matched by a search query in GraphQL.
