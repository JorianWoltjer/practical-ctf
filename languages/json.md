---
description: >-
  JSON is a widely used format to store structured data, with arrays and
  dictionary keys
---

# JSON

## Description

JSON (JavaScript Object Notation) was originally only used for JavaScript, but nowadays it's used in all sorts of languages and applications. It's a simple format consisting of lists, dictionaries, strings, and numbers which almost all languages can understand.&#x20;

The power comes from being able to nest lists and dictionaries:

{% code title="Example" %}
```json
{
    "something": {
        "list": [1, 2, 3, 4],
        "keys": {
            "number": 123,
            "string": "Hello, world!"
        },
        "array": [
            {
                "with": "a"
            },
            {
                "dictionary": "inside"
            }
        ]
    }
}
```
{% endcode %}

You can represent any combination of lists and dictionaries like this. With numbers or strings as the final value for a key.&#x20;

To validate a JSON string, or to format it nicely you can use the following online tool:

{% embed url="https://jsonformatter.curiousconcept.com/" %}
A tool where you can paste in JSON to validate and format it
{% endembed %}

### Format rules

There are a few edge cases where JSON has some rules on how it's formatted.&#x20;

* **Escaping strings**: Not all characters can be in `""` strings. This `"` double quote itself for example needs to be escaped if you want to represent it in a string. This is done with the `\` **backslash**, like `\"`. You can also escape the backslash by escaping it with another backslash, like `\\`. Newlines are also not allowed in strings, which is why you need to `\n` character to represent a newline.&#x20;
* **No comma on the end of a list/dictionary**: When defining a list like `[1,2,3,4]` you may not include an extra comma like `[1,2,3,4,]`. Some programming languages are flexible with this, but JSON is not.&#x20;
* **No single quotes**: JSON works exclusively with `"` double quotes, meaning you **cannot** define strings with `'` single quotes. Some programming languages are flexible with this, but JSON is not.&#x20;
* **Whitespace does not matter**: Whitespace between lists, dictionary keys, etc. does not matter in JSON. You can have a very compact format without any newlines or spaces. Or a very readable format like in the example above, with newlines and spaces.&#x20;

## Languages

A few examples of how to use JSON for specific programming languages.&#x20;

### JavaScript

You can use the [`JSON.stringify()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global\_Objects/JSON/stringify) and [`JSON.parse()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global\_Objects/JSON/parse) standard functions to convert to and from JSON. Here JavaScript will output compact JSON without any whitespace by default.&#x20;

```javascript
// Object to JSON string
>>> let data = {
        'something': {
            "list": [1, 2, 3, 4],
            'keys': {
                "number": 123,
                "string": 'Hello, world!'
            },
            "array": [
                {"with": 'a'},
                {"dictionary": "inside"}
            ]
        }
    }
>>> JSON.stringify(data)
'{"something":{"list":[1,2,3,4],"keys":{"number":123,"string":"Hello, world!"},"array":[{"with":"a"},{"dictionary":"inside"}]}}'

// JSON string to Object
>>> JSON.parse('{"something":{"list":[1,2,3,4],"keys":{"number":123,"string":"Hello, world!"},"array":[{"with":"a"},{"dictionary":"inside"}]}}')
{something: {…}}
```

### Python

Python has the standard [`json`](https://docs.python.org/3/library/json.html) module that can load and dump JSON data. It works very similarly to the JavaScript functions from above.&#x20;

```python
import json

# Object to JSON string
>>> data = {
        'something': {
            "list": [1, 2, 3, 4],
            'keys': {
                "number": 123,
                "string": 'Hello, world!'
            },
            "array": [
                {"with": 'a'},
                {"dictionary": "inside"}
            ]
        }
    }
>>> json.dumps(data)
'{"something": {"list": [1, 2, 3, 4], "keys": {"number": 123, "string": "Hello, world!"}, "array": [{"with": "a"}, {"dictionary": "inside"}]}}'
>>> json.dumps(data, indent=4)  # Pretty formatted
'{\n    "something": {\n        "list": [\n            1,\n            2,\n            3,\n            4\n        ],\n        "keys": {\n            "number": 123,\n            "string": "Hello, world!"\n        },\n        "array": [\n            {\n                "with": "a"\n            },\n            {\n                "dictionary": "inside"\n            }\n        ]\n    }\n}'

# JSON string to Object
>>> json.loads('{"something": {"list": [1, 2, 3, 4], "keys": {"number": 123, "string": "Hello, world!"}, "array": [{"with": "a"}, {"dictionary": "inside"}]}}')
{'something': {…}}
```

## [jq](https://stedolan.github.io/jq/) (JSON Query)

`jq` is a command-line utility to parse and filter JSON. It has its own syntax that allows you to transform and select things from a JSON string. For a complete and detailed manual of all the functionality see the following page:

{% embed url="https://stedolan.github.io/jq/manual/" %}
Manual for the jq syntax
{% endembed %}

There are two main ways to get some JSON data into `jq`. You can either specify a file to read the data from or pipe data into `jq` with the `|` in bash (in this example `.` matches everything):

```shell-session
$ jq [FILTER] [FILES...]
$ jq . data.json  # Read from file
$ echo '{"hello":"world"}' | jq .  # Read from STDIN
{
  "hello": "world"
}
```

### Options

* `-r`: Raw output, shows strings in the output as raw text without the surrounding `"` quotes. Useful when passing output to other tools that need simple newline separated values.&#x20;

```shell-session
$ echo '[{"some": "thing"}, {"some": "other"}]' | jq .[].some
"thing"
"other"
$ echo '[{"some": "thing"}, {"some": "other"}]' | jq -r .[].some
thing
other
```

### Filters

The power of `jq` is when you learn to different filters. Forget having to write Python scripts to parse and search through JSON, use `jq` instead.&#x20;

Filters **always start** with `.`, to start from the root of the JSON.&#x20;

#### Lists and Objects

To get to a specific value in JSON you can use the `.` and `[]` syntax.&#x20;

* [`.foo.bar`](https://stedolan.github.io/jq/manual/#ObjectIdentifier-Index:.foo,.foo.bar): Gets a **key** from an object
  * Input: `{"foo": {"bar": 123}}`
  * Output: `123` a
* [`.[2]`](https://stedolan.github.io/jq/manual/#ArrayIndex:.\[2]): Gets an array **index**. Starting from 0
  * Input: `["first", "second", "third", "fourth"]`
  * Output: `"third"`
* [`.[1:3]`](https://stedolan.github.io/jq/manual/#Array/StringSlice:.\[10:15]): Gets a **slice** of the array from one index to another
  * Input: `["first", "second", "third", "fourth"]`
  * Output: `[ "second", "third" ]`&#x20;
* [`.[].foo`](https://stedolan.github.io/jq/manual/#Array/ObjectValueIterator:.\[]): **Iterate** through all indexes of the array
  * Input: `[{"some": "thing"}, {"some": "other"}]`
  * Output: `"thing"` `"other"`
* [`?`](https://stedolan.github.io/jq/manual/#OptionalObjectIdentifier-Index:.foo?): Optional. Place after some key or array to not give errors when `null`
* [`..`](https://stedolan.github.io/jq/manual/#RecursiveDescent:..): Recursively descend JSON to every value. Very useful when used with `?`

#### Combining filters

You can combine all these filters to get very specific values from a JSON object. Using the `|` pipe operator, you can feed the output of one filter, into the next filter. When the first filter gives multiple outputs, the second filter runs on all outputs separately, allowing you to for example iterate through some array, and get keys from those entries.&#x20;

{% code title="Examples" %}
```jq
# Get all "some" keys from objects in an array
[{"some": "thing"}, {"some": "other"}]
jq .[] | .some
"thing"
"other"

# Recursively search for key "some", ignoring null values
[{"some": "thing"}, {"further": {"some": "other"}}]
jq '.. | .some? | select(. != null)'
"thing"
"other"
```
{% endcode %}

#### Functions

There are some functions in the `jq` syntax that allow you to test or select specific values.&#x20;

* [`select(boolean)`](https://stedolan.github.io/jq/manual/#select\(boolean\_expression\)): Continue with this value if true, and stop if false. Only selects when the boolean condition passes

```jq
# Select "value" key where "name" is "b"
[{"name": "a", "value": "value_a"}, {"name": "b", "value": "value_b"}]
jq '.[] | select(.name == "b") | .value'
"value_b"
```

* [`test(regex; flags)`](https://stedolan.github.io/jq/manual/#test\(val\),test\(regex;flags\)): Test if the value matches [regular-expressions-regex.md](regular-expressions-regex.md "mention"). Useful for checking if a value contains some text or pattern in a `select()` statement

```jq
# Match /second/i regex for name, and return value
[{"name": "this_First_name", "value": "value_a"}, {"name": "and_Second_name", "value": "value_b"}]
jq '.[] | select(.name | test("second"; "i")) | .value'
"value_b"
```

#### Constructing Objects/Arrays

Sometimes the JSON format is not exactly what you want, and you want to restructure it a bit, or only select a few values. This is where you can use `jq` to select and reconstruct an object in a new format. At any time you can use `{.key: value, .other: value}` to construct an object to either pass into another filter, or just as output.&#x20;

```jq
# Select where name is "b", then change name to matched_name, and add 10 to value
[{"name": "a", "value": 1}, {"name": "b", "value": 2}]'
jq '.[] | select(.name == "b") | {matched_name: .name, value: (.value+10)}
{
  "matched_name": "b",
  "value": 12
}
```

The same idea works for arrays. You can use `[values...]` to output a certain array:

```jq
# Get "value" key from all items and put them in an array
[{"name": "a", "value": 1}, {"name": "b", "value": 2}]
jq '[.[].value]'
[1, 2]
```

### Examples

Some practical examples of using `jq` to parse and filter JSON

#### Server List Ping

The [Minecraft Server List Ping](https://wiki.vg/Server\_List\_Ping) protocol returns JSON in the following format:

```json
{
  "version": "1.19.1",
  "protocol": 760,
  "ip": [
    "127.0.0.1",
    25565
  ],
  "players": [],
  "favicon": "",
  "motd": {
    "text": "A Vanilla Minecraft Server powered by Docker",
    "bold": false,
    "italic": false,
    "underlined": false,
    "strikethrough": false,
    "obfuscated": false,
    "color": null,
    "extra": []
  }
}
```

Imagine we have an array of these objects, and we want to find servers where the `motd` text contains "docker". In this case, we can use the recursive descend, `select()` and `test()` functions:

```jq
jq '.[] | select(.motd | ..|.text? | select(. != null) | test("docker"; "i"))'
```
