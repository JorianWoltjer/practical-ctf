---
description: Using timing information to extract information
---

# Timing Attacks

While certain endpoints may only return a `true`/`false` response like a login page, there is other information that is often forgotten: Time. From sending a request to receiving a response, a few things happen. Firstly, the data need to be transferred and read by the server. Then the data is processed and any algorithms are performed like checking a password. Finally, the response is sent back to the client. The important thing to know is that the timing of that **middle** part may reveal sensitive information.&#x20;

Let's say for example that we have a very simple password-checking mechanism that takes longer to run as we get closer to the real password:

```python
def check_password(password):
    # Check length
    if len(password) != len(REAL_PASSWORD):
        return False
    
    # Check password character by character
    for i in range(len(password)):
        if password[i] != REAL_PASSWORD[i]:
            return False
        
    return True  # Correct
```

This function first checks if the length is correct, and then loops through every character in the password one by one. At the first incorrect character, it quickly returns `False` and does not even look at the rest of the characters. This causes a completely wrong password to be discarded almost instantly, while a password close to the real password takes more loops and time to check.&#x20;

This timing information can be used to try **different characters** and **look for when the computing time increases**. Let's try to attack the above example, with a `REAL_PASSWORD="hunter2"`. This will cause timings to be different depending on how close we are to the password:

```python
setup = "from __main__ import check_password"
py
print(timeit.timeit("check_password('incorrect_length')", setup=setup, number=1000000))
# 0.106 -> very short, because length check instantly returns False
print(timeit.timeit("check_password('closer!')", setup=setup, number=1000000))
# 0.288 -> a bit longer, because the length check passes
print(timeit.timeit("check_password('hunter1')", setup=setup, number=1000000))
# 0.574 -> much longer because of more iterations in the loop
```

We will have to start by finding the correct length, which we can try by just providing different lengths and finding the one that took the longest to compute, meaning it likely passed the first `if` statement:

```python
samples = {}

for length in range(1, 10):
    password = "a" * length
    time = timeit.timeit(f"check_password({password!r})", setup=setup, number=1000000)
    print(f"{length} -> {time:.3f}")
    samples[length] = time
    
print("Found length:", max(samples, key=samples.get))
```

This will try all lengths from 1-9, and show the execution time of 1 million iterations:

```rust
0 -> 0.099
1 -> 0.099
2 -> 0.126
3 -> 0.098
4 -> 0.101
5 -> 0.101
6 -> 0.108
7 -> 0.302  // longest
8 -> 0.121
9 -> 0.111
Found length: 7
```

Now we know the length is 7, and we can try to find the first character. Only if this first character is correct, will it continue with checking the second character, causing it to take longer. We'll start by trying every possible character in the first spot, with a correct length to actually reach this loop:

```python
samples = {}

for c in "abcdefghijklmnopqrstuvwxyz0123456789":
    password = c.ljust(length, "a")  # "Xaaaaaa"
    
    time = timeit.timeit(f"check_password({password!r})", setup=setup, number=1000000)
    print(f"{password!r} -> {time:.3f}")

c = max(samples, key=samples.get)
print("Found char:", c)
```

Running this code is less reliable than the first leak because the difference between correct and incorrect guesses is smaller. But even with this difference, we are able to find the first character: `'h'` which takes slightly longer on average:

```rust
'aaaaaaa' -> 0.299
...
'gaaaaaa' -> 0.286
'haaaaaa' -> 0.361  // longest
'iaaaaaa' -> 0.323
...
'9aaaaaa' -> 0.283
Found char: h
```

Now that we know the first character, we can keep continuing like this by just prefixing our guess with the part we already know. Slowly we will build out the `REAL_PASSWORD` character by character and eventually find the whole string:

```python
found = ""
for i in range(length):
    samples = {}

    for c in "abcdefghijklmnopqrstuvwxyz0123456789":
        password = (found + c).ljust(length, "a")
        
        time = timeit.timeit(f"check_password({password!r})", setup=setup, number=1000000)
        print(f"{password!r} -> {time:.3f}")
        samples[c] = time
        
    c = max(samples, key=samples.get)
    print("Found char:", c)
    found += c

print("Found password:", found)
```

```rust
...
Found char: h
'haaaaaa' -> 0.318
...
'htaaaaa' -> 0.332
'huaaaaa' -> 0.370  // longest
'hvaaaaa' -> 0.327
...
'h9aaaaa' -> 0.322
Found char: u
...
'hunter1' -> 0.600
'hunter2' -> 0.611  // longest
'hunter3' -> 0.580
Found char: 2
Found password: hunter2
```

While the above example output shows it working, this code is **very unreliable,** especially near the end where random speedups and slowdowns happen more often. This is because the timing attack we are performing here is based on differences of **microseconds**, and even the slightest disturbance can mess up our measurements. Using the `timeit` library we are taking a million measurements of this function directly, without random network delays or anything. Still, the differences in timing are so tiny that it is hard to tell the correct character for sure near the end.&#x20;

For a practical attack, there often needs to be something more than more loop iterations slowing the program down. It can be useful to try and make something special happen that takes a long time if the first part is correct, like with [#string-exfiltration-via-redos](../languages/regular-expressions-regex.md#string-exfiltration-via-redos "mention"), but otherwise try to get the **most accurate** measurements and take advantage of **statistics** to find the outlier.&#x20;

{% hint style="info" %}
While the above example shows a password login system, this idea is applicable in many more places with many developers being unaware of the issue. Especially in cryptographic algorithms timing information can leak valuable information, so this is a good place to check
{% endhint %}

## Statistics

Getting accurate measurements is one of the most important things in timing attacks. Intuitively using more samples will give better results, but a tricky part is often how to analyze all those samples and extract the outlier.&#x20;

There is an important difference between the **average** (mean), **median**, and **mode**. All 3 are useful statistical functions that try to combine many samples into one that summarizes the sequence the best.&#x20;

* **Average (mean)**: Sum all values, then divide that sum by the number of samples. Will be swayed by a very high or low outlier
* **Median**: Order the values, and take the center one. Won't be swayed by a few outliers as they will not be in the center
* **Mode**: Most common value. Not possible if all values are different, but if they fall into certain 'buckets' the most common bucket can be chosen. Also won't be swayed by outliers

As you can see, the _average_ function is problematic in that it will be swayed one way very heavily if the value is large, which can be a problem when outliers try to pull on either end of the average with a big deviation. The _mode_ function works pretty well, but it is often hard or complicated to apply in practice. The _**median**_ function however seems like a perfect fit as it is not easily affected by outliers, and is always applicable. That is why we often use this function to find a regular sample value without much noise.&#x20;

Then when we have all the regular samples of attempts, we need to find which one constantly outperforms the others. This can be done with a simple **`max`** function that takes the highest one, or a smarter algorithm that checks to see if the maximum value actually has a significant difference, or if we are unsure. If we have values of `[1.9, 1.8, 2.1, 4.2, 2.0, 10.8]`, for example, the `max` function would give `10.8` as output while there is also the `4.2` value that stands out to us. A smart algorithm might take these best values, and run more tests to see if the `10.8` was just a random outlier, or if that was actually the correct value. \
This idea could be implemented by performing a **tournament-style elimination** where values need to keep performing well in order to reach the top, at which point we can be more sure they are correct. Often simply taking the maximum value is enough, however, because we are already normalizing outliers with the median function.&#x20;

## Reducing noise

While statistics can help, sometimes it is just impossible to tell which value has significance. Depending on the situation, a few tricks can be used to get the most consistent possible values, eliminating as much outside noise as possible.&#x20;

### Warming up

A simple trick that can mitigate startup slowdowns, is sending a few bogus requests to the server beforehand so that it 'warms up', and then without pause switch over to your real queries.

### Randomizing order

While running your timing attack, a server might slow down for a small period of time because of high load, or speed back up later when optimization kicks in. This can mess up your measurements if you are all A's at first, then B's, C's, etc. one after the other. Your first A's might then be slower on average, than the Z's at the end. Not because the A's are correct, but because of this noise in the system that slows down or speeds up randomly.&#x20;

To mitigate this, you can try randomizing the order in which you send samples to the server. This way, if a random slowdown happens, all values are affected equally and not just a big batch of A's but no Z's. You can implement this by creating a queue of requests to send, and then randomly resolving items from the queue to put in the result. When the queue is empty, the result should be filled up as everything is resolved and you can use [#statistics](timing-attacks.md#statistics "mention") to further analyze which is correct. This will help significantly reduce noise that happens for more requests at a time.&#x20;

### Racing using Parallel requests

Instead of measuring response _time_, you might also be able to measure response **order**. If you can make sure two requests are received on the server at the exact same time, they will be processed at the same time, and the first one to complete is sent back first. If this is done through the same TCP connection, TCP will guarantee that the order of the packets stays the same and you will be able to determine based off of this which is most likely correct.&#x20;

Instead of finding the maximum time it took to respond, this method will measure the **number of races won** which should be 50/50 for incorrect guesses, but significantly higher/lower for correct ones. The number of races you should do depends on how big the difference in time is, but this can be found by testing.&#x20;

When possible, this attack is so powerful that it can detect **microsecond** differences on **remote** servers, as has been shown for HTTP/2 in [this paper](https://www.usenix.org/system/files/sec20-van\_goethem.pdf).&#x20;

## Existing Attacks

{% embed url="https://github.com/ConnorNelson/spaceless-spacing" %}
Parallel requestst in HTTP/2 can releal microscopic timing differences from a server
{% endembed %}

{% embed url="https://tom.vg/2016/08/browser-based-timing-attacks/" %}
Via browser side-channels timing of the first and last received byte can leak response sizes
{% endembed %}
