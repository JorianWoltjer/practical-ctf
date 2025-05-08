---
description: Frontend framework with template-like syntax
---

# Angular

{% hint style="warning" %}
This page is about [Angular](https://angular.dev/) (V2+), _not_ [AngularJS](https://angularjs.org/) (V1.x). Check out the [#angularjs](../client-side/cross-site-scripting-xss/#angularjs "mention") page for ways to achieve XSS using Client-Side Template Injection in that older version of the framework.
{% endhint %}

### innerHTML

The [`innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML) property of HTML elements is notorious in the world of [cross-site-scripting-xss](../client-side/cross-site-scripting-xss/ "mention"). This is because in regular JavaScript, it will render a string to the DOM, which may include JavaScript code like `<img src onerror=alert(origin)>`.

Because you can still write raw JavaScript in Angular, the following code will still be vulnerable in the same way:

```javascript
elem.innerHTML = `<p>${input}</p>`
```

The more common way to do this, however, is using a _bind_:

```html
<p [innerHTML]="input"></p>
```

`input` here refers to a variable with that name, defined in JavaScript. While this may look similar, the bind example will apply the [Angular Sanitizer](https://angular.dev/best-practices/security#sanitization-example) ([source code](https://github.com/angular/angular/blob/main/packages/core/src/sanitization/html_sanitizer.ts)). This removes any dangerous HTML elements or attributes.

The filter is pretty tight, and any bypass would be a vulnerability in Angular itself. It is so restricted that some developers will notice intended markup being removed, so they **disable the sanitization**. This can be done using the [`bypassSecurityTrustHtml()`](https://angular.dev/api/platform-browser/DomSanitizer#bypassSecurityTrustHtml) function.

```typescript
constructor(private sanitizer: DomSanitizer) {
  this.input = this.sanitizer.bypassSecurityTrustHtml("<img src onerror=alert(origin)>");
}
```

This is often companied by some sort of sanitizer, which you should carefully review to determine if there are any bypasses possible in this potentially less secure version instead of the Angular default.

Another indirect way to put a string into the DOM is using [`DOMParser.parseFromString()`](https://developer.mozilla.org/en-US/docs/Web/API/DOMParser/parseFromString). Because Angular doesn't see this, it will bypass its sanitizer too:

```typescript
@ViewChild("p") p: ElementRef | undefined;
ngAfterViewInit() {
  const html = new DOMParser().parseFromString("<img src onerror=alert(origin)>", "text/html").body.firstChild;
  this.p?.nativeElement.appendChild(html);
}
```
