---
description: >-
  Markdown is an easy to use markup language used in the Github README for
  example
---

# Markdown

## Syntax

Markdown is a standard for text markup. It allows you to make text **bold**, _italic_, and in all kinds of different styles. It uses special characters around certain text to apply markup to it. Often markdown is used in text editors like on GitHub `README.md` files or Discord messages. Then the files are converted to another language like HTML with CSS or PDF to actually show the Here are the rules:

{% embed url="https://www.markdownguide.org/cheat-sheet/" %}
A cheatsheet explaining all of the Markdown syntax
{% endembed %}

| Element                                                             | Markdown Syntax                                                                                    |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| <h3>Heading</h3>                                                    | <p><code># H1</code><br><code>## H2</code><br><code>### H3</code></p>                              |
| **Bold**                                                            | `**bold text**`                                                                                    |
| _Italic_                                                            | `*italicized text*`                                                                                |
| ![](<../.gitbook/assets/image (8) (1).png>)                         | `> blockquote`                                                                                     |
| <ol><li>First item</li><li>Second item</li><li>Third item</li></ol> | <p><code>1. First item</code><br><code>2. Second item</code><br><code>3. Third item</code><br></p> |
| <ul><li>First item</li><li>Second item</li><li>Third item</li></ul> | <p><code>- First item</code><br><code>- Second item</code><br><code>- Third item</code><br></p>    |
| `code`                                                              | `` `code` ``                                                                                       |
| ![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png>) | `---`                                                                                              |
| [Link](https://www.example.com)                                     | `[title](https://www.example.com)`                                                                 |
| ![](<../.gitbook/assets/image (11) (1).png>)                        | `![alt text](image.jpg)`                                                                           |

### Advanced Syntax

| <p></p><table><thead><tr><th>Syntax</th><th>Description</th></tr></thead><tbody><tr><td>Header</td><td>Title</td></tr><tr><td>Paragraph</td><td>Text</td></tr></tbody></table> | <p><code>| Syntax | Description |</code><br><code>| ----------- | ----------- |</code><br><code>| Header | Title |</code><br><code>| Paragraph | Text |</code></p>                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <p></p><pre class="language-json"><code class="lang-json">{
  "firstName": "John",
  "lastName": "Smith",
  "age": 25
}
</code></pre>                                          | <p><code>```json</code><br><code>{</code><br>  <code>"firstName": "John",</code><br>  <code>"lastName": "Smith",</code><br>  <code>"age": 25</code><br><code>}</code><br><code>```</code></p> |
| ~~Strikethrough~~                                                                                                                                                              | `~~strikethrough~~`                                                                                                                                                                           |
| <p></p><ul class="contains-task-list"><li><input type="checkbox" checked>Checklist</li><li><input type="checkbox">Item 2</li><li><input type="checkbox">Item 3</li></ul>       | <p><code>- [x] Write the press release</code><br><code>- [ ] Update the website</code><br><code>- [ ] Contact the media</code></p>                                                            |
| Emoji! 😀                                                                                                                                                                      | `Emoji! :grinning:`                                                                                                                                                                           |

## Markdown XSS

Markdown often gets compiled to HTML to be styled with CSS later. When converting something to HTML you need to make sure attackers can't inject arbitrary HTML, like `<script>` tags. Another idea is a `javascript:` URL in links so JavaScript code is executed when clicked. You can find a lot of Markdown XSS payloads in the following list:

{% embed url="https://github.com/cujanovic/Markdown-XSS-Payloads/blob/master/Markdown-XSS-Payloads.txt" %}
List of Markdown XSS payloads
{% endembed %}

To fuzz for and create **your own payloads**, read the following article where they explore an idea for different nested parsers that can mutate into XSS:

{% embed url="https://swarm.ptsecurity.com/fuzzing-for-xss-via-nested-parsers-condition/" %}
A methodology for finding Markdown XSS parser vulnerabilities in custom implementations
{% endembed %}
