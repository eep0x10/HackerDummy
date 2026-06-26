<?php
/*
 * Admin gate.  *** INTENTIONALLY VULNERABLE — LAB ONLY ***
 *
 * The key check uses loose comparison (==) against a "magic hash" secret. In PHP,
 * two strings that both look like scientific-notation numbers (0e[digits]) are
 * compared AS NUMBERS and both equal 0 -> PHP type-juggling authentication bypass.
 * A submitted key of "0e1" (or any 0e<digits>) authenticates as admin.
 */
define('ADMIN_FLAG', 'flag{php_type_juggling_auth_bypass}');

// magic-hash-shaped secret: 0e followed by digits only
$SECRET_HASH = '0e462097431906509019562988736854';

$authed = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['key'])) {
    if ($_POST['key'] == $SECRET_HASH) {     // == (loose) instead of === (strict)
        $authed = true;
    }
}

echo "<h2>Admin Panel</h2>";
if ($authed) {
    echo "<p>Authenticated as <b>admin</b>. " . ADMIN_FLAG . "</p>";
} else {
    echo "<form method='post'><input name='key' placeholder='admin key'> "
       . "<button>login</button></form>";
}
