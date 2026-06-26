<?php
/*
 * Built-in-server router (NOT a vulnerability — server plumbing).
 *
 * Without it, PHP's CLI server falls back to index.php for EVERY unknown path, so
 * the app answers 200 for /web.config, /wp-admin/, /totally-random, ... and any
 * content scan thinks the whole wordlist exists. This router serves real files,
 * routes "/" to the front controller, and 404s everything else — matching how a
 * real deployment behaves. The LFI/upload/etc. bugs live in www/*.php, untouched.
 */
$uri = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
$docroot = realpath($_SERVER['DOCUMENT_ROOT']);
$file = realpath($docroot . $uri);

// Serve a real file that lives inside the docroot (PHP executed, static served).
if ($uri !== '/' && $file !== false && is_file($file) && strpos($file, $docroot) === 0) {
    return false;
}
// Front controller for the site root.
if ($uri === '/' || $uri === '') {
    require $docroot . '/index.php';
    return true;
}
// Everything else genuinely does not exist.
http_response_code(404);
header('Content-Type: text/plain');
echo "404 Not Found\n";
return true;
