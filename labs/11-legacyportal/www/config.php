<?php
/*
 * Application configuration. NOT meant to be web-readable — but the LFI sink in
 * index.php exposes its SOURCE via php://filter/convert.base64-encode.
 * (Secret-shaped strings here are non-functional lab placeholders.)
 */
$DB_HOST    = 'localhost';
$DB_USER    = 'portal_admin';
$DB_PASS    = 'Pr0d-Portal-DB-2026!';
$APP_SECRET = 'legacyportal_hardcoded_secret_9f8a7c2b1d';
define('FLAG', 'flag{php_filter_source_disclosure}');
