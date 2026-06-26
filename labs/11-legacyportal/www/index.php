<?php
/*
 * LegacyPortal — front controller.  *** INTENTIONALLY VULNERABLE — LAB ONLY ***
 *
 * The page router does an unsanitized include() of a user-controlled path — the
 * classic PHP Local File Inclusion sink. It is reachable by every LFI wrapper:
 *   ?page=php://filter/convert.base64-encode/resource=config.php   (source disclosure)
 *   ?page=../../../../Windows/win.ini                              (path traversal read)
 *   ?page=../storage/uploads/<your-upload>                         (upload -> LFI -> RCE)
 *   ?page=phpinfo.php                                              (env disclosure)
 *
 * LAB SAFETY: the server is launched with disable_functions covering OS-exec and
 * destructive file ops (see serve.ps1 / serve.sh). So an included webshell still
 * EXECUTES PHP (proving RCE) but cannot run shell commands or trash the host.
 */
chdir(__DIR__);                       // relative wrappers/traversal resolve from docroot
$page = isset($_GET['page']) ? $_GET['page'] : 'pages/home.php';

echo "<!doctype html><html><head><title>LegacyPortal</title></head><body>";
echo "<h1>LegacyPortal CMS</h1>";
echo "<nav>[<a href='?page=pages/home.php'>home</a>] "
   . "[<a href='?page=pages/about.php'>about</a>] "
   . "[<a href='upload.php'>upload avatar</a>] "
   . "[<a href='admin.php'>admin</a>]</nav><hr>";

include($page);                       // <-- LFI sink (no sanitization)

echo "</body></html>";
