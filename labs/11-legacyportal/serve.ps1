# Launch LegacyPortal (PHP) on http://127.0.0.1:18811
# Safe-by-design: disable_functions blocks OS-exec + destructive file ops, so an
# included webshell still EXECUTES PHP (proving RCE) but cannot run shell commands
# or damage the host. display_errors=1 keeps the (intended) verbose-error leak on.
$php = Join-Path $env:USERPROFILE "scoop\apps\php\current\php.exe"
if (-not (Test-Path $php)) { $php = "php" }
$df = "system,exec,shell_exec,passthru,popen,proc_open,proc_close,pcntl_exec,mail," +
      "unlink,rmdir,rename,chmod,symlink,link,file_put_contents,fwrite,fputs"
& $php -d display_errors=1 -d error_reporting=E_ALL -d file_uploads=1 `
  -d upload_max_filesize=8M -d post_max_size=10M -d allow_url_include=0 `
  -d "disable_functions=$df" `
  -S 127.0.0.1:18811 -t (Join-Path $PSScriptRoot "www") (Join-Path $PSScriptRoot "router.php")
