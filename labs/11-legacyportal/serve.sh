#!/bin/sh
# Launch LegacyPortal (PHP) on http://127.0.0.1:18811
# disable_functions blocks OS-exec + destructive file ops: an included webshell
# still EXECUTES PHP (proving RCE) but cannot run shell commands or harm the host.
DIR="$(cd "$(dirname "$0")" && pwd)"
DF="system,exec,shell_exec,passthru,popen,proc_open,proc_close,pcntl_exec,mail,unlink,rmdir,rename,chmod,symlink,link,file_put_contents,fwrite,fputs"
exec php -d display_errors=1 -d error_reporting=E_ALL -d file_uploads=1 \
  -d upload_max_filesize=8M -d post_max_size=10M -d allow_url_include=0 \
  -d "disable_functions=$DF" \
  -S 127.0.0.1:18811 -t "$DIR/www" "$DIR/router.php"
