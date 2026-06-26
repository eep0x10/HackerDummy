<?php
// Diagnostics page left in production — exposes full PHP environment, paths,
// loaded modules, disable_functions, env vars. Classic info leak.
phpinfo();
