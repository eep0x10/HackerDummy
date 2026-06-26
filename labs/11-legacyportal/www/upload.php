<?php
/*
 * Avatar upload.  *** INTENTIONALLY VULNERABLE — LAB ONLY ***
 *
 * "Validation" trusts the client-supplied Content-Type and a filename-extension
 * substring — both attacker-controlled — so ANY file (incl. PHP) is accepted
 * (unrestricted upload). Files land in ../storage/uploads (OUTSIDE the docroot,
 * so they are NOT directly web-served) — but the LFI sink in index.php will
 * include() them: upload PHP -> include via ?page=../storage/uploads/<name> -> RCE.
 */
$store = __DIR__ . '/../storage/uploads';
@mkdir($store, 0777, true);

echo "<h2>Avatar Upload</h2>";
echo "<form method='post' enctype='multipart/form-data'>"
   . "<input type='file' name='avatar'> <button>upload</button></form>";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $name = basename($_FILES['avatar']['name']);
    $type = $_FILES['avatar']['type'];                       // client-controlled
    // bypassable: pass if client says image/* OR the name ends in an image ext
    $ok = (strpos((string)$type, 'image/') === 0)
        || preg_match('/\.(jpe?g|png|gif|webp)$/i', $name);
    if ($ok && $name !== '') {
        $dest = $store . '/' . $name;                        // keeps attacker filename
        if (move_uploaded_file($_FILES['avatar']['tmp_name'], $dest)) {
            echo "<p>stored as <code>storage/uploads/" . htmlspecialchars($name) . "</code> — "
               . "include it via <code>index.php?page=../storage/uploads/"
               . htmlspecialchars($name) . "</code></p>";
        } else {
            echo "<p>upload failed</p>";
        }
    } else {
        echo "<p>rejected: not an image</p>";
    }
}
