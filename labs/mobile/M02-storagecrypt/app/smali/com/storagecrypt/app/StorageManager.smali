.class public Lcom/storagecrypt/app/StorageManager;
.super Ljava/lang/Object;
.source "StorageManager.java"


.method public saveSession(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 4
    .param p1, "ctx"        # Landroid/content/Context;
    .param p2, "token"      # Ljava/lang/String;
    .param p3, "cardPan"    # Ljava/lang/String;

    # MODE_WORLD_READABLE (0x1) — every other app on the device can read these prefs
    const-string v0, "session"

    const/4 v1, 0x1

    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v1

    # auth token written in cleartext
    const-string v2, "auth_token"

    invoke-interface {v1, v2, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    # full card PAN written in cleartext
    const-string v2, "card_pan"

    invoke-interface {v1, v2, p3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    # ...and leaks the same secrets to logcat
    const-string v2, "StorageManager"

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v0, "saved session token="

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " card_pan="

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method


.method public openDb(Landroid/content/Context;)Landroid/database/sqlite/SQLiteDatabase;
    .locals 3
    .param p1, "ctx"    # Landroid/content/Context;

    # plaintext SQLite DB (no SQLCipher) storing PII in cleartext — see assets/db_schema.sql
    const-string v0, "wallet.db"

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1, v1}, Landroid/content/Context;->openOrCreateDatabase(Ljava/lang/String;ILandroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v2

    const-string v0, "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, cpf TEXT, full_name TEXT, card_number TEXT, pin_md5 TEXT)"

    invoke-virtual {v2, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-object v2
.end method
