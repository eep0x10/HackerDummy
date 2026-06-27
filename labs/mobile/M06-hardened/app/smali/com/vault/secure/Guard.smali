.class public Lcom/vault/secure/Guard;
.super Ljava/lang/Object;
.source "Guard.java"


.method public static native nativeAntiDebug()Z
.end method


.method public static isTampered(Landroid/content/Context;)Z
    .locals 4
    .param p1, "ctx"

    const-string v0, "cfg"

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    const-string v2, "qa_disable_checks"

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v2

    if-eqz v2, :run_checks

    return v1

    :run_checks
    invoke-static {}, Lcom/vault/secure/Guard;->nativeAntiDebug()Z

    move-result v3

    return v3
.end method
