.class public Lcom/vault/secure/Guard;
.super Ljava/lang/Object;
.source "Guard.java"

# The anti-tamper guard. The HEAVY part is real: a native check in libtamper.so
# (anti-debug / anti-Frida / ptrace) plus a Play Integrity verdict. That part is
# strong. THE FLAW: a leftover QA override read from a plain SharedPreference —
# if "qa_disable_checks" is true, isTampered() short-circuits to false and the
# entire guard (native check included) is skipped. A software backdoor defeats the
# whole RASP, and it can be flipped by anyone who can write that pref (see QaActivity).

.method public static native nativeAntiDebug()Z
.end method


.method public static isTampered(Landroid/content/Context;)Z
    .locals 4
    .param p1, "ctx"

    # ---- QA BACKDOOR: if the override pref is set, skip ALL tamper checks ----
    const-string v0, "cfg"

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    const-string v2, "qa_disable_checks"

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v2

    if-eqz v2, :run_checks

    # backdoor hit -> report "not tampered", bypassing the native guard entirely
    return v1

    :run_checks
    # otherwise run the strong native anti-debug/anti-Frida check
    invoke-static {}, Lcom/vault/secure/Guard;->nativeAntiDebug()Z

    move-result v3

    return v3
.end method
