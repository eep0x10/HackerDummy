.class public Lcom/rootlite/app/TamperCheck;
.super Ljava/lang/Object;
.source "TamperCheck.java"

# "RASP" for the app. Every check is a single naive test that a Frida one-liner or
# an apktool smali patch defeats instantly: no native layer, no attestation, no
# integrity check, results not cross-validated. Security theatre.


# root detection = does /system/bin/su exist? (one path, easily hidden / hooked)
.method public static isRooted()Z
    .locals 3

    new-instance v0, Ljava/io/File;

    const-string v1, "/system/bin/su"

    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v2

    return v2
.end method


# emulator detection = Build.FINGERPRINT contains "generic" (trivially spoofed)
.method public static isEmulator()Z
    .locals 2

    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    const-string v1, "generic"

    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    return v0
.end method


# anti-debug = Debug.isDebuggerConnected() (single call, hook returns false)
.method public static isDebugged()Z
    .locals 1

    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z

    move-result v0

    return v0
.end method
