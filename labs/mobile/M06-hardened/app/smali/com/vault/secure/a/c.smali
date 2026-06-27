.class public Lcom/vault/secure/a/c;
.super Ljava/lang/Object;
.source "c.java"

# ProGuard/R8-obfuscated class (a.c). Despite the renaming, it still ships the
# HMAC request-signing secret as a base64 string constant compiled into the dex.
# Anyone who unpacks the APK and greps for the constant recovers the live signing
# key — obfuscation is not a secret store. (placeholder value, training only)

.field private static final a:Ljava/lang/String; = "aE1hYz0xZjljMWU3YTJiNmQ0MGY4YTFjNWU5ZDdiMjg0c2VjcmV0"


# returns the decoded HMAC signing key used to sign API requests
.method public static a()Ljava/lang/String;
    .locals 3

    const-string v0, "aE1hYz0xZjljMWU3YTJiNmQ0MGY4YTFjNWU5ZDdiMjg0c2VjcmV0"

    const/4 v1, 0x0

    invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v0

    new-instance v2, Ljava/lang/String;

    invoke-direct {v2, v0}, Ljava/lang/String;-><init>([B)V

    return-object v2
.end method
