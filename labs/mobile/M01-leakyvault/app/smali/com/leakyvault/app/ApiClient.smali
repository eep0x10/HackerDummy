.class public Lcom/leakyvault/app/ApiClient;
.super Ljava/lang/Object;
.source "ApiClient.java"

.field private static final API_KEY:Ljava/lang/String; = "lv_live_3f9c1e7a2b6d40f8a1c5e9d7b2840000"

.field private static final HMAC_SECRET:Ljava/lang/String; = "lv_sign_s3cr3t_DO_NOT_SHIP_00000000"

.field private static final BASE_URL:Ljava/lang/String; = "http://api.leakyvault.example/v1"


.method public static authHeader()Ljava/lang/String;
    .locals 2

    const-string v0, "LeakyVault"

    const-string v1, "Bearer lv_live_3f9c1e7a2b6d40f8a1c5e9d7b2840000"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-object v1
.end method


.method public static endpoint(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .param p0, "path"

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "http://api.leakyvault.example/v1"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
