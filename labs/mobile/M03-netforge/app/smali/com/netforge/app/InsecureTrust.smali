.class public Lcom/netforge/app/InsecureTrust;
.super Ljava/lang/Object;
.source "InsecureTrust.java"

.implements Ljavax/net/ssl/X509TrustManager;


.method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    .param p1, "chain"
    .param p2, "authType"

    return-void
.end method


.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    .param p1, "chain"
    .param p2, "authType"

    return-void
.end method


.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/security/cert/X509Certificate;

    return-object v0
.end method


.method public static allowAllHostnames()Ljavax/net/ssl/HostnameVerifier;
    .locals 1

    new-instance v0, Lcom/netforge/app/InsecureTrust$1;

    invoke-direct {v0}, Lcom/netforge/app/InsecureTrust$1;-><init>()V

    return-object v0
.end method
