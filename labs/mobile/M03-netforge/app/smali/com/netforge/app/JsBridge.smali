.class public Lcom/netforge/app/JsBridge;
.super Ljava/lang/Object;
.source "JsBridge.java"


.field private final ctx:Landroid/content/Context;


.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    .param p1, "ctx"

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/netforge/app/JsBridge;->ctx:Landroid/content/Context;

    return-void
.end method


.method public getToken()Ljava/lang/String;
    .locals 1
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    const-string v0, "auth_token"

    invoke-direct {p0, v0}, Lcom/netforge/app/JsBridge;->readPref(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method


.method public readFile(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p1, "path"
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    invoke-static {p1}, Lcom/netforge/app/JsBridge;->slurp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
