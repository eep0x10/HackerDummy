.class public Lcom/dlforge/app/DeepLinkActivity;
.super Landroid/app/Activity;
.source "DeepLinkActivity.java"


.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    .param p1, "savedInstanceState"

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    # data of the inbound (exported, BROWSABLE) deep link: dlforge://go?target=...
    invoke-virtual {p0}, Lcom/dlforge/app/DeepLinkActivity;->getIntent()Landroid/content/Intent;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v1

    const-string v2, "target"

    invoke-virtual {v1, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    # INTENT REDIRECTION: parse an arbitrary intent URI from the link and fire it,
    # with no validation of the component/target. An attacker can redirect into
    # any unexported internal Activity (auth bypass) or out to an attacker target.
    const/4 v3, 0x0

    invoke-static {v2, v3}, Landroid/content/Intent;->parseUri(Ljava/lang/String;I)Landroid/content/Intent;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/dlforge/app/DeepLinkActivity;->startActivity(Landroid/content/Intent;)V

    return-void
.end method
