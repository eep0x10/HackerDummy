.class public Lcom/rootlite/app/PinActivity;
.super Landroid/app/Activity;
.source "PinActivity.java"



.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    .param p1, "savedInstanceState"

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V


    const v0, 0x7f030002

    invoke-virtual {p0, v0}, Lcom/rootlite/app/PinActivity;->setContentView(I)V

    return-void
.end method


.method public verifyPin(Ljava/lang/String;)Z
    .locals 1
    .param p1, "pin"

    invoke-static {}, Lcom/rootlite/app/TamperCheck;->isRooted()Z

    move-result v0

    return v0
.end method
