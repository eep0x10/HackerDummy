.class public Lcom/dlforge/app/DashboardActivity;
.super Landroid/app/Activity;
.source "DashboardActivity.java"

# The authenticated account dashboard. It assumes it is only ever reached AFTER
# the login flow and performs NO auth check of its own — but it is exported in the
# manifest with no permission, so any app can launch it directly and view the
# account screen without logging in (broken authorization / auth bypass via IPC).


.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    .param p1, "savedInstanceState"

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    const v0, 0x7f030001

    invoke-virtual {p0, v0}, Lcom/dlforge/app/DashboardActivity;->setContentView(I)V

    # no session/auth check here

    return-void
.end method
