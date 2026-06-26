.class public Lcom/rootlite/app/PinActivity;
.super Landroid/app/Activity;
.source "PinActivity.java"

# The PIN-entry screen for the wallet. It displays/handles the user's secret PIN
# but never calls getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE),
# so the screen (the PIN) is captured by screenshots, screen recording, and shows
# up in the recent-apps thumbnail. No FLAG_SECURE anywhere in the app.


.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    .param p1, "savedInstanceState"

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    # NOTE: no getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) here — sensitive screen
    # left screenshot-/recording-capturable.

    const v0, 0x7f030002

    invoke-virtual {p0, v0}, Lcom/rootlite/app/PinActivity;->setContentView(I)V

    return-void
.end method


.method public verifyPin(Ljava/lang/String;)Z
    .locals 1
    .param p1, "pin"

    # runs the naive RASP checks before accepting the PIN
    invoke-static {}, Lcom/rootlite/app/TamperCheck;->isRooted()Z

    move-result v0

    return v0
.end method
