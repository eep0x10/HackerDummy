.class public Lcom/dlforge/app/FilesProvider;
.super Landroid/content/ContentProvider;
.source "FilesProvider.java"



.method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
    .locals 4
    .param p1, "uri"     # Landroid/net/Uri;
    .param p2, "mode"    # Ljava/lang/String;

    new-instance v0, Ljava/io/File;

    invoke-virtual {p0}, Lcom/dlforge/app/FilesProvider;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    move-result-object v1

    invoke-virtual {p1}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    const v3, 0x10000000    # MODE_READ_ONLY

    invoke-static {v0, v3}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;

    move-result-object v0

    return-object v0
.end method
