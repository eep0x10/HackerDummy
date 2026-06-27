.class public Lcom/common/lib/TlsPinning;
.super Ljava/lang/Object;
.source "TlsPinning.java"


.method public static client()Lokhttp3/OkHttpClient;
    .locals 5

    new-instance v0, Lokhttp3/CertificatePinner$Builder;

    invoke-direct {v0}, Lokhttp3/CertificatePinner$Builder;-><init>()V

    const-string v1, "api.common.example"

    const/4 v2, 0x2

    new-array v2, v2, [Ljava/lang/String;

    const/4 v3, 0x0

    const-string v4, "sha256/K2v9gT0Qf3mN8pLxY1wZc4aB6dE7hJ0kR5sU2vW8xY="

    aput-object v4, v2, v3

    const/4 v3, 0x1

    const-string v4, "sha256/9mP1qR3tU5wX7yZ0bC2dF4gH6jK8lN0pQ2sT4vW6xY="

    aput-object v4, v2, v3

    invoke-virtual {v0, v1, v2}, Lokhttp3/CertificatePinner$Builder;->add(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;

    invoke-virtual {v0}, Lokhttp3/CertificatePinner$Builder;->build()Lokhttp3/CertificatePinner;

    move-result-object v0

    new-instance v1, Lokhttp3/OkHttpClient$Builder;

    invoke-direct {v1}, Lokhttp3/OkHttpClient$Builder;-><init>()V

    invoke-virtual {v1, v0}, Lokhttp3/OkHttpClient$Builder;->certificatePinner(Lokhttp3/CertificatePinner;)Lokhttp3/OkHttpClient$Builder;

    move-result-object v1

    invoke-virtual {v1}, Lokhttp3/OkHttpClient$Builder;->build()Lokhttp3/OkHttpClient;

    move-result-object v1

    return-object v1
.end method
