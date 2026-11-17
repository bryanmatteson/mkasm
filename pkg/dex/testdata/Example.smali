.class public LExample;
.super Ljava/lang/Object;

.method public static choose(I)I
    .registers 3
    packed-switch p0, :packed
    const/4 v0, -0x1
    goto :done
    :case0
    const/4 v0, 0x5
    goto :done
    :case1
    const/4 v0, 0x6
    :done
    return v0
    :packed
    .packed-switch 0x0
        :case0
        :case1
    .end packed-switch
.end method

.method public static arrays()[I
    .registers 2
    const/4 v0, 0x3
    new-array v0, v0, [I
    fill-array-data v0, :array
    return-object v0
    :array
    .array-data 4
        0x11223344
        -0x2
        0x7fffffff
    .end array-data
.end method

.method public static sparse(I)I
    .registers 2
    sparse-switch p0, :sparse
    const/4 v0, -0x1
    return v0
    :a
    const/4 v0, 0x1
    return v0
    :b
    const/4 v0, 0x2
    return v0
    :sparse
    .sparse-switch
        -0x64 -> :a
        0x1388 -> :b
    .end sparse-switch
.end method

.method public static guarded(Ljava/lang/Object;)V
    .registers 2
    :try_start
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v0
    :try_end
    return-void
    :catch
    move-exception v0
    return-void
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch
.end method

.method public static wide()J
    .registers 2
    const-wide v0, -0x123456789abcdefL
    return-wide v0
.end method
