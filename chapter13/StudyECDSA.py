# “自作 ECDSA 風” 実装：secp256k1 っぽいパラメータで署名と検証を行うデモ
# -----------------------------------------------------------------------------
# 目的
# - 楕円曲線暗号（ECC）の基本演算（点加算・倍算・スカラー倍）を自前で実装し、
#   それを使って ECDSA の署名生成と検証を体験する。
#
# 注意（非常に重要）
# - このコードは「学習用」であり、実務で使ってはいけない。
#   理由：
#   1) 群演算の境界条件が簡略化されており、一般の ECC 演算として不完全。
#   2) ECDSA の検証式が標準の ECDSA と一致していない（u1,u2 の形になっていない）。
#   3) 公開鍵のエンコード/デコードの扱いが secp256k1 の標準とズレる可能性がある。
#   4) KeyGen が “パスフレーズの SHA256 をそのまま秘密鍵” にしており、
#      正規の鍵導出（KDF、salt、反復）ではない。
#   5) 署名の r,s の範囲チェックや 0 の扱いなど、必須の検証が省略されている。
#
# それでも「アルゴリズムの骨格」を理解する教材としては役に立つ。
#
# -----------------------------------------------------------------------------
# 背景：secp256k1（Bitcoin で有名な曲線）
# -----------------------------------------------------------------------------
# 有限体 F_p の素数 p は
#
#   p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
#
# 曲線は
#
#   y^2 = x^3 + 7
#
# で、基点 G=(Gx,Gy)、その位数 n=ordG が与えられている。
#
# ECDSA の要点（標準形）
# - 署名：k を乱数で選び、R=kG、r=R_x mod n、
#         s = k^{-1}(m + r*sk) mod n
# - 検証：w=s^{-1} mod n、
#         u1=m*w mod n, u2=r*w mod n、
#         X = u1*G + u2*PK、
#         r ?= X_x mod n
#
# ※このコードは「署名生成」は上式に近いが、「検証」は標準形と異なる式になっている。
#   学習の際は “標準の検証式” と照合するのが良い。
#
# -----------------------------------------------------------------------------
# 実装の概略
# -----------------------------------------------------------------------------
# 1) mod p の逆元（フェルマー）
# 2) ECC 点演算（加算・倍算・スカラー倍）
# 3) KeyGen：パスフレーズ→SHA256→秘密鍵 sk を作り、公開鍵 sk*G を計算
# 4) ECDSA：メッセージ hash を m とし、乱数 k で署名 (r,s) を作る
# 5) Verify：署名を検証して True/False を返す


from hashlib import sha256
import secrets


def modinv(s, prime):
    # mod prime における逆元 s^{-1} を返す（prime は素数前提）
    #
    # フェルマーの小定理：
    #   s^{prime-1} ≡ 1 (mod prime)
    # よって
    #   s^{prime-2} ≡ s^{-1} (mod prime)
    #
    # 注意：
    # - s≡0 (mod prime) のとき逆元は存在しない（ここでは呼ばれない前提）。
    return pow(s, prime - 2, prime)


def ECadd(P, Q, prime):
    # 楕円曲線上の点の加算 R = P + Q（簡略版）
    #
    # 一般形（x_P != x_Q）：
    #   λ = (y_Q - y_P)/(x_Q - x_P)
    #   x_R = λ^2 - x_P - x_Q
    #   y_R = λ(x_P - x_R) - y_P
    #
    # 注意：
    # - 無限遠点 O の扱いが本来必要だが、ここでは (0,0) を O の代用として返している。
    # - x差が0の場合も一律で (0,0) を返しており、
    #   Q=P（倍算）と Q=-P（加法逆元）の区別をしていない。
    if (Q[0] - P[0]) % prime == 0:
        return (0, 0)  # “無限遠点の代用”

    lam = ((Q[1] - P[1]) * modinv(Q[0] - P[0], prime)) % prime
    x3 = (lam**2 - P[0] - Q[0]) % prime
    y3 = (lam * (P[0] - x3) - P[1]) % prime
    return (x3, y3)


def ECdouble(P, prime):
    # 楕円曲線上の点の倍算 R = 2P（簡略版）
    #
    #   λ = (3x_P^2 + a)/(2y_P)
    #   x_R = λ^2 - 2x_P
    #   y_R = λ(x_P - x_R) - y_P
    #
    # 注意：
    # - y_P==0 のとき 2P=O なので (0,0) を返している。
    # - 係数 a はグローバル変数 a を参照している（関数引数で渡す方が安全）。
    if (2 * P[1]) % prime == 0:
        return (0, 0)

    lam = ((3 * (P[0]**2) + a) * modinv(2 * P[1], prime)) % prime
    x3 = (lam**2 - 2 * P[0]) % prime
    y3 = (lam * (P[0] - x3) - P[1]) % prime
    return (x3, y3)


def ECmult(k, P, prime):
    # スカラー倍 Q = kP を double-and-add（左から右）で計算する。
    #
    # k の2進表現を MSB→LSB で走査し、
    # - 毎回倍算
    # - ビットが1なら加算
    #
    # 注意：
    # - k==0 を invalid として例外にしている（ここでは署名や鍵生成で 0 は不要なのでOK）。
    if k == 0:
        raise ValueError('invalid scalar')

    k_bin = str(bin(k))[2:]
    point = P
    for i in range(1, len(k_bin)):
        point = ECdouble(point, prime)
        if k_bin[i] == "1":
            point = ECadd(point, P, prime)
    return point


def KeyGen(string, P, prime):
    # “秘密フレーズ” から鍵ペアを作る（学習用・簡易版）
    #
    # 1) phrase を SHA256 して 256bit 値を得る
    # 2) それを整数 sk（秘密鍵）として扱う
    # 3) 公開鍵点 pkpt = sk*G を ECC 演算で計算する
    # 4) 公開鍵を "04 || x || y"（非圧縮形式）っぽい 16進列として整数化して返す
    #
    # 注意：
    # - 実務では phrase→鍵 は KDF（salt, 反復, memory-hard 等）を使う。
    # - sk は本来 1..n-1（n=ordG）に落とす必要がある（mod n）。
    shash = sha256(string.encode('utf-8')).hexdigest()
    sk = int(shash, 16)

    # 公開鍵点（楕円曲線上の点）
    pkpt = ECmult(sk, P, prime)

    # 公開鍵の “非圧縮形式” 風エンコード
    # "04" は uncompressed の先頭バイト（本来は bytes で扱うのが普通）
    pk = int("04" + "%064x" % pkpt[0] + "%064x" % pkpt[1], 16)
    return (pk, sk)


def ECDSA(Message, G, sk, order, prime):
    # ECDSA 署名生成（署名 (r,s) を返す）
    #
    # 1) m = SHA256(Message) を整数化
    # 2) 乱数 k を 1..order-1 から選ぶ（k=0 は不可）
    # 3) R = kG を計算し、r = R_x を取る（本来は r = R_x mod n）
    # 4) s = k^{-1}(m + r*sk) mod n を計算
    #
    # 注意：
    # - 本来は r==0 や s==0 のときは k を引き直す必要がある。
    # - ここでは rx=R[0] をそのまま使っており mod order を取っていない。
    # - k の逆元は mod order（位数 n）で取るのが正しいため、modinv(k, order) を使っている。
    Mhash = sha256(Message.encode('utf-8')).hexdigest()
    m = int(Mhash, 16)

    # 署名用乱数 k（secrets は暗号用に安全な乱数）
    k = 0
    while k == 0:
        k = secrets.randbelow(order)

    # R = kG
    R = ECmult(k, G, prime)
    rx = R[0]  # 本来は rx % order を使うのが標準

    # s = k^{-1} (m + r*sk) mod n
    kinv = modinv(k, order)
    S = (kinv * (m + rx * sk)) % order
    return (rx, S)


def Verify(sign, Message, G, pk, order, prime):
    # 署名検証（True/False）
    #
    # 署名 sign=(rx,S) とメッセージ Message が与えられたとき、
    # 正しい署名なら True を返すことを狙う。
    #
    # 実装の流れ（このコードの形）：
    # 1) m = SHA256(Message)
    # 2) pk（整数）から (pkx,pky) を復元（ただしここは非圧縮形式の厳密な復元ではない）
    # 3) Sinv = S^{-1} mod order
    # 4) v = Sinv * (mG + rx*PK) を計算
    # 5) v_x == rx なら True
    #
    # 注意：
    # - 標準 ECDSA の検証は
    #     w=S^{-1}
    #     u1=m*w mod n
    #     u2=r*w mod n
    #     X=u1*G + u2*PK
    #     r ?= X_x mod n
    #   の形。
    # - このコードは “Sinv を最後に掛ける” 形で同等を狙っているが、
    #   m や r の mod n の扱い、rx の mod n 化、公開鍵復元の整合などが揃っていないと破綻し得る。
    Mhash = sha256(Message.encode('utf-8')).hexdigest()
    m = int(Mhash, 16)

    # 公開鍵 pk の “分解”
    # ※ pk は "04||x||y" の整数化だが、この分解は先頭 "04" を無視している。
    #    本来は bytes から厳密にパースする。
    pky = pk % 2**256
    pkx = ((pk - pky) // 2**256) % 2**256
    pkpoint = (pkx, pky)

    rx, S = sign

    # S^{-1} mod n
    Sinv = modinv(S, order)

    # mG と rx*PK を作って加算
    mG = ECmult(m, G, prime)
    rxpk = ECmult(rx, pkpoint, prime)
    v = ECadd(mG, rxpk, prime)

    # Sinv を掛けて v = Sinv*(mG + rx*PK)
    v = ECmult(Sinv, v, prime)

    # x座標が一致するか
    return v[0] == rx


# -----------------------------------------------------------------------------
# secp256k1 のパラメータ設定
# -----------------------------------------------------------------------------
# 素数 p（有限体 F_p）
p = (
    pow(2, 256)
    - pow(2, 32)
    - pow(2, 9)
    - pow(2, 8)
    - pow(2, 7)
    - pow(2, 6)
    - pow(2, 4)
    - pow(2, 0)
)

# 曲線：y^2 = x^3 + ax + b
a = 0
b = 7

# 基点 G
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# 基点 G の位数 n（order）
ordG = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# -----------------------------------------------------------------------------
# 鍵生成（パスフレーズ由来：学習用）
# -----------------------------------------------------------------------------
pk, sk = KeyGen("Change before you have to.", G, p)
print("secret key = ", hex(sk))
print("public key = ", hex(pk))

# -----------------------------------------------------------------------------
# 署名と検証
# -----------------------------------------------------------------------------
Message = "Hello"

# 署名生成
sign = ECDSA(Message, G, sk, ordG, p)
print("x of Digital Signature = ", sign[0])

# 署名検証
verify = Verify(sign, Message, G, pk, ordG, p)
print(verify)
