# ECDH（Elliptic Curve Diffie–Hellman）で共有鍵を生成し、HKDF で鍵素材を整形するデモ
# -----------------------------------------------------------------------------
# 目的
# - 楕円曲線版 Diffie–Hellman（ECDH）により
#   「通信相手と同じ共有秘密（shared secret）」を計算できることを確認する。
# - ECDH の出力（共有秘密）はそのまま暗号鍵として使わず、
#   HKDF のような KDF（Key Derivation Function）で 32 バイト鍵へ整形して使うのが定石。
#
# このコードがやっていること（全体像）
# 1) A と B がそれぞれ楕円曲線の秘密鍵（private key）を生成
# 2) 公開鍵（public key）を取り出して相互に渡す
# 3) A は自分の秘密鍵 d_A と相手の公開鍵 P_B から共有秘密 shk を計算（ECDH）
# 4) B も同様に d_B と P_A から共享秘密を計算
# 5) それぞれ HKDF(SHA-256) で 32 バイトの鍵 K を導出
# 6) A 側の K と B 側の K が一致することを hex 表示で確認
#
# -----------------------------------------------------------------------------
# 背景（ECDH の数学的イメージ）
# -----------------------------------------------------------------------------
# 楕円曲線暗号では（概念的に）
# - 秘密鍵: d（整数）
# - 公開鍵: P = dG（G は曲線上の基点）
#
# ECDH の共有秘密は
#   S = d_A * P_B = d_A * (d_B * G) = (d_A*d_B) * G
#   S = d_B * P_A = d_B * (d_A * G) = (d_A*d_B) * G
# となり一致する（順序が入れ替わっても同じ）。
#
# 実ライブラリでは、共有秘密として点 S そのものではなく、
# 典型的に「点の x 座標」などをバイト列にして返す。
#
# -----------------------------------------------------------------------------
# HKDF を使う理由（非常に重要）
# -----------------------------------------------------------------------------
# ECDH の生出力は “鍵素材（key material）” であり、そのまま AES 鍵などに使うのは推奨されない。
# 理由：
# - 共有秘密の分布や形式が暗号鍵としてそのまま適切とは限らない
# - 異なる用途（暗号化鍵/認証鍵）へ安全に分離したい
# - salt / info により文脈を固定し、鍵の取り違えを防ぐ
#
# HKDF は
# - Extract（擬似乱数化、salt で強化）
# - Expand（用途に応じた長さへ伸長、info で文脈固定）
# を行う標準的な KDF。
#
# このコードでは
# - hash = SHA256
# - length = 32 bytes（256-bit鍵）
# - salt = None（salt無し）
# - info = b'Time is money'（コンテキスト文字列）
# で鍵を導出している。
#
# 実務的な注意：
# - salt=None は「salt を使わない」設定で、理論上は動くが、
#   通常はランダム salt を使う方が望ましい（再利用や構成ミスへの耐性が上がる）。
#
# -----------------------------------------------------------------------------
# PEM 出力についての注意（秘密鍵の扱い）
# -----------------------------------------------------------------------------
# printsk は秘密鍵を PEM でそのまま表示している（NoEncryption）。
# これは学習用としては便利だが、実務では絶対にログ出力しないのが基本。
# -----------------------------------------------------------------------------

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def generate_shk(sk, pk):
    # ECDH で共有秘密（shared secret key material）を生成し、HKDF で 32 バイト鍵へ導出する。
    #
    # 引数:
    # - sk: 自分の秘密鍵（EllipticCurvePrivateKey）
    # - pk: 相手の公開鍵（EllipticCurvePublicKey）
    #
    # 戻り値:
    # - K: HKDF により導出された 32 バイトの共有鍵（bytes）
    #
    # 手順:
    # 1) ECDH により共有秘密 shk（bytes）を得る
    # 2) HKDF(SHA-256) で 32 bytes の鍵へ整形する
    #
    # cryptography の exchange:
    # - sk.exchange(ec.ECDH(), pk) は ECDH の共有秘密を計算して bytes を返す。
    shk = sk.exchange(ec.ECDH(), pk)

    # HKDF による鍵導出
    # - algorithm: 抽出/伸長に使うハッシュ（SHA-256）
    # - length: 欲しい鍵長（32 bytes）
    # - salt: None（salt無し。実用ではランダムsalt推奨）
    # - info: 文脈固定のラベル（用途の分離や取り違え防止）
    K = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'Time is money',
    ).derive(shk)

    return K


def printsk(sk):
    # 秘密鍵を PEM 形式で出力する（学習用）
    #
    # - Encoding.PEM: PEM 形式（Base64 + ヘッダ）
    # - PrivateFormat.PKCS8: 秘密鍵の標準コンテナ形式
    # - NoEncryption: 暗号化なし（本番では危険。学習用途限定）
    print(
        sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def printpk(pk):
    # 公開鍵を PEM 形式で出力する（学習用）
    #
    # - PublicFormat.SubjectPublicKeyInfo: X.509 の一般的な公開鍵表現
    print(
        pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


# -----------------------------------------------------------------------------
# 1) 鍵生成（A側、B側）
# -----------------------------------------------------------------------------
# ec.SECP256R1() は NIST P-256（secp256r1）という楕円曲線。
# - 256-bit セキュリティレベル相当の代表的曲線の一つ。
#
# A の鍵ペア
d_A = ec.generate_private_key(ec.SECP256R1())  # A の秘密鍵
printsk(d_A)
P_A = d_A.public_key()                        # A の公開鍵
printpk(P_A)

# B の鍵ペア
d_B = ec.generate_private_key(ec.SECP256R1())  # B の秘密鍵
printsk(d_B)
P_B = d_B.public_key()                         # B の公開鍵
printpk(P_B)

# -----------------------------------------------------------------------------
# 2) 共有鍵の計算（A側、B側）
# -----------------------------------------------------------------------------
# A 側：d_A と P_B から共有鍵を計算
P_AB = generate_shk(d_A, P_B)
print('P_AB = ', P_AB.hex())

# B 側：d_B と P_A から共有鍵を計算
P_BA = generate_shk(d_B, P_A)
print('P_BA = ', P_BA.hex())

# 期待されること：
# - P_AB と P_BA は同じ bytes 列になる（共有鍵が一致）
# - これが ECDH の基本性質
