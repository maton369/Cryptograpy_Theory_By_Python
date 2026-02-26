# PyCryptodome で ECDSA 署名を生成・検証するデモ（DSS / FIPS 186-3 準拠）
# -----------------------------------------------------------------------------
# 目的
# - 楕円曲線 ECDSA（Elliptic Curve Digital Signature Algorithm）を
#   “自作実装” ではなく、信頼できる暗号ライブラリ（PyCryptodome）で正しく使う練習をする。
# - 署名は「秘密鍵で署名を作り、公開鍵で検証する」ことを確認する。
#
# 使うコンポーネント
# - Crypto.PublicKey.ECC : ECC 鍵生成・インポート/エクスポート
# - Crypto.Hash.SHA256   : メッセージのハッシュ（メッセージダイジェスト）
# - Crypto.Signature.DSS : ECDSA を含む DSS（Digital Signature Standard）実装
#   * FIPS PUB 186-3 に準拠した署名方式として扱う
# - binascii             : 署名バイト列を16進表記で見やすく表示する
#
# -----------------------------------------------------------------------------
# 背景：なぜハッシュするのか？
# -----------------------------------------------------------------------------
# ECDSA は “メッセージそのもの” を直接署名するのではなく、
# まずハッシュ（ダイジェスト）に変換して署名する。
#
#   md = H(message)
#   signature = Sign(sk, md)
#
# こうする理由
# - 任意長メッセージを固定長に圧縮できる（署名アルゴリズムの入力を固定長化）
# - メッセージ全体を扱うより効率的
# - 衝突困難性などハッシュ関数の性質が安全性に寄与する
#
# -----------------------------------------------------------------------------
# 背景：DSS.new(..., 'fips-186-3') とは？
# -----------------------------------------------------------------------------
# DSS モジュールは ECDSA 署名を生成する “枠組み” を提供する。
# 'fips-186-3' は FIPS 186-3 の仕様に沿った署名生成方式を選ぶ指定で、
# 特に署名生成で必要な nonce k（毎回ランダムに選ぶ秘密値）などの取り扱いが
# 仕様に沿って実装されている。
#
# 実務上のポイント
# - ECDSA の安全性は nonce k の品質に強く依存する。
# - 自作実装で k の生成をミスると秘密鍵が漏れる事故が起きやすい。
# - ライブラリを使う利点は、こうした危険な部分を正しく実装してくれていること。
#
# -----------------------------------------------------------------------------
# このコードがやっていること（流れ）
# -----------------------------------------------------------------------------
# 1) 署名対象メッセージ（bytes）を用意
# 2) P-256 の ECC 鍵ペアを生成
# 3) 公開鍵（または鍵情報）を PEM 形式でエクスポートして表示
# 4) 署名生成：
#    - SHA256(message) を作る
#    - DSS.new(sk,'fips-186-3') で署名器を作る
#    - signer.sign(md) で署名（bytes）を得る
# 5) 検証：
#    - 公開鍵を import
#    - 同じく SHA256(message) を作る
#    - verifier.verify(md, signature) を実行
#    - 例外が出なければ True、出れば False
# 6) 署名を 16進表示し、検証結果を表示


from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import binascii


# -----------------------------------------------------------------------------
# 署名対象メッセージ（bytes）
# -----------------------------------------------------------------------------
message = b'Living well is the best revenge.'

# -----------------------------------------------------------------------------
# 鍵生成（P-256）
# -----------------------------------------------------------------------------
# curve='P-256' は NIST P-256（secp256r1）の楕円曲線。
# ECC.generate は秘密鍵を含む鍵オブジェクトを返す（公開鍵も導出できる）。
key = ECC.generate(curve='P-256')

# 鍵を PEM 形式で出力（通常は秘密鍵を含む形式で出ることがあるので注意）
# 学習用として表示しているが、実務では秘密鍵のログ出力は避ける。
pk = key.export_key(format='PEM')
print(pk)


def ECDSAsignature(sk, message):
    # ECDSA 署名生成
    #
    # 引数:
    # - sk: 秘密鍵（ECC key object）
    # - message: bytes
    #
    # 手順:
    # 1) md = SHA256(message) を作る（message digest）
    # 2) signer = DSS.new(sk, 'fips-186-3') を作る
    # 3) signature = signer.sign(md) で署名を得る（bytes）
    #
    # 署名はバイト列として返る（DER形式のようなエンコードである場合がある）。
    md = SHA256.new(message)              # message digest（ハッシュ）
    signer = DSS.new(sk, 'fips-186-3')    # FIPS 186-3 準拠の署名器
    signature = signer.sign(md)           # 署名生成（bytes）
    return signature


def ecdsa_verify(pk, message, signature):
    # 署名検証
    #
    # 引数:
    # - pk: PEM 形式の公開鍵（または鍵情報）文字列
    # - message: bytes
    # - signature: bytes（署名）
    #
    # 手順:
    # 1) key = ECC.import_key(pk) で鍵を読み込む
    # 2) md = SHA256(message) を作る
    # 3) verifier = DSS.new(key,'fips-186-3') を作る
    # 4) verifier.verify(md, signature) を呼ぶ
    #    - 正しければ何も起きない
    #    - 不正なら ValueError が投げられる
    key = ECC.import_key(pk)
    md = SHA256.new(message)
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(md, signature)
        return True
    except ValueError:
        return False


# -----------------------------------------------------------------------------
# 署名生成 → 16進表示 → 検証
# -----------------------------------------------------------------------------
signature = ECDSAsignature(key, message)
print('ECDSA signature:', binascii.hexlify(signature))

print(ecdsa_verify(pk, message, signature))
