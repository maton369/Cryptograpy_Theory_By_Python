# PyCryptodome を使った RSA の鍵生成 / OAEP 暗号化・復号 / 署名・検証（PKCS#1 v1.5）デモ
# -----------------------------------------------------------------------------
# このコードは「RSA で現実的に正しい使い方」に寄せたサンプルで、
# 以下を一通り行う：
#
# 1) RSA 鍵ペア（秘密鍵・公開鍵）を生成
# 2) PEM 形式でファイルに保存（private.pem, public.pem）
# 3) OAEP（PKCS#1 OAEP）で公開鍵暗号化 → 秘密鍵復号
# 4) SHA-256 と PKCS#1 v1.5 署名（pkcs1_15）で署名生成 → 公開鍵で検証
#
# -----------------------------------------------------------------------------
# 重要（セキュリティ上の注意）
# -----------------------------------------------------------------------------
# - keysize=1024 は現代の安全水準では弱い（推奨は少なくとも 2048bit 以上）。
#   教材として軽く動かすなら 1024 でも良いが、実務では使わない。
#
# - 秘密鍵 private.pem を平文で保存している。
#   実務ならパスフレーズで暗号化して保存する（export_key(passphrase=..., pkcs=8, protection=...) 等）。
#
# - 署名方式に pkcs1_15（PKCS#1 v1.5 署名）を使っている。
#   v1.5 は広く使われているが、可能ならより新しい RSA-PSS を使うのが推奨されることが多い。
#
# - OAEP は “暗号化” 用の安全なパディング方式で、textbook RSA（素の RSA）より安全。
#   署名は OAEP ではなく PSS / PKCS#1 v1.5 を使う（用途が違う）。
#
# -----------------------------------------------------------------------------
# ライブラリ（PyCryptodome）の役割
# -----------------------------------------------------------------------------
# - Crypto.PublicKey.RSA      : RSA 鍵の生成、PEM 形式の import/export
# - Crypto.Cipher.PKCS1_OAEP  : RSA-OAEP による暗号化/復号
# - Crypto.Hash.SHA256        : ハッシュ（署名対象のダイジェスト計算）
# - Crypto.Signature.pkcs1_15 : RSA PKCS#1 v1.5 署名と検証
#
# -----------------------------------------------------------------------------
# 1) import
# -----------------------------------------------------------------------------
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

# -----------------------------------------------------------------------------
# 2) RSA 鍵生成
# -----------------------------------------------------------------------------
keysize = 1024  # 鍵長（bit）※実務なら 2048 以上推奨

# RSA.generate(keysize) は (n, e, d, p, q, ...) を含む秘密鍵オブジェクトを生成する。
# - 内部でランダム素数 p, q を作り、n=pq を構成する。
# - 乱数は OS の CSPRNG（暗号学的擬似乱数）に依存する。
private_key = RSA.generate(keysize)

# print(private_key) は鍵の中身を表示するので、実務では危険（ここは教材としてのデモ）。
print(private_key)

# -----------------------------------------------------------------------------
# 3) 秘密鍵を PEM 形式で保存
# -----------------------------------------------------------------------------
# export_key() は PEM（Base64 + ヘッダ/フッタ）形式の bytes を返す。
# decode('utf-8') で文字列にしてファイルへ書く。
#
# 注意：この書き方だと秘密鍵が “暗号化されずに” 保存される。
# 実務なら export_key(passphrase=..., pkcs=8, protection="scryptAndAES128-CBC" など) を検討する。
with open('private.pem', 'w') as f:
    f.write(private_key.export_key().decode('utf-8'))

# -----------------------------------------------------------------------------
# 4) 公開鍵を取り出して PEM 保存
# -----------------------------------------------------------------------------
# publickey() で公開鍵（n と e を持つ）を取得する。
public_key = private_key.publickey()

with open('public.pem', 'w') as f:
    f.write(public_key.export_key().decode('utf-8'))

# -----------------------------------------------------------------------------
# 5) RSA-OAEP による暗号化（公開鍵）→復号（秘密鍵）
# -----------------------------------------------------------------------------
message = 'The man who has no imagination has no wings.'

# OAEP (Optimal Asymmetric Encryption Padding)
# - RSA の暗号化用途で推奨されるパディング方式。
# - 同じ message を暗号化してもランダム性が入るため、ciphertext が毎回変わる（決定的でない）。
#
# PKCS1_OAEP.new(public_key) で OAEP 暗号器を作る。
pubcipher = PKCS1_OAEP.new(public_key)

# encrypt は bytes を入力に取るので、encode() して渡す。
ciphertext = pubcipher.encrypt(message.encode())

# 復号器（秘密鍵側）
private_cipher = PKCS1_OAEP.new(private_key)

# decrypt は bytes を返すので、decode('utf-8') して文字列に戻す。
message2 = private_cipher.decrypt(ciphertext).decode("utf-8")

# ※ここでは message2 を表示していないが、正しく復号できていれば message と一致するはず。

# -----------------------------------------------------------------------------
# 6) RSA デジタル署名（PKCS#1 v1.5）と検証
# -----------------------------------------------------------------------------
# 署名は「暗号化」と目的が違う：
# - 暗号化: 秘密を守る（機密性）
# - 署名  : 改ざん検知 + 本人性（鍵所有の証明）
#
# 署名ではメッセージ全体をそのまま RSA するのではなく、
# まず SHA-256 でハッシュ（ダイジェスト）を取り、それに署名する。
#
# SHA256.new(data) は PyCryptodome の hash オブジェクトを返す。
# このオブジェクトは署名APIが期待する形式（ASN.1/DER での識別子込み）に対応している。
message = 'The man who has no imagination has no wings.'
h1 = SHA256.new(message.encode())

# pkcs1_15.new(private_key).sign(hashobj) で署名を生成
# - 署名は bytes（RSA の modexp の結果をバイト列化したもの）として返る
signature = pkcs1_15.new(private_key).sign(h1)

# -----------------------------------------------------------------------------
# 7) 署名検証（公開鍵）
# -----------------------------------------------------------------------------
# 検証側も同じメッセージからダイジェストを作る。
mdigest = SHA256.new(message.encode())

# verify は「署名が正しいなら何も返さず成功」「失敗なら例外」を投げる設計。
try:
    pkcs1_15.new(public_key).verify(mdigest, signature)
    verified = True
except ValueError:
    verified = False

# 検証結果を表示（True なら署名は正しい）
print(verified)

# -----------------------------------------------------------------------------
# 追加メモ（学習の次の一手）
# -----------------------------------------------------------------------------
# - 署名方式を RSA-PSS に変える例：
#     from Crypto.Signature import pss
#     signature = pss.new(private_key).sign(h1)
#     pss.new(public_key).verify(mdigest, signature)
#
# - 鍵長を 2048/3072 にするとより現実的（ただし生成が少し重くなる）。
#
# - 秘密鍵のファイル保存はパスフレーズ暗号化して保護するのが定石。
