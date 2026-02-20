# PyCryptodome を使った AES 暗号化モード比較（ECB / CBC / CTR）+ PKCS#7 パディング
# -----------------------------------------------------------------------------
# このコードは、同じ平文・同じ鍵を使って AES を
#   - ECB モード
#   - CBC モード
#   - CTR モード
# で暗号化し、復号して元の平文に戻ることを確認するデモである。
#
# 重要（セキュリティ観点の注意）
# - ECB は「同じ平文ブロックが同じ暗号文ブロックになる」ためパターンが漏れやすく、実務では基本的に非推奨。
# - CBC は IV（初期化ベクトル）が必須で、毎回ランダム IV を使うのが通常。
#   このデモでは説明のため固定IV（b'0'*16）にしているが、実務では危険。
# - CTR は「ストリーム暗号化」と同様の性質になり、nonce（およびカウンタ）を再利用すると致命的。
#   したがって nonce は毎回一意（通常ランダム）にする必要がある。
# - さらに実務では “暗号化だけ” ではなく改ざん検知（MAC / AEAD）が必要。
#   例: AES-GCM / ChaCha20-Poly1305 など。
#
# 重要（パディング観点）
# - AES はブロック暗号なので、ECB/CBC は入力がブロックサイズの倍数である必要がある。
# - そのため PKCS#7 でパディングしている。
# - CTR は本来ブロック境界不要だが、このコードはモード比較のため同じ padded plaintext を使っている。
#
# 依存ライブラリ
# - PyCryptodome（Crypto.* 名前空間）
#   pip install pycryptodome

import Crypto.Cipher.AES as AES              # AES 本体（ブロック暗号アルゴリズム）
import Crypto.Util.Padding as PAD            # PKCS#7 pad/unpad（ブロック境界合わせ）
from Crypto.Random import get_random_bytes   # 暗号学的に安全な乱数（nonce 生成等に利用）

# -----------------------------------------------------------------------------
# パラメータ準備
# -----------------------------------------------------------------------------

# AES のブロックサイズは 16 bytes（=128 bits）で固定
blocksize = AES.block_size  # 16

# 平文（デモ用の英語文）
# ここでは ASCII のみで構成される文字列なので .encode('ascii') が成功する。
ptext = 'The man who has no imagination has no wings.'

# AES の鍵（16/24/32 bytes が可能 = AES-128/192/256）
# ここでは 16 bytes なので AES-128。
# 注意: 実務では固定鍵をコードに直書きしない（KMS/環境変数/安全な保管が必要）。
key = b'0123456789abcdef'

# 入力確認表示
print('plaintext: %s' % ptext.encode('ascii'))
print('key: %s' % key)

# -----------------------------------------------------------------------------
# PKCS#7 パディング
# -----------------------------------------------------------------------------
# AES-ECB/CBC は入力長が 16byte の倍数でないと暗号化できない。
# PKCS#7 は「足すバイト数 N を値 N のバイトで埋める」方式。
#
# 例）ブロックサイズ16で残りが 5byte 足りないなら
#   ... 0x05 0x05 0x05 0x05 0x05
# を末尾に付ける。
#
# PyCryptodome の pad は bytes を受け取り、パディング済み bytes を返す。
ptext_pad = PAD.pad(ptext.encode('ascii'), blocksize, 'pkcs7')
print('plaintext_pkcs7pad: %s' % ptext_pad)

# -----------------------------------------------------------------------------
# AES-ECB モード
# -----------------------------------------------------------------------------
# ECB（Electronic Codebook）
# - 各ブロックを独立に暗号化する最も単純なモード。
# - IV が不要。
# - しかし同じ平文ブロックは同じ暗号文ブロックになり、パターンが漏れるため実務では基本非推奨。
#
# 暗号化手順
# 1) cipher = AES.new(key, AES.MODE_ECB)
# 2) ciphertext = cipher.encrypt(padded_plaintext)
aesECB = AES.new(key, AES.MODE_ECB)
cipherECB = aesECB.encrypt(ptext_pad)
print('ciphertext using ECB mode: %s' % cipherECB.hex())

# 復号手順
# 1) cipher = AES.new(key, AES.MODE_ECB)  ※同じ鍵・同じモード
# 2) decrypted_padded = cipher.decrypt(ciphertext)
# 3) unpad して元の平文 bytes を得る
aesECB = AES.new(key, AES.MODE_ECB)
decctext = aesECB.decrypt(cipherECB)
decptext = PAD.unpad(decctext, blocksize, 'pkcs7')
print('decrypted ciphertext(ECB): %s' % decptext.decode('ascii'))

# -----------------------------------------------------------------------------
# AES-CBC モード
# -----------------------------------------------------------------------------
# CBC（Cipher Block Chaining）
# - 前の暗号文ブロックを次の平文ブロックに XOR してから暗号化する方式。
# - 最初のブロックは IV と XOR してから暗号化する。
#
# 重要
# - IV は「毎回ランダム」が基本（同じ鍵で IV 再利用は危険）。
# - このコードではデモの再現性のため iv = b'0'*16 にしているが、
#   実務用途では必ず get_random_bytes(16) を使うべき。
iv = b'0' * blocksize  # デモ用の固定IV（実務ではNG）
aesCBC = AES.new(key, AES.MODE_CBC, iv)
cipherCBC = aesCBC.encrypt(ptext_pad)
print('ciphertext(CBC): %s' % cipherCBC.hex())

# CBC の復号
# - 同じ key と同じ iv が必要
aesCBC = AES.new(key, AES.MODE_CBC, iv)
decctext = aesCBC.decrypt(cipherCBC)
decptext = PAD.unpad(decctext, blocksize, 'pkcs7')
print('decrypted ciphertext(CBC): %s' % decptext.decode('ascii'))

# -----------------------------------------------------------------------------
# AES-CTR モード
# -----------------------------------------------------------------------------
# CTR（Counter）
# - ブロック暗号を「ストリーム暗号的」に使うモード。
# - (nonce || counter) を AES で暗号化して得られる "keystream" と平文を XOR する。
# - 復号も同じ XOR なので、encrypt/decrypt は同じ操作になる（API上は decrypt を使っているだけ）。
#
# 重要
# - nonce（およびカウンタ系列）は「同じ鍵で絶対に再利用しない」必要がある。
#   再利用すると keystream が一致し、XOR から平文差分が漏れて致命的。
#
# 実装メモ（PyCryptodome）
# - AES.new(..., AES.MODE_CTR, nonce=..., initial_value=...) で CTR を作れる。
# - nonce の長さ + counter の長さ = ブロックサイズ（16byte）になるように内部で構成される。
# - このコードでは nonce を 4byte にし、initial_value=0 からカウントを開始している。
#
# 注意（パディング）
# - CTR はブロック境界に合わせる必要がないので本来 pad 不要。
# - ただしこのコードは ECB/CBC と比較しやすいように pad 済み平文をそのまま使っている。
nc = get_random_bytes(4)  # nonce（毎回ランダムに生成する）
aesCTR = AES.new(key, AES.MODE_CTR, nonce=nc, initial_value=0)
cipherCTR = aesCTR.encrypt(ptext_pad)
print('ciphertext using CTR mode: %s' % cipherCTR.hex())

# CTR の復号
# - 同じ key と同じ nonce と同じ initial_value が必要
aesCTR = AES.new(key, AES.MODE_CTR, nonce=nc, initial_value=0)
decctext = aesCTR.decrypt(cipherCTR)
decptext = PAD.unpad(decctext, blocksize, 'pkcs7')
print('decrypted ciphertext(CTR): %s' % decptext.decode('ascii'))
