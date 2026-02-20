# 暗号学的に安全な乱数（CSPRNG）を使ってパスワードを生成する例
# -----------------------------------------------------------------------------
# このコードは「英大小文字 + 数字」からなる長さ length のランダム文字列を生成して表示する。
#
# 重要（セキュリティ観点）
# - パスワード生成では「予測困難な乱数」が必要なので、CSPRNG（暗号学的に安全な乱数生成器）を使う。
# - Python 標準では secrets モジュールが推奨される（内部で OS の安全な乱数を使う）。
# - ここでは PyCryptodome 系の Crypto.Random.random を使っている。
#
# 注意（ライブラリ観点）
# - `Crypto.Random.random` は「乱数 API」を提供するモジュールで、Python の random に似た関数群を持つ。
# - その中の `choice` を使うと、与えたシーケンス（文字列など）から 1 要素を CSPRNG に基づいて選べる。
#
# 依存関係
# - `Crypto` は PyCryptodome（または古い PyCrypto）の名前空間で提供される。
#   現在は PyCryptodome の利用が一般的。
#
# インストール例（参考）
# - pip install pycryptodome
#
# 実装方針
# - lst に「許可文字集合」を作る
# - Crypto.Random.random.choice(lst) を length 回呼んで、文字を連結してパスワードにする

import Crypto.Random.random  # PyCryptodome の CSPRNG ベース乱数API（random互換）
import string               # ASCII文字集合（英字/数字などの定数が入っている）

# 生成するパスワード長
length = 8

# パスワードに使用する文字の候補集合
# - string.ascii_letters: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
# - string.digits       : '0123456789'
# これらを連結して「英大小文字 + 数字」の集合にしている
lst = string.ascii_letters + string.digits

# パスワード生成本体
# - Crypto.Random.random.choice(lst) により、lst から 1 文字を CSPRNG に基づいて選ぶ
# - それを length 回繰り返す
# - join で連結して 1 つの文字列にする
#
# Python の内包表記:
#   (Crypto.Random.random.choice(lst) for i in range(length))
# は「length 回 choice を呼んで文字を生成するイテレータ」を作っている
password = ''.join(Crypto.Random.random.choice(lst) for i in range(length))

# 結果表示
print("password:", password)
