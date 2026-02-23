# べき乗剰余（modular exponentiation）の実装例
# -----------------------------------------------------------------------------
# このコードは、a^b mod n を計算するための代表的なアルゴリズムを3種類示している。
#
# (1) ModpowerLtoR : Left-to-Right（左から右）二乗法（square-and-multiply）
# (2) ModpowerRtoL : Right-to-Left（右から左）二乗法（square-and-multiply）
# (3) Modpower2kary: 2^k-ary（ウィンドウ法/基数 2^k 法）の Left-to-Right 版
#
# 背景（なぜ重要か）
# - RSA, Diffie-Hellman, ElGamal, ECC（有限体上）などの公開鍵暗号では
#   a^b mod n の計算（modexp）がコアになる。
# - そのまま a**b を計算すると指数 b が大きい場合に巨大になり非現実的なので、
#   各ステップで mod n を取りつつ「繰り返し二乗法」で高速化する。
#
# 計算量の目安
# - 二乗法（LtoR/RtoL）: O(log b) 回の平方 + （ビットが1の回数）回の乗算
# - 2^k-ary 法: 事前計算 O(2^k) + 本体 O((log b)/k) ブロックごとの平方（k回）+ 乗算（非ゼロブロック時）
#
# 注意（セキュリティ/実装上）
# - ここでは exponent b のビット列を文字列にして分岐している。
#   実務の暗号実装ではサイドチャネル（タイミング攻撃など）対策として
#   分岐の仕方や一定時間化（constant-time）が重要になる。
# - Python は多倍長整数が標準なので動作は簡単だが、速度やサイドチャネル対策は別問題。


def ModpowerLtoR(a, b, n):
    # Left-to-Right 二乗法（square-and-multiply）
    #
    # 目的：a^b mod n を計算する。
    #
    # アルゴリズム（左から右）
    # - b を2進数表現したビット列（MSB→LSB）を順に見る。
    # - 毎ステップ：
    #     S = S^2 mod n
    #     もしビットが 1 なら S = S*a mod n
    #
    # 直感
    # - 既に上位ビットまで処理した値を S に持っているとすると、
    #   次のビットを読むと指数が「2倍（シフト）」されるので平方が必要。
    # - 次のビットが1なら +1 されるので a を掛ける。
    #
    # 例：b=13 (1101b)
    #   S=1
    #   bit=1: S=S^2=1,  S=S*a=a          -> a^1
    #   bit=1: S=S^2=a^2, S=S*a=a^3       -> a^3
    #   bit=0: S=S^2=a^6                   -> a^6
    #   bit=1: S=S^2=a^12,S=S*a=a^13      -> a^13
    bit = str(format(b, "b"))  # b を2進文字列へ（例: 13 -> "1101"）

    S = 1  # 途中結果（累積）
    for i in range(len(bit)):
        # 次のビットに進むたび指数が 2倍になるので平方
        S = (S ** 2) % n

        # そのビットが 1 なら、指数に +1 が入るので a を掛ける
        if bit[i] == "1":
            S = (S * a) % n

    return S


def ModpowerRtoL(a, b, n):
    # Right-to-Left 二乗法（square-and-multiply）
    #
    # 目的：a^b mod n を計算する。
    #
    # アルゴリズム（右から左）
    # - b の LSB→MSB を見ていく（下位ビットから）。
    # - 途中で「a^(2^i) mod n」を T に保持しておく。
    # - 毎ステップ：
    #     もし iビット目が1なら S = S*T mod n
    #     T = T^2 mod n   （次の桁に進むため）
    #
    # 直感
    # - b の2進展開は b = Σ b_i 2^i
    # - a^b = Π (a^(2^i))^{b_i}
    # - b_i が1のときだけその因子を掛ければよい。
    bit = str(format(b, "b"))  # MSB→LSB の文字列
    bitrev = bit[::-1]         # 反転して LSB→MSB にする

    S = 1      # 結果の累積（掛け合わせ）
    T = a % n  # 現在の a^(2^i) を表す値（最初は i=0 なので a）

    for i in range(len(bitrev)):
        # iビット目が1なら、その因子 a^(2^i) を掛ける
        if bitrev[i] == "1":
            S = (S * T) % n

        # 次のビットへ：a^(2^(i+1)) = (a^(2^i))^2
        T = (T ** 2) % n

    return S


def Divide(b, k):
    # b を “基数 2^k” の桁列に分解する関数
    #
    # 目的：
    # - 2^k-ary 法（ウィンドウ法）では、指数 b を k ビットずつのブロックに分けて処理する。
    # - ここでは b を w = 2^k 進数とみなして、下位桁から parts に詰める。
    #
    # 例：k=3 なら w=8
    #   b を 8進数的に分解して parts=[下位, ..., 上位] を返す。
    parts = []
    w = 2 ** k  # 基数（1ブロックが k ビット）

    while b != 0:
        # 下位 k ビット（= b mod 2^k）を1桁として取り出す
        parts.append(b % w)
        # 次の桁へ（b を 2^k で割る）
        b //= w

    return parts  # 下位→上位の順


def Modpower2kary(a, b, n, k=3):
    # Left-to-Right 2^k-ary method（いわゆる “固定ウィンドウ法” の一種）
    #
    # 目的：a^b mod n を計算する。
    #
    # 発想
    # - b を 2^k 進数（= k ビット単位）で表す：
    #     b = Σ d_i * (2^k)^i   （各 d_i は 0..2^k-1）
    # - すると
    #     a^b = Π (a^{d_i})^{(2^k)^i}
    # - 左から処理すると、
    #   「次のブロックに進む」たびに指数が (2^k) 倍になるので、
    #   S を 2^k 乗（= k 回の平方）してから a^{d_i} を掛ける形になる。
    #
    # アルゴリズム概要
    # 1) 事前計算（precomputation）:
    #    tbl[d] = a^d mod n を d=0..2^k-1 まで作る
    # 2) b を kビットブロックに分割し、上位ブロック→下位ブロックで処理
    #    - 毎ブロック:
    #        S = S^(2^k) mod n  （k回平方）
    #        if d != 0: S = S * tbl[d] mod n
    #
    # 計算量のイメージ（概算）
    # - 事前計算: 2^k 回程度の乗算
    # - 本体: ブロック数 = 約 (bitlength(b)/k)
    #   各ブロックで k 回平方 +（非ゼロブロックなら）1回乗算

    # -------------------------
    # 1) 事前計算：tbl[d] = a^d mod n
    # -------------------------
    tblsize = 2 ** k
    tbl = [1] * tblsize

    # tbl[0]=1, tbl[1]=a, tbl[2]=a^2, ... を順に作る
    # ※累積で作っているので乗算回数が少ない
    a_mod = a % n
    for i in range(1, tblsize):
        tbl[i] = (tbl[i - 1] * a_mod) % n

    # -------------------------
    # 2) b を kビット単位（2^k進数）に分割して左から処理
    # -------------------------
    S = 1

    # Divide は “下位→上位” で返すので、[::-1] で “上位→下位” にする
    bitslst = Divide(b, k)[::-1]

    for bits in bitslst:
        # 次のブロックに進む：指数が 2^k 倍になるので S = S^(2^k)
        # S^(2^k) は “k回の平方” で計算できる（2倍→4倍→...→2^k倍）
        for _ in range(k):
            S = (S ** 2) % n

        # ブロック値 bits（0..2^k-1）が 0 でなければ a^bits を掛ける
        if bits != 0:
            S = (S * tbl[bits]) % n

    return S
