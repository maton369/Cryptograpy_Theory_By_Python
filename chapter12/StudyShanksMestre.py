# 楕円曲線 E(F_p) 上でトレース t を（Baby-step Giant-step 的に）求めようとする実装
# -----------------------------------------------------------------------------
# このコードは、有限体 F_p（p は素数）上の楕円曲線
#
#   E: y^2 ≡ x^3 + a x + b  (mod p)
#
# に対して、点 P をランダムに選び、いくつかの群演算を使って
# 「p+1 - t + u」らしき量を出力している（最後の print）。
#
# 使っている道具立てとしては：
# - 楕円曲線の群演算（加算・倍算・スカラー倍・逆元）
# - ルジャンドル記号（平方剰余判定）
# - Tonelli–Shanks（一般の mod p 平方根）
# - ランダムに曲線上の点を拾う関数
# - Baby-step Giant-step（BSGS）型のテーブル探索（in tbl で一致探索）
#
# -----------------------------------------------------------------------------
# 背景（何を狙っているコードか）
# -----------------------------------------------------------------------------
# 楕円曲線の点数は
#
#   |E(F_p)| = p + 1 - t
#
# と書ける（t がトレース）。
# Hasse の評価より
#
#   |t| <= 2*sqrt(p)
#
# なので、t は大きくても sqrt(p) スケールの値に収まる。
#
# 典型的な点数計算（暗号で重要）には Schoof 系アルゴリズムがあるが、
# 教材としては「ある点の位数や (p+1)P の関係」を使って t を探索する発想が出てくる。
#
# なお、このコードは “数学的に完全に整理された” Schoof の実装ではなく、
# 群演算と BSGS の枠組みで何らかの一致式を作り、t を復元しようとしている構造を持つ。
#
# -----------------------------------------------------------------------------
# 重要な注意（実装の厳密性）
# -----------------------------------------------------------------------------
# - ECadd/ECdouble の無限遠点の扱いが統一されていない（(-1,-1) と (0,0) が混在）。
# - ECadd は x座標差が 0 の場合は無限遠点を返すが、P==Q の倍算ケースと P==-Q のケースを区別していない。
# - randpicpoint で x を random.randint(0,prime) としており prime 自身が出る可能性がある
#   （F_p の要素は 0..p-1 なので、本来は randint(0,prime-1)）。
#
# ここでは「何を意図しているか／どの理論を使っているか」を中心に読み解く目的でコメントする。


import math
import random
import sympy


def modinv(s, prime):
    # mod prime における逆元 s^{-1} を返す（prime は素数前提）
    #
    # フェルマーの小定理：
    #   s^{prime-1} ≡ 1 (mod prime)   (s≠0)
    # よって
    #   s^{prime-2} ≡ s^{-1} (mod prime)
    return pow(s, prime - 2, prime)


def ECadd(P, Q, prime):
    # 楕円曲線上の点の加算 R = P + Q（簡略版）
    #
    # 一般の加算（x_P != x_Q）では
    #   λ = (y_Q - y_P)/(x_Q - x_P)
    #   x_R = λ^2 - x_P - x_Q
    #   y_R = λ(x_P - x_R) - y_P
    # を mod prime で計算する。
    #
    # この実装は「x差が 0 なら無限遠点」としている：
    # - Q == -P のときは正しい（縦線で交わり O）
    # - Q == P のときは本来倍算を使うべきだが、ここでは区別していない
    if (Q[0] - P[0]) % prime == 0:
        return (-1, -1)  # 無限遠点 O を番兵で表す

    lam = ((Q[1] - P[1]) * modinv(Q[0] - P[0], prime)) % prime
    x3 = (lam**2 - P[0] - Q[0]) % prime
    y3 = (lam * (P[0] - x3) - P[1]) % prime
    return (x3, y3)


def ECdouble(P, a, prime):
    # 点の倍算 R = 2P
    #
    # 倍算式：
    #   λ = (3x_P^2 + a)/(2y_P)
    #   x_R = λ^2 - 2x_P
    #   y_R = λ(x_P - x_R) - y_P
    #
    # y_P == 0 のとき 2P = O になる。
    #
    # 注意：
    # - この関数は O を (0,0) で返しているが、他関数では (-1,-1) を O としている。
    #   表現が混在している点は学習用としても混乱しやすい。
    if (2 * P[1]) % prime == 0:
        return (0, 0)  # ここでは O の代わりとして返してしまっている

    lam = ((3 * (P[0]**2) + a) * modinv(2 * P[1], prime)) % prime
    x3 = (lam**2 - 2 * P[0]) % prime
    y3 = (lam * (P[0] - x3) - P[1]) % prime
    return (x3, y3)


def ECmult(k, P, a, prime):
    # スカラー倍 Q = kP を double-and-add（左から右）で計算する。
    #
    # - k を2進表現し、MSB→LSB で走査
    # - 各ステップで倍算
    # - ビットが1なら加算
    #
    # この実装は MSB が 1 であることを利用して point=P から始める形。
    if k == 0:
        return (-1, -1)

    k_bin = str(bin(k))[2:]
    point = P
    for i in range(1, len(k_bin)):
        point = ECdouble(point, a, prime)
        if k_bin[i] == "1":
            point = ECadd(point, P, prime)
    return point


def ECinv(P, prime):
    # 群の逆元（加法逆元）-P を返す。
    #
    # 楕円曲線上で
    #   -(x,y) = (x, -y mod p)
    # なので
    #   -y mod p = p - y（ただし y=0 のときは 0）
    return (P[0], (prime - P[1]) % prime)


def Legendre(s, prime):
    # ルジャンドル記号 (s/prime) を Euler 判定法で計算
    L = pow(s, (prime - 1) // 2, prime)
    if L == prime - 1:
        L = -1
    return L


def Find_QNR_v(p):
    # 非平方剰余 v（Legendre(v,p)=-1）を見つける（線形探索）
    v = 2
    while Legendre(v, p) != -1:
        v += 1
    return v


def modsqrt(a, p):
    # mod p における平方根（Tonelli–Shanks を含む一般版）
    #
    # - p==2 の特別ケース
    # - Legendre(a,p)=-1 なら平方根なし
    # - a≡0 なら 0
    # - p≡3(mod4) の簡単ケース：a^{(p+1)/4}
    # - それ以外は Tonelli–Shanks
    if p == 2:
        return a

    if Legendre(a, p) == -1:
        raise Exception('sqrt does not exist')
    elif a % p == 0:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # p-1 = 2^s * t（t odd）へ分解
    t = p - 1
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1

    # Tonelli–Shanks の準備
    v = Find_QNR_v(p)   # 非平方剰余
    g = pow(v, t, p)    # 2^s 位の元の候補
    x = pow(a, (t + 1) // 2, p)
    b = pow(a, t, p)
    r = s

    # 反復で b の位数を下げて b==1 を目指す
    while True:
        bpow = b
        m = 0
        for m in range(r):
            if bpow == 1:
                break
            bpow = pow(bpow, 2, p)

        if m == 0:
            return x

        w = pow(g, 2 ** (r - m - 1), p)
        g = pow(w, 2, p)
        x = (x * w) % p
        b = (b * g) % p
        r = m


def f(x, a, b, p):
    # RHS(x) = x^3 + a x + b (mod p)
    return (x**3 + a * x + b) % p


def randpicpoint(a, b, prime):
    # 楕円曲線上の “ランダムっぽい点” を1つ拾う。
    #
    # 手順：
    # - x をランダムに選ぶ
    # - RHS(x) が平方剰余（Legendre != -1）なら y が存在
    # - modsqrt で y を1つ求めて点 (x,y) を返す
    #
    # 注意：
    # - x の選択は本来 0..prime-1 であるべき（ここは 0..prime を選んでしまっている）。
    # - 曲線の非特異条件 Δ!=0 のチェックはしていない（前提として曲線は非特異とする）。
    if not sympy.isprime(prime):
        raise ValueError("modulo is not a prime")

    while True:
        x = random.randint(0, prime)  # 本来は randint(0, prime-1)
        ysq = f(x, a, b, prime)
        if Legendre(ysq, prime) != -1:
            y = modsqrt(ysq, prime)
            return (x, y)


# -----------------------------------------------------------------------------
# ここから “トレース t の探索” 部分（BSGS 風）
# -----------------------------------------------------------------------------
# p は大きな素数を選び、曲線パラメータ a,b を固定している。
# p = 2^41 + 2^11 + 3 は巨大な素数である想定（sympy.isprime は randpicpoint 内で検査している）。
p = 2**41 + 2**11 + 3
a = 71
b = 602

# m と u は探索に使うパラメータ
# - m ≈ 2 * p^{1/4}（Hasse の範囲 |t|<=2√p を利用して探索を分割する発想に近い）
# - u ≈ 2 * √p（Hasse 上限の代表値）
m = math.ceil(2 * p**(1 / 4))
u = math.floor(2 * math.sqrt(p))

# 曲線上の点 P をランダムに拾う
P = randpicpoint(a, b, p)

# Q = (p+1)P を計算
# （Frobenius との関係で (p+1 - t)P が O になる、という点数公式の構造を意識している可能性がある）
Q = ECmult(p + 1, P, a, p)

# V = uP を作り、Q1 = Q + V
# （t の探索を “u 近傍” へ寄せるためのシフト項のように見える）
V = ECmult(u, P, a, p)
Q1 = ECadd(Q, V, p)

# P1 = -(mP)
# 後で Q1 + i*P1 = Q1 - i*(mP) の形を作ることで giant-step に相当させる
P1 = ECinv(ECmult(m, P, a, p), p)

# Baby-step: jP を 0..m-1 まで列挙してテーブル化
tbl = []
for j in range(m):
    tbl.append(ECmult(j, P, a, p))

# Giant-step: Q1 - i*(mP) を計算し、baby-step テーブルに一致するか探す
for i in range(m):
    LHS = ECadd(Q1, ECmult(i, P1, a, p), p)  # Q1 + i*P1 = Q1 - i*(mP)
    if LHS in tbl:
        # 一致したら LHS = jP となる j を探し、t' = m*i + j を復元
        # ここは線形探索になっている（本来は辞書化で O(1) にする）
        for j in range(m):
            if LHS == tbl[j]:
                tprime = m * i + j

                # 最後に p + 1 - tprime + u を出力
                # これは “p+1 - t + u” の形を意識した復元式に見える。
                # （tprime が t に対応する候補値になる想定）
                print(p + 1 - tprime + u)
