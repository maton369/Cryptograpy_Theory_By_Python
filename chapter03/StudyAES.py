# ブロック暗号 AES-128（学習用：ビット演算で状態(State)を4本の32bitワードとして扱う実装）
# -----------------------------------------------------------------------------
# AES-128 の基本仕様
# - ブロック長: 128bit（16バイト）
# - 鍵長      : 128bit（16バイト）
# - 段数 Nr   : 10（AES-128 の場合）
#
# このコードの設計方針（重要）
# - AES の「状態(State)」は 4x4 のバイト行列（列優先）で扱うのが仕様の見方。
# - 本実装では状態を「32bit ワード4本」の配列 x[0..3] で表現する。
#   各 x[i] は 4バイトを詰めた 32bit（上位が先頭バイト）になっている。
#
# 用語
# - SubBytes     : S-box によるバイト単位の非線形置換
# - ShiftRows    : 行ごとの循環シフト
# - MixColumns   : 列ごとの GF(2^8) 上の線形変換
# - AddRoundKey  : ラウンド鍵（拡大鍵）との XOR
#
# 暗号化のラウンド構成（AES-128, Nr=10）
# 1) 初期 AddRoundKey（ラウンド0）
# 2) ラウンド1〜9: SubBytes → ShiftRows → MixColumns → AddRoundKey
# 3) ラウンド10 : SubBytes → ShiftRows → AddRoundKey（最後だけ MixColumns なし）
#
# 復号は逆変換（InvSubBytes, InvShiftRows, InvMixColumns）を逆順に適用する。
#
# 注意（セキュリティ/実務）
# - これは学習用の「参照実装」スタイルで、速度やサイドチャネル（定数時間性）対策は考慮していない。
# - 実務では自前実装ではなく、標準ライブラリ/信頼できる暗号ライブラリを使うべきである。


# -----------------------------------------------------------------------------
# AES-128 の段数（Nr）
# -----------------------------------------------------------------------------
N = 10  # AES-128 のラウンド数（Nr=10）


# -----------------------------------------------------------------------------
# GF(2^8) 上の乗算（MixColumns/InvMixColumns で必要）
# -----------------------------------------------------------------------------
# AES のバイト演算は GF(2^8)（有限体）上で行う。
# 既約多項式は
#
#   m(x) = x^8 + x^4 + x^3 + x + 1
#
# これをビット列として表したものが 0x11b。
# mul2/mul3 は MixColumns の係数 {02},{03} に対応。
# mul9/mulb/muld/mule は InvMixColumns の係数 {09},{0B},{0D},{0E} に対応。
#
# 実装上の注意
# - 8bit（0..255）として扱う必要があるので、適宜 &0xff を入れる実装も多い。
# - このコードは計算結果が 9bit以上になり得る箇所があるが、後段で 8bit 化される前提で動いている。
#   学習目的ならよいが、堅牢にするなら各 mul の戻り値で &0xff をかけると安全。

def mul2(x):
    # GF(2^8) 上で {02} を掛ける（= x を 1bit 左シフト）
    # ただし、左シフトで x^8 の項（9bit目）が立った場合は、
    # 既約多項式 m(x) による剰余を取る必要がある。
    #
    # 条件: x の MSB（bit7）が 1 か？
    # - 1なら左シフト後に 0x11b を XOR して剰余処理（mod m(x)）
    # - 0なら単に左シフト
    return ( (0x11b ^ (x << 1)) if (x & (1 << 7)) else (x << 1) )

def mul3(x):
    # {03} * x = ({02}*x) XOR x
    # GF(2^8) では加算が XOR に相当する
    return (mul2(x) ^ x)

def mul9(x):
    # {09} * x = ({08}*x) XOR x
    # {08}*x = mul2(mul2(mul2(x)))
    return (mul2(mul2(mul2(x))) ^ x)

def mulb(x):
    # {0B} * x = {09}*x XOR {02}*x
    return (mul9(x) ^ mul2(x))

def muld(x):
    # {0D} * x = {09}*x XOR {04}*x
    # {04}*x = mul2(mul2(x))
    return (mul9(x) ^ mul2(mul2(x)))

def mule(x):
    # {0E} * x = {0D}*x XOR {03}*x
    return (muld(x) ^ mul3(x))


# -----------------------------------------------------------------------------
# S-box / Inv S-box（SubBytes / InvSubBytes）
# -----------------------------------------------------------------------------
# AES の非線形性の中心。
# - 1バイト入力（0..255）に対し 1バイト出力（0..255）を与える置換表。
# - 実装上は配列参照なので高速・簡単だが、サイドチャネル（キャッシュタイミング）に注意が必要。
#   学習用途ではそのままで良い。

sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

isbox = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
]


# -----------------------------------------------------------------------------
# 32bit ワード操作（ShiftRows で “バイト単位回転” をするために使用）
# -----------------------------------------------------------------------------
def rotword(x, l):
    # 32bit の x を l ビット左回転（循環シフト）
    # AES ではバイト単位の回転（l=8,16,24）がよく出てくる。
    return (((x << l) | (x >> (32 - l))) & 0xffffffff)


def subword4(x, ed):
    # 32bit のワード x を 4 バイトに分解し、各バイトに S-box を適用して 32bit に戻す。
    #
    # ed=0: 暗号化（SubBytes） → sbox を使う
    # ed=1: 復号   （InvSubBytes）→ isbox を使う
    #
    # x>>24         : 最上位バイト
    # (x>>16)&0xff  : 上から2番目
    # (x>>8 )&0xff  : 上から3番目
    # x&0xff        : 最下位バイト
    if ed == 0:
        return (sbox[x >> 24] << 24) | (sbox[(x >> 16) & 0xff] << 16) | (sbox[(x >> 8) & 0xff] << 8) | sbox[x & 0xff]
    else:
        return (isbox[x >> 24] << 24) | (isbox[(x >> 16) & 0xff] << 16) | (isbox[(x >> 8) & 0xff] << 8) | isbox[x & 0xff]


# -----------------------------------------------------------------------------
# 鍵スケジュール（AES-128 の拡大鍵生成）
# -----------------------------------------------------------------------------
def keysched(key):
    # Rcon: ラウンド定数（GF(2^8) の 2^(i-1) を使う）
    # AES-128 は 10 ラウンドなので 10 個必要
    Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    # rk[i] は「ラウンド i の 128bit ラウンド鍵」を整数として保持する実装になっている。
    # rk[0] = 初期鍵（元の128bit鍵）
    rk = []
    rk.append(key)

    # AES-128 の鍵スケジュール（概念）
    # - 鍵を 32bit ワード W[0..43] に展開する（合計44ワード）
    # - 4ワードごとに 128bit のラウンド鍵になる（rk[0]..rk[10]）
    #
    # ただしこのコードは W 配列を明示せず、「128bitの丸ごとXOR式」でまとめて更新している。
    # 具体的には
    #   w = SubWord(RotWord(last_word)) XOR Rcon
    #   new_key = old_key XOR (old_key>>32) XOR (old_key>>64) XOR (old_key>>96) XOR (wを各ワード位置に拡散)
    # という形で 128bit の次ラウンド鍵を計算している。
    for i in range(N):
        # rk[i] の最下位32bit（最後のワード）を取り出して RotWord（1バイト左回転）
        # その後 SubWord（S-box で4バイト置換）し、Rcon を最上位バイトに XOR する。
        w = subword4(rotword(rk[i] & 0xffffffff, 8), 0) ^ (Rcon[i] << 24)

        # 次の 128bit ラウンド鍵を生成（ワード連鎖 XOR を 128bit 一括で表現）
        rk.append(
            rk[i]
            ^ (rk[i] >> 32)
            ^ (rk[i] >> 64)
            ^ (rk[i] >> 96)
            ^ (w << 96)
            ^ (w << 64)
            ^ (w << 32)
            ^ w
        )

    return rk


# -----------------------------------------------------------------------------
# SubBytes / InvSubBytes（状態を 32bit×4 で持つ実装）
# -----------------------------------------------------------------------------
def subbytes(x, ed):
    # x は 32bitワード4本: x[0..3]
    # 各ワードに subword4 を適用する = 状態中の全16バイトに S-box を適用することに対応する。
    for i in range(4):
        x[i] = subword4(x[i], ed)
    return x


# -----------------------------------------------------------------------------
# ShiftRows / InvShiftRows
# -----------------------------------------------------------------------------
def shiftrows(x, ed):
    # AES の ShiftRows は「行ごと」に循環シフトする操作だが、
    # この実装では状態をワード配列で持っているため、
    # “ワード単位のバイト回転” で等価な処理を実現している。
    #
    # ed=0（暗号化 ShiftRows）:
    #   row0: 0バイト（そのまま）
    #   row1: 1バイト左回転
    #   row2: 2バイト左回転
    #   row3: 3バイト左回転
    #
    # ed=1（復号 InvShiftRows）:
    #   row1: 1バイト右回転（= 3バイト左回転）
    #   row2: 2バイト右回転（= 2バイト左回転）※対称
    #   row3: 3バイト右回転（= 1バイト左回転）
    if ed == 0:
        x[0], x[1], x[2], x[3] = x[0], rotword(x[1], 8), rotword(x[2], 16), rotword(x[3], 24)
    else:
        x[0], x[1], x[2], x[3] = x[0], rotword(x[1], 24), rotword(x[2], 16), rotword(x[3], 8)
    return x


# -----------------------------------------------------------------------------
# MixColumns / InvMixColumns
# -----------------------------------------------------------------------------
def mixcolumns(x, ed):
    # MixColumns は状態の「各列（4バイト）」に対し、
    # GF(2^8) 上の 4x4 行列を掛ける線形変換である。
    #
    # 暗号化時（ed=0）は係数行列:
    #   [02 03 01 01]
    #   [01 02 03 01]
    #   [01 01 02 03]
    #   [03 01 01 02]
    #
    # 復号時（ed=1）は逆行列（係数 {0E},{0B},{0D},{09}）を使う。
    #
    # 実装の流れ
    # 1) x[0..3]（4ワード=16バイト）を 1バイト配列 s[0..15] に展開
    # 2) 列ごとに 4バイトずつ線形変換して t に格納
    # 3) t を 다시 32bitワード×4 に詰め直して x に戻す
    s = [0 for _ in range(16)]
    t = [0 for _ in range(16)]

    # x[i] の 32bit から 4バイトを取り出して s に格納
    for i in range(4):
        for j in range(4):
            s[4 * i + j] = (x[i] >> (24 - 8 * j)) & 0xff

    # 列ごとの変換
    # ここでは「列 i」を (s[i], s[i+4], s[i+8], s[i+12]) として扱っている。
    # つまり s の並びは “列優先” の配置に対応している。
    for i in range(4):
        if ed == 0:
            t[i    ] = mul2(s[i])    ^ mul3(s[i+4])  ^      s[i+8]   ^      s[i+12]
            t[i + 4] =      s[i]     ^ mul2(s[i+4])  ^ mul3(s[i+8])  ^      s[i+12]
            t[i + 8] =      s[i]     ^      s[i+4]   ^ mul2(s[i+8])  ^ mul3(s[i+12])
            t[i +12] = mul3(s[i])    ^      s[i+4]   ^      s[i+8]   ^ mul2(s[i+12])
        else:
            t[i    ] = mule(s[i])   ^ mulb(s[i+4])  ^ muld(s[i+8])  ^ mul9(s[i+12])
            t[i + 4] = mul9(s[i])   ^ mule(s[i+4])  ^ mulb(s[i+8])  ^ muld(s[i+12])
            t[i + 8] = muld(s[i])   ^ mul9(s[i+4])  ^ mule(s[i+8])  ^ mulb(s[i+12])
            t[i +12] = mulb(s[i])   ^ muld(s[i+4])  ^ mul9(s[i+8])  ^ mule(s[i+12])

    # t を 32bit×4 の形に戻す
    for i in range(4):
        x[i] = (t[4 * i] << 24) | (t[4 * i + 1] << 16) | (t[4 * i + 2] << 8) | t[4 * i + 3]

    return x


# -----------------------------------------------------------------------------
# AddRoundKey（状態 x と 128bit ラウンド鍵 k を XOR）
# -----------------------------------------------------------------------------
def addroundkey(x, k):
    # AES の AddRoundKey は「状態の各バイト」と「ラウンド鍵の各バイト」を XOR する操作。
    #
    # この実装では
    # - k を 128bit 整数として持つ
    # - (120 - 8*(...)) のシフトで k の該当バイトを取り出す
    # - それを x[j] の該当バイト位置（<< (24-8*i)）に配置して XOR
    #
    # ループの意味
    # - i は「ワード内のバイト位置」(0..3) を表す
    # - j は「どのワード（0..3）」を表す
    #
    # 注意:
    # - 状態の内部表現（列優先/行優先）と、このループの取り出し順が一致している必要がある。
    # - ここが AES 実装で最もバグりやすい部分の1つ（バイト順/エンディアン問題）。
    for i in range(4):
        for j in range(4):
            x[j] ^= ((k >> (120 - 8 * (4 * i + j))) & 0xff) << (24 - 8 * i)
    return x


# -----------------------------------------------------------------------------
# AES 本体（暗号化/復号）
# -----------------------------------------------------------------------------
def ciph(txt, rk, ed):
    # txt: 128bit 入力ブロック（整数）
    # rk : ラウンド鍵配列（rk[0]..rk[N]）
    # ed : 0=暗号化, 1=復号
    #
    # 1) 128bit txt を状態 x[0..3]（32bit×4）に展開
    # 2) AES のラウンド処理を行う
    # 3) 状態を 128bit 整数 y に詰め直して返す

    # 状態（State）を 32bitワード×4 として初期化
    x = [0 for _ in range(4)]

    # txt からバイトを取り出し、x[0..3] の各ワードへ配置する。
    # 取り出し側:
    #   (txt >> (120 - 8*(...))) & 0xff で上位バイトから順に取っている。
    # 置く側:
    #   << (24-8*i) でワード内のバイト位置に詰める。
    for i in range(4):
        for j in range(4):
            x[j] |= ((txt >> (120 - 8 * (4 * i + j))) & 0xff) << (24 - 8 * i)

    # -----------------------------
    # 暗号化（ed=0）
    # -----------------------------
    if ed == 0:
        # 初期ラウンド（ラウンド0）：AddRoundKey のみ
        x = addroundkey(x, rk[0])

        # ラウンド1〜9（N-1回）：
        # SubBytes → ShiftRows → MixColumns → AddRoundKey
        for i in range(N - 1):
            x = addroundkey(
                mixcolumns(
                    shiftrows(
                        subbytes(x, ed),
                        ed
                    ),
                    0  # 暗号化側の MixColumns
                ),
                rk[i + 1]
            )

        # 最終ラウンド（ラウンド10）：
        # SubBytes → ShiftRows → AddRoundKey（MixColumns は無し）
        x = addroundkey(
            shiftrows(
                subbytes(x, ed),
                ed
            ),
            rk[N]
        )

    # -----------------------------
    # 復号（ed=1）
    # -----------------------------
    else:
        # 復号は暗号化の逆順・逆操作を適用する。
        #
        # 暗号化最終ラウンドの逆:
        # AddRoundKey(rk[N]) → InvShiftRows → InvSubBytes
        x = subbytes(
            shiftrows(
                addroundkey(x, rk[N]),
                ed
            ),
            ed
        )

        # 中間ラウンド（逆順で N-1回）:
        # AddRoundKey(rk[round]) → InvMixColumns → InvShiftRows → InvSubBytes
        for i in range(N - 1):
            x = subbytes(
                shiftrows(
                    mixcolumns(
                        addroundkey(x, rk[N - 1 - i]),
                        ed  # 復号側の InvMixColumns
                    ),
                    ed
                ),
                ed
            )

        # 最後に初期鍵を XOR（暗号化の最初 AddRoundKey の逆）
        x = addroundkey(x, rk[0])

    # 状態 x[0..3] を 128bit 整数 y に詰め直す
    y = 0
    for i in range(4):
        for j in range(4):
            y |= ((x[i] >> (24 - 8 * j)) & 0xff) << (120 - 8 * (4 * j + i))

    return y


# -----------------------------------------------------------------------------
# 動作確認（AES-128 の典型テストベクタ形式）
# -----------------------------------------------------------------------------
rk = [0 for _ in range(N + 1)]  # RoundKey 配列（実際は keysched が生成）

txt = 0x00112233445566778899aabbccddeeff  # PlainText (128bit)
key = 0x000102030405060708090a0b0c0d0e0f  # Secret key (128bit)

rk = keysched(key)               # 鍵スケジュール（rk[0..10] を生成）
ctx = ciph(txt, rk, 0)           # 暗号化

# 暗号文 ctx と、復号した結果（元の平文に戻るはず）を 32桁16進で表示
print(format(ctx, '032x'), format(ciph(ctx, rk, 1), '032x'))
