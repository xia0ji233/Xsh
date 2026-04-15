#ifndef RSA_H
#define RSA_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/*
 * 简易 RSA 公钥加密（1024-bit）。
 * 仅用于加密短数据（< 128 字节），无 padding。
 *
 * 内部用 uint32_t 作为 limb（肢），每个 limb 存 32 bit。
 * 1024 bit = 32 个 limb，little-endian limb order（limb[0] 最低位）。
 *
 * 对外接口保持 big-endian uint8_t[128] 不变。
 */

#define RSA_BYTES 128   /* 1024 bits */
#define RSA_LIMBS 32    /* 1024 / 32 */

/* ============================================================
 * 公钥配置（只需改这两行）
 * ============================================================ */
#define RSA_N_HEX "cd1e0dd48a42263b1d6d25d8a7e325aaa2995c4e3f63432ba73bd54590f477320d090a31767c82661465579e5f5296743bbddb09452851003011be8edbc14d0eb20d96cca6f39e9bc06630d6523775a5a3c8a4bbfddf48a44b240532fb3947ea9d301297c0326ae9f6d74fc2fd439e4d85b99613c4417b54bbd5ed9c708ad2d5"
static const uint32_t RSA_E = 65537;

/* ---- hex → bytes ---- */

static uint8_t _rsa_hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void _rsa_hex2bytes(const char *hex, uint8_t *out, int nbytes)
{
    memset(out, 0, nbytes);
    int hexlen = 0;
    while (hex[hexlen]) hexlen++;
    if (hexlen == 0) return;
    int hi = hexlen - 1;
    int oi = nbytes - 1;
    while (hi >= 0 && oi >= 0) {
        uint8_t lo = _rsa_hexval(hex[hi--]);
        uint8_t ho = (hi >= 0) ? _rsa_hexval(hex[hi--]) : 0;
        out[oi--] = (ho << 4) | lo;
    }
}

/* ---- big-endian bytes ↔ little-endian limbs 转换 ---- */

static void bytes_to_limbs(const uint8_t *be, uint32_t *limbs, int nlimbs)
{
    for (int i = 0; i < nlimbs; i++) {
        int base = (nlimbs - 1 - i) * 4;
        limbs[i] = ((uint32_t)be[base] << 24) |
                   ((uint32_t)be[base + 1] << 16) |
                   ((uint32_t)be[base + 2] << 8) |
                   ((uint32_t)be[base + 3]);
    }
}

static void limbs_to_bytes(const uint32_t *limbs, uint8_t *be, int nlimbs)
{
    for (int i = 0; i < nlimbs; i++) {
        int base = (nlimbs - 1 - i) * 4;
        be[base]     = (limbs[i] >> 24) & 0xFF;
        be[base + 1] = (limbs[i] >> 16) & 0xFF;
        be[base + 2] = (limbs[i] >> 8) & 0xFF;
        be[base + 3] = limbs[i] & 0xFF;
    }
}

/* 获取 RSA_N 的 limb 形式 */
static const uint32_t *rsa_get_n()
{
    static uint32_t n[RSA_LIMBS] = {0};
    static int inited = 0;
    if (!inited) {
        uint8_t tmp[RSA_BYTES];
        _rsa_hex2bytes(RSA_N_HEX, tmp, RSA_BYTES);
        bytes_to_limbs(tmp, n, RSA_LIMBS);
        inited = 1;
    }
    return n;
}

/* ---- 大整数运算（little-endian uint32_t limbs） ---- */

/* a >= b ? */
static int bn_cmp_limbs(const uint32_t *a, const uint32_t *b, int n)
{
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* r = a - b, 假设 a >= b */
static void bn_sub_limbs(uint32_t *r, const uint32_t *a, const uint32_t *b, int n)
{
    uint64_t borrow = 0;
    for (int i = 0; i < n; i++) {
        uint64_t diff = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        r[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
}

/*
 * bn_mulmod_limbs: r = (a * b) mod n
 *
 * 优化点（相比旧版 uint8_t + while 减法取模）：
 *   1. uint32_t limb：乘法循环从 128² 降到 32²（16 倍）
 *   2. uint64_t 累加：乘法无需逐字节进位
 *   3. 取模用逐 bit 移位法：将乘积的每一位从高到低移入余数，
 *      余数 >= n 则减之。确定性 2048 次迭代，无 while 试减。
 */
static void bn_mulmod_limbs(uint32_t *r,
                            const uint32_t *a, const uint32_t *b,
                            const uint32_t *n, int nlimbs)
{
    int plen = nlimbs * 2;
    uint32_t *prod = (uint32_t *)calloc(plen, sizeof(uint32_t));

    /* 乘法: prod = a * b */
    for (int i = 0; i < nlimbs; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < nlimbs; j++) {
            uint64_t val = (uint64_t)a[i] * (uint64_t)b[j] +
                           (uint64_t)prod[i + j] + carry;
            prod[i + j] = (uint32_t)val;
            carry = val >> 32;
        }
        prod[i + nlimbs] += (uint32_t)carry;
    }

    /*
     * 取模：逐 bit 移位法。
     * rem = 0, 从 prod 的最高 bit 到最低 bit：
     *   rem = (rem << 1) | current_bit
     *   if (rem >= n) rem -= n
     * 循环次数 = plen * 32 = 2048，每次做 nlimbs 次比较/减法。
     */
    int rlen = nlimbs + 1;
    uint32_t *rem = (uint32_t *)calloc(rlen, sizeof(uint32_t));
    uint32_t *n_ext = (uint32_t *)calloc(rlen, sizeof(uint32_t));
    memcpy(n_ext, n, nlimbs * sizeof(uint32_t));
    /* n_ext[nlimbs] = 0 已由 calloc 保证 */

    int total_bits = plen * 32;
    for (int bit = total_bits - 1; bit >= 0; bit--) {
        /* rem <<= 1 */
        uint32_t carry = 0;
        for (int i = 0; i < rlen; i++) {
            uint32_t new_carry = rem[i] >> 31;
            rem[i] = (rem[i] << 1) | carry;
            carry = new_carry;
        }

        /* 取 prod 的第 bit 位，放入 rem[0] 的最低位 */
        int limb_idx = bit / 32;
        int bit_idx = bit % 32;
        rem[0] |= (prod[limb_idx] >> bit_idx) & 1;

        /* if rem >= n then rem -= n */
        if (bn_cmp_limbs(rem, n_ext, rlen) >= 0) {
            bn_sub_limbs(rem, rem, n_ext, rlen);
        }
    }

    memcpy(r, rem, nlimbs * sizeof(uint32_t));
    free(prod);
    free(rem);
    free(n_ext);
}

/*
 * rsa_encrypt: RSA 公钥加密。
 *   in:    明文（big-endian），长度 in_len（<= RSA_BYTES）
 *   out:   密文，固定 RSA_BYTES 字节
 *
 * 计算 out = in^e mod n
 */
static void rsa_encrypt(const uint8_t *in, int in_len, uint8_t *out)
{
    const uint32_t *n = rsa_get_n();

    uint32_t base_l[RSA_LIMBS] = {0};
    uint32_t result_l[RSA_LIMBS] = {0};

    uint8_t tmp_bytes[RSA_BYTES] = {0};
    if (in_len > RSA_BYTES) in_len = RSA_BYTES;
    memcpy(tmp_bytes + (RSA_BYTES - in_len), in, in_len);
    bytes_to_limbs(tmp_bytes, base_l, RSA_LIMBS);

    result_l[0] = 1; /* result = 1 (little-endian) */

    uint32_t exp = RSA_E;
    int bits = 0;
    uint32_t tmp_e = exp;
    while (tmp_e) { bits++; tmp_e >>= 1; }

    for (int i = bits - 1; i >= 0; i--) {
        uint32_t t[RSA_LIMBS];
        bn_mulmod_limbs(t, result_l, result_l, n, RSA_LIMBS);
        memcpy(result_l, t, sizeof(t));

        if (exp & (1U << i)) {
            bn_mulmod_limbs(t, result_l, base_l, n, RSA_LIMBS);
            memcpy(result_l, t, sizeof(t));
        }
    }

    limbs_to_bytes(result_l, out, RSA_LIMBS);
}

#endif /* RSA_H */
