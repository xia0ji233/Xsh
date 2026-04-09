#ifndef RSA_H
#define RSA_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/*
 * 简易 RSA 公钥加密（1024-bit）。
 * 仅用于加密短数据（< 128 字节），无 padding。
 * 大整数用 uint8_t[128] 表示（big-endian）。
 */

#define RSA_BYTES 128  /* 1024 bits */

/* ============================================================
 * 公钥配置（只需改这两行）
 * RSA_N_HEX: 256 个 hex 字符 = 128 字节 = 1024 bit
 * RSA_E:     公钥指数，一般 65537
 * ============================================================ */
#define RSA_N_HEX "cd1e0dd48a42263b1d6d25d8a7e325aaa2995c4e3f63432ba73bd54590f477320d090a31767c82661465579e5f5296743bbddb09452851003011be8edbc14d0eb20d96cca6f39e9bc06630d6523775a5a3c8a4bbfddf48a44b240532fb3947ea9d301297c0326ae9f6d74fc2fd439e4d85b99613c4417b54bbd5ed9c708ad2d5"

static const uint32_t RSA_E = 65537;

/* ---- hex 字符串 → uint8_t 数组 ---- */

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

    /* 从 hex 末尾往前解析，结果右对齐写入 out */
    int hi = hexlen - 1;
    int oi = nbytes - 1;
    while (hi >= 0 && oi >= 0) {
        uint8_t lo = _rsa_hexval(hex[hi--]);
        uint8_t ho = (hi >= 0) ? _rsa_hexval(hex[hi--]) : 0;
        out[oi--] = (ho << 4) | lo;
    }
}

/* 获取 RSA_N 的 uint8_t[128] 形式（首次调用时解析，后续缓存） */
static const uint8_t *rsa_get_n()
{
    static uint8_t n[RSA_BYTES] = {0};
    static int inited = 0;
    if (!inited) {
        _rsa_hex2bytes(RSA_N_HEX, n, RSA_BYTES);
        inited = 1;
    }
    return n;
}

/* ---- 大整数运算（big-endian uint8_t[RSA_BYTES]） ---- */

static int bn_cmp(const uint8_t *a, const uint8_t *b, int len)
{
    for (int i = 0; i < len; i++) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static void bn_sub(uint8_t *r, const uint8_t *a, const uint8_t *b, int len)
{
    int borrow = 0;
    for (int i = len - 1; i >= 0; i--) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else { borrow = 0; }
        r[i] = (uint8_t)diff;
    }
}

static void bn_mulmod(uint8_t *r, const uint8_t *a, const uint8_t *b,
                       const uint8_t *n, int len)
{
    int dlen = len * 2;
    uint8_t *prod = (uint8_t *)calloc(dlen, 1);

    for (int i = len - 1; i >= 0; i--) {
        uint16_t carry = 0;
        for (int j = len - 1; j >= 0; j--) {
            int pos = i + j + 1;
            uint16_t val = (uint16_t)a[i] * (uint16_t)b[j] + prod[pos] + carry;
            prod[pos] = (uint8_t)(val & 0xFF);
            carry = val >> 8;
        }
        prod[i] += (uint8_t)carry;
    }

    uint8_t *tmp = (uint8_t *)calloc(dlen, 1);
    uint8_t *rem = (uint8_t *)calloc(dlen, 1);
    memcpy(rem, prod, dlen);

    for (int shift = len; shift >= 0; shift--) {
        memset(tmp, 0, dlen);
        if (shift <= len) {
            int dst_start = dlen - len - shift;
            if (dst_start >= 0)
                memcpy(tmp + dst_start, n, len);
        }
        while (bn_cmp(rem, tmp, dlen) >= 0) {
            bn_sub(rem, rem, tmp, dlen);
        }
    }

    memcpy(r, rem + len, len);

    free(prod);
    free(tmp);
    free(rem);
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
    const uint8_t *n = rsa_get_n();

    uint8_t base[RSA_BYTES] = {0};
    uint8_t result[RSA_BYTES] = {0};

    if (in_len > RSA_BYTES) in_len = RSA_BYTES;
    memcpy(base + (RSA_BYTES - in_len), in, in_len);

    result[RSA_BYTES - 1] = 1;

    uint32_t exp = RSA_E;
    int bits = 0;
    uint32_t tmp_e = exp;
    while (tmp_e) { bits++; tmp_e >>= 1; }

    for (int i = bits - 1; i >= 0; i--) {
        uint8_t t[RSA_BYTES];
        bn_mulmod(t, result, result, n, RSA_BYTES);
        memcpy(result, t, RSA_BYTES);

        if (exp & (1U << i)) {
            bn_mulmod(t, result, base, n, RSA_BYTES);
            memcpy(result, t, RSA_BYTES);
        }
    }

    memcpy(out, result, RSA_BYTES);
}

#endif /* RSA_H */
