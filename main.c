#include <stdio.h>
#include <stdint.h>

// SHA512 functionality

static const uint64_t K[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                               0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                               0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                               0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                               0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                               0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                               0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                               0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                               0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                               0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                               0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                               0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                               0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                               0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                               0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                               0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                               0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                               0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                               0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                               0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static void compressSHA512Buf(uint64_t *state, const unsigned char *buf) {
    uint64_t s[8], w[80], t0;
    int i;

    for (i = 0; i < 8; i++) {
        s[i] = state[i];
    }

    for (i = 0; i < 16; i++) {
        const unsigned char *a = buf + (8 * i);

        w[i] = (((uint64_t) a[0]) << 56) | (((uint64_t) a[1]) << 48) | (((uint64_t) a[2]) << 40) |
               (((uint64_t) a[3]) << 32) | (((uint64_t) a[4]) << 24) | (((uint64_t) a[5]) << 16) |
               (((uint64_t) a[6]) << 8) | ((uint64_t) a[7]);
    }

    for (i = 16; i < 80; i++) {
        const uint64_t a = w[i - 2], b = w[i - 15];

        w[i] = (((a >> 19 | a << 45)) ^ ((a >> 61 | a << 3)) ^ (a >> 6)) + w[i - 7] +
               (((b >> 1 | b << 63)) ^ ((b >> 8 | b << 56)) ^ (b >> 7)) + w[i - 16];
    }

    for (i = 0; i < 80; i += 8) {
        // A LOT OF BYTE SHIFTING
        t0 = s[7] + (((s[4] >> 14 | s[4] << 50)) ^ ((s[4] >> 18 | s[4] << 46)) ^ ((s[4] >> 41 | s[4] << 23))) +
             (s[6] ^ (s[4] & (s[5] ^ s[6]))) + K[i] + w[i];
        s[3] += t0;
        s[7] = t0 + ((((s[0] >> 28 | s[0] << 36)) ^ ((s[0] >> 34 | s[0] << 30)) ^ ((s[0] >> 39 | s[0] << 25))) +
                     ((s[0] | s[1]) & s[2] | s[0] & s[1]));

        t0 = s[6] + (((s[3] >> 14 | s[3] << 50)) ^ ((s[3] >> 18 | s[3] << 46)) ^ ((s[3] >> 41 | s[3] << 23))) +
             (s[5] ^ (s[3] & (s[4] ^ s[5]))) + K[i + 1] + w[i + 1];
        s[2] += t0;
        s[6] = t0 + ((((s[7] >> 28 | s[7] << 36)) ^ ((s[7] >> 34 | s[7] << 30)) ^ ((s[7] >> 39 | s[7] << 25))) +
                     ((s[7] | s[0]) & s[1] | s[7] & s[0]));

        t0 = s[5] + (((s[2] >> 14 | s[2] << 50)) ^ ((s[2] >> 18 | s[2] << 46)) ^ ((s[2] >> 41 | s[2] << 23))) +
             (s[4] ^ (s[2] & (s[3] ^ s[4]))) + K[i + 2] + w[i + 2];
        s[1] += t0;
        s[5] = t0 + ((((s[6] >> 28 | s[6] << 36)) ^ ((s[6] >> 34 | s[6] << 30)) ^ ((s[6] >> 39 | s[6] << 25))) +
                     ((s[6] | s[7]) & s[0] | s[6] & s[7]));

        t0 = s[4] + (((s[1] >> 14 | s[1] << 50)) ^ ((s[1] >> 18 | s[1] << 46)) ^ ((s[1] >> 41 | s[1] << 23))) +
             (s[3] ^ (s[1] & (s[2] ^ s[3]))) + K[i + 3] + w[i + 3];
        s[0] += t0;
        s[4] = t0 + ((((s[5] >> 28 | s[5] << 36)) ^ ((s[5] >> 34 | s[5] << 30)) ^ ((s[5] >> 39 | s[5] << 25))) +
                     ((s[5] | s[6]) & s[7] | s[5] & s[6]));

        t0 = s[3] + (((s[0] >> 14 | s[0] << 50)) ^ ((s[0] >> 18 | s[0] << 46)) ^ ((s[0] >> 41 | s[0] << 23))) +
             (s[2] ^ (s[0] & (s[1] ^ s[2]))) + K[i + 4] + w[i + 4];
        s[7] += t0;
        s[3] = t0 + ((((s[4] >> 28 | s[4] << 36)) ^ ((s[4] >> 34 | s[4] << 30)) ^ ((s[4] >> 39 | s[4] << 25))) +
                     ((s[4] | s[5]) & s[6] | s[4] & s[5]));

        t0 = s[2] + (((s[7] >> 14 | s[7] << 50)) ^ ((s[7] >> 18 | s[7] << 46)) ^ ((s[7] >> 41 | s[7] << 23))) +
             (s[1] ^ (s[7] & (s[0] ^ s[1]))) + K[i + 5] + w[i + 5];
        s[6] += t0;
        s[2] = t0 + ((((s[3] >> 28 | s[3] << 36)) ^ ((s[3] >> 34 | s[3] << 30)) ^ ((s[3] >> 39 | s[3] << 25))) +
                     ((s[3] | s[4]) & s[5] | s[3] & s[4]));

        t0 = s[1] + (((s[6] >> 14 | s[6] << 50)) ^ ((s[6] >> 18 | s[6] << 46)) ^ ((s[6] >> 41 | s[6] << 23))) +
             (s[0] ^ (s[6] & (s[7] ^ s[0]))) + K[i + 6] + w[i + 6];
        s[5] += t0;
        s[1] = t0 + ((((s[2] >> 28 | s[2] << 36)) ^ ((s[2] >> 34 | s[2] << 30)) ^ ((s[2] >> 39 | s[2] << 25))) +
                     ((s[2] | s[3]) & s[4] | s[2] & s[3]));

        t0 = s[0] + (((s[5] >> 14 | s[5] << 50)) ^ ((s[5] >> 18 | s[5] << 46)) ^ ((s[5] >> 41 | s[5] << 23))) +
             (s[7] ^ (s[5] & (s[6] ^ s[7]))) + K[i + 7] + w[i + 7];
        s[4] += t0;
        s[0] = t0 + ((((s[1] >> 28 | s[1] << 36)) ^ ((s[1] >> 34 | s[1] << 30)) ^ ((s[1] >> 39 | s[1] << 25))) +
                     ((s[1] | s[2]) & s[3] | s[1] & s[2]));
    }

    for (i = 0; i < 8; i++) {
        state[i] = state[i] + s[i];
    }
}

int sha512(const unsigned char *message, size_t messageLen, unsigned char *hash) {
    if (message == 0 || hash == 0) {
        return 1;
    }

    uint64_t length = 0, state[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                     0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

    size_t currentLen = 0, n, i;
    unsigned char buf[128];

    int result;

    while (messageLen > 0) {
        if (currentLen == 0 && messageLen >= 128) {
            compressSHA512Buf(state, message);

            length += 128 * 8;
            message += 128;
            messageLen -= 128;
        } else {
            size_t y = 128 - currentLen;

            n = messageLen < y ? messageLen : y;

            for (i = 0; i < n; i++) {
                buf[i + currentLen] = message[i];
            }

            currentLen += n;
            message += n;
            messageLen -= n;

            if (currentLen == 128) {
                compressSHA512Buf(state, buf);

                length += 8 * 128;
                currentLen = 0;
            }
        }
    }

    if (currentLen >= sizeof(buf)) {
        return 1;
    }

    length += currentLen * 8;

    buf[currentLen++] = (unsigned char) 0x80;

    if (currentLen > 112) {
        while (currentLen < 128) {
            buf[currentLen++] = (unsigned char) 0;
        }

        compressSHA512Buf(state, buf);

        currentLen = 0;
    }

    while (currentLen < 120) {
        buf[currentLen++] = (unsigned char) 0;
    }

    unsigned char *a = buf + 120;

    a[0] = (unsigned char) (length >> 56);
    a[1] = (unsigned char) (length >> 48);
    a[2] = (unsigned char) (length >> 40);
    a[3] = (unsigned char) (length >> 32);
    a[4] = (unsigned char) (length >> 24);
    a[5] = (unsigned char) (length >> 16);
    a[6] = (unsigned char) (length >> 8);
    a[7] = (unsigned char) length;

    compressSHA512Buf(state, buf);

    for (i = 0; i < 8; i++) {
        unsigned char *b = hash + (8 * i);

        b[0] = (unsigned char) (state[i] >> 56);
        b[1] = (unsigned char) (state[i] >> 48);
        b[2] = (unsigned char) (state[i] >> 40);
        b[3] = (unsigned char) (state[i] >> 32);
        b[4] = (unsigned char) (state[i] >> 24);
        b[5] = (unsigned char) (state[i] >> 16);
        b[6] = (unsigned char) (state[i] >> 8);
        b[7] = (unsigned char) state[i];
    }

    return 0;
}

// ED25519 functionality

void createKeyPair(unsigned char *publicKey, unsigned char *privateKey, const unsigned char *hash) {

}

void sign(unsigned char *signature, const unsigned char *message, long messageLen, const unsigned char *publicKey,
          const unsigned char *privateKey) {

}

int
verify(const unsigned char *signature, const unsigned char *message, long messageLen, const unsigned char *publicKey) {
    return 0;
}


int main() {
    const unsigned char message1[32] = "CZDuj3KWUT30b3va1QiE5ZENRGDM9Mu3";
    const unsigned char message2[32] = "rRgvlP3V6F2lIpUwfXrSHsbQmxZKUFyR";
    unsigned char returnedMessage1[64], returnedMessage2[64], returnedMessage3[64];

    int result;

    result = sha512(message1, 32, returnedMessage1);

    if (result != 0) {
        return result;
    }

    result = sha512(message1, 32, returnedMessage2);

    if (result != 0) {
        return result;
    }

    for (int i = 0; i < sizeof(returnedMessage1) / sizeof(returnedMessage1[0]); ++i) {
        if (returnedMessage1[i] != returnedMessage2[i]) {
            printf("[x] %d [%c:%c] seems to be different\n", i, returnedMessage1[i], returnedMessage2[i]);

            return -1;
        }
    }

    printf("[y] identical!\n");

    result = sha512(message2, 32, returnedMessage3);

    if (result != 0) {
        return result;
    }

    for (int i = 0; i < sizeof(returnedMessage1) / sizeof(returnedMessage1[0]); ++i) {
        if (returnedMessage1[i] != returnedMessage3[i]) {
            printf("[y] index %d [%c:%c] seems to be different\n", i, returnedMessage1[i], returnedMessage3[i]);

            return 0;
        }
    }

    printf("[x] identical!\n");

    return -1;
}
