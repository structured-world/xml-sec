/* The Base64 codec as a libxmlsec1 caller sees it. Built unmodified against
 * the pinned libxmlsec1 and against this crate, both must print the same
 * encodings, decodings, chunked streaming results and refusals. */

#include <stdio.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>

static void encode(const char *label, const xmlSecByte *data, xmlSecSize size, int columns) {
    xmlChar *text = xmlSecBase64Encode(data, size, columns);
    printf("encode %s/%d: %s\n", label, columns, text != NULL ? (const char *)text : "(null)");
    if (text != NULL) {
        xmlFree(text);
    }
}

static void decode(const char *text) {
    xmlSecByte out[256];
    xmlSecSize written = 0;
    xmlSecSize ii;
    int ret = xmlSecBase64Decode_ex(BAD_CAST text, out, sizeof(out), &written);

    printf("decode [%s]: %d", text, ret);
    if (ret == 0) {
        printf(" " XMLSEC_SIZE_FMT ":", written);
        for (ii = 0; ii < written; ++ii) {
            printf("%02x", out[ii]);
        }
    }
    printf("\n");
}

/* Streams `size` bytes through a context in chunks of `chunk`. */
static void stream(int encodeFlag, const xmlSecByte *data, xmlSecSize size, xmlSecSize chunk, int columns) {
    xmlSecBase64CtxPtr ctx = xmlSecBase64CtxCreate(encodeFlag, columns);
    xmlSecByte out[512];
    xmlSecSize total = 0;
    xmlSecSize pos;
    xmlSecSize written;
    int ret = 0;

    for (pos = 0; (pos < size) && (ret == 0); pos += chunk) {
        xmlSecSize part = (size - pos < chunk) ? size - pos : chunk;
        written = 0;
        ret = xmlSecBase64CtxUpdate_ex(ctx, data + pos, part, out + total, sizeof(out) - total, &written);
        total += written;
    }
    if (ret == 0) {
        written = 0;
        ret = xmlSecBase64CtxFinal_ex(ctx, out + total, sizeof(out) - total, &written);
        total += written;
    }
    printf("stream %s chunk=" XMLSEC_SIZE_FMT " columns=%d: %d [%.*s]\n",
           encodeFlag ? "encode" : "decode", chunk, columns, ret, (int)total, (const char *)out);
    xmlSecBase64CtxDestroy(ctx);
}

int main(void) {
    static const xmlSecByte binary[] = { 0x00, 0xff, 0x10, 0x80, 0x7f, 0x01, 0xfe };
    static const char *inputs[] = {
        "", "Zg==", "Zm8=", "Zm9v", "Zm9vYmFy", " Zm 9v\r\nYmFy \t", "Zg==\n", "Zg==Zg==",
        "Z===", "Zm9", "Zm9v!", "Zm9v=", "=", "Zg=", "AP8QgH8B/g==",
    };
    char inPlace[] = "Zm9vYmFy";
    xmlSecSize written = 0;
    xmlSecByte small[2];
    size_t ii;

    printf("default line size: %d\n", xmlSecBase64GetDefaultLineSize());
    encode("empty", BAD_CAST "", 0, 0);
    encode("foobar", BAD_CAST "foobar", 6, 0);
    encode("foobar", BAD_CAST "foobar", 6, 4);
    encode("fooba", BAD_CAST "fooba", 5, 4);
    encode("binary", binary, sizeof(binary), 0);
    encode("binary", binary, sizeof(binary), 3);
    encode("binary", binary, sizeof(binary), 1);
    encode("negative", BAD_CAST "x", 1, -1);
    for (ii = 0; ii < sizeof(inputs) / sizeof(inputs[0]); ++ii) {
        decode(inputs[ii]);
    }
    printf("decode too small: %d\n", xmlSecBase64Decode_ex(BAD_CAST "Zm9v", small, sizeof(small), &written));
    {
        /* the decode runs before its outputs are read */
        int decoded = xmlSecBase64DecodeInPlace(BAD_CAST inPlace, &written);
        printf("in place: %d " XMLSEC_SIZE_FMT " [%.*s]\n", decoded, written, (int)written, inPlace);
    }
    stream(1, BAD_CAST "the quick brown fox", 19, 1, 8);
    stream(1, BAD_CAST "the quick brown fox", 19, 5, 0);
    stream(0, BAD_CAST "dGhlIHF1aWNr\nIGJyb3du", 21, 3, 0);
    stream(0, BAD_CAST "dGhlIHF1a", 9, 4, 0);
    xmlSecBase64SetDefaultLineSize(10);
    printf("default line size: %d\n", xmlSecBase64GetDefaultLineSize());
    printf("create negative: %s\n", xmlSecBase64CtxCreate(1, -5) == NULL ? "null" : "ctx");
    return 0;
}
