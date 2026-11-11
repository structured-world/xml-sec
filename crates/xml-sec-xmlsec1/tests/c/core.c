/* Buffers and pointer lists as a libxmlsec1 caller sees them. The program is
 * built against the pinned libxmlsec1 and against this crate, and both must
 * print the same: sizes, allocation sizes, the zeroed bytes past the data,
 * item order and ownership, and every refusal's return value. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>

/* The data and the first `extra` bytes past it, which the library keeps zero. */
static void dump(const char *label, xmlSecBufferPtr buf, xmlSecSize extra) {
    xmlSecSize size = xmlSecBufferGetSize(buf);
    xmlSecSize max = xmlSecBufferGetMaxSize(buf);
    xmlSecSize shown = size + extra;
    const xmlSecByte *data = xmlSecBufferGetData(buf);
    xmlSecSize ii;

    if (shown > max) {
        shown = max;
    }
    printf("%s: size=" XMLSEC_SIZE_FMT " max=" XMLSEC_SIZE_FMT " empty=%d data=",
           label, size, max, xmlSecBufferIsEmpty(buf));
    for (ii = 0; ii < shown; ++ii) {
        printf("%02x", data[ii]);
    }
    printf("\n");
}

static void buffers(void) {
    xmlSecBufferPtr buf;
    xmlSecBufferPtr other;
    xmlSecBuffer local;
    static const xmlSecByte big[3000] = { 1 };

    buf = xmlSecBufferCreate(0);
    dump("created empty", buf, 0);
    printf("append: %d\n", xmlSecBufferAppend(buf, BAD_CAST "world", 5));
    printf("prepend: %d\n", xmlSecBufferPrepend(buf, BAD_CAST "hello ", 6));
    dump("hello world", buf, 4);
    printf("remove head: %d\n", xmlSecBufferRemoveHead(buf, 6));
    dump("head removed", buf, 4);
    printf("remove tail: %d\n", xmlSecBufferRemoveTail(buf, 2));
    dump("tail removed", buf, 4);
    printf("set size: %d\n", xmlSecBufferSetSize(buf, 1));
    dump("shrunk", buf, 4);
    printf("remove head past end: %d\n", xmlSecBufferRemoveHead(buf, 100));
    dump("emptied", buf, 2);
    printf("append big: %d\n", xmlSecBufferAppend(buf, big, sizeof(big)));
    dump("grown", buf, 0);
    printf("set data: %d\n", xmlSecBufferSetData(buf, BAD_CAST "abc", 3));
    dump("replaced", buf, 2);
    printf("reverse: %d\n", xmlSecBufferReverse(buf));
    dump("reversed", buf, 0);
    printf("set max size below: %d\n", xmlSecBufferSetMaxSize(buf, 4));
    dump("unchanged", buf, 0);
    xmlSecBufferEmpty(buf);
    dump("empty", buf, 3);

    printf("hex: %d\n", xmlSecBufferHexRead(buf, BAD_CAST "0aFf10"));
    dump("hex", buf, 1);
    printf("odd hex: %d\n", xmlSecBufferHexRead(buf, BAD_CAST "abc"));
    printf("bad hex: %d\n", xmlSecBufferHexRead(buf, BAD_CAST "11zz"));
    dump("after bad hex", buf, 1);
    printf("empty hex: %d\n", xmlSecBufferHexRead(buf, BAD_CAST ""));
    dump("after empty hex", buf, 0);

    other = xmlSecBufferCreate(10);
    dump("created sized", other, 4);
    xmlSecBufferAppend(other, BAD_CAST "other", 5);
    xmlSecBufferAppend(buf, BAD_CAST "mine", 4);
    xmlSecBufferSwap(buf, other);
    dump("swapped mine", buf, 0);
    dump("swapped other", other, 0);
    xmlSecBufferDestroy(other);

    printf("initialize local: %d\n", xmlSecBufferInitialize(&local, 7));
    dump("local", &local, 2);
    xmlSecBufferAppend(&local, BAD_CAST "xy", 2);
    xmlSecBufferFinalize(&local);
    printf("finalized: size=" XMLSEC_SIZE_FMT " max=" XMLSEC_SIZE_FMT " data=%s\n",
           local.size, local.maxSize, local.data == NULL ? "null" : "set");

    xmlSecBufferSetDefaultAllocMode(xmlSecAllocModeExact, 16);
    other = xmlSecBufferCreate(100);
    dump("exact mode", other, 0);
    printf("exact append: %d\n", xmlSecBufferAppend(other, big, 200));
    dump("exact grown", other, 0);
    xmlSecBufferDestroy(other);
    xmlSecBufferSetDefaultAllocMode(xmlSecAllocModeDouble, 1024);

    printf("equal: %d %d %d %d\n",
           xmlSecMemEqual(BAD_CAST "abc", BAD_CAST "abc", 3),
           xmlSecMemEqual(BAD_CAST "abc", BAD_CAST "abd", 3),
           xmlSecMemEqual(BAD_CAST "abc", BAD_CAST "abd", 2),
           xmlSecMemEqual(NULL, NULL, 0));

    printf("null buffer: %d %d %d " XMLSEC_SIZE_FMT " " XMLSEC_SIZE_FMT "\n",
           xmlSecBufferIsEmpty(NULL),
           xmlSecBufferAppend(buf, NULL, 0),
           xmlSecBufferInitialize(NULL, 1) < 0,
           xmlSecBufferGetSize(NULL),
           xmlSecBufferGetMaxSize(NULL));
    xmlSecBufferDestroy(buf);
}

static int destroyed = 0;

static void count_destroy(xmlSecPtr item) {
    (void)item;
    ++destroyed;
}

static xmlSecPtrListKlass counting = {
    BAD_CAST "counting",
    NULL,
    count_destroy,
    NULL,
    NULL,
};

/* Distinct non-null items, never dereferenced by the counting klass. */
static char items[16];

static void print_items(const char *label, xmlSecPtrListPtr list) {
    xmlSecSize ii;

    printf("%s:", label);
    for (ii = 0; ii < xmlSecPtrListGetSize(list); ++ii) {
        printf(" %d", (int)((char *)xmlSecPtrListGetItem(list, ii) - items));
    }
    printf("\n");
}

static void lists(void) {
    xmlSecPtrListPtr list;
    xmlSecPtrListPtr strings;
    xmlSecPtrListPtr copy;
    xmlSecPtrList local;
    int ii;
    int ret;

    list = xmlSecPtrListCreate(&counting);
    printf("list name: %s\n", xmlSecPtrListGetName(list));
    for (ii = 1; ii <= 3; ++ii) {
        printf("add: %d\n", xmlSecPtrListAdd(list, &items[ii]));
    }
    printf("insert: %d\n", xmlSecPtrListInsert(list, &items[9], 1));
    printf("insert past end: %d\n", xmlSecPtrListInsert(list, &items[8], 100));
    print_items("inserted", list);
    /* each call runs before the counter it changes is read */
    ret = xmlSecPtrListRemove(list, 1);
    printf("remove: %d destroyed=%d\n", ret, destroyed);
    printf("remove and return: %d\n",
           (int)((char *)xmlSecPtrListRemoveAndReturn(list, 0) - items));
    ret = (int)((char *)xmlSecPtrListPopLast(list) - items);
    printf("pop last: %d destroyed=%d\n", ret, destroyed);
    ret = xmlSecPtrListSet(list, &items[5], 0);
    printf("set: %d destroyed=%d\n", ret, destroyed);
    print_items("after set", list);
    printf("out of range: %s %d %d\n",
           xmlSecPtrListGetItem(list, 2) == NULL ? "null" : "item",
           xmlSecPtrListSet(list, &items[6], 2),
           xmlSecPtrListRemove(list, 2));
    for (ii = 0; ii < 100; ++ii) {
        xmlSecPtrListAdd(list, &items[ii % 16]);
    }
    printf("grown: use=" XMLSEC_SIZE_FMT " max=" XMLSEC_SIZE_FMT "\n", list->use, list->max);
    xmlSecPtrListEmpty(list);
    printf("emptied: use=" XMLSEC_SIZE_FMT " max=" XMLSEC_SIZE_FMT " destroyed=%d pop=%s\n",
           list->use, list->max, destroyed,
           xmlSecPtrListPopLast(list) == NULL ? "null" : "item");
    xmlSecPtrListAdd(list, &items[4]);

    strings = xmlSecPtrListCreate(xmlSecStringListId);
    printf("strings name: %s\n", xmlSecPtrListGetName(strings));
    printf("copy across klasses: %d\n", xmlSecPtrListCopy(strings, list));
    xmlSecPtrListAdd(strings, xsStrdup(BAD_CAST "first"));
    copy = xmlSecPtrListDuplicate(strings);
    printf("duplicate: " XMLSEC_SIZE_FMT " %s %s\n", xmlSecPtrListGetSize(copy),
           (char *)xmlSecPtrListGetItem(copy, 0),
           xmlSecPtrListGetItem(copy, 0) == xmlSecPtrListGetItem(strings, 0) ? "shared" : "copied");
    xmlSecPtrListDestroy(strings);
    printf("copy survives: %s\n", (char *)xmlSecPtrListGetItem(copy, 0));
    xmlSecPtrListDestroy(copy);

    copy = xmlSecPtrListDuplicate(list);
    print_items("pointer copy", copy);
    xmlSecPtrListDestroy(copy);
    xmlSecPtrListDestroy(list);
    printf("destroyed=%d\n", destroyed);

    printf("initialize local: %d %d\n",
           xmlSecPtrListInitialize(&local, NULL),
           xmlSecPtrListInitialize(&local, &counting));
    xmlSecPtrListAdd(&local, &items[1]);
    xmlSecPtrListFinalize(&local);
    printf("finalized: id=%s use=" XMLSEC_SIZE_FMT, local.id == NULL ? "null" : "set", local.use);
    ret = xmlSecPtrListAdd(&local, &items[2]);
    printf(" add=%d size=" XMLSEC_SIZE_FMT "\n", ret, xmlSecPtrListGetSize(&local));
    printf("null list: %s %d\n",
           xmlSecPtrListCreate(NULL) == NULL ? "null" : "list",
           xmlSecPtrListAdd(NULL, &items[1]));
}

int main(void) {
    buffers();
    lists();
    return 0;
}
