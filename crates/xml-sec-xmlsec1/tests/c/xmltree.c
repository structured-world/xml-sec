/* The xmltree.h helpers as a libxmlsec1 caller uses them: adding elements
 * and namespaces with line feeds, replacing nodes, content and buffers,
 * registering IDs, hex and size content, escaping, qualified names and the
 * QName mappings. Built against the pinned libxmlsec1 and against this
 * crate, both must print the same trees, results and reports. */

#include <stdio.h>
#include <string.h>

#include "tree.h"
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>

/* A parser's own diagnostic after "xml error: " (its code and wording) is
 * the parser's, not part of the contract, so only its presence is printed. */
static void record(const char *file, int line, const char *func, const char *object,
                   const char *subject, int reason, const char *msg) {
    const char *diagnostic = msg != NULL ? strstr(msg, "xml error: ") : NULL;
    (void)file;
    (void)line;
    printf("  report: func=%s obj=%s subj=%s reason=%d msg=[%.*s%s]\n", func,
           object != NULL ? object : "(null)", subject != NULL ? subject : "(null)", reason,
           diagnostic != NULL ? (int)(diagnostic - msg) : (int)strlen(msg != NULL ? msg : "(null)"),
           msg != NULL ? msg : "(null)", diagnostic != NULL ? "xml error: <parser diagnostic>" : "");
}

static void dump(const char *label, xmlDocPtr doc) {
    xmlChar *text = NULL;
    int size = 0;
    xsDocDumpMemory(doc, &text, &size);
    printf("%s: %.*s", label, size, (const char *)text);
    xsFree(text);
}

static xmlDocPtr parse(const char *text) {
    return xsReadMemory(text, (int)strlen(text), "t.xml", NULL, 0);
}

/* `text`, released, as a printable string; `fallback` for null. */
static const char *shown(xmlChar *text, const char *fallback) {
    static char out[4][128];
    static int next = 0;
    char *slot = out[next++ % 4];
    snprintf(slot, sizeof(out[0]), "%s", text != NULL ? (const char *)text : fallback);
    xsFree(text);
    return slot;
}

static const char *name_of(xmlNodePtr node) {
    return shown(xsNodeGetName(node), "none");
}

static const xmlSecQName2IntegerInfo integers[] = {
    {BAD_CAST "urn:a", BAD_CAST "one", 1},
    {BAD_CAST "urn:a", BAD_CAST "two", 2},
    {NULL, BAD_CAST "plain", 3},
    {NULL, NULL, 0},
};

static const xmlSecQName2BitMaskInfo bits[] = {
    {BAD_CAST "urn:a", BAD_CAST "read", 1},
    {BAD_CAST "urn:a", BAD_CAST "write", 2},
    {NULL, BAD_CAST "exec", 4},
    {NULL, NULL, 0},
};

static void adding(void) {
    xmlDocPtr doc = parse("<r xmlns:p='urn:p'><x/></r>");
    xmlNodePtr root = xsDocGetRootElement(doc);
    xmlNodePtr empty;
    xmlNodePtr cur;

    printf("adding\n");
    cur = xmlSecAddChild(root, BAD_CAST "c", BAD_CAST "urn:p");
    printf("  child ns prefix: %s\n", shown(xsNodeGetNsPrefix(cur), "(none)"));
    cur = xmlSecAddChild(root, BAD_CAST "d", BAD_CAST "urn:q");
    xmlSecAddChild(cur, BAD_CAST "e", BAD_CAST "urn:q");
    xmlSecAddChild(cur, BAD_CAST "f", NULL);
    xmlSecAddNextSibling(cur, BAD_CAST "next", BAD_CAST "urn:p");
    xmlSecAddPrevSibling(cur, BAD_CAST "prev", BAD_CAST "urn:z");
    xmlSecAddChildNode(root, xsNewDocNode(doc, NULL, BAD_CAST "node", NULL));
    empty = xmlSecAddChild(root, BAD_CAST "slot", NULL);
    xsNodeSetContent(empty, BAD_CAST " \n ");
    printf("  ensure existing: %d\n", xmlSecEnsureEmptyChild(root, BAD_CAST "slot", NULL) == empty);
    xsNodeSetContent(empty, BAD_CAST "taken");
    cur = xmlSecEnsureEmptyChild(root, BAD_CAST "slot", NULL);
    printf("  ensure new after: %d\n", cur != NULL && xsNodeGetPrev(cur) != NULL &&
                                           xsNodeGetPrev(xsNodeGetPrev(cur)) == empty);
    printf("  ensure absent: %s\n",
           name_of(xmlSecEnsureEmptyChild(root, BAD_CAST "fresh", BAD_CAST "urn:p")));
    dump("  tree", doc);
    printf("  null parent: %p\n", (void *)xmlSecAddChild(NULL, BAD_CAST "c", NULL));
    printf("  null name: %p\n", (void *)xmlSecAddNextSibling(root, NULL, NULL));
    xsFreeDoc(doc);
}

static void line_feed(void) {
    xmlDocPtr doc = parse("<r/>");
    const xmlChar *saved = xmlSecGetDefaultLineFeed();

    printf("line feed: [%s]\n", (const char *)saved);
    xmlSecSetDefaultLineFeed(BAD_CAST "\r\n  ");
    xmlSecAddChild(xsDocGetRootElement(doc), BAD_CAST "c", NULL);
    xmlSecSetDefaultLineFeed(saved);
    dump("  custom", doc);
    xsFreeDoc(doc);
}

static void replacing(void) {
    xmlDocPtr doc = parse("<r><a>1</a><b><x/>t<y/></b><c/></r>");
    xmlNodePtr root = xsDocGetRootElement(doc);
    xmlNodePtr replaced = NULL;
    xmlNodePtr cur;
    int count = 0;

    printf("replacing\n");
    printf("  node: %d\n", xmlSecReplaceNode(xsNodeGetChildren(root),
                                             xsNewDocNode(doc, NULL, BAD_CAST "n", BAD_CAST "new")));
    printf("  content: %d\n",
           xmlSecReplaceContentAndReturn(xsNodeGetNext(xsNodeGetChildren(root)),
                                         xsNewDocNode(doc, NULL, BAD_CAST "z", NULL), &replaced));
    for (cur = replaced; cur != NULL; cur = xsNodeGetNext(cur)) {
        ++count;
    }
    printf("  returned content nodes: %d first=%s\n", count, name_of(replaced));
    xsFreeNodeList(replaced);
    printf("  content freed: %d\n", xmlSecReplaceContent(xsNodeGetNext(xsNodeGetChildren(root)),
                                                         xsNewDocText(doc, BAD_CAST "plain")));
    printf("  buffer: %d\n", xmlSecReplaceNodeBuffer(xsNodeGetLast(root), BAD_CAST "<p>1</p><q/>", 12));
    printf("  bad buffer: %d\n", xmlSecReplaceNodeBuffer(xsNodeGetLast(root), BAD_CAST "<p>", 3));
    replaced = NULL;
    printf("  root: %d\n", xmlSecReplaceNodeAndReturn(
                               root, xsNewDocNode(doc, NULL, BAD_CAST "newroot", NULL), &replaced));
    printf("  old root: %s new root: %s\n", name_of(replaced), name_of(xsDocGetRootElement(doc)));
    xsFreeNode(replaced);
    dump("  tree", doc);
    /* the refused node stays the caller's */
    cur = xsNewDocNode(doc, NULL, BAD_CAST "lone", NULL);
    printf("  no parent: %d\n", xmlSecReplaceNodeBuffer(cur, BAD_CAST "<a/>", 4));
    xsFreeNode(cur);
    xsFreeDoc(doc);
}

static void ids(void) {
    xmlDocPtr doc = parse("<r Id='a'><x Id='b' ID='c'/><y Id='a'/></r>");
    const xmlChar *names[] = {BAD_CAST "Id", BAD_CAST "ID", NULL};

    printf("ids\n");
    xmlSecAddIDs(doc, NULL, names);
    printf("  a=%s b=%s c=%s\n", xsGetID(doc, BAD_CAST "a") != NULL ? "yes" : "no",
           xsGetID(doc, BAD_CAST "b") != NULL ? "yes" : "no",
           xsGetID(doc, BAD_CAST "c") != NULL ? "yes" : "no");
    xmlSecAddIDs(doc, xsNodeGetChildren(xsDocGetRootElement(doc)), names);
    xmlSecAddIDs(NULL, NULL, names);
    xsFreeDoc(doc);
}

static void content(void) {
    xmlDocPtr doc = parse("<r><h> 0aFf </h><s> 42 </s><n>-5</n><g>4x</g><t>7 \n</t><e></e><w> \t</w>"
                          "<k><x/></k></r>");
    xmlNodePtr root = xsDocGetRootElement(doc);
    xmlNodePtr first = xsNodeGetChildren(root);
    xmlNodePtr node;
    xmlSecBuffer buffer;
    xmlSecSize size = 0;

    printf("content\n");
    xmlSecBufferInitialize(&buffer, 0);
    for (node = first; node != NULL; node = xsNodeGetNext(node)) {
        printf("  %s: empty=%d", name_of(node), xmlSecIsEmptyNode(node));
        size = 99;
        printf(" size=%d/%d\n", xmlSecGetNodeContentAsSize(node, 7, &size), (int)size);
    }
    printf("  hex read: %d size=%d\n", xmlSecGetNodeContentAsHex(first, &buffer),
           (int)xmlSecBufferGetSize(&buffer));
    printf("  hex write: %d\n", xmlSecSetNodeContentAsHex(first, BAD_CAST "\x01\xab\x00\xff", 4));
    printf("  bad hex: %d\n",
           xmlSecGetNodeContentAsHex(xsNodeGetNext(xsNodeGetNext(xsNodeGetNext(first))), &buffer));
    printf("  empty strings: %d %d %d\n", xmlSecIsEmptyString(BAD_CAST ""),
           xmlSecIsEmptyString(BAD_CAST " \v\f"), xmlSecIsEmptyString(BAD_CAST " x"));
    printf("  encode: %d\n", xmlSecNodeEncodeAndSetContent(xsNodeGetLast(root), BAD_CAST "a<b>&\"c\""));
    printf("  encode null: %d\n", xmlSecNodeEncodeAndSetContent(xsNodeGetNext(first), NULL));
    dump("  tree", doc);
    printf("  print: ");
    fflush(stdout);
    printf(" -> %d\n", xmlSecPrintXmlString(stdout, BAD_CAST "<&>'\""));
    printf("  print null: ");
    fflush(stdout);
    printf(" -> %d\n", xmlSecPrintXmlString(stdout, NULL));
    xmlSecBufferFinalize(&buffer);
    xsFreeDoc(doc);
}

static void tree(void) {
    xmlDocPtr doc = xmlSecCreateTree(BAD_CAST "root", BAD_CAST "urn:root");
    printf("tree\n");
    dump("  created", doc);
    xsFreeDoc(doc);
    doc = xmlSecCreateTree(BAD_CAST "bare", NULL);
    printf("  no namespace: %s\n", doc != NULL ? "doc" : "none");
    if (doc != NULL) {
        xsFreeDoc(doc);
    }
}

static void qnames(void) {
    xmlDocPtr doc = parse("<r xmlns='urn:d' xmlns:a='urn:a'><v>a:two</v><w>plain</w><u>x:one</u>"
                          "<m>a:read</m><m>exec</m><m>a:write</m><z/></r>");
    xmlNodePtr root = xsDocGetRootElement(doc);
    xmlNodePtr first = xsNodeGetChildren(root);
    xmlNodePtr cur;
    xmlChar *text;
    int value = -1;
    xmlSecBitMask mask = 0;

    printf("qnames\n");
    text = xmlSecGetQName(root, BAD_CAST "urn:a", BAD_CAST "loc");
    printf("  qname: %s\n", (const char *)text);
    xsFree(text);
    text = xmlSecGetQName(root, NULL, BAD_CAST "loc");
    printf("  unqualified: %s\n", (const char *)text);
    xsFree(text);
    printf("  unknown ns: %p\n", (void *)xmlSecGetQName(root, BAD_CAST "urn:none", BAD_CAST "loc"));

    printf("  info: %s\n", (const char *)xmlSecQName2IntegerGetInfo(integers, 2)->qnameLocalPart);
    printf("  get: %d", xmlSecQName2IntegerGetInteger(integers, BAD_CAST "urn:a", BAD_CAST "one", &value));
    printf(" -> %d\n", value);
    printf("  missing: %d\n", xmlSecQName2IntegerGetInteger(integers, NULL, BAD_CAST "one", &value));
    printf("  node read: %d", xmlSecQName2IntegerNodeRead(integers, first, &value));
    printf(" -> %d\n", value);
    printf("  unbound prefix: %d\n",
           xmlSecQName2IntegerNodeRead(integers, xsNodeGetNext(xsNodeGetNext(first)), &value));
    printf("  default ns: %d\n", xmlSecQName2IntegerNodeRead(integers, xsNodeGetNext(first), &value));
    printf("  node write: %d\n",
           xmlSecQName2IntegerNodeWrite(integers, xsNodeGetLast(root), BAD_CAST "q", BAD_CAST "urn:a", 1));
    printf("  write unknown: %d\n",
           xmlSecQName2IntegerNodeWrite(integers, xsNodeGetLast(root), BAD_CAST "q", NULL, 9));
    printf("  attr write: %d\n",
           xmlSecQName2IntegerAttributeWrite(integers, xsNodeGetLast(root), BAD_CAST "kind", 2));
    printf("  attr read: %d",
           xmlSecQName2IntegerAttributeRead(integers, xsNodeGetLast(root), BAD_CAST "kind", &value));
    printf(" -> %d\n", value);
    printf("  attr absent: %d\n",
           xmlSecQName2IntegerAttributeRead(integers, xsNodeGetLast(root), BAD_CAST "none", &value));
    text = xmlSecQName2IntegerGetStringFromInteger(integers, root, 3);
    printf("  string: %s\n", (const char *)text);
    xsFree(text);
    fflush(stdout);
    xmlSecQName2IntegerDebugDump(integers, 1, BAD_CAST "Kind", stdout);
    xmlSecQName2IntegerDebugXmlDump(integers, 3, BAD_CAST "Kind", stdout);
    xmlSecQName2IntegerDebugDump(integers, 8, BAD_CAST "Kind", stdout);
    fflush(stdout);

    cur = xsNodeGetNext(xsNodeGetNext(xsNodeGetNext(first)));
    printf("  mask nodes read: %d",
           xmlSecQName2BitMaskNodesRead(bits, &cur, BAD_CAST "m", BAD_CAST "urn:d", 1, &mask));
    printf(" -> %u next=%s\n", mask, name_of(cur));
    printf("  mask info: %s\n", (const char *)xmlSecQName2BitMaskGetInfo(bits, 4)->qnameLocalPart);
    printf("  mask get: %d", xmlSecQName2BitMaskGetBitMask(bits, BAD_CAST "urn:a", BAD_CAST "write", &mask));
    printf(" -> %u\n", mask);
    text = xmlSecQName2BitMaskGetStringFromBitMask(bits, root, 1);
    printf("  mask string: %s\n", (const char *)text);
    xsFree(text);
    printf("  mask unknown string: %p\n", (void *)xmlSecQName2BitMaskGetStringFromBitMask(bits, root, 8));
    printf("  mask nodes write: %d\n", xmlSecQName2BitMaskNodesWrite(bits, xsNodeGetLast(root), BAD_CAST "m", NULL, 7));
    fflush(stdout);
    xmlSecQName2BitMaskDebugDump(bits, 5, BAD_CAST "Perm", stdout);
    xmlSecQName2BitMaskDebugXmlDump(bits, 6, BAD_CAST "Perm", stdout);
    xmlSecQName2BitMaskDebugDump(bits, 0, BAD_CAST "Perm", stdout);
    fflush(stdout);
    dump("  tree", doc);
    xsFreeDoc(doc);
}

int main(void) {
    xmlSecErrorsSetCallback(record);
    adding();
    line_feed();
    replacing();
    ids();
    content();
    tree();
    qnames();
    printf("done\n");
    return 0;
}
