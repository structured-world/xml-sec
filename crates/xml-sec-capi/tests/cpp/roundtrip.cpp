// Uses the C ABI from C++ through owning wrappers, the way a C++ application
// would: the header compiles as C++, handles are trivially copyable values,
// and destruction is tied to scope.
#include "xml_sec.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <utility>

static_assert(std::is_standard_layout<XsBytes>::value, "XsBytes is a C structure");
static_assert(std::is_trivially_copyable<XsPolicy>::value, "handles are plain values");
static_assert(sizeof(XsPolicy) == sizeof(uint64_t), "a handle is one 64-bit value");

namespace {

int failures = 0;

void check(bool condition, const char *what) {
    if (!condition) {
        std::fprintf(stderr, "check failed: %s\n", what);
        ++failures;
    }
}

XsBytes bytes(const std::string &value) {
    return XsBytes{reinterpret_cast<const uint8_t *>(value.data()), value.size()};
}

// Owns one handle and destroys it at scope end.
template <typename Handle, xs_status (*Destroy)(Handle)> class Owned {
  public:
    Owned() = default;
    Owned(const Owned &) = delete;
    Owned &operator=(const Owned &) = delete;
    ~Owned() {
        if (handle_.value != 0) {
            check(Destroy(handle_) == XS_OK, "destroyed at scope end");
        }
    }
    Handle *out() { return &handle_; }
    Handle get() const { return handle_; }

  private:
    Handle handle_{};
};

using Provider = Owned<XsProvider, xs_provider_destroy>;
using Store = Owned<XsPolicyStore, xs_policy_store_destroy>;
using Policy = Owned<XsPolicy, xs_policy_destroy>;
using Document = Owned<XsDocument, xs_document_destroy>;
using Error = Owned<XsError, xs_error_destroy>;

std::string message(const Error &error) {
    XsBytes text{};
    if (xs_error_message(error.get(), &text) != XS_OK) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(text.ptr), text.len);
}

} // namespace

int main() {
    const std::string configuration = "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n";
    const XsCompileContext context{0, 1};
    Provider provider;
    Store store;
    Policy policy;

    check(xs_provider_new_rustcrypto(provider.out(), nullptr) == XS_OK, "provider");
    check(xs_policy_store_new(bytes(configuration), bytes("app"), provider.get(), &context,
                              nullptr, store.out(), nullptr) == XS_OK,
          "store");
    check(xs_policy_store_load(store.get(), policy.out(), nullptr) == XS_OK, "load");

    XsPolicyIdentity identity{};
    check(xs_policy_identity(policy.get(), &identity, nullptr) == XS_OK, "identity");
    check(identity.present == 1 && identity.revision == 1, "revision 1");
    check(std::string(reinterpret_cast<const char *>(identity.profile.ptr),
                      identity.profile.len) == "app",
          "profile name");

    {
        Document document;
        check(xs_document_parse(policy.get(), XS_OPERATION_VERIFY, bytes("<root><a/></root>"),
                                document.out(), nullptr) == XS_OK,
              "parse");
        XsBuffer buffer{};
        check(xs_document_serialize(document.get(), &buffer, nullptr) == XS_OK, "serialize");
        std::string xml(reinterpret_cast<const char *>(buffer.ptr), buffer.len);
        xs_buffer_free(buffer);
        check(xml.find("<a/>") != std::string::npos, "serialized content");
    }

    {
        Document document;
        Error error;
        check(xs_document_parse(policy.get(), XS_OPERATION_VERIFY, bytes("<broken"),
                                document.out(), error.out()) == XS_DOCUMENT,
              "malformed XML is a document failure");
        check(!message(error).empty(), "error message");
    }

    {
        Store refused;
        Error error;
        check(xs_policy_store_new(bytes(configuration), bytes("missing"), provider.get(),
                                  &context, nullptr, refused.out(), error.out()) != XS_OK,
              "an unknown profile is refused");
        check(refused.get().value == 0, "no store on failure");
        check(error.get().value != 0, "an error handle on failure");
    }

    if (failures != 0) {
        std::fprintf(stderr, "%d checks failed\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
