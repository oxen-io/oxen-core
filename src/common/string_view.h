#pragma once
#include <string>

#ifdef __cpp_lib_string_view
#include <string_view>
#endif

namespace common
{
#ifdef __cpp_lib_string_view
using string_view = std::string_view;
#else
class simple_string_view {
    const char *_data;
    size_t _size;
    using char_traits = std::char_traits<char>;
public:
    constexpr simple_string_view() noexcept : _data{nullptr}, _size{0} {}
    constexpr simple_string_view(const simple_string_view &) noexcept = default;
    simple_string_view(const std::string &str) : _data{str.data()}, _size{str.size()} {}
    constexpr simple_string_view(const char *data, size_t size) noexcept : _data{data}, _size{size} {}
    simple_string_view(const char *data) : _data{data}, _size{std::char_traits<char>::length(data)} {}
    simple_string_view &operator=(const simple_string_view &) = default;
    constexpr const char *data() const { return _data; }
    constexpr size_t size() const { return _size; }
    constexpr bool empty() { return _size == 0; }
    operator std::string() const { return {_data, _size}; }
    const char *begin() const { return _data; }
    const char *end() const { return _data + _size; }
};
bool operator==(simple_string_view lhs, simple_string_view rhs) {
    return lhs.size() == rhs.size() && 0 == std::char_traits<char>::compare(lhs.data(), rhs.data(), lhs.size());
};
bool operator!=(simple_string_view lhs, simple_string_view rhs) {
    return !(lhs == rhs);
}
std::ostream &operator<<(std::ostream &os, const simple_string_view &s) { return os.write(s.data(), s.size()); }
using string_view = simple_string_view;
#endif
}; // namespace common
