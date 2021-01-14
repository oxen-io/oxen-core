#pragma once
#include <string>
#include <oxenmq/variant.h>
#include <array>
#include <typeinfo>
#ifdef __GNUG__
#include <cxxabi.h>
#include <cstdlib>
#endif

namespace tools {

namespace detail {

template <typename T, typename T1, typename... Ts>
constexpr size_t template_index_impl_inner() {
    if constexpr (std::is_same_v<T, T1>) return 0;
    else {
        static_assert(sizeof...(Ts) > 0, "Type not found");
        return 1 + template_index_impl_inner<T, Ts...>();
    }
}

template <typename T, typename C> struct template_index_impl {};

template <typename T, template<typename...> typename C, typename... Ts>
struct template_index_impl<T, C<Ts...>> : std::integral_constant<size_t, template_index_impl_inner<T, Ts...>()> {};

} // namespace detail

/// Type wrapper that contains an arbitrary list of types.
template <typename...> struct type_list {};

/// Accesses the index of the first T within a template type's type list.  E.g.
///
///     template_index<int, std::variant<double, short, int>>() == 2
///
/// Fails at compile time if T is not in any of the type's class list.
template <typename T, typename C>
constexpr size_t template_index = detail::template_index_impl<T, C>::value;

/// Access the std::type_info& of the hold value of the given variant.  This is basically a runtime
/// version of `typeid(std::variant_alternative_t<N, variant>)`.  Throws std::bad_variant_access if
/// the variant is valueless_by_exception.
template <typename... T>
const std::type_info& variant_type(const std::variant<T...>& v) {
    const size_t index = v.index();
    if (index != std::variant_npos)
        return *std::array<const std::type_info*, sizeof...(T)>{{&typeid(T)...}}[index];
#ifndef BROKEN_APPLE_VARIANT
    throw std::bad_variant_access{};
#else
    throw std::runtime_error{"Bad variant access"};
#endif
}

/// Converts a std::type_info (typically from a typeid(T) call) into a human-readable name.  For GCC
/// and clang this means demangling it.  For anything else we just return .name().
inline std::string type_name(const std::type_info& ti) {
#ifdef __GNUG__
    int status = 0;
    char* realname = abi::__cxa_demangle(ti.name(), nullptr, nullptr, &status);
    std::string name = status == 0 ? realname : ti.name();
    std::free(realname);
#else
    std::string name = ti.name();
#endif
    return name;
}

/// Same as above, but uses a templated type instead of a type_info argument.
template <typename T>
inline std::string type_name() { return type_name(typeid(T)); }

} // namespace tools
