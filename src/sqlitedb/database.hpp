#pragma once

#include <SQLiteCpp/SQLiteCpp.h>
#include <common/string_util.h>
#include <epee/misc_log_ex.h>

#include <cstdlib>
#include <optional>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "common/fs.h"
#include "common/guts.h"
#include "common/exception.h"
#include "logging/oxen_logger.h"

namespace db {
namespace log = oxen::log;
inline auto sqlitedb_logcat = log::Cat("db.sqlite");

template <typename T>
constexpr bool is_cstr = false;
template <size_t N>
inline constexpr bool is_cstr<char[N]> = true;
template <size_t N>
inline constexpr bool is_cstr<const char[N]> = true;
template <>
inline constexpr bool is_cstr<char*> = true;
template <>
inline constexpr bool is_cstr<const char*> = true;

// Simple wrapper class that can be used to bind a blob through the templated binding code below.
// E.g. `exec_query(st, 100, 42, blob_binder{data})` binds the third parameter using no-copy blob
// binding of the contained data.
struct blob_binder {
    std::string_view data;
    explicit blob_binder(std::string_view d) : data{d} {}
};

// Binds a string_view as a no-copy blob at parameter index i.
inline void bind_blob_ref(SQLite::Statement& st, int i, std::string_view blob) {
    st.bindNoCopy(i, static_cast<const void*>(blob.data()), blob.size());
}

// Wrapper for extracting BLOB values from a query without unnecessary copying.  This is intended
// to be called via `db::get` such as:
//
//    auto [num, data] = db::get<int, blob>(st);
//
// The `.data` string view here will point to the BLOB data directly.  Note that this view remains
// only value while the statement remains active, and so it must be used as needed immediately.
// This also means that this is *unsuitable* for one-shot methods like `prepared_get` (which
// finalize the statement before returning).
struct blob {
    std::string_view data;
    blob(SQLite::Column&& col) :
            data{static_cast<const char*>(col.getBlob()), static_cast<size_t>(col.getBytes())} {}
};

// Takes a primitive struct from which we can directly initialize from the stored blob value.  The
// type `T` must be usable with `make_from_guts`.  Unlike `blob` this value *is* suitable for use
// in a one-shot method.
template <typename T>
struct blob_guts {
    T value;
    blob_guts(SQLite::Column&& col) : value{tools::make_from_guts<T>(blob(std::move(col)).data)} {}

    // Implicit rvalue-convertible to `T&&` so that you can use it somewhat transparently, for
    // example, allowing implicit conversion from a `std::tuple<..., blob_guts<T>>` into a
    // `std::tuple<..., T>`.
    operator T&&() && { return std::move(value); }
};

namespace detail {
    template <typename T>
    void bind_oneshot_single(SQLite::Statement& st, int i, const T& val) {
        if constexpr (std::is_same_v<T, std::string> || is_cstr<T>)
            st.bindNoCopy(i, val);
        else if constexpr (std::is_same_v<T, blob_binder>)
            bind_blob_ref(st, i, val.data);
        else
            st.bind(i, val);
    }

    template <typename... T, int... Index>
    void bind_oneshot(
            SQLite::Statement& st, std::integer_sequence<int, Index...>, const T&... bind) {
        (bind_oneshot_single(st, Index + 1, bind), ...);
    }
}  // namespace detail

// Called from exec_query and similar to bind statement parameters for immediate execution.
// strings (and c strings) use no-copy binding; integer values are bound by value.  You can bind a
// blob (by reference, like strings) by passing `blob_binder{data}`.
template <typename... T>
void bind_oneshot(SQLite::Statement& st, const T&... bind) {
    detail::bind_oneshot(st, std::make_integer_sequence<int, sizeof...(T)>{}, bind...);
}

// Executes a query that does not expect results.  Optionally binds parameters, if provided.
// Returns the number of affected rows; throws on error or if results are returned.
template <typename... T, int... Index>
int exec_query(SQLite::Statement& st, const T&... bind) {
    bind_oneshot(st, bind...);
    return st.exec();
}

// Same as above, but prepares a literal query on the fly for use with queries that are only used
// once.
template <typename... T>
int exec_query(SQLite::Database& db, const char* query, const T&... bind) {
    SQLite::Statement st{db, query};
    return exec_query(st, bind...);
}

template <typename T, typename... More>
struct first_type {
    using type = T;
};
template <typename... T>
using first_type_t = typename first_type<T...>::type;

template <typename... T>
using type_or_tuple = std::conditional_t<sizeof...(T) == 1, first_type_t<T...>, std::tuple<T...>>;

// Retrieves a single row of values from the current state of a statement (i.e. after a
// executeStep() call that is expecting a return value).  If `T...` is a single type then this
// returns the single T value; if T... has multiple types then you get back a tuple of values.
template <typename T>
T get(SQLite::Statement& st) {
    return static_cast<T>(st.getColumn(0));
}
template <typename T1, typename T2, typename... Tn>
std::tuple<T1, T2, Tn...> get(SQLite::Statement& st) {
    return st.getColumns<std::tuple<T1, T2, Tn...>, 2 + sizeof...(Tn)>();
}

// Steps a statement to completion that is expected to return at most one row, optionally binding
// values into it (if provided).  Returns a filled out optional<T> (or optional<std::tuple<T...>>)
// if a row was retrieved, otherwise a nullopt.  Throws if more than one row is retrieved.
template <typename... T, typename... Args>
std::optional<type_or_tuple<T...>> exec_and_maybe_get(SQLite::Statement& st, const Args&... bind) {
    bind_oneshot(st, bind...);
    std::optional<type_or_tuple<T...>> result;
    while (st.executeStep()) {
        if (result) {
            log::error(
                    sqlitedb_logcat,
                    "Expected single-row result, got multiple rows from {}",
                    st.getQuery());
            throw oxen::traced<std::runtime_error>{"DB error: expected single-row result, got multiple rows"};
        }
        result = get<T...>(st);
    }
    return result;
}

// Executes a statement to completion that is expected to return exactly one row, optionally
// binding values into it (if provided).  Returns a T or std::tuple<T...> (depending on whether or
// not more than one T is provided) for the row.  Throws an exception if no rows or more than one
// row are returned.
template <typename... T, typename... Args>
type_or_tuple<T...> exec_and_get(SQLite::Statement& st, const Args&... bind) {
    auto maybe_result = exec_and_maybe_get<T...>(st, bind...);
    if (!maybe_result) {
        log::error(
                sqlitedb_logcat, "Expected single-row result, got no rows from {}", st.getQuery());
        throw oxen::traced<std::runtime_error>{"DB error: expected single-row result, got no rows"};
    }
    return *std::move(maybe_result);
}

// Executes a query to completion, collecting each row into a vector<T> (or vector<tuple<T...>> if
// multiple T are given).  Can optionally bind before executing.
template <typename... T, typename... Bind>
std::vector<type_or_tuple<T...>> get_all(SQLite::Statement& st, const Bind&... bind) {
    bind_oneshot(st, bind...);
    std::vector<type_or_tuple<T...>> results;
    while (st.executeStep())
        results.push_back(get<T...>(st));
    return results;
}

// Takes a query prefix and suffix and places <count> ? separated by commas between them
// Example: multi_in_query("foo(", 3, ")bar") will return "foo(?,?,?)bar"
std::string multi_in_query(std::string_view prefix, size_t count, std::string_view suffix);

// Storage database class.
class Database {
  public:
    // This must be declared *before* the prepared statements container,
    // so that it is destroyed *after* because sqlite_close() fails if any
    // prepared statements are not finalized.
    SQLite::Database db;

  private:
    // SQLiteCpp's statements are not thread-safe, so we prepare them thread-locally when needed
    std::unordered_map<std::thread::id, std::unordered_map<std::string, SQLite::Statement>>
            prepared_sts;
    std::shared_mutex prepared_sts_mutex;

    /** Wrapper around a SQLite::Statement that calls `tryReset()` on destruction of the wrapper. */
    class StatementWrapper {
      protected:
        SQLite::Statement& st;

      public:
        /// Whether we should reset on destruction; can be set to false if needed.
        bool reset_on_destruction = true;

        explicit StatementWrapper(SQLite::Statement& st) noexcept : st{st} {}

        StatementWrapper(StatementWrapper&& sw) noexcept : st{sw.st} {
            sw.reset_on_destruction = false;
        }

        ~StatementWrapper() noexcept {
            if (reset_on_destruction)
                st.tryReset();
        }
        SQLite::Statement& operator*() noexcept { return st; }
        SQLite::Statement* operator->() noexcept { return &st; }
        operator SQLite::Statement&() noexcept { return st; }
    };

    /** Extends the above with the ability to iterate through results. */
    template <typename... T>
    class IterableStatementWrapper : StatementWrapper {
      public:
        using StatementWrapper::StatementWrapper;

        class iterator {
            IterableStatementWrapper& sw;
            bool finished;
            explicit iterator(IterableStatementWrapper& sw, bool finished = false) :
                    sw{sw}, finished{finished} {
                ++*this;
            }
            friend class IterableStatementWrapper;

          public:
            iterator(const iterator&) = delete;
            iterator(iterator&&) = delete;
            void operator=(const iterator&) = delete;
            void operator=(iterator&&) = delete;

            type_or_tuple<T...> operator*() { return get<T...>(sw); }

            iterator& operator++() {
                if (!finished)
                    finished = !sw->executeStep();
                return *this;
            }
            void operator++(int) { ++*this; }
            bool operator==(const iterator& other) {
                return &sw == &other.sw && finished == other.finished;
            }
            bool operator!=(const iterator& other) { return !(*this == other); }

            using value_type = type_or_tuple<T...>;
            using reference = value_type;
            using difference_type = std::ptrdiff_t;
            using pointer = const value_type*;
            using iterator_category = std::input_iterator_tag;
        };

        iterator begin() { return iterator{*this}; }
        iterator end() { return iterator{*this, true}; }
    };

  public:
    /// Prepares a query, caching it, and returns a wrapper that automatically resets the prepared
    /// statement on destruction.
    StatementWrapper prepared_st(const std::string& query);

    /// Prepares (with caching) and binds a query, returning the active statement handle.  Like
    /// `prepared_st` the wrapper resets the prepared statement on destruction.
    template <typename... T>
    StatementWrapper prepared_bind(const std::string& query, const T&... bind) {
        auto st = prepared_st(query);
        bind_oneshot(st, bind...);
        return st;
    }

    /// Prepares (with caching), binds parameters, then returns an object that lets you iterate
    /// through results where each row is a T or tuple<T...>:
    template <typename... T, typename... Bind>
        requires(sizeof...(T) != 0)
    IterableStatementWrapper<T...> prepared_results(const std::string& query, const Bind&... bind) {
        return IterableStatementWrapper<T...>{prepared_bind(query, bind...)};
    }

    /// Prepares (with caching) a query and then executes it, optionally binding the given
    /// parameters when executing.
    template <typename... T>
    int prepared_exec(const std::string& query, const T&... bind) {
        return exec_query(prepared_st(query), bind...);
    }

    /// Prepares (with caching) a query that returns a single row (with optional bind parameters),
    /// executes it, and returns the value.  Throws if the query returns 0 or more than 1 rows.
    template <typename... T, typename... Bind>
    auto prepared_get(const std::string& query, const Bind&... bind) {
        return exec_and_get<T...>(prepared_st(query), bind...);
    }

    /// Prepares (with caching) a query that returns at most a single row (with optional bind
    /// parameters), executes it, and returns the value or nullopt if the query returned no rows.
    /// Throws if the query returns more than 1 rows.
    template <typename... T, typename... Bind>
    auto prepared_maybe_get(const std::string& query, const Bind&... bind) {
        return exec_and_maybe_get<T...>(prepared_st(query), bind...);
    }

    explicit Database(const fs::path& db_path, const std::string_view db_password);

    ~Database() = default;
};

}  // namespace db
