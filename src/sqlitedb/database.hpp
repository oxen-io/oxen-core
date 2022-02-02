#pragma once

#include <epee/misc_log_ex.h>

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>
#include <fmt/format.h>

#include <chrono>
#include <cstdlib>
#include <exception>
#include <string_view>
#include <shared_mutex>
#include <thread>
#include <unordered_set>
#include <optional>

#include "common/fs.h"

namespace db
{
  template <typename T>
  inline constexpr bool is_cstr = false;
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
  struct blob_binder
  {
    std::string_view data;
    explicit blob_binder(std::string_view d) : data{d}
    {}
  };

  // Binds a string_view as a no-copy blob at parameter index i.
  inline void
  bind_blob_ref(SQLite::Statement& st, int i, std::string_view blob)
  {
    st.bindNoCopy(i, static_cast<const void*>(blob.data()), blob.size());
  }

  namespace detail
  {
    template <typename T>
    void
    bind_oneshot_single(SQLite::Statement& st, int i, const T& val)
    {
      if constexpr (std::is_same_v<T, std::string> || is_cstr<T>)
        st.bindNoCopy(i, val);
      else if constexpr (std::is_same_v<T, blob_binder>)
        bind_blob_ref(st, i, val.data);
      else
        st.bind(i, val);
    }

    template <typename... T, int... Index>
    void
    bind_oneshot(SQLite::Statement& st, std::integer_sequence<int, Index...>, const T&... bind)
    {
      (bind_oneshot_single(st, Index + 1, bind), ...);
    }
  }  // namespace detail

  // Called from exec_query and similar to bind statement parameters for immediate execution.
  // strings (and c strings) use no-copy binding; integer values are bound by value.  You can bind a
  // blob (by reference, like strings) by passing `blob_binder{data}`.
  template <typename... T>
  void
  bind_oneshot(SQLite::Statement& st, const T&... bind)
  {
    detail::bind_oneshot(st, std::make_integer_sequence<int, sizeof...(T)>{}, bind...);
  }

  // Executes a query that does not expect results.  Optionally binds parameters, if provided.
  // Returns the number of affected rows; throws on error or if results are returned.
  template <typename... T, int... Index>
  int
  exec_query(SQLite::Statement& st, const T&... bind)
  {
    bind_oneshot(st, bind...);
    return st.exec();
  }

  // Same as above, but prepares a literal query on the fly for use with queries that are only used
  // once.
  template <typename... T>
  int
  exec_query(SQLite::Database& db, const char* query, const T&... bind)
  {
    SQLite::Statement st{db, query};
    return exec_query(st, bind...);
  }

  template <typename T, typename... More>
  struct first_type
  {
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
  T
  get(SQLite::Statement& st)
  {
    return static_cast<T>(st.getColumn(0));
  }
  template <typename T1, typename T2, typename... Tn>
  std::tuple<T1, T2, Tn...>
  get(SQLite::Statement& st)
  {
    return st.getColumns<std::tuple<T1, T2, Tn...>, 2 + sizeof...(Tn)>();
  }

  // Steps a statement to completion that is expected to return at most one row, optionally binding
  // values into it (if provided).  Returns a filled out optional<T> (or optional<std::tuple<T...>>)
  // if a row was retrieved, otherwise a nullopt.  Throws if more than one row is retrieved.
  template <typename... T, typename... Args>
  std::optional<type_or_tuple<T...>>
  exec_and_maybe_get(SQLite::Statement& st, const Args&... bind)
  {
    bind_oneshot(st, bind...);
    std::optional<type_or_tuple<T...>> result;
    while (st.executeStep())
    {
      if (result)
      {
        MERROR("Expected single-row result, got multiple rows from {}" << st.getQuery());
        throw std::runtime_error{"DB error: expected single-row result, got multiple rows"};
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
  type_or_tuple<T...>
  exec_and_get(SQLite::Statement& st, const Args&... bind)
  {
    auto maybe_result = exec_and_maybe_get<T...>(st, bind...);
    if (!maybe_result)
    {
      MERROR("Expected single-row result, got no rows from {}" << st.getQuery());
      throw std::runtime_error{"DB error: expected single-row result, got no rows"};
    }
    return *std::move(maybe_result);
  }

  // Executes a query to completion, collecting each row into a vector<T> (or vector<tuple<T...>> if
  // multiple T are given).  Can optionally bind before executing.
  template <typename... T, typename... Bind>
  std::vector<type_or_tuple<T...>>
  get_all(SQLite::Statement& st, const Bind&... bind)
  {
    bind_oneshot(st, bind...);
    std::vector<type_or_tuple<T...>> results;
    while (st.executeStep())
      results.push_back(get<T...>(st));
    return results;
  }

  // Takes a query prefix and suffix and places <count> ? separated by commas between them
  // Example: multi_in_query("foo(", 3, ")bar") will return "foo(?,?,?)bar"
  inline std::string
  multi_in_query(std::string_view prefix, size_t count, std::string_view suffix)
  {
    std::string query;
    query.reserve(prefix.size() + (count == 0 ? 0 : 2 * count - 1) + suffix.size());
    query += prefix;
    for (size_t i = 0; i < count; i++)
    {
      if (i > 0)
        query += ',';
      query += '?';
    }
    query += suffix;
    return query;
  }

  // Storage database class.
  class Database
  {
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
    class StatementWrapper
    {
      SQLite::Statement& st;

     public:
      /// Whether we should reset on destruction; can be set to false if needed.
      bool reset_on_destruction = true;

      explicit StatementWrapper(SQLite::Statement& st) noexcept : st{st}
      {}
      ~StatementWrapper() noexcept
      {
        if (reset_on_destruction)
          st.tryReset();
      }
      SQLite::Statement&
      operator*() noexcept
      {
        return st;
      }
      SQLite::Statement*
      operator->() noexcept
      {
        return &st;
      }
      operator SQLite::Statement&() noexcept
      {
        return st;
      }
    };

   public:

    StatementWrapper
    prepared_st(const std::string& query)
    {
      std::unordered_map<std::string, SQLite::Statement>* sts;
      {
        std::shared_lock rlock{prepared_sts_mutex};
        if (auto it = prepared_sts.find(std::this_thread::get_id()); it != prepared_sts.end())
          sts = &it->second;
        else
        {
          rlock.unlock();
          std::unique_lock wlock{prepared_sts_mutex};
          sts = &prepared_sts.try_emplace(std::this_thread::get_id()).first->second;
        }
      }
      if (auto qit = sts->find(query); qit != sts->end())
        return StatementWrapper{qit->second};
      return StatementWrapper{sts->try_emplace(query, db, query).first->second};
    }

    template <typename... T>
    int
    prepared_exec(const std::string& query, const T&... bind)
    {
      return exec_query(prepared_st(query), bind...);
    }

    template <typename... T, typename... Bind>
    auto
    prepared_get(const std::string& query, const Bind&... bind)
    {
      return exec_and_get<T...>(prepared_st(query), bind...);
    }

    template <typename... T, typename... Bind>
    auto
    prepared_maybe_get(const std::string& query, const Bind&... bind)
    {
      return exec_and_maybe_get<T...>(prepared_st(query), bind...);
    }

    explicit Database(const fs::path& db_path, const std::string_view db_password)
        : db{db_path.u8string(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE | SQLite::OPEN_FULLMUTEX, 5000/*ms*/}
    {
      // Don't fail on these because we can still work even if they fail
      if (int rc = db.tryExec("PRAGMA journal_mode = WAL"); rc != SQLITE_OK)
        MERROR("Failed to set journal mode to WAL: {}" << sqlite3_errstr(rc));

      if (int rc = db.tryExec("PRAGMA synchronous = NORMAL"); rc != SQLITE_OK)
        MERROR("Failed to set synchronous mode to NORMAL: {}" << sqlite3_errstr(rc));

      if (int rc = db.tryExec("PRAGMA foreign_keys = ON");
          rc != SQLITE_OK) {
        auto m = fmt::format("Failed to enable foreign keys constraints: {}", sqlite3_errstr(rc));
        MERROR(m);
        throw std::runtime_error{m};
      }
      int fk_enabled = db.execAndGet("PRAGMA foreign_keys").getInt();
      if (fk_enabled != 1) {
        MERROR("Failed to enable foreign key constraints; perhaps this sqlite3 is compiled without it?");
        throw std::runtime_error{"Foreign key support is required"};
      }

      // FIXME: SQLite / SQLiteCPP may not have encryption available
      //       so this may fail, or worse silently fail and do nothing
      if (not db_password.empty())
      {
        db.key(std::string{db_password});
      }
    }

    ~Database() = default;
  };

}  // namespace db
