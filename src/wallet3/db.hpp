#pragma once

#include <memory>
#include <SQLiteCpp/SQLiteCpp.h>

namespace wallet
{

  std::shared_ptr<SQLite::Database> OpenDB(std::string_view filename, std::string_view password);

}
