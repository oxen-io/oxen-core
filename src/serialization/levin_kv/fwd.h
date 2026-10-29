#pragma once

// For headers declaring a type's `void serialize(levin_kv::archive&)`, which only the .cpp
// defining it needs the archive itself for.
namespace levin_kv {
class archive;
}
