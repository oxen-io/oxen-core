#pragma once

#include <ctime>
#include <string>
#include <vector>
#include <map>

class TimingsDatabase
{
public:
  struct instance
  {
    time_t t;
    size_t npoints;
    std::chrono::duration<double> min, max, mean, median, stddev, npskew;
    std::vector<std::chrono::duration<double>> deciles;
  };

public:
  TimingsDatabase();
  TimingsDatabase(const std::string &filename);
  ~TimingsDatabase();

  std::vector<instance> get(const char *name) const;
  void add(const char *name, const instance &data);

private:
  bool load();
  bool save();

private:
  std::string filename;
  std::multimap<std::string, instance> instances;
};
