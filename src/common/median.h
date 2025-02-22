// Copyright (c) 2022, The Oxen Project

#include <algorithm>
#include <vector>

namespace tools {

// Calculate the median element (the middle element, if an odd size, and the mean of the two
// middle elements if even).  Pass first=true if you don't care about the mean of the middle two,
// in which case you'll get back the value of lower of the two middle elements.
// This leaves the given range in an indeterminant (partially sorted) order.
template <typename RandomAccessIter>
auto median(RandomAccessIter begin, RandomAccessIter end, bool first = false) {
    std::size_t size = end - begin;
    if (size == 0)
        return std::decay_t<decltype(*begin)>{};

    auto mid = begin + (size - 1) / 2;
    std::nth_element(begin, mid, end);

    if (first || size % 2)
        return *mid;

    auto mid2 = std::min_element(mid + 1, end);
    return (*mid + *mid2) / 2;
}

// Same as above, but takes a vector by value or move for convenience.
template <typename T>
T median(std::vector<T> v, bool first = false) {
    return median(v.begin(), v.end(), first);
}
}  // namespace tools
