#pragma once

#include <algorithm>
#include <concepts>
#include <deque>
#include <utility>

#include "l2_tracker/events.h"

namespace eth {

// Container for holding recent events with expiry functionality.
template <std::derived_from<event::L2StateChange> Event>
struct RecentEvents {
  private:
    std::map<Event, uint64_t> events; // Event -> expiry

  public:
    // Adds an event into the container.  If the event is already present and has an older l2_height
    // than is given then its l2_height will be updated to the given value; if it has a new
    // l2_height then nothing happens.
    void add(Event&& evt, uint64_t l2_height) {
        auto it = events.lower_bound(evt);
        if (it != events.end() && it->first == evt) {
            if (l2_height > it->second)
                it->second = l2_height;
        } else {
            events.emplace_hint(it, std::move(evt), l2_height);
        }
    }

    // Returns true iff this event contain contains the given event.
    bool contains(const Event& evt) const {
        return events.count(evt);
    }

    // Removes an event from the container.  If the optional max_height is given then the event is
    // only removed if the l2_height of the contained value is <= the given max_height value.
    // Returns true if an event was removed, false if not found.
    bool remove(const Event& evt, std::optional<uint64_t> max_height = std::nullopt) {
        auto it = events.find(evt);
        if (it == events.end())
            return false;
        if (max_height && it->second > *max_height)
            return false;
        events.erase(it);
        return true;
    }

    // Removes any events from the container than have l2_heights less than or equal to the given
    // expiry_height.  Returns the number of removed events.
    size_t expire(uint64_t expiry_height) {
        size_t removed = 0;
        for (auto it = events.begin(); it != events.end(); ) {
            if (it->second <= expiry_height) {
                it = events.erase(it);
                removed++;
            }
            else
                ++it;
        }
        return removed;
    }
};

}  // namespace eth
