#include "scoped_message_writer.h"

#include "common/format.h"

namespace tools {

static auto logcat = log::Cat("msgwriter");

scoped_message_writer& scoped_message_writer::flush() {
    if (!m_content.empty()) {
        if (m_color) {
            rdln::suspend_readline pause_readline;
            fmt::print(fg(*m_color), "{}{}\n", m_prefix, m_content);
        } else
            fmt::print("{}{}\n", m_prefix, m_content);

        m_content.clear();
    }
    return *this;
}
scoped_message_writer::~scoped_message_writer() {
    flush();
}

}  // namespace tools
