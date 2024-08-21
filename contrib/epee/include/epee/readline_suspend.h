#pragma once

namespace rdln {
class readline_buffer;

// RAII class to suspend readline.  If not built with readline support, this class is a no-op.
class suspend_readline {
#ifdef HAVE_READLINE
  public:
    suspend_readline();
    ~suspend_readline();

  private:
    readline_buffer* m_buffer;
    bool m_restart;
#endif
};
}  // namespace rdln
