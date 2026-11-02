#include "common/spawn.h"

#include <gtest/gtest.h>

#ifndef _WIN32

#include <sys/wait.h>

#include <cerrno>

TEST(spawn, no_wait_leaves_child_waiting_alone) {
    ASSERT_EQ(tools::spawn("/bin/sh", {"sh", "-c", "exit 0"}, false), 0);

    // A spawn that doesn't wait mustn't leave a zombie for us to reap...
    errno = 0;
    EXPECT_EQ(waitpid(-1, nullptr, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);

    // ... nor stop the process from waiting for its other children.
    EXPECT_EQ(tools::spawn("/bin/sh", {"sh", "-c", "exit 3"}, true), 3);
}

#endif
