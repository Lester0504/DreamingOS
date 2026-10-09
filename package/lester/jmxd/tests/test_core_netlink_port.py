"""The rule socket must coexist with other netlink clients in the core process."""
import pathlib
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux netlink sockets")
class CoreNetlinkPortTest(unittest.TestCase):
    def test_rule_socket_after_another_client_claims_process_port(self):
        source = (pathlib.Path(__file__).parents[1] / "src/jmx_netlink.c").read_text()
        function = source[source.index("int jmx_v2_netlink_init(void)"):]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#define JMX_NETLINK_ID NETLINK_USERSOCK
#define LOG_DEBUG(...) fprintf(stderr, __VA_ARGS__)
''' + function + r'''
int main(void) {
    int owner = socket(AF_NETLINK, SOCK_RAW, JMX_NETLINK_ID);
    struct sockaddr_nl address = { .nl_family = AF_NETLINK };
    socklen_t size = sizeof(address);
    assert(owner >= 0);
    assert(bind(owner, (void *)&address, size) == 0);
    assert(getsockname(owner, (void *)&address, &size) == 0);
    assert(address.nl_pid == (unsigned)getpid());
    int first = jmx_v2_netlink_init();
    assert(first >= 0);
    assert(getsockname(first, (void *)&address, &size) == 0);
    unsigned port = address.nl_pid;
    assert(port != 0 && port != (unsigned)getpid());
    int second = jmx_v2_netlink_init();
    assert(second >= 0);
    assert(getsockname(second, (void *)&address, &size) == 0);
    assert(address.nl_pid != port && address.nl_pid != (unsigned)getpid());
    close(second); close(first); close(owner);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="core-netlink-port-") as directory:
            root = pathlib.Path(directory)
            (root / "test.c").write_text(harness)
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(root / "test.c"),
                            "-o", str(root / "test")], check=True, timeout=30)
            subprocess.run([str(root / "test")], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
