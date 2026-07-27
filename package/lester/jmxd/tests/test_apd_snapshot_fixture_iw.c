// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "dev") != 0)
        return 2;
    fputs(
        "phy#1\n"
        "\tInterface wlan1\n"
        "\t\tifindex 12\n"
        "\t\twdev 0x100000001\n"
        "\t\taddr 02:00:00:00:01:01\n"
        "\t\tssid Phase1-5G\n"
        "\t\ttype AP\n"
        "\t\tchannel 149 (5745 MHz), width: 80 MHz, center1: 5775 MHz\n"
        "\t\ttxpower 23.00 dBm\n"
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tifindex 11\n"
        "\t\twdev 0x1\n"
        "\t\taddr 02:00:00:00:00:01\n"
        "\t\tssid Phase1-2G\n"
        "\t\ttype AP\n"
        "\t\tchannel 6 (2437 MHz), width: 40 MHz, center1: 2447 MHz\n"
        "\t\ttxpower 20.00 dBm\n",
        stdout);
    return ferror(stdout) ? 1 : 0;
}
