"""Source readers for the physically split jmx_netconfig_db translation unit.

The production shell includes its fragments into one C translation unit.  Tests
that inspect the old monolith must inspect that same logical source, otherwise
they silently stop covering implementation after the physical split.
"""

from pathlib import Path
import re


_INCLUDE = re.compile(r'^#include "netconfig/([^"]+)"$', re.MULTILINE)


def netconfig_source_text(main: Path) -> str:
    """Return the source text fed to C after the shell expands its fragments."""
    shell = main.read_text(encoding="utf-8")
    names = _INCLUDE.findall(shell)
    if not names:
        return shell
    first = shell.index(f'#include "netconfig/{names[0]}"')
    result = shell[:first] + "".join(
        (main.parent / "netconfig" / name).read_text(encoding="utf-8")
        for name in names
    )
    return result.replace('#include "009_nc_dhcp_authority.c"',
        (main.parent / "netconfig/009_nc_dhcp_authority.c").read_text(encoding="utf-8")) if (
        '#include "009_nc_dhcp_authority.c"' in result) else result
