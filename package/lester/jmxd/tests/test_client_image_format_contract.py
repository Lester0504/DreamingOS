#!/usr/bin/env python3
"""Device image responses must name their format.

A user-uploaded device icon may be SVG (webd accepts image/svg+xml), and a
client with no vector rasteriser cannot decode it: Android's
BitmapFactory.decodeByteArray returns null, which is indistinguishable from a
missing image, so the UI silently shows a placeholder. iOS had to add its own
rasterisation pass. Naming the format lets a client tell "cannot decode this
format" apart from "no image" before it even fetches the bytes.

The classifier is duplicated between core (jmx_db.c) and webd (jmx_app_api.c)
because they are separate translation units. Divergence between the two is the
realistic failure here, so it is asserted directly.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
DB = (ROOT / "src/jmx_db.c").read_text(encoding="utf-8")
API = webd_dispatch_text()

KNOWN = (("png", "png"), ("jpg", "jpeg"), ("jpeg", "jpeg"),
         ("webp", "webp"), ("gif", "gif"), ("svg", "svg"))
BITMAP = ("png", "jpeg", "webp", "gif")


def _function(text: str, name: str) -> str:
    match = re.search(r"^[a-z ]*(?:const char \*|int )" + name + r"\(.*?^\}",
                      text, re.S | re.M)
    assert match, f"{name}() not found"
    return match.group(0)


def test_both_translation_units_agree_on_the_mapping() -> None:
    """The two copies must classify every extension identically."""
    core = _function(DB, "db_image_format_of")
    web = _function(API, "webd_image_format_of")

    def mapping(body: str) -> list[tuple[str, str]]:
        return re.findall(r'strcasecmp\(dot, "\.(\w+)"\)\) return "(\w+)"', body)

    # The jpg/jpeg pair shares one return, so compare as sets of what is handled.
    def handled(body: str) -> set[str]:
        return set(re.findall(r'strcasecmp\(dot, "\.(\w+)"\)', body))

    assert handled(core) == handled(web), (
        f"extension coverage diverged: core={handled(core)} web={handled(web)}")
    assert handled(core) == {ext for ext, _ in KNOWN}
    assert mapping(core) == mapping(web), "format labels diverged between copies"

    core_bitmap = _function(DB, "db_image_format_is_bitmap")
    web_bitmap = _function(API, "webd_image_format_is_bitmap")
    formats = lambda body: set(re.findall(r'strcmp\(format, "(\w+)"\)', body))
    assert formats(core_bitmap) == formats(web_bitmap) == set(BITMAP), (
        "bitmap sets diverged; svg must never be listed as a bitmap")
    assert "svg" not in formats(core_bitmap)


def test_clients_list_emits_format_beside_the_image() -> None:
    """/api/v1/clients resolves one image for the row; format rides along."""
    assert 'json_object_object_add(o, "image_format"' in DB
    assert 'json_object_object_add(o, "image_is_bitmap"' in DB
    # The fingerprint sub-object describes the detected image, not the effective
    # one, so it must be classified from `detected`.
    assert 'json_object_object_add(fp, "image_format",\n' \
           '                               json_object_new_string(db_image_format_of(detected)));' in DB


def test_client_profile_basic_and_upload_both_report_format() -> None:
    assert 'webd_obj_add_str(basic, "image_format", webd_image_format_of(image));' in API, \
        "client_profile.basic builds its own image fields and must not omit format"
    assert 'json_object_object_add(basic, "image_is_bitmap"' in API
    # Upload reply: classify from the saved URL, not from `ext`, so a JPEG is
    # reported as "jpeg" here and by the read paths rather than "jpg".
    assert "const char *image_format = webd_image_format_of(url);" in API
    assert 'json_object_object_add(resp, "image_format"' in API
    assert 'json_object_object_add(data, "image_format"' in API
    assert 'json_object_object_add(resp, "image_format", json_object_new_string(ext))' not in API


def test_svg_upload_is_still_accepted() -> None:
    """This change reports the format; it does not start rejecting SVG.

    Rejecting would break the LuCI web UI, which can display SVG perfectly well,
    and would discard icons users already uploaded.
    """
    assert 'if (!strcmp(main_mime, "image/svg+xml")) {' in API
    assert '"unsupported_image_type"' in API


def test_compiled_classifier_behaviour() -> None:
    """Compile the real core helpers and check every case, including oddities."""
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "a C compiler is required for this contract"

    harness = (
        # strcasecmp() is declared in <strings.h>, not <string.h>. glibc only
        # exposes it via <string.h> under _GNU_SOURCE, so omitting this header
        # compiled on macOS and failed on Linux with an implicit-declaration
        # error under -Werror. Include both rather than relaxing -Werror.
        "#include <stdio.h>\n#include <string.h>\n#include <strings.h>\n\n"
        + _function(DB, "db_image_format_of") + "\n\n"
        + _function(DB, "db_image_format_is_bitmap") + "\n\n"
        "struct expectation { const char *url; const char *format; int bitmap; };\n"
        "int main(void)\n"
        "{\n"
        "    struct expectation cases[] = {\n"
        "        { \"/a/b/257x257.png\", \"png\", 1 },\n"
        "        { \"/uploads/clients/aabbccddeeff.svg\", \"svg\", 0 },\n"
        "        { \"/x/y.JPG\", \"jpeg\", 1 },\n"
        "        { \"/x/y.jpeg\", \"jpeg\", 1 },\n"
        "        { \"/x/y.WebP\", \"webp\", 1 },\n"
        "        { \"/x/y.gif\", \"gif\", 1 },\n"
        "        { \"\", \"\", 0 },\n"
        "        { \"/no-extension\", \"unknown\", 0 },\n"
        "        { \"/x/y.bmp\", \"unknown\", 0 },\n"
        "        { \"/dir.png/file\", \"unknown\", 0 },\n"
        "    };\n"
        "    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {\n"
        "        const char *got = db_image_format_of(cases[i].url);\n"
        "        int bitmap = db_image_format_is_bitmap(got);\n"
        "        if (strcmp(got, cases[i].format) || bitmap != cases[i].bitmap) {\n"
        "            fprintf(stderr, \"case %u (%s): got %s bitmap=%d\\n\",\n"
        "                    i, cases[i].url, got, bitmap);\n"
        "            return 1;\n"
        "        }\n"
        "    }\n"
        "    if (db_image_format_of(0)[0]) {\n"
        "        fputs(\"NULL must classify as empty\\n\", stderr);\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n")

    with tempfile.TemporaryDirectory(prefix="image-format-") as raw:
        temporary = Path(raw)
        source = temporary / "contract.c"
        binary = temporary / "contract"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} client image format contracts")
