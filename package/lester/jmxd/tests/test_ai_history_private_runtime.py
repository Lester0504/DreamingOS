from pathlib import Path
import subprocess
import tempfile
import apd_test_deps

def test_private_history():
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='ai-private-history-') as tmp:
        binary = str(Path(tmp) / 'fixture')
        subprocess.run(['cc', '-std=c11', '-D_DARWIN_C_SOURCE', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra', str(here / 'ai_history_private_fixture.c'), '-o', binary, *apd_test_deps.package_flags('json-c'), *apd_test_deps.package_flags('sqlite3')], check=True)
        subprocess.run([binary], check=True)

if __name__ == '__main__':
    test_private_history()
