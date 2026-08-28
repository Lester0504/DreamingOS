#!/bin/sh
set -eu

if [ -n "${DREAMINGWRT_TARGET_ROOT:-}" ]; then
    export STORAGE_TEST_JSON_C_ROOT="$DREAMINGWRT_TARGET_ROOT/usr"
    export STORAGE_FILES_TEST_JSON_C_ROOT="$DREAMINGWRT_TARGET_ROOT/usr"
fi

python3 tests/test_storage_file_services_backend_contract.py
python3 tests/test_storage_overview_backend_contract.py
python3 tests/test_storage_blockdev_extents_runtime.py
python3 tests/test_storage_files_backend_contract.py
python3 tests/test_storage_files_runtime.py
python3 tests/test_vpn_management_backend_contract.py
python3 tests/test_vpn_management_runtime.py
python3 tests/test_vpn_transaction_runtime.py
