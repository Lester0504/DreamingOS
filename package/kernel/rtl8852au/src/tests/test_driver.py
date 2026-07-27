#!/usr/bin/env python3
"""
RTL8852AU Driver Test Suite
Verifies that the out-of-tree RTL8852AU WiFi driver works correctly
on the current system.

Run as root: sudo python3 tests/test_driver.py
"""

import subprocess
import os
import sys
import time
import re
import json
import unittest
import glob
import signal

MODULE_NAME = "8852au"
MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), f"{MODULE_NAME}.ko")
DRIVER_NAME = "rtl8852au"
EXPECTED_CHIP_ID = 0x50  # RTL8852A


def run(cmd, timeout=30, check=False):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd}\n{r.stderr}")
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def is_root():
    return os.geteuid() == 0


def get_wlan_interface():
    """Find the wlan interface bound to our driver."""
    for iface_dir in glob.glob("/sys/class/net/wlan*"):
        iface = os.path.basename(iface_dir)
        driver_link = os.path.join(iface_dir, "device", "driver")
        if os.path.islink(driver_link):
            target = os.readlink(driver_link)
            if DRIVER_NAME in target:
                return iface
    return None


def module_loaded():
    """Check if the 8852au module is loaded."""
    rc, out, _ = run(f"lsmod | grep -w {MODULE_NAME}")
    return rc == 0 and MODULE_NAME in out


class TestModuleBasics(unittest.TestCase):
    """Test 1: Module load/unload and basic registration."""

    def test_01_module_file_exists(self):
        """Verify the compiled .ko file exists."""
        self.assertTrue(os.path.isfile(MODULE_PATH),
                        f"Module file not found: {MODULE_PATH}")

    def test_02_module_info(self):
        """Verify modinfo reports correct metadata."""
        rc, out, _ = run(f"modinfo {MODULE_PATH}")
        self.assertEqual(rc, 0, "modinfo failed")
        self.assertIn("rtl8852au", out.lower(),
                       "Driver name not found in modinfo")
        self.assertIn("vermagic:", out, "No vermagic in modinfo")
        # Verify kernel version matches
        rc2, kver, _ = run("uname -r")
        self.assertIn(kver, out,
                       f"Module vermagic doesn't match kernel {kver}")

    def test_03_module_is_loaded(self):
        """Verify module is currently loaded."""
        self.assertTrue(module_loaded(),
                        f"Module {MODULE_NAME} is not loaded")

    def test_04_module_srcversion_matches(self):
        """Verify loaded module matches our built .ko file."""
        rc1, built_src, _ = run(f"modinfo -F srcversion {MODULE_PATH}")
        self.assertEqual(rc1, 0)
        loaded_src_path = f"/sys/module/{MODULE_NAME}/srcversion"
        self.assertTrue(os.path.exists(loaded_src_path),
                        "Module srcversion sysfs entry not found")
        with open(loaded_src_path) as f:
            loaded_src = f.read().strip()
        self.assertEqual(built_src, loaded_src,
                         f"srcversion mismatch: built={built_src} loaded={loaded_src}")

    def test_05_driver_registered(self):
        """Verify USB driver is registered."""
        driver_dir = f"/sys/bus/usb/drivers/{DRIVER_NAME}"
        self.assertTrue(os.path.isdir(driver_dir),
                        f"Driver {DRIVER_NAME} not registered in sysfs")


class TestDeviceBinding(unittest.TestCase):
    """Test 2: Device binding and interface creation."""

    def setUp(self):
        self.iface = get_wlan_interface()

    def test_01_device_bound(self):
        """Verify at least one USB device is bound to our driver."""
        driver_dir = f"/sys/bus/usb/drivers/{DRIVER_NAME}"
        bound = [f for f in os.listdir(driver_dir)
                 if re.match(r'\d+-\d+:\d+\.\d+', f)]
        self.assertGreater(len(bound), 0,
                           "No USB devices bound to driver")

    def test_02_wlan_interface_exists(self):
        """Verify a wlan interface was created for the device."""
        self.assertIsNotNone(self.iface,
                             f"No wlan interface found for {DRIVER_NAME}")

    def test_03_interface_has_mac(self):
        """Verify interface has a valid MAC address."""
        self.assertIsNotNone(self.iface)
        rc, out, _ = run(f"cat /sys/class/net/{self.iface}/address")
        self.assertEqual(rc, 0)
        mac = out.strip()
        self.assertRegex(mac, r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$',
                         f"Invalid MAC: {mac}")
        self.assertNotEqual(mac, "00:00:00:00:00:00", "MAC is all zeros")

    def test_04_interface_mtu(self):
        """Verify MTU is set to a reasonable value."""
        self.assertIsNotNone(self.iface)
        with open(f"/sys/class/net/{self.iface}/mtu") as f:
            mtu = int(f.read().strip())
        self.assertGreaterEqual(mtu, 1500, f"MTU too low: {mtu}")

    def test_05_interface_operstate(self):
        """Verify interface has a valid operational state."""
        self.assertIsNotNone(self.iface)
        with open(f"/sys/class/net/{self.iface}/operstate") as f:
            state = f.read().strip()
        self.assertIn(state, ["up", "down", "dormant", "unknown"],
                      f"Unexpected operstate: {state}")


class TestInterfaceUp(unittest.TestCase):
    """Test 3: Interface can be brought up and down."""

    def setUp(self):
        self.iface = get_wlan_interface()
        if not self.iface:
            self.skipTest("No wlan interface found")

    def test_01_bring_up(self):
        """Verify interface can be brought up."""
        rc, _, err = run(f"ip link set {self.iface} up")
        self.assertEqual(rc, 0, f"Failed to bring up {self.iface}: {err}")
        time.sleep(1)
        with open(f"/sys/class/net/{self.iface}/flags") as f:
            flags = int(f.read().strip(), 16)
        self.assertTrue(flags & 0x1, "IFF_UP flag not set")

    def test_02_bring_down_up(self):
        """Verify interface can be cycled down and up."""
        rc, _, err = run(f"ip link set {self.iface} down")
        self.assertEqual(rc, 0, f"Failed to bring down: {err}")
        time.sleep(1)
        rc, _, err = run(f"ip link set {self.iface} up")
        self.assertEqual(rc, 0, f"Failed to bring back up: {err}")
        time.sleep(1)


class TestWiFiScan(unittest.TestCase):
    """Test 4: WiFi scanning capability."""

    def setUp(self):
        self.iface = get_wlan_interface()
        if not self.iface:
            self.skipTest("No wlan interface found")
        run(f"ip link set {self.iface} up")
        time.sleep(1)

    def test_01_iw_scan_trigger(self):
        """Verify scan can be triggered via iw."""
        # May need to disconnect first
        rc, out, err = run(f"iw dev {self.iface} scan trigger", timeout=10)
        # Allow -EBUSY (rc=240) if already scanning
        self.assertIn(rc, [0, 240],
                      f"Scan trigger failed: rc={rc} err={err}")

    def test_02_iw_scan_results(self):
        """Verify scan returns results."""
        # Trigger and wait
        run(f"iw dev {self.iface} scan trigger", timeout=10)
        time.sleep(5)
        rc, out, err = run(f"iw dev {self.iface} scan dump", timeout=15)
        self.assertEqual(rc, 0, f"Scan dump failed: {err}")
        # Check for at least one BSS
        bss_count = out.count("BSS ")
        self.assertGreater(bss_count, 0,
                           "No access points found in scan results")

    def test_03_supported_bands(self):
        """Verify driver reports supported frequency bands."""
        rc, out, _ = run(f"iw phy")
        self.assertEqual(rc, 0)
        # RTL8852AU should support 2.4GHz and 5GHz
        has_2g = "2412 MHz" in out or "Band 1" in out
        has_5g = "5180 MHz" in out or "Band 2" in out
        self.assertTrue(has_2g, "2.4GHz band not reported")
        self.assertTrue(has_5g, "5GHz band not reported")


class TestCfg80211(unittest.TestCase):
    """Test 5: cfg80211/nl80211 interface."""

    def setUp(self):
        self.iface = get_wlan_interface()
        if not self.iface:
            self.skipTest("No wlan interface found")

    def test_01_iw_info(self):
        """Verify iw can query interface info."""
        rc, out, err = run(f"iw dev {self.iface} info")
        self.assertEqual(rc, 0, f"iw dev info failed: {err}")
        self.assertIn(self.iface, out)
        self.assertIn("type", out)

    def test_02_phy_info(self):
        """Verify phy info is available."""
        # Get phy name for our interface
        rc, out, _ = run(f"iw dev {self.iface} info")
        match = re.search(r'wiphy (\d+)', out)
        if not match:
            self.skipTest("Could not determine wiphy")
        phy_idx = match.group(1)
        rc, out, _ = run(f"iw phy phy{phy_idx} info")
        self.assertEqual(rc, 0)
        self.assertIn("Capabilities:", out)

    def test_03_interface_modes(self):
        """Verify supported interface modes include managed."""
        rc, out, _ = run(f"iw phy")
        self.assertEqual(rc, 0)
        self.assertIn("managed", out.lower(),
                       "Managed mode not supported")

    def test_04_station_dump(self):
        """Verify station dump command works (even if empty)."""
        rc, out, err = run(f"iw dev {self.iface} station dump")
        self.assertEqual(rc, 0,
                         f"Station dump failed: {err}")


class TestProcFS(unittest.TestCase):
    """Test 6: /proc interface."""

    def test_01_proc_entry_exists(self):
        """Verify proc entry for the driver exists."""
        proc_dirs = glob.glob("/proc/net/rtw_*")
        # It's ok if proc isn't enabled
        if not proc_dirs:
            self.skipTest("No /proc/net/rtw_* entries (proc may be disabled)")
        self.assertGreater(len(proc_dirs), 0)


class TestUSBEndpoints(unittest.TestCase):
    """Test 7: USB endpoint verification."""

    def setUp(self):
        self.iface = get_wlan_interface()
        if not self.iface:
            self.skipTest("No wlan interface found")
        # Get USB device path
        dev_path = os.path.realpath(f"/sys/class/net/{self.iface}/device")
        self.usb_path = dev_path

    def test_01_usb_speed(self):
        """Verify USB speed is high-speed or super-speed."""
        parent = os.path.dirname(self.usb_path)
        speed_file = os.path.join(parent, "speed")
        if os.path.exists(speed_file):
            with open(speed_file) as f:
                speed = int(f.read().strip())
            self.assertGreaterEqual(speed, 480,
                                    f"USB speed too low: {speed} Mbps")

    def test_02_usb_endpoints(self):
        """Verify USB endpoints are present."""
        ep_dirs = glob.glob(os.path.join(self.usb_path, "ep_*"))
        # Should have at least bulk in + bulk out
        self.assertGreaterEqual(len(ep_dirs), 2,
                                f"Too few endpoints: {len(ep_dirs)}")


class TestDmesgClean(unittest.TestCase):
    """Test 8: Kernel log check for errors."""

    def test_01_no_kernel_errors(self):
        """Verify no kernel errors/warnings related to our driver."""
        rc, out, _ = run("dmesg")
        if rc != 0:
            self.skipTest("Cannot read dmesg (need root?)")
        lines = out.split('\n')
        errors = []
        for line in lines:
            lower = line.lower()
            if DRIVER_NAME in lower or MODULE_NAME in lower:
                if any(w in lower for w in ['error', 'bug', 'oops', 'panic',
                                             'null pointer', 'unable to handle',
                                             'general protection fault']):
                    errors.append(line.strip())
        self.assertEqual(len(errors), 0,
                         f"Kernel errors found:\n" + "\n".join(errors))

    def test_02_no_usb_errors(self):
        """Check for USB-related errors on our device."""
        iface = get_wlan_interface()
        if not iface:
            self.skipTest("No wlan interface")
        rc, out, _ = run("dmesg")
        lines = out.split('\n')
        usb_errors = []
        for line in lines:
            lower = line.lower()
            if 'usb' in lower and any(w in lower for w in
                    ['disconnect', 'reset', 'error', 'timeout']):
                # Filter for our driver
                if DRIVER_NAME in lower or MODULE_NAME in lower:
                    usb_errors.append(line.strip())
        # Warn but don't fail for minor USB issues
        if usb_errors:
            print(f"\nWARNING: USB issues detected:\n" +
                  "\n".join(usb_errors[:5]))


class TestModuleReload(unittest.TestCase):
    """Test 9: Module unload/reload stability."""

    @unittest.skipUnless(is_root(), "Requires root")
    def test_01_reload_module(self):
        """Verify module can be unloaded and reloaded cleanly."""
        iface_before = get_wlan_interface()

        # Unload
        rc, _, err = run(f"rmmod {MODULE_NAME}", timeout=15)
        self.assertEqual(rc, 0, f"rmmod failed: {err}")
        time.sleep(2)

        self.assertFalse(module_loaded(), "Module still loaded after rmmod")

        # Reload
        rc, _, err = run(f"insmod {MODULE_PATH}", timeout=15)
        self.assertEqual(rc, 0, f"insmod failed: {err}")
        time.sleep(3)

        self.assertTrue(module_loaded(), "Module not loaded after insmod")

        # Verify interface comes back
        iface_after = get_wlan_interface()
        self.assertIsNotNone(iface_after,
                             "Interface not recreated after reload")


class TestStability(unittest.TestCase):
    """Test 10: Basic stability tests."""

    def setUp(self):
        self.iface = get_wlan_interface()
        if not self.iface:
            self.skipTest("No wlan interface found")

    def test_01_rapid_ifup_ifdown(self):
        """Stress test: rapidly toggle interface 10 times."""
        for i in range(10):
            run(f"ip link set {self.iface} down")
            time.sleep(0.2)
            run(f"ip link set {self.iface} up")
            time.sleep(0.2)

        # Verify interface still works
        time.sleep(1)
        rc, out, _ = run(f"iw dev {self.iface} info")
        self.assertEqual(rc, 0, "Interface broken after rapid toggle")

    def test_02_multiple_scan_triggers(self):
        """Stress test: trigger multiple scans in succession."""
        run(f"ip link set {self.iface} up")
        time.sleep(1)
        for i in range(5):
            run(f"iw dev {self.iface} scan trigger")
            time.sleep(1)
        # Verify scan dump still works
        rc, out, _ = run(f"iw dev {self.iface} scan dump", timeout=15)
        self.assertEqual(rc, 0, "Scan dump failed after multiple triggers")


def generate_report(result):
    """Generate a JSON test report."""
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "module": MODULE_NAME,
        "driver": DRIVER_NAME,
        "kernel": subprocess.getoutput("uname -r"),
        "total": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "details": []
    }

    for test, traceback in result.failures:
        report["details"].append({
            "test": str(test),
            "status": "FAILED",
            "message": traceback
        })
    for test, traceback in result.errors:
        report["details"].append({
            "test": str(test),
            "status": "ERROR",
            "message": traceback
        })
    for test, reason in result.skipped:
        report["details"].append({
            "test": str(test),
            "status": "SKIPPED",
            "message": reason
        })

    return report


if __name__ == "__main__":
    if not is_root():
        print("WARNING: Some tests require root privileges. Run with sudo for full coverage.")

    # Run tests with verbosity
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Generate report
    report = generate_report(result)
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to: {report_path}")
    print(f"Total: {report['total']} | Passed: {report['passed']} | "
          f"Failed: {report['failed']} | Errors: {report['errors']} | "
          f"Skipped: {report['skipped']}")

    sys.exit(0 if result.wasSuccessful() else 1)
