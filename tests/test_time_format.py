import unittest

from app import format_scan_timestamp


class TestTimestampDisplay(unittest.TestCase):
    def test_iso_utc_is_shown_in_bahrain_time(self):
        shown = format_scan_timestamp("2026-10-01T22:22:20.935124+00:00")

        self.assertEqual(shown, "02 Oct 2026, 01:22 AM AST")

    def test_offset_is_converted_to_bahrain_before_labeling(self):
        shown = format_scan_timestamp("2026-10-01T23:22:20+03:00")

        self.assertEqual(shown, "01 Oct 2026, 11:22 PM AST")

    def test_missing_and_invalid_timestamps_do_not_crash(self):
        self.assertEqual(format_scan_timestamp(None), "Unknown time")
        self.assertEqual(format_scan_timestamp(""), "Unknown time")
        self.assertEqual(format_scan_timestamp("not-a-date"), "Unknown time")
