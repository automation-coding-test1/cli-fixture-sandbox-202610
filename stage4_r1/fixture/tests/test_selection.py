"""Public-only deterministic contract; no repositories, credentials, or network."""
import unittest
from src.selection import parse_selection

class SelectionContract(unittest.TestCase):
    def test_one_number(self):
        self.assertEqual(parse_selection("4"), [4])

    def test_csv_simple(self):
        self.assertEqual(parse_selection("1,3"), [1, 3])

    def test_inclusive_range(self):
        self.assertEqual(parse_selection("2-4"), [2, 3, 4])

    def test_whitespace_range(self):
        self.assertEqual(parse_selection(" 3 - 4 , 1 "), [1, 3, 4])

    def test_dedupe_and_sort(self):
        self.assertEqual(parse_selection("4,1-2,4,2"), [1, 2, 4])

    def test_reversed_range_rejected(self):
        with self.assertRaises(ValueError):
            parse_selection("8-6")

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            parse_selection("-2")

    def test_junk_rejected(self):
        with self.assertRaises(ValueError):
            parse_selection("3,nope")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            parse_selection("")

if __name__ == "__main__":
    unittest.main()
