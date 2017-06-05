import unittest
from idblib import FileSection, binary_search, makeStringIO


class TestFileSection(unittest.TestCase):
    """ unittest for FileSection object """
    def test_file(self):
        s = makeStringIO(b"0123456789abcdef")
        fh = FileSection(s, 3, 11)
        self.assertEqual(fh.read(3), b"345")
        self.assertEqual(fh.read(8), b"6789a")
        self.assertEqual(fh.read(8), b"")

        fh.seek(-1, 2)
        self.assertEqual(fh.read(8), b"a")
        fh.seek(3)
        self.assertEqual(fh.read(2), b"67")
        fh.seek(-2, 1)
        self.assertEqual(fh.read(2), b"67")
        fh.seek(2, 1)
        self.assertEqual(fh.read(2), b"a")

        fh.seek(8)
        self.assertEqual(fh.read(1), b"")
        with self.assertRaises(Exception):
            fh.seek(9)


class TestBinarySearch(unittest.TestCase):
    """ unittests for binary_search """
    class Object:
        def __init__(self, num):
            self.key = num

        def __repr__(self):
            return "o(%d)" % self.num

    def test_bs(self):
        obj = self.Object
        lst = [obj(_) for _ in (2, 3, 5, 6)]
        self.assertEqual(binary_search(lst, 1), -1)
        self.assertEqual(binary_search(lst, 2), 0)
        self.assertEqual(binary_search(lst, 3), 1)
        self.assertEqual(binary_search(lst, 4), 1)
        self.assertEqual(binary_search(lst, 5), 2)
        self.assertEqual(binary_search(lst, 6), 3)
        self.assertEqual(binary_search(lst, 7), 3)

    def test_emptylist(self):
        obj = self.Object
        lst = []
        self.assertEqual(binary_search(lst, 1), -1)

    def test_oneelem(self):
        obj = self.Object
        lst = [obj(1)]
        self.assertEqual(binary_search(lst, 0), -1)
        self.assertEqual(binary_search(lst, 1), 0)
        self.assertEqual(binary_search(lst, 2), 0)

    def test_twoelem(self):
        obj = self.Object
        lst = [obj(1), obj(3)]
        self.assertEqual(binary_search(lst, 0), -1)
        self.assertEqual(binary_search(lst, 1), 0)
        self.assertEqual(binary_search(lst, 2), 0)
        self.assertEqual(binary_search(lst, 3), 1)
        self.assertEqual(binary_search(lst, 4), 1)

    def test_listsize(self):
        obj = self.Object
        for l in range(3, 32):
            lst = [obj(_ + 1) for _ in range(l)]
            lst = lst[:1] + lst[2:]
            self.assertEqual(binary_search(lst, 0), -1)
            self.assertEqual(binary_search(lst, 1), 0)
            self.assertEqual(binary_search(lst, 2), 0)
            self.assertEqual(binary_search(lst, 3), 1)
            self.assertEqual(binary_search(lst, l - 1), l - 3)
            self.assertEqual(binary_search(lst, l), l - 2)
            self.assertEqual(binary_search(lst, l + 1), l - 2)
            self.assertEqual(binary_search(lst, l + 2), l - 2)
