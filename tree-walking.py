"""
Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>

Experiment in btree walking


                   *-------->[00]
         *------>[02]---+    [01]
root ->[08]---+  [05]-+ |
       [17]-+ |       | +--->[03]
            | |       |      [04]
            | |       |
            | |       +----->[06]
            | |              [07]
            | |
            | |    *-------->[09]
            | +->[11]---+    [10]
            |    [14]-+ |
            |         | +--->[12]
            |         |      [13]
            |         |
            |         +----->[15]
            |                [16]
            |
            |      *-------->[18]
            +--->[20]---+    [19]
                 [23]-+ |
                      | +--->[21]
                      |      [22]
                      |
                      +----->[24]
                             [25]


decrement from 08 : ix-- -> getpage, ix=len-1 -> getpage -> ix=len-1
decrement from 17 : ix-- -> getpage, ix=len-1 -> getpage -> ix=len-1
decrement from 02 : ix-- -> getpage, ix=len-1
decrement from 05 : ix-- -> getpage, ix=len-1

decrement from 01  : ix-- -> ix>=0 -> use key at ix
decrement from 03  : ix-- -> <0 -> pop -> ix>=0 -> use key at ix
decrement from 09  : ix-- -> <0 -> pop -> ix<0 -> pop -> ix>=0 -> use key at ix

increment from 09  : ix++
increment from 10  : ix++  -> ix==len(index)  -> pop: ix==-1  -> ix++ -> ix==0  -> use
increment from 11  : recurse, ix=0  -> use
increment from 08  : recurse, ix=-1 -> recurse, ix=0 -> use
increment from 07  : ix++ -> ix==len(index) -> pop,    ix++ -> ix==len -> pop -> ix++ -> ix==0 -> use
"""
from __future__ import division, print_function, absolute_import, unicode_literals

# shape of the tree
# a <2,2>  tree is basically like the tree pictured in the ascii art above.
TREEDEPTH = 2
NODEWIDTH = 2


def binary_search(a, k):
    # c++: a.upperbound(k)--
    first, last = 0, len(a)
    while first < last:
        mid = (first + last) >> 1
        if k < a[mid].key:
            last = mid
        else:
            first = mid + 1
    return first - 1


class Entry(object):
    """
    a key/value entry from a b-tree page
    """
    def __init__(self, key, val):
        self.key = key
        self.val = val

    def __repr__(self):
        return "%s=%d" % (self.key, self.val)


class BasePage(object):
    """
    BasePage has methods common to both leaf and index pages
    """
    def __init__(self, kv):
        self.index = []
        for k, v in kv:
            self.index.append(Entry(k, v))

    def find(self, key):
        i = binary_search(self.index, key)
        if i < 0:
            if self.isindex():
                return ('recurse', -1)
            return ('gt', 0)
        if self.index[i].key == key:
            return ('eq', i)
        if self.isindex():
            return ('recurse', i)
        return ('lt', i)

    def getkey(self, ix):
        return self.index[ix].key

    def getval(self, ix):
        return self.index[ix].val

    def isleaf(self):
        return self.preceeding is None

    def isindex(self):
        return self.preceeding is not None

    def __repr__(self):
        return ("leaf" if self.isleaf() else ("index<%d>" % self.preceeding)) + repr(self.index)


class LeafPage(BasePage):
    """ a leaf page in the b-tree """
    def __init__(self, kv):
        super(self.__class__, self).__init__(kv)
        self.preceeding = None


class IndexPage(BasePage):
    """
    An index page in the b-tree.
    This page has a preceeding page plus several key+subpage pairs.
    For each key+subpage: all keys in the subpage are greater than the key
    """
    def __init__(self, preceeding, kv):
        super(self.__class__, self).__init__(kv)
        self.preceeding = preceeding

    def getpage(self, ix):
        return self.preceeding if ix < 0 else self.index[ix].val


class Cursor:
    """
    A Cursor object represents a position in the b-tree.

    It has methods for moving to the next or previous item.
    And methods for retrieving the key and value of the current position
    """
    def __init__(self, db, stack):
        self.db = db
        self.stack = stack

    def next(self):
        page, ix = self.stack.pop()
        if page.isleaf():
            # from leaf move towards root
            ix += 1
            while self.stack and ix == len(page.index):
                page, ix = self.stack.pop()
                ix += 1
            if ix < len(page.index):
                self.stack.append((page, ix))
        else:
            # from node move towards leaf
            self.stack.append((page, ix))
            page = self.db.readpage(page.getpage(ix))
            while page.isindex():
                ix = -1
                self.stack.append((page, ix))
                page = self.db.readpage(page.getpage(ix))
            ix = 0
            self.stack.append((page, ix))

        self.verify()

    def prev(self):
        page, ix = self.stack.pop()
        ix -= 1
        if page.isleaf():
            # move towards root, until non 'prec' item found
            while self.stack and ix < 0:
                page, ix = self.stack.pop()
            if ix >= 0:
                self.stack.append((page, ix))
        else:
            # move towards leaf
            self.stack.append((page, ix))
            while page.isindex():
                page = self.db.readpage(page.getpage(ix))
                ix = len(page.index) - 1
                self.stack.append((page, ix))

        self.verify()

    def verify(self):
        """ verify cursor state consistency """
        if len(self.stack) == 3:
            if not self.stack[-1][0].isleaf():
                print("WARN no leaf")
        elif len(self.stack) > 3:
            print("WARN: stack too large")

        if len(self.stack) >= 2:
            if self.stack[0][0] == self.stack[1][0]:
                print("WARN: identical index pages on stack")
            if not self.stack[0][0].isindex():
                print("WARN: expected root=index")
            if not self.stack[1][0].isindex():
                print("WARN: expected 2nd=index")

    def eof(self):
        return len(self.stack) == 0

    def getkey(self):
        page, ix = self.stack[-1]
        return page.getkey(ix)

    def getval(self):
        page, ix = self.stack[-1]
        return page.getval(ix)

    def __repr__(self):
        return "cursor:" + repr(self.stack)


class Btree:
    """
    A B-tree implementation
    """
    def __init__(self):
        self.pages = []
        self.generate(TREEDEPTH, NODEWIDTH)

    def manual(self):
        """ manually construct the ascii art tree """
        for i in range(9):
            self.pages.append(LeafPage((("%02d" % (3 * i), 0), ("%02d" % (3 * i + 1), 0))))
        for i in range(3):
            self.pages.append(IndexPage(3 * i, (("%02d" % (9 * i + 2), 3 * i + 1), ("%02d" % (9 * i + 5), 3 * i + 2))))
        self.pages.append(IndexPage(9, (("08", 10), ("17", 11))))
        self.rootindex = len(self.pages) - 1

    def generate(self, depth, nodesize):
        """ automatically generate the try in the ascii art above """

        def namegen():
            i = 0
            while True:
                yield "%03d" % i
                i += 1

        self.rootindex = self.construct(namegen(), depth, nodesize)
        print("%d pages" % (len(self.pages)))

    def construct(self, namegen, depth, nodesize):
        if depth:
            return self.createindex(namegen, depth, nodesize)
        else:
            return self.createleaf(namegen, nodesize)

    def createindex(self, namegen, depth, nodesize):
        page = IndexPage(self.construct(namegen, depth - 1, nodesize),
                         [(next(namegen), self.construct(namegen, depth - 1, nodesize)) for _ in range(nodesize)])
        self.pages.append(page)
        return len(self.pages) - 1

    def createleaf(self, namegen, nodesize):
        page = LeafPage([(next(namegen), 0) for _ in range(nodesize)])
        self.pages.append(page)
        return len(self.pages) - 1

    def readpage(self, pn):
        return self.pages[pn]

    def find(self, key):
        """
        Find a node in the tree, returns the cursor plus the reletion to the wanted key:
        'eq' for equal, 'lt' when the found key is less than the wanted key,
        or 'gt' when the found key is greater than the wanted key.
        """
        page = self.readpage(self.rootindex)
        stack = []
        while True:
            act, ix = page.find(key)
            stack.append((page, ix))
            if act != 'recurse':
                break
            page = self.readpage(page.getpage(ix))
        return act, Cursor(self, stack)

    def dumptree(self, pn, indent=0):
        """ dump all nodes of the current b-tree """
        page = self.readpage(pn)
        print("  " * indent, page)
        if page.isindex():
            print("  " * indent, end="")
            self.dumptree(page.preceeding, indent + 1)
            for p in range(len(page.index)):
                print("  " * indent, end="")
                self.dumptree(page.getpage(p), indent + 1)


db = Btree()
print("<<")
db.dumptree(db.rootindex)
print(">>")


for i in range(NODEWIDTH * len(db.pages)):
    print("--------- %03d" % i)
    act, cursor = db.find("%03d" % i)
    print("found", act, cursor.getkey(), cursor)
    cursor.prev()
    if not cursor.eof():
        print("prev:", "..", cursor.getkey(), cursor)
    else:
        print("prev:  EOF", cursor)

for i in range(NODEWIDTH * len(db.pages)):
    print("--------- %03d" % i)
    act, cursor = db.find("%03d" % i)
    print("found", act, cursor.getkey(), cursor)
    cursor.next()
    if not cursor.eof():
        print("next:", "..", cursor.getkey(), cursor)
    else:
        print("next:  EOF", cursor)

for k in ('', '0', '1', '2', '3', '000', '010', '020', '100'):
    print("--------- %s" % k)
    act, cursor = db.find(k)
    print(cursor)
    print(act, cursor.getkey(), end=" next=")
    cursor.next()
    if cursor.eof():
        print("EOF")
    else:
        print(cursor.getkey())

act, cursor = db.find("000")
print("get000", end=" ")
for i in range(NODEWIDTH * len(db.pages)):
    cursor.next()
    if cursor.eof():
        print("EOF")
    else:
        print("-> %s" % cursor.getkey(), end=" ")
print()

act, cursor = db.find("025")
print("get025", end=" ")
for i in range(NODEWIDTH * len(db.pages)):
    cursor.prev()
    if cursor.eof():
        print("EOF")
    else:
        print("-> %s" % cursor.getkey(), end=" ")
print()
