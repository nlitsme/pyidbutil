IDBTOOL
=======

A tool for extracting information from IDA databases.
`idbtool` knows how to handle databases from all IDA versions since v2.0, both `i64` and `idb` files.
You can also use `idbtool` to recover information from unclosed databases.

Usage
=====

Usage: 

    idbtool [options] [database file(s)]

 * `--names`  will list all named values in the database.
 * `--scripts` will list all scripts stored in the database.
 * `--structs` will list all structs stored in the database.
 * `--imports` will list all imported symbols from the database
 * `--enums` will list all enums stored in the database.
 * `--info` will print some general info about the database. 

query
-----

Queries need to be specified last on the commandline.

example:

    idbtool [database file(s)]  --query  "Root Node;V"

Will list the source binary for all the databases specified on the commandline.

a full database dump
--------------------

Several methods exist for printing all records in the database. This may be useful if
you want to investigate more of IDA''s internals. But can also be useful in recovering
data from corrupted databases.

 * `--inc`, `--dec` can be used to enumerate all b-tree nodes in either forward, or backward direction.
    * add `-v` to get a prettier key/value output
 * `--id0`  walks the page tree, instead of the node tree, printing the contents of each page
 * `--pagedump` linearly skip through the file, this will also reveal information in deleted pages.

naked files
===========

When IDA or your computer crashed while working on a disassembly, and you did not yet save the database,
you are left with a couple of files with extensions like `.id0`, `.id1`, `.nam`, etc.

These files are the unpacked database, i call them `naked` files.

Using the `--filetype` and `--i64` or `--i32` options you can inspect these `naked` files individually.
or use the `--recover` option to view them as a complete database together.
`idbtool` will figure out automatically which files would belong together.

`idbtool` can figure out the bitsize of the database from an `.id0` file, but not(yet) from the others.




stack frames
============

stored in structs named like this:

    "$ fr[0-9a-f]+"           -- M
    "$ fr[0-9a-f]+. r"
    "$ fr[0-9a-f]+. s"
    "$ fr[0-9a-f]+.<varname>" -- S
    
    "$ F[0-9A-F]+"  with the same format
           ". r", ". s", ".<varname>"


TODO
====

 * I plan to publish a c++ version of this library soon.
 * add option to list all comments stored in the database

Author
======

Willem Hengeveld <itsme@xs4all.nl>

