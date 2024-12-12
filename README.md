# Example

```
python3 ida_migrate_9.py /xx/yy/zz/myplugin/                                                                                                                                                                                                                                                                                10:08:29

Warnings for /xxx/../ida_helpers.py:
Line 271: Function 'idautils.StructMembers' signature changed in IDA 9.0
Old: StructMembers(sid) -> [(offset, name, size)]
New: StructMembers(sid) -> [(offset_in_bytes, name, size_in_bytes)]
Line 324: Function 'idautils.StructMembers' signature changed in IDA 9.0
Old: StructMembers(sid) -> [(offset, name, size)]
New: StructMembers(sid) -> [(offset_in_bytes, name, size_in_bytes)]
Line 163: Function 'ida_typeinf.get_ordinal_qty' was removed in IDA 9.0. Use ida_typeinf.get_ordinal_count or ida_typeinf.get_ordinal_limit instead
Line 275: Function 'get_struc' was removed in IDA 9.0. See documentation for example implementation
Line 276: Function 'get_member' was removed in IDA 9.0. See documentation for example implementation
Line 328: Function 'get_struc' was removed in IDA 9.0. See documentation for example implementation
Line 329: Function 'get_member' was removed in IDA 9.0. See documentation for example implementation
Line 180: Function 'idautils.StructMembers' signature changed in IDA 9.0
Old: StructMembers(sid) -> [(offset, name, size)]
New: StructMembers(sid) -> [(offset_in_bytes, name, size_in_bytes)]
```
