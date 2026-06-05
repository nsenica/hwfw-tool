Huawei ONT HG8120C upgrade file repack tool (Python 3 port)
==========

Tools for working with Huawei ONT HG8120C firmware upgrade files. It can unpack
an upgrade file and repack it after your modifications. The repacking process
recalculates the checksums so the result can be flashed to the device safely.
It may also work for other devices in the HG8xxx series, but those are untested.

> **This is a Python 3 port** of [LeeXiaolan/hwfw-tool](https://github.com/LeeXiaolan/hwfw-tool)
> (Copyright © 2016 Xiaolan.Lee, GPLv2). The upstream tool is Python 2 only and
> has been unmaintained since 2016. The behaviour and CLI are unchanged.

Requirements
---------

- Python 3
- [`docopt`](https://pypi.org/project/docopt/) — `pip install docopt`

Usage
---------

1. `./hwfw.py unpack -r fw test/upgrade.bin`

		saving   /var/UpgradeCheck.xml(1069)...
		saving   /mnt/jffs2/equipment.tar.gz(84238)...
		saving   /mnt/jffs2/ProductLineMode(1)...
		saving   /mnt/jffs2/TelnetEnable(1)...
		saving x /tmp/duit9rr.sh(4801)...
		saving   /var/efs(68)...

2. Modify the files of interest under the `fw` directory.

		A file marked with an `x` is executed with `root` permission on the device.

3. `./hwfw.py pack -r fw upgrade-mod.bin`
4. Happy upgrading or pwning.

About `test/upgrade.bin`
------------------------
This is not a real firmware upgrade file — it is only used to enable
maintenance. So you are safe to use it without worrying about bricking your
device, unless your own modifications do so.

Changes in this port
------------------------

- Ported to Python 3 (`print_function`, `xrange`/`range`, `bytes` handling).
- Fixed checksum packing so repacked headers are valid under Python 3 — upstream
  relied on Python 2's signed `zlib.crc32`/`socket.htonl` return values.
