#!/usr/bin/env python3
'''
Copyright (C) 2016 Xiaolan.Lee<LeeXiaolan@gmail.com>
License: GPLv2 (see LICENSE for details).
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

import logging
import os
import socket
import struct
import sys
import zlib

import docopt

__opt__ = '''Usage:
  %(prog)s unpack [-v... -r DIR] FILE
  %(prog)s pack [-v... -r DIR] FILE

Options:
  -r DIR, --root           Root directory, unpack to or pack from[default: .].
  -v, --verbose            Verbose mode.
'''

def crc32(data, start=0):
  return zlib.crc32(data, start)

def seqCrc32(seq, start=0):
  for i in seq:
    start = crc32(i, start)
  return start

class HuaweiFirmware(object):
  _HEADER_FILE = '.header'

  def open(self, path, noItemData=False):
    with open(path, 'rb') as f:
      data = f.read()
    self._loadFromString(data, noItemData)

  def _loadFromString(self, data, noItemData):
    mv = memoryview(data)
    offset = 0
    offset += self._parseHeader(data[offset:])
    if self.header.extraHeaderLength:
      offset += self._parseExtraHeader(data[offset:])
    offset += self._parseItemInfo(data, offset, noItemData)

  def _parseHeader(self, data):
    self.header = HuaweiFirmwareHeader()
    return self.header.loadFromString(data)

  def _parseExtraHeader(self, data):
    size = self.header.extraHeaderLength
    self.extraHeader = data[:size]
    return size

  def _parseItemInfo(self, data, offset, noItemData):
    totalLength = len(data)
    initialOffset = offset
    itemDataBegin = initialOffset + self.header.itemCount * HuaweiFirmwareItem._FORMAT.size
    self.items = []
    for i in range(self.header.itemCount):
      item, size = self._parseSingleItemInfo(data[offset:])
      offset += size
      if not noItemData:
        assert item.start >= itemDataBegin, 'Item data underflow.'
        assert item.end <= totalLength, 'Item data end overflow.'
        item.data = data[item.start:item.end]
      self.items.append(item)
    return offset - initialOffset

  def _parseSingleItemInfo(self, data):
    item = HuaweiFirmwareItem()
    size = item.loadInfo(data)
    return (item, size)

  def pack(self, directory, output):
    path = os.path.join(directory, self._HEADER_FILE)
    if not os.path.exists(path):
      logging.error('header file does not exist.')
      return 2
    self.open(path, noItemData=True)
    self.loadItemDataFromFile(directory)
    with open(output, 'wb') as f:
      f.write(self.toString(noItemData=False))

  def loadItemDataFromFile(self, directory):
    offset = (HuaweiFirmwareHeader._FORMAT.size 
        + self.header.extraHeaderLength
        + self.header.itemCount * HuaweiFirmwareItem._FORMAT.size
    )
    for item in self.items:
      item.loadDataFromFile(directory)
      item.start = offset
      offset += item.size

  def unpack(self, directory):
    if not os.path.exists(directory):
      os.makedirs(directory)
    return self.save(directory)

  def save(self, directory):
    with open(os.path.join(directory, self._HEADER_FILE), 'wb') as f:
      f.write(self.toString())
    for item in self.items:
      item.saveData(directory)

  def toString(self, noItemData=True):
    self.header.fileLength = (
        self.header._FORMAT.size 
        + self.header.itemCount * HuaweiFirmwareItem._FORMAT.size
        - 0x4c # FIXME: Can not find where does this bias come from.
    )
    strs = [
      self.header.toString()[20:], # Partial header used for calculate CRC32 value.
    ]
    if self.header.extraHeaderLength:
      strs.append(self.extraHeader)
      self.header.fileLength += len(self.extraHeader)
    data = []
    for item in self.items:
      strs.append(item.toString())
      data.append(item.data)
      self.header.fileLength += item.size
    # Convert to big endian and ensure it's in the signed int32 range
    file_length_be = socket.htonl(self.header.fileLength & 0xFFFFFFFF)
    # Convert back to signed if needed
    if file_length_be > 0x7FFFFFFF:
      self.header.fileLength = file_length_be - 0x100000000
    else:
      self.header.fileLength = file_length_be

    # Update header CRC32 value.
    self.header.headerCrc = seqCrc32(strs) & 0xFFFFFFFF
    # Convert to signed int32
    if self.header.headerCrc > 0x7FFFFFFF:
      self.header.headerCrc -= 0x100000000

    if not noItemData:
      strs.extend(data)
      # All data are present, now update file CRC32 value.
      strs[0] = self.header.toString()[12:]
      crc_value = seqCrc32(strs) & 0xFFFFFFFF
      # Convert to signed int32
      if crc_value > 0x7FFFFFFF:
        self.header.fileCrc = crc_value - 0x100000000
      else:
        self.header.fileCrc = crc_value

    # Using the latest header with correct CRC32 value and file length.
    strs[0] = self.header.toString()
    return b''.join(strs)

  def getDotDirectory(self, directory):
    return os.path.join(directory, '.fw')

class HuaweiFirmwareHeader(object):
  _FORMAT = struct.Struct('<4sIiIiI3H6s')

  def loadFromString(self, data):
    size = self._FORMAT.size
    (
      self.magic,
      self.fileLength,
      self.fileCrc,
      self.headerSize,
      self.headerCrc,
      self.itemCount,
      dummy,
      self.extraHeaderLength,
      self.itemSize,
      dummy,
    ) = self._FORMAT.unpack(data[:size])
    return size

  def toString(self):
    # Ensure unsigned values are in valid range (0 to 4294967295)
    fileLength = self.fileLength if self.fileLength >= 0 else self.fileLength + 0x100000000
    headerSize = self.headerSize if self.headerSize >= 0 else self.headerSize + 0x100000000
    itemCount = self.itemCount if self.itemCount >= 0 else self.itemCount + 0x100000000
    
    return self._FORMAT.pack(
      self.magic,
      fileLength & 0xFFFFFFFF,
      self.fileCrc,
      headerSize & 0xFFFFFFFF,
      self.headerCrc,
      itemCount & 0xFFFFFFFF,
      0,
      self.extraHeaderLength,
      self.itemSize,
      b'\0' * 6,
    )

class HuaweiFirmwareItem(object):
  _FORMAT = struct.Struct('<IiII256s80s2I')

  def loadInfo(self, data):
    size = self._FORMAT.size
    (
      self.seq,
      self.crc,
      self.start,
      self.size,
      self.name,
      self.typeName,
      self.policy,
      self.unknown,
    ) = self._FORMAT.unpack(data[:size])
    self.data = None
    return size

  @property
  def end(self):
    return self.start + self.size

  def toString(self):
    # Ensure unsigned values are in valid range
    seq = self.seq if self.seq >= 0 else self.seq + 0x100000000
    start = self.start if self.start >= 0 else self.start + 0x100000000
    size = self.size if self.size >= 0 else self.size + 0x100000000
    policy = self.policy if self.policy >= 0 else self.policy + 0x100000000
    unknown = self.unknown if self.unknown >= 0 else self.unknown + 0x100000000
    
    return self._FORMAT.pack(
      seq & 0xFFFFFFFF,
      self.crc,
      start & 0xFFFFFFFF,
      size & 0xFFFFFFFF,
      self.name,
      self.typeName,
      policy & 0xFFFFFFFF,
      unknown & 0xFFFFFFFF,
    )

  def saveData(self, directory):
    name = self.path
    path = name.lstrip(r'\/')
    path = os.path.join(directory, path)
    targetDirectory = os.path.dirname(path)
    if targetDirectory and not os.path.exists(targetDirectory):
        os.makedirs(targetDirectory)
    policyIndicator = 'x' if self.policy & 0x2 else ' '
    print('saving %s %s(%d)...' %  (
      policyIndicator,
      name,
      self.size,
    ))
    with open(path, 'wb') as f:
      f.write(self.data)

  def loadDataFromFile(self, directory):
    name = self.path
    path = name.lstrip(r'\/')
    path = os.path.join(directory, path)
    print('reading %s...' %  name)
    with open(path, 'rb') as f:
      self.data = f.read()
    self.update()

  def update(self):
    self.size = len(self.data)
    crc_value = crc32(self.data) & 0xFFFFFFFF
    # Convert to signed int32
    if crc_value > 0x7FFFFFFF:
      self.crc = crc_value - 0x100000000
    else:
      self.crc = crc_value

  @property
  def path(self):
    # Decode bytes to string for Python 3
    name_str = self.name.decode('utf-8', errors='ignore') if isinstance(self.name, bytes) else self.name
    if name_str.startswith('file:'):
      return name_str[5:].rstrip('\0')
    elif name_str.startswith('flash:'):
      return os.path.join('flash', name_str[6:].rstrip('\0'))
    raise NotImplementedError(name_str.rstrip('\0'))

def unpack(opt):
  fw = HuaweiFirmware()
  fw.open(opt['FILE'])
  return fw.unpack(opt['--root'])

def pack(opt):
  fw = HuaweiFirmware()
  return fw.pack(opt['--root'], opt['FILE'])

def entry(opt):
  if opt['unpack']:
    return unpack(opt)
  elif opt['pack']:
    return pack(opt)
  else:
    return 1

def main():
  opt = docopt.docopt(__opt__ % {'prog': os.path.basename(sys.argv[0])})
  verbose = opt['--verbose']
  logging.getLogger().setLevel(getattr(logging, (
      'ERROR',
      'WARNING',
      'INFO',
      'DEBUG',
  )[min(verbose, 3)]))
  logging.debug(opt)
  sys.exit(entry(opt))

if __name__ == '__main__':
  main()
