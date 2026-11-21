#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .server import lock_hang_server

if __name__ == "__main__":
    lock_hang_server.run(transport="stdio", show_banner=False)
