#!/usr/bin/env python3
"""Shared compact progress bar for ReconShell scanner modules.

Provides a small-width, creative progress bar with spinner and protocol icons.
"""
from __future__ import annotations

class ProgressBar:
    """Compact, creative progress bar with protocol icons and spinner.

    - Small default width (12) suitable for single-line CLI output
    - Optional protocol label (TCP/UDP/SYN) shown as emoji-like icons
    - Rotating spinner to indicate activity
    - Human readable percent and counts
    """
    SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    # protocol icons removed per user request; keep mapping for compatibility
    PROT_ICON = {'tcp': '', 'udp': '', 'syn': '', '': ''}

    def __init__(self, total: int, desc: str = "", width: int = 12, protocol: str = ""):
        self.total = max(1, int(total))
        self.desc = desc
        self.width = max(6, int(width))
        self.protocol = protocol.lower() if protocol else ''
        self.current = 0
        self._spin = 0

    def _render_bar(self) -> str:
        filled = int(self.width * self.current / self.total)
        empty = self.width - filled
        return '■' * filled + '·' * empty

    def update(self, n: int = 1) -> None:
        self.current = min(self.total, self.current + int(n))
        pct = int(100 * self.current / self.total)
        bar = self._render_bar()
        spinner = ProgressBar.SPINNER[self._spin % len(ProgressBar.SPINNER)]
        self._spin += 1
        icon = ProgressBar.PROT_ICON.get(self.protocol, '')
        counts = f"{self.current}/{self.total}"
        # only include icon slot when non-empty to avoid extra spaces
        if icon:
            out = f"\r{spinner} {icon} {self.desc}: [{bar}] {pct:3d}% {counts}"
        else:
            out = f"\r{spinner} {self.desc}: [{bar}] {pct:3d}% {counts}"
        print(out, end='', flush=True)

    def close(self) -> None:
        if self.current < self.total:
            self.current = self.total
            self.update(0)
        print()
