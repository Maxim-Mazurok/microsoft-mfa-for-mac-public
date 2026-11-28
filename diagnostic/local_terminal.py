"""Protected interactive input without background threads or echoed secrets."""
import asyncio
import os
import select
import termios
from research_runtime import require


class Terminal:
    def __init__(self):
        self.fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        require(os.isatty(self.fd), "local_interactive_terminal_required")

    def close(self): os.close(self.fd)

    def show(self, text): os.write(self.fd, (text + "\n").encode())

    async def ask(self, prompt, seconds=120, limit=8192):
        old = termios.tcgetattr(self.fd); hidden = termios.tcgetattr(self.fd)
        hidden[3] &= ~termios.ECHO
        # Canonical terminal processing handles backspace; secrets stay hidden.
        termios.tcsetattr(self.fd, termios.TCSANOW, hidden)
        data = bytearray()
        try:
            self.show(prompt)
            # Darwin's kqueue rejects the controlling /dev/tty alias with
            # EINVAL, even though a newly opened PTY slave accepts add_reader.
            # select() supports this alias. Poll readiness without blocking the
            # event loop, so MCS reception and deadlines continue during input.
            # No background thread survives cancellation or reads a later prompt.
            async with asyncio.timeout(seconds):
                while True:
                    if not select.select([self.fd], [], [], 0)[0]:
                        await asyncio.sleep(0.02)
                        continue
                    value = os.read(self.fd, 1)
                    require(bool(value), "local_terminal_input_closed")
                    if value == b"\n":
                        return data.decode("utf-8")
                    require(len(data) < limit, "local_terminal_input_limit")
                    data.extend(value)
        finally:
            termios.tcsetattr(self.fd, termios.TCSANOW, old)
            self.show("")
