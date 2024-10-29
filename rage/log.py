from rich.console import Console 

from rich.logging import *

aegis_log = logging.getLogger('aegis_log') 
aegis_log.setLevel(logging.DEBUG)
console = Console()

COLORS = {
    logging.DEBUG: "cyan",
    logging.INFO: "green",
    logging.WARNING: "magenta",
    logging.ERROR: "red",
    logging.CRITICAL: "yellow"
}

def custom_formatter(record):
    color = COLORS.get(record.levelno, "white")
    log_message = f"🛡️  [bold]{color}[{record.levelname}] ⚔️  - aegis:[/bold] {record.msg}"
    return log_message

class UniqueLogFilter(logging.Filter):
    def __init__(self):
        self.logged_messages = set()

    def filter(self, record):
        if record.msg in self.logged_messages:
            return False
        self.logged_messages.add(record.msg)
        return True

formatter = logging.Formatter("%(message)s")
formatter.format = custom_formatter

unique_log_filter = UniqueLogFilter()
aegis_log.addFilter(unique_log_filter)

handler = RichHandler(console=console, show_time=False, rich_tracebacks=True)
handler.setFormatter(formatter)
aegis_log.addHandler(handler)

if __name__ == "__main__":
    aegis_log.info("This is an info message")
    aegis_log.warning("This is a warning message")
    aegis_log.error("This is an error message")
    aegis_log.debug("This is a debug message")
    aegis_log.critical("Critical")


