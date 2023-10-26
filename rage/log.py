import logging
import colorama

colorama.init()
aegis_log = logging.getLogger('aegis_log')
aegis_log.setLevel(logging.DEBUG)

COLORS = {
    logging.DEBUG: colorama.Fore.CYAN,     
    logging.INFO: colorama.Fore.GREEN,     
    logging.WARNING: colorama.Fore.MAGENTA, 
    logging.ERROR: colorama.Fore.RED,       
}

def custom_formatter(record):
    color = COLORS.get(record.levelno, colorama.Fore.WHITE)  
    log_message = f"🛡️  {color}[{record.levelname}] - aegis: {record.msg}{colorama.Style.RESET_ALL}"
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


console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

aegis_log.addHandler(console_handler)


if __name__ == "__main__":
    aegis_log.info("This is an info message")
    aegis_log.warning("This is a warning message")
    aegis_log.error("This is an error message")
    aegis_log.debug("This is a debug message")

