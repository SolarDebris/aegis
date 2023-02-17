import logging
import colorama

# Initialize colorama to allow printing colored text on the console
colorama.init()

# Create a custom logger with the name 'aegis_log'
aegis_log = logging.getLogger('aegis_log')

# Set the logging level to INFO
aegis_log.setLevel(logging.INFO)

# Create a formatter that will add colors to the log messages
formatter = logging.Formatter(
    f"{colorama.Fore.MAGENTA}%(asctime)s [%(levelname)s] %(message)s{colorama.Style.RESET_ALL}"
)

# Create a console handler and set its formatter to the one we just created
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

# Add the console handler to the logger
aegis_log.addHandler(console_handler)

# Now we can log messages using our custom logger with colors
#aegis_log.info("This is an info message")
#aegis_log.warning("This is a warning message")
#aegis_log.error("This is an error message")
