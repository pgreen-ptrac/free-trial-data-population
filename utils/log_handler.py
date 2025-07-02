import time
import logging
import os
os.system("")  # enables ansi escape characters in windows terminals
import re

import settings

# logging settings - these setting should be defined in setting.py - these default values are used if this file is missing
# console_log_level = logging.DEBUG
# file_log_level = logging.INFO
# save_logs_to_file = False


class IterationMetrics:
    """
    A class to handle printing time based metric logs when doing iterative operations.
    """
    def __init__(self, iterations: int):
        """
        Create an IterationMetrics object to track elapsed time for an interation operation

        :param iterations: number of iteration that will be preformed. Used to calculate an estimated time remaining
        :type iterations: int
        """
        self.max_iterations = iterations
        self.curr_iteration = 0
        self.start_time = time.time()
        self.last_time = self.start_time
        self.total_time = 0
        self.avg_time = 0
        self.time_remaining = self.avg_time * (self.max_iterations - (self.curr_iteration+1))

    def print_iter_metrics(self) -> str:
        curr_time = time.time()
        iter_time = curr_time - self.last_time
        self.total_time += iter_time
        self.avg_time = self.total_time/(self.curr_iteration+1)
        self.time_remaining = self.avg_time * (self.max_iterations - (self.curr_iteration+1))

        self.curr_iteration += 1
        self.last_time = curr_time
        return f'METRICS: ({self.curr_iteration}/{self.max_iterations}) Completed in {round(iter_time, 1)} sec(s) - Total time: {round(self.total_time/60, 1)} min(s) - Est. Time Remaining: {round(self.time_remaining/60, 1)} min(s)'        


class ColorPrint:
    def print_red(message):
        return f'\x1b[1;31m{message}\x1b[0m'

    def print_green(message):
        return f'\x1b[1;32m{message}\x1b[0m'

    def print_yellow(message):
        return f'\x1b[1;33m{message}\x1b[0m'

    def print_blue(message):
        return f'\x1b[1;34m{message}\x1b[0m'

    def print_purple(message):
        return f'\x1b[1;35m{message}\x1b[0m'

    def print_cyan(message):
        return f'\x1b[1;36m{message}\x1b[0m'

    def print_bold(message):
        return f'\x1b[1;37m{message}\x1b[0m'



class TermEscapeCodeFormatter(logging.Formatter):
    """
    A class to strip the color escape codes when printing to non ANSI terminals, like a text file
    """
    def __init__(self, fmt=None, datefmt=None, style='%', validate=True):
        super().__init__(fmt, datefmt, style, validate)

    def format(self, record):
        escape_re = re.compile(r'\x1b\[[0-9;]*m')
        record.msg = re.sub(escape_re, "", str(record.msg))
        return super().format(record)



class LogFormatHandler():
    """
    A class to act as an interface to the python logger and handle adding font colors depending on log level
    """
    def __init__(self, stream_level, file_level=logging.WARN, output_to_file=False):
        self.LOGS_FILE_PATH = f'logs_{time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime(time.time()))}.txt'

        lger = logging.getLogger()
        lger.setLevel(logging.DEBUG) # do not change - logging level set individually below

        stdo = logging.StreamHandler()
        stdo.setLevel(stream_level)
        fmer = logging.Formatter('%(asctime)s %(message)s')
        stdo.setFormatter(fmer)
        lger.addHandler(stdo)

        if output_to_file:
            fhdr = logging.FileHandler(self.LOGS_FILE_PATH, "w")
            fhdr.setLevel(file_level)
            cfmer = TermEscapeCodeFormatter('%(asctime)s %(message)s')
            fhdr.setFormatter(cfmer)
            lger.addHandler(fhdr)

        self.logger = lger

    def debug(self, message):
        self.logger.debug(ColorPrint.print_purple(f'[DEBUG] {message}'))

    def info(self, message):
        self.logger.info(ColorPrint.print_blue(f'[INFO] {message}'))

    def success(self, message):
        self.logger.info(ColorPrint.print_green(f'[SUCCESS] {message}'))

    def warning(self, message):
        self.logger.warning(ColorPrint.print_yellow(f'[WARNING] {message}'))

    def error(self, message):
        self.logger.error(ColorPrint.print_red(f'[ERROR] {message}'))

    def critical(self, message):
        self.logger.critical(ColorPrint.print_red(f'[CRITICAL] {message}'))

    def exception(self, message):
        self.logger.exception(ColorPrint.print_yellow(f'[EXCEPTION] {message}'))



log = LogFormatHandler(settings.console_log_level, settings.file_log_level, settings.save_logs_to_file)
