import threading
import time
import logging


class IntervalScheduler:
    def __init__(self, interval_seconds: int, fn):
        self.interval_seconds = interval_seconds
        self.fn = fn
        self._stop = False
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logging.info("Scheduler started (interval=%ss)", self.interval_seconds)

    def stop(self):
        self._stop = True

    def _run(self):
        while not self._stop:
            try:
                self.fn()
            except Exception as e:
                logging.exception("Scheduled job failed: %s", e)
            time.sleep(self.interval_seconds)
