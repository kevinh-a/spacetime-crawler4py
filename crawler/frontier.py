import os
import shelve
import time
from urllib.parse import urlparse

from threading import Condition, RLock

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid


class Frontier(object):
    def __init__(self, config, restart):
        self.logger = get_logger("FRONTIER")
        self.config = config
        self.to_be_downloaded = list()
        self.lock = RLock()
        self.cv = Condition(self.lock)
        self.next_allowed_by_domain = dict()
        self.in_flight_by_domain = dict()
        self.in_progress = 0

        if not os.path.exists(self.config.save_file) and not restart:
            # Save file does not exist, but request to load save.
            self.logger.info(
                f"Did not find save file {self.config.save_file}, "
                f"starting from seed.")
        elif os.path.exists(self.config.save_file) and restart:
            # Save file does exists, but request to start from seed.
            self.logger.info(
                f"Found save file {self.config.save_file}, deleting it.")
            os.remove(self.config.save_file)
        # Load existing save file, or create one if it does not exist.
        self.save = shelve.open(self.config.save_file)
        if restart:
            for url in self.config.seed_urls:
                self.add_url(url)
        else:
            # Set the frontier state with contents of save file.
            self._parse_save_file()
            if not self.save:
                for url in self.config.seed_urls:
                    self.add_url(url)

    def _parse_save_file(self):
        ''' This function can be overridden for alternate saving techniques. '''
        total_count = len(self.save)
        tbd_count = 0
        for url, completed in self.save.values():
            if not completed and is_valid(url):
                self.to_be_downloaded.append(url)
                tbd_count += 1
        self.logger.info(
            f"Found {tbd_count} urls to be downloaded from {total_count} "
            f"total urls discovered.")

    def _get_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc.lower().rstrip(".")

    def get_tbd_url(self):
        with self.cv:
            while True:
                if self.to_be_downloaded:
                    next_url = self.to_be_downloaded.pop()
                    self.in_progress += 1
                    return next_url

                if self.in_progress == 0:
                    return None

                self.cv.wait(timeout=self.config.time_delay)

    def wait_for_politeness(self, url):
        domain = self._get_domain(url)
        if not domain:
            return

        with self.cv:
            while True:
                now = time.time()
                next_allowed = self.next_allowed_by_domain.get(domain, 0.0)
                wait_time = next_allowed - now
                if wait_time <= 0 and not self.in_flight_by_domain.get(domain, False):
                    self.in_flight_by_domain[domain] = True
                    return
                self.cv.wait(timeout=max(wait_time, 0.01))

    def complete_politeness(self, url):
        domain = self._get_domain(url)
        if not domain:
            return

        with self.cv:
            self.in_flight_by_domain[domain] = False
            self.next_allowed_by_domain[domain] = (
                    time.time() + self.config.time_delay
            )
            self.cv.notify_all()

    def add_url(self, url):
        url = normalize(url)
        urlhash = get_urlhash(url)
        with self.cv:
            if urlhash not in self.save:
                self.save[urlhash] = (url, False)
                self.save.sync()
                self.to_be_downloaded.append(url)
                self.cv.notify()

    def mark_url_complete(self, url):
        urlhash = get_urlhash(url)
        with self.cv:
            if urlhash not in self.save:
                # This should not happen.
                self.logger.error(
                    f"Completed url {url}, but have not seen it before.")
            else:
                self.save[urlhash] = (url, True)
                self.save.sync()
            if self.in_progress > 0:
                self.in_progress -= 1
            self.cv.notify_all()
