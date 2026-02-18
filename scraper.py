import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import json
import os
from collections import defaultdict
from threading import Lock

analytics_file = "analytics_data.json"
analytics_lock = Lock()

if os.path.exists(analytics_file):
    with open(analytics_file, 'r') as f:
        analytics_data = json.load(f)
else:
    analytics_data = {
        'unique_urls': set(),
        'longest_page': {'url': '', 'word_count': 0},
        'word_freq': defaultdict(int),
        'subdomains': defaultdict(int)
    }
    analytics_data['word_freq'] = dict(analytics_data['word_freq'])
    analytics_data['subdomains'] = dict(analytics_data['subdomains'])
    analytics_data['unique_urls'] = list(analytics_data['unique_urls'])

STOP_WORDS = set([
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', "aren't",
    'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by',
    "can't", 'cannot', 'could', "couldn't", 'did', "didn't", 'do', 'does', "doesn't", 'doing', "don't",
    'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', "hadn't", 'has', "hasn't", 'have',
    "haven't", 'having', 'he', "he'd", "he'll", "he's", 'her', 'here', "here's", 'hers', 'herself', 'him',
    'himself', 'his', 'how', "how's", 'i', "i'd", "i'll", "i'm", "i've", 'if', 'in', 'into', 'is', "isn't",
    'it', "it's", 'its', 'itself', "let's", 'me', 'more', 'most', "mustn't", 'my', 'myself', 'no', 'nor',
    'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out',
    'over', 'own', 'same', "shan't", 'she', "she'd", "she'll", "she's", 'should', "shouldn't", 'so', 'some',
    'such', 'than', 'that', "that's", 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there',
    "there's", 'these', 'they', "they'd", "they'll", "they're", "they've", 'this', 'those', 'through', 'to',
    'too', 'under', 'until', 'up', 'very', 'was', "wasn't", 'we', "we'd", "we'll", "we're", "we've", 'were',
    "weren't", 'what', "what's", 'when', "when's", 'where', "where's", 'which', 'while', 'who', "who's",
    'whom', 'why', "why's", 'with', "won't", 'would', "wouldn't", 'you', "you'd", "you'll", "you're",
    "you've", 'your', 'yours', 'yourself', 'yourselves'
])


def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    links = []

    if resp.status != 200:
        return links

    if not resp.raw_response or not resp.raw_response.content:
        return links

    try:
        content = resp.raw_response.content

        # Likely low information value if they have very large files (>10MB)
        if len(content) > 10 * 1024 * 1024:
            return links

        try:
            if isinstance(content, bytes):
                try:
                    content_str = content.decode('utf-8')
                except UnicodeDecodeError:
                    content_str = content.decode('utf-8', errors='replace')
                soup = BeautifulSoup(content_str, 'html.parser')
            else:
                soup = BeautifulSoup(content, 'html.parser')
        except Exception as e:
            print(f"Parsing error for {url}: {e}")
            return links

        for script in soup(["script", "style"]):
            script.decompose()

        text = soup.get_text()

        words = re.findall(r'\b[a-z]+\b', text.lower())

        if len(words) < 100:
            return links

        if len(words) > 0:
            unique_words = len(set(words))
            if unique_words / len(words) < 0.2:
                return links

        defragged_url, _ = urldefrag(url)

        with analytics_lock:
            # Fix to stop corrupting analytics file with multithreading
            if os.path.exists(analytics_file):
                with open(analytics_file, 'r') as f:
                    analytics_data = json.load(f)
            else:
                analytics_data = {
                    'unique_urls': [],
                    'longest_page': {'url': '', 'word_count': 0},
                    'word_freq': {},
                    'subdomains': {}
                }

            if defragged_url not in analytics_data['unique_urls']:
                analytics_data['unique_urls'].append(defragged_url)

            word_count = len(words)
            if word_count > analytics_data['longest_page']['word_count']:
                analytics_data['longest_page'] = {'url': defragged_url, 'word_count': word_count}

            for word in words:
                if word not in STOP_WORDS and len(word) > 2:  # Also ignore very short words
                    analytics_data['word_freq'][word] = analytics_data['word_freq'].get(word, 0) + 1

            parsed = urlparse(defragged_url)
            if parsed.netloc.endswith('.uci.edu'):
                analytics_data['subdomains'][parsed.netloc] = analytics_data['subdomains'].get(parsed.netloc, 0) + 1

            with open(analytics_file, 'w') as f:
                json.dump(analytics_data, f)

        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(url, href)
            defragged_link, _ = urldefrag(absolute_url)
            links.append(defragged_link)

    except Exception as e:
        print(f"Error processing {url}: {e}")

    return links


def is_valid(url):
    # Decide whether to crawl this url or not.
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        allowed_domains = [
            '.ics.uci.edu',
            '.cs.uci.edu',
            '.informatics.uci.edu',
            '.stat.uci.edu'
        ]

        netloc = parsed.netloc.lower()

        # Check if netloc matches any allowed domain (including subdomains)
        is_allowed = False
        for domain in allowed_domains:
            if netloc == domain[1:] or netloc.endswith(domain):
                is_allowed = True
                break

        if not is_allowed:
            return False

        # Block specific domains/paths below

        # Avoid grape.ics.uci.edu wiki due to huge revision histories
        if 'grape.ics.uci.edu' in netloc and '/wiki/' in parsed.path.lower():
            return False

        # File extensions to avoid
        if re.match(
                r".*\.(css|js|bmp|gif|jpe?g|ico"
                + r"|png|tiff?|mid|mp2|mp3|mp4"
                + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
                + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
                + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
                + r"|epub|dll|cnf|tgz|sha1"
                + r"|thmx|mso|arff|rtf|jar|csv"
                + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            return False

        # Avoid calendar traps
        lower_path = parsed.path.lower()
        lower_query = parsed.query.lower()

        # Block any URLs with ?redirect_to parameter
        if 'redirect_to' in lower_query:
            return False

        # Avoid wics.ics.uci.edu urls with ?share in query params
        if 'wics.ics.uci.edu' in netloc and 'share' in lower_query:
            return False

        # Avoid ngs.ics.uci.edu urls with specific paths
        if 'ngs.ics.uci.edu' in netloc:
            if '/category' in lower_path or '/author' in lower_path or '/tag' in lower_path:
                return False

        # Block all events
        if re.search(r'/(calendar|events?)(/|$)', lower_path):
            return False

        # Block date-based events urls /events/2024-06-02
        if re.search(r'/(calendar|events?)/(week|month|day|\d{4})', lower_path):
            return False

        # Block event tag/category/list pages /events/
        if re.search(r'/events?/(tag|category|list)', lower_path):
            return False

        # Block iCal feeds and event display queries ?ical=1&eventDisplay=past
        if '/events' in lower_path and ('ical=' in lower_query or 'eventdisplay=' in lower_query):
            return False

        # Block recurring event pagination ?page=, ?tribe_paged=
        if '/events' in lower_path and ('page=' in lower_query or 'tribe' in lower_query):
            return False

        # Avoid image view traps with tons of parameters
        if '?' in url and len(url) > 200:
            return False

        # Avoid URLs with too many path segments
        if len(parsed.path.split('/')) > 15:
            return False

        # Avoiding wiki division traps here
        if 'doku.php' in lower_path:
            # Block any ?do= param, only allowing normal page views
            if 'do=' in lower_query or 'rev=' in lower_query or 'rev2' in lower_query or 'sectok=' in lower_query:
                return False

        # pages with oldid/diff parameters in the wiki
        if ('index.php' in lower_path or '/wiki/' in lower_path) and lower_query:
            mw_actions = ['action=', 'oldid=', 'diff=', 'curid=', 'printable=']
            if any(action in lower_query for action in mw_actions):
                return False

        # Block wiki pages
        if re.search(r'/(special|especial):', lower_path):
            return False

        # Blocking some common GitLab and repository endpoints to avoid crawl traps
        gitlab_patterns = [
            '/-/',
            '/-/tree/',
            '/-/blob/',
            '/-/raw/',
            '/-/commit/',
            '/-/merge_requests/',
            '/commit/',
            '/merge_requests/',
            '/issues/',
            '/tags',
            '/branches',
            '/releases',
            '/archive',
            '/compare',
            '/.git'
        ]
        for p in gitlab_patterns:
            if p in lower_path:
                return False

        return True

    except TypeError:
        print("TypeError for ", parsed)
        raise

