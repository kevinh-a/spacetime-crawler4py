import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import json
import os
import hashlib
from collections import defaultdict

# Analytics data storage
analytics_file = "analytics_data.json"

# Seen exact hashesh storage
seen_exact_hashes = set()

# Global shingle storage
seen_shingles = []

# Load or initialize analytics data
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
    # Convert defaultdict to dict for JSON serialization
    analytics_data['word_freq'] = dict(analytics_data['word_freq'])
    analytics_data['subdomains'] = dict(analytics_data['subdomains'])
    analytics_data['unique_urls'] = list(analytics_data['unique_urls'])

# Load stop words
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


def exact_fingerprint(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def scramble(words, k=5):
    return set(
        tuple(words[i:i + k])
        for i in range(len(words) - k + 1)
    )


def similarity_score(a, b):
    return len(a & b) / len(a | b) if a and b else 0


def text_normalizer(text):
    text = text.lower()
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


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
    global seen_exact_hashes

    # Check if response is valid
    if resp.status != 200:
        return links

    # Check if response has content
    if not resp.raw_response or not resp.raw_response.content:
        return links

    try:
        # Get content
        content = resp.raw_response.content

        # Check for very large files (>10MB) - likely low information value
        if len(content) > 10 * 1024 * 1024:
            return links

        # Parse HTML - handle encoding errors gracefully
        try:
            # Use html.parser instead of lxml for better encoding tolerance
            # Or decode with error handling first
            if isinstance(content, bytes):
                # Try to decode with UTF-8, replace bad bytes if needed
                try:
                    content_str = content.decode('utf-8')
                except UnicodeDecodeError:
                    # Fall back to latin-1 or replace errors
                    content_str = content.decode('utf-8', errors='replace')
                soup = BeautifulSoup(content_str, 'html.parser')
            else:
                soup = BeautifulSoup(content, 'html.parser')
        except Exception as e:
            # If parsing fails completely, skip this page
            print(f"Parsing error for {url}: {e}")
            return links

        # Extract text for analytics
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()

        text = soup.get_text()

        # Get words (alphanumeric sequences)
        words = re.findall(r'\b[a-z]+\b', text.lower())

        # Check for low information content
        # If page has fewer than 100 words, it's likely low value (this includes examples like: log in screens)
        if len(words) < 100:
            return links

        # Check for repetitive content (potential trap)
        # If more than 80% of words are the same, it's likely a trap (skips calendars, spam pages, etc.)
        if len(words) > 0:
            unique_words = len(set(words))
            if unique_words / len(words) < 0.2:
                return links

        # Checking for exact duplicate page
        page_hash = exact_fingerprint(text_normalizer(text))
        if page_hash in seen_exact_hashes:
            print(f"[DUPLICATE] Skipping duplicate page: {url}")
            return links
        else:
            seen_exact_hashes.add(page_hash)

        # Checking for near-duplicate page
        shingles = scramble(words)
        for prev in seen_shingles:
            similarity = similarity_score(shingles, prev)
            if similarity >= 0.7:  # similarity threshhold is .9
                print(f"[NEAR DUPLICATE] Skipping page: {url} (similarity={similarity:.2f})")
                return links
        seen_shingles.append(shingles)

        # Update analytics
        defragged_url, _ = urldefrag(url)

        # Load current analytics
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

        # Add unique URL
        if defragged_url not in analytics_data['unique_urls']:
            analytics_data['unique_urls'].append(defragged_url)

        # Update longest page
        word_count = len(words)
        if word_count > analytics_data['longest_page']['word_count']:
            analytics_data['longest_page'] = {'url': defragged_url, 'word_count': word_count}

        # Update word frequency (excluding stop words)
        for word in words:
            if word not in STOP_WORDS and len(word) > 2:  # Also ignore very short words
                analytics_data['word_freq'][word] = analytics_data['word_freq'].get(word, 0) + 1

        # Update subdomain count
        parsed = urlparse(defragged_url)
        if parsed.netloc.endswith('.uci.edu'):
            analytics_data['subdomains'][parsed.netloc] = analytics_data['subdomains'].get(parsed.netloc, 0) + 1

        # Save analytics
        with open(analytics_file, 'w') as f:
            json.dump(analytics_data, f)

        # Extract all links
        for link in soup.find_all('a', href=True):
            href = link['href']
            # Convert relative URLs to absolute
            absolute_url = urljoin(url, href)
            # Defragment URL
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

        # Check if URL is in allowed domains
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

        # Check for file extensions to avoid
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

        # Avoid calendar/event traps (common infinite trap)
        lower_path = parsed.path.lower()
        lower_query = parsed.query.lower()

        # Block date-based calendar/event URLs (e.g., /events/2024-06-02, /events/week/2025-06-01, /events/month/2025-05)
        if re.search(r'/(calendar|events?)/(week|month|day|\d{4})', lower_path):
            return False

        # Block event tag/category/list pages (e.g., /events/tag/talk/list/)
        if re.search(r'/events?/(tag|category|list)', lower_path):
            return False

        # Block iCal feeds and event display queries (e.g., ?ical=1&eventDisplay=past)
        if '/events' in lower_path and ('ical=' in lower_query or 'eventdisplay=' in lower_query):
            return False

        # Block recurring event pagination (e.g., ?page=, ?tribe_paged=)
        if '/events' in lower_path and ('page=' in lower_query or 'tribe' in lower_query):
            return False

        # Avoid gallery/image view traps with excessive parameters
        if '?' in url and len(url) > 200:
            return False

        # Avoid URLs with too many path segments (potential trap)
        if len(parsed.path.split('/')) > 15:
            return False

        # Block wiki traps (DokuWiki, MediaWiki revision/diff/history pages)
        # DokuWiki: Block ALL action URLs (do=anything) to avoid edit/export/login/diff/revision traps
        if 'doku.php' in lower_path:
            # Block any ?do= parameter (edit, export, diff, login, etc.) - only allow normal page views
            if 'do=' in lower_query or 'rev=' in lower_query or 'rev2' in lower_query or 'sectok=' in lower_query:
                return False

        # MediaWiki: index.php?action=/Special: pages with oldid/diff parameters
        if ('index.php' in lower_path or '/wiki/' in lower_path) and lower_query:
            mw_actions = ['action=', 'oldid=', 'diff=', 'curid=', 'printable=']
            if any(action in lower_query for action in mw_actions):
                return False

        # Block wiki Special: namespace pages (user lists, recent changes, etc.)
        if re.search(r'/(special|especial):', lower_path):
            return False

        # Block common GitLab / repository endpoints to avoid crawl traps
        # Examples: /-/tree/, /-/blob/, /-/raw/, /-/commit/, /-/merge_requests/, /.git, /commit/
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
