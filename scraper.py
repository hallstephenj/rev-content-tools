import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from collections import deque
import re
from config import Config
from models import Database
import trafilatura


class WebsiteScraper:
    """Scraper for downloading all content from a website"""

    def __init__(self, base_url, max_pages=None, skip_existing=False, user_id=None):
        self.base_url = base_url
        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        # Preserve the base path so we only scrape within that subdirectory
        base_path = parsed.path.rstrip('/') or '/'
        # Ensure it ends with / for prefix matching (unless it's just /)
        self.base_path = base_path if base_path == '/' else base_path + '/'
        self.max_pages = max_pages or Config.MAX_PAGES
        self.skip_existing = skip_existing
        self.user_id = user_id
        self.visited_urls = set()
        self.urls_to_visit = deque([base_url])
        self.db = Database()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        self.skipped_count = 0  # Track how many pages were skipped

    def is_valid_url(self, url):
        """Check if URL is valid, belongs to the same domain, and is within the base path"""
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False
        if parsed.netloc != self.domain:
            return False
        if url.endswith(('.pdf', '.jpg', '.png', '.gif', '.zip', '.exe')):
            return False
        # Ensure the URL path is within (or equal to) the base subdirectory
        path = parsed.path.rstrip('/') or '/'
        path_with_slash = path if path == '/' else path + '/'
        if self.base_path != '/':
            # Must start with the base path
            if not (path_with_slash.startswith(self.base_path) or path + '/' == self.base_path):
                return False
        return True

    def extract_links(self, soup, current_url):
        """Extract all links from the page"""
        links = []
        for link in soup.find_all('a', href=True):
            url = urljoin(current_url, link['href'])
            # Remove fragments
            url = url.split('#')[0]
            if self.is_valid_url(url) and url not in self.visited_urls:
                links.append(url)
        return links

    def extract_content(self, html, url):
        """Extract main content from HTML using trafilatura"""
        try:
            # Use trafilatura for better content extraction
            content = trafilatura.extract(html, include_comments=False,
                                         include_tables=True)
            if content:
                return content
        except:
            pass

        # Fallback to BeautifulSoup
        soup = BeautifulSoup(html, 'lxml')

        # Remove script and style elements
        for script in soup(['script', 'style', 'nav', 'footer', 'header']):
            script.decompose()

        # Try to find main content
        main_content = None
        for tag in ['article', 'main', 'div[role="main"]']:
            main_content = soup.find(tag)
            if main_content:
                break

        if not main_content:
            main_content = soup.find('body')

        if main_content:
            text = main_content.get_text(separator='\n', strip=True)
            # Clean up excessive whitespace
            text = re.sub(r'\n\s*\n', '\n\n', text)
            return text

        return ""

    def extract_metadata(self, soup):
        """Extract metadata from the page"""
        metadata = {
            'title': '',
            'description': '',
            'keywords': ''
        }

        # Extract title
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.get_text().strip()

        # Extract meta description
        desc_tag = soup.find('meta', attrs={'name': 'description'})
        if desc_tag and desc_tag.get('content'):
            metadata['description'] = desc_tag.get('content').strip()

        # Extract keywords
        keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
        if keywords_tag and keywords_tag.get('content'):
            metadata['keywords'] = keywords_tag.get('content').strip()

        return metadata

    def scrape_page(self, url):
        """Scrape a single page"""
        try:
            # Skip if URL already exists in database and skip_existing is enabled
            if self.skip_existing and self.db.url_exists(url, user_id=self.user_id):
                print(f"Skipping (already in DB): {url}")
                self.skipped_count += 1
                return True  # Still return True so we continue crawling

            print(f"Scraping: {url}")
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'lxml')

            # Extract content and metadata
            content = self.extract_content(response.text, url)
            metadata = self.extract_metadata(soup)

            # Calculate word count
            word_count = len(content.split())

            # Save to database
            if content and word_count > 50:  # Only save if there's substantial content
                self.db.add_scraped_content(
                    url=url,
                    title=metadata['title'],
                    content=content,
                    meta_description=metadata['description'],
                    keywords=metadata['keywords'],
                    word_count=word_count,
                    domain=self.domain,
                    user_id=self.user_id
                )

            # Extract links for further crawling
            new_links = self.extract_links(soup, url)
            for link in new_links:
                if link not in self.visited_urls:
                    self.urls_to_visit.append(link)

            return True

        except Exception as e:
            print(f"Error scraping {url}: {e}")
            return False

    def scrape_website(self, delay=1):
        """Scrape entire website"""
        print(f"Starting to scrape {self.base_url}")
        if self.base_path != '/':
            print(f"Restricting to subdirectory: {self.base_path}")
        if self.skip_existing:
            print("Mode: Only scraping NEW pages (skipping existing)")
        print(f"Maximum pages: {self.max_pages}")

        while self.urls_to_visit and len(self.visited_urls) < self.max_pages:
            url = self.urls_to_visit.popleft()

            if url in self.visited_urls:
                continue

            self.scrape_page(url)
            self.visited_urls.add(url)

            # Be polite - add delay between requests
            time.sleep(delay)

            # Progress update
            if len(self.visited_urls) % 10 == 0:
                print(f"Progress: {len(self.visited_urls)} pages scraped")

        print(f"\nScraping complete!")
        print(f"Total pages visited: {len(self.visited_urls)}")
        if self.skip_existing and self.skipped_count > 0:
            print(f"Pages skipped (already in DB): {self.skipped_count}")
            print(f"New pages scraped: {len(self.visited_urls) - self.skipped_count}")
        return len(self.visited_urls)

    def get_sitemap_urls(self):
        """Try to get URLs from sitemap.xml"""
        sitemap_urls = [
            urljoin(self.base_url, '/sitemap.xml'),
            urljoin(self.base_url, '/sitemap_index.xml'),
        ]

        all_urls = []
        for sitemap_url in sitemap_urls:
            try:
                response = self.session.get(sitemap_url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'xml')
                    urls = [loc.text for loc in soup.find_all('loc')]
                    all_urls.extend(urls)
            except:
                continue

        return all_urls


def scrape_website(url, max_pages=100, skip_existing=False, user_id=None):
    """Convenience function to scrape a website"""
    scraper = WebsiteScraper(url, max_pages=max_pages, skip_existing=skip_existing, user_id=user_id)

    # Try to use sitemap first
    sitemap_urls = scraper.get_sitemap_urls()
    if sitemap_urls:
        # Filter sitemap URLs to only include those within the base path
        filtered_urls = [u for u in sitemap_urls if scraper.is_valid_url(u)]
        print(f"Found {len(sitemap_urls)} URLs in sitemap, {len(filtered_urls)} within base path")
        for sitemap_url in filtered_urls[:max_pages]:
            scraper.urls_to_visit.append(sitemap_url)

    result = scraper.scrape_website()
    return result
