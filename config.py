import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""

    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

    # Flask Configuration
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')

    # Database Configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///seo_content.db')

    # Scraper Configuration
    MAX_PAGES = int(os.getenv('MAX_PAGES', 100))
    CONCURRENT_REQUESTS = int(os.getenv('CONCURRENT_REQUESTS', 5))
    USER_AGENT = os.getenv('USER_AGENT',
                          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')

    # Content Storage
    CONTENT_DIR = 'scraped_content'
    GENERATED_DIR = 'generated_content'

    # SEO Configuration
    MIN_WORD_COUNT = 300
    TARGET_WORD_COUNT = 1500
    MAX_KEYWORD_DENSITY = 0.03  # 3%
