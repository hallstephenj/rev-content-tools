# AI SEO Content Generator

A powerful tool for downloading website content and generating SEO-optimized articles at scale using AI. This application helps content marketers leverage AI to produce high-value content that attracts organic traffic and generates qualified leads.

## Features

- **Website Content Scraper**: Automatically download all written content from any website
- **AI Content Generation**: Generate new articles based on your existing content style
- **SEO Optimization**: Automatic keyword analysis and optimization recommendations
- **Content Series Generator**: Create multiple related articles on a topic
- **Topic Idea Generator**: Get AI-powered topic suggestions based on your content
- **SEO Analysis**: Comprehensive scoring and recommendations for all content
- **Web Interface**: Easy-to-use dashboard for managing all operations

## How It Works

1. **Scrape Your Website**: The tool downloads all written content from your company's website, analyzing the style, tone, and topics
2. **AI Analysis**: The system learns from your existing content to understand your brand voice
3. **Generate New Content**: Create SEO-optimized articles that match your style and target specific keywords
4. **Optimize for Search**: Each article is analyzed for SEO performance with actionable recommendations

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenAI API key

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd SEO-tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
```

Edit `.env` and add your OpenAI API key:
```
OPENAI_API_KEY=your_openai_api_key_here
```

4. Initialize the database:
```bash
python -c "from models import Database; Database()"
```

## Usage

### Starting the Web Interface

```bash
python app.py
```

The application will be available at `http://localhost:5000`

### Scraping a Website

1. Navigate to "Scrape Website" in the web interface
2. Enter the website URL (e.g., `https://example.com`)
3. Set the maximum number of pages to scrape
4. Click "Start Scraping"

The scraper will:
- Automatically discover pages via links and sitemaps
- Extract clean content and metadata
- Store everything in the database
- Respect a 1-second delay between requests

### Generating Content

#### Single Article

1. Navigate to "Generate Content"
2. Enter a topic or title
3. Provide target keywords (comma-separated)
4. Set desired word count
5. Click "Generate Content"

#### Topic Ideas

1. In the "Generate Content" page, scroll to "Generate Topic Ideas"
2. Optionally specify a niche
3. Set number of topics to generate
4. Click "Generate Topic Ideas"

#### Content Series

1. In the "Generate Content" page, scroll to "Generate Content Series"
2. Enter a main topic
3. Specify number of posts
4. Click "Generate Series"

The AI will create multiple related articles automatically.

### Viewing Results

- **Scraped Content**: View all downloaded pages with metadata
- **Generated Content**: Browse all AI-generated articles
- Click on any article to see:
  - Full content
  - SEO analysis and score
  - Optimization recommendations
  - Top keywords

## Command Line Usage

### Scrape a Website

```python
from scraper import scrape_website

# Scrape up to 100 pages
scrape_website("https://example.com", max_pages=100)
```

### Generate Content

```python
from content_generator import AIContentGenerator

generator = AIContentGenerator()

# Generate a single article
content_id = generator.generate_and_save_content(
    topic="The Future of Bitcoin Security",
    keywords=["bitcoin", "security", "cryptocurrency"],
    word_count=1500
)

# Generate topic ideas
topics = generator.generate_topic_ideas(num_topics=10, niche="cryptocurrency")

# Generate content series
generator.generate_content_series(
    main_topic="Bitcoin Investment Strategies",
    num_posts=5
)
```

### Analyze SEO

```python
from seo_analyzer import SEOAnalyzer

analyzer = SEOAnalyzer()

# Generate SEO report
report = analyzer.generate_seo_report(
    content="Your article content here...",
    title="Article Title",
    keywords=["keyword1", "keyword2"]
)

print(f"SEO Score: {report['seo_score']}/100")
print(f"Recommendations: {report['recommendations']}")
```

## Project Structure

```
SEO-tool/
├── app.py                 # Flask web application
├── config.py              # Configuration settings
├── models.py              # Database models
├── scraper.py             # Website scraper
├── content_generator.py   # AI content generation
├── seo_analyzer.py        # SEO analysis tools
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── .gitignore            # Git ignore rules
└── templates/            # HTML templates
    ├── base.html
    ├── index.html
    ├── scrape.html
    ├── scraped_content.html
    ├── generate.html
    ├── generated_content.html
    └── view_generated.html
```

## Configuration

Edit `.env` to customize:

```bash
# OpenAI API Configuration
OPENAI_API_KEY=your_key_here

# Application Settings
FLASK_SECRET_KEY=your_secret_key
FLASK_ENV=development

# Database
DATABASE_URL=sqlite:///seo_content.db

# Scraper Settings
MAX_PAGES=100
CONCURRENT_REQUESTS=5
USER_AGENT=Mozilla/5.0...
```

## Database Schema

### ScrapedContent
- `id`: Primary key
- `url`: Page URL (unique)
- `title`: Page title
- `content`: Main content text
- `meta_description`: Meta description
- `keywords`: Meta keywords
- `word_count`: Word count
- `domain`: Website domain
- `scraped_at`: Timestamp

### GeneratedContent
- `id`: Primary key
- `title`: Article title
- `content`: Article content
- `keywords`: Target keywords (JSON)
- `meta_description`: Meta description
- `word_count`: Word count
- `seo_score`: SEO score (0-100)
- `source_urls`: Source URLs (JSON)
- `topic`: Main topic
- `generated_at`: Timestamp

## SEO Scoring

The SEO analyzer evaluates content on:

- **Word Count** (20 points): Longer, comprehensive content ranks better
- **Title Optimization** (15 points): Ideal length is 50-60 characters
- **Meta Description** (15 points): Ideal length is 150-160 characters
- **Heading Structure** (20 points): Proper use of H2, H3 headings
- **Keyword Usage** (15 points): Natural keyword integration (0.5-2.5% density)
- **Readability** (15 points): Flesch reading ease score

**Score Interpretation:**
- 70-100: Excellent SEO optimization
- 50-69: Good, with room for improvement
- 0-49: Needs significant optimization

## Best Practices

1. **Scraping**:
   - Start with your homepage
   - Allow the scraper to discover pages naturally
   - Scrape at least 20-30 pages for best results

2. **Content Generation**:
   - Provide specific, descriptive topics
   - Use 3-5 targeted keywords
   - Aim for 1000-1500 words for SEO impact
   - Review and edit generated content before publishing

3. **SEO Optimization**:
   - Target SEO scores above 70
   - Follow the recommendations provided
   - Include natural keyword variations
   - Use clear heading hierarchy

## API Endpoints

- `GET /` - Home page with statistics
- `GET/POST /scrape` - Scrape website
- `GET /scraped-content` - View scraped content
- `GET/POST /generate` - Generate content
- `POST /generate-topics` - Generate topic ideas
- `POST /generate-series` - Generate content series
- `GET /generated-content` - View generated content
- `GET /generated/<id>` - View specific article
- `POST /analyze` - Analyze content for SEO
- `GET /api/stats` - Get statistics (JSON)

## Requirements

Key dependencies:
- Flask 3.0.0 - Web framework
- OpenAI 1.6.1 - AI content generation
- BeautifulSoup4 4.12.2 - HTML parsing
- Trafilatura 1.6.3 - Content extraction
- SQLAlchemy 2.0.23 - Database ORM
- Requests 2.31.0 - HTTP requests

See `requirements.txt` for full list.

## Troubleshooting

### OpenAI API Errors
- Ensure your API key is correctly set in `.env`
- Check your OpenAI account has sufficient credits
- Verify you're using a supported model (GPT-4)

### Scraping Issues
- Some websites may block scrapers - this is normal
- Check that the URL is accessible in your browser
- Try reducing `MAX_PAGES` for initial tests

### Database Errors
- Delete `seo_content.db` and restart to reset database
- Ensure SQLite is installed on your system

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please open an issue on GitHub.

## Roadmap

Future enhancements:
- [ ] Support for multiple AI models (Claude, Gemini)
- [ ] Scheduled content generation
- [ ] Integration with WordPress/CMS platforms
- [ ] Advanced keyword research tools
- [ ] Content calendar and planning
- [ ] Multi-language support
- [ ] A/B testing for headlines
- [ ] Social media integration

## Credits

Built with:
- OpenAI GPT-4 for content generation
- Flask for web framework
- Trafilatura for content extraction
- BeautifulSoup for HTML parsing

---

**Note**: This tool is designed to assist content creation, not replace human creativity. Always review and edit AI-generated content before publishing to ensure accuracy, quality, and alignment with your brand voice.

## Deploying to Railway

This project is ready to deploy on Railway as a Python web service.

- The production entrypoint is `wsgi.py`.
- Railway will start the app with Gunicorn via `railway.toml` (and there’s also a `Procfile` for compatibility).

### Railway environment variables

Set these in your Railway service **Variables**:

- `FLASK_SECRET_KEY`: **Required** (use a long random string).
- `OPENAI_API_KEY`: Required only for AI generation features.
- `DATABASE_URL`: Optional.
  - If unset, the app uses a local SQLite file: `sqlite:///seo_content.db`.

### Persistence note (SQLite)

Railway’s filesystem is **ephemeral** by default. If you keep SQLite, you’ll want to add a Railway **Volume** and point `DATABASE_URL` at it, or switch to Railway Postgres and set `DATABASE_URL` accordingly.

