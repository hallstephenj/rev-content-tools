# Rev Content Tools

**A suite of tools to empower content marketers** — built by [Reverent Content Co.](https://reverentcontent.co)

---

## Overview

Rev Content Tools is an integrated platform designed to streamline the content marketing workflow. From research and creation to tracking and optimization, this toolkit helps marketing teams produce high-quality content at scale while maintaining brand consistency and measuring performance.

### The Toolkit

| Tool | Description |
|------|-------------|
| **SEO Content Generator** | AI-powered content creation with built-in SEO optimization |
| **Website Scraper** | Extract and analyze existing content to inform strategy |
| **SEO Analyzer** | Score and optimize content for search performance |
| **UTM Link Builder** | Create, manage, and audit tracked campaign links |
| **Topic Cluster Generator** | Plan content series around pillar topics |

---

## Features

### 🤖 AI Content Generation
- Generate SEO-optimized articles based on your brand voice
- Create content series around pillar topics
- Get AI-powered topic suggestions tailored to your niche
- Automatic keyword integration and optimization

### 🔍 Website Scraping & Analysis
- Download and analyze content from any website
- Learn brand voice and style patterns
- Extract metadata, keywords, and content structure
- Discover content gaps and opportunities

### 📊 SEO Analysis & Scoring
- Comprehensive SEO scoring (0-100) for all content
- Actionable optimization recommendations
- Keyword density and placement analysis
- Readability scoring and heading structure review

### 🔗 UTM Link Management
- Generate tracked links with consistent UTM parameters
- Define channel-specific defaults and naming conventions
- Maintain a searchable link library
- Export links for reporting and auditing
- Enforce UTM policies across your organization

### 👥 Team Features
- User authentication and account management
- Centralized content and link libraries
- Consistent branding across all generated content

---

## Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/hallstephenj/rev-content-tools.git
cd rev-content-tools/SEO-tool

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Run the application
python app.py
```

The application will be available at `http://localhost:5000`

---

## Tools Guide

### SEO Content Generator

Create high-quality, SEO-optimized content at scale:

1. **Single Article**: Enter a topic, target keywords, and desired word count
2. **Topic Ideas**: Generate AI-powered topic suggestions for your niche
3. **Content Series**: Create multiple related articles around a pillar topic

Each piece of generated content includes:
- Full article with proper heading structure
- Meta description
- SEO score and optimization recommendations
- Keyword analysis

### Website Scraper

Build your content intelligence by analyzing existing websites:

1. Enter a website URL
2. Set the maximum pages to scrape
3. The scraper automatically discovers pages via links and sitemaps
4. Content is extracted, cleaned, and stored for analysis

Use cases:
- Analyze your own site to understand content patterns
- Research competitor content strategies
- Build a reference library for AI training

### UTM Link Builder

Maintain consistent campaign tracking across all channels:

1. **Set Policies**: Define your organization's UTM naming conventions
2. **Configure Channels**: Set up default parameters for each marketing channel
3. **Generate Links**: Create tracked URLs with auto-filled defaults
4. **Library**: Search and manage all generated links
5. **Audit**: Review link creation history and usage

---

## Configuration

Create a `.env` file with the following variables:

```bash
# Required
OPENAI_API_KEY=your_openai_api_key

# Optional
FLASK_SECRET_KEY=your_secret_key
FLASK_ENV=development
DATABASE_URL=sqlite:///seo_content.db
```

---

## Project Structure

```
SEO-tool/
├── app.py                 # Flask web application
├── config.py              # Configuration settings
├── models.py              # Database models
├── scraper.py             # Website content scraper
├── content_generator.py   # AI content generation
├── seo_analyzer.py        # SEO analysis engine
├── requirements.txt       # Python dependencies
├── templates/
│   ├── base.html          # Base template
│   ├── index.html         # Dashboard
│   ├── scrape.html        # Scraper interface
│   ├── generate.html      # Content generator
│   ├── analyze.html       # SEO analyzer
│   └── utm/               # UTM tool templates
│       ├── index.html
│       ├── generate.html
│       ├── library.html
│       ├── policy.html
│       ├── channels.html
│       └── audit.html
└── wsgi.py                # Production WSGI entry point
```

---

## SEO Scoring Methodology

Content is evaluated across six dimensions:

| Factor | Weight | Criteria |
|--------|--------|----------|
| Word Count | 20 pts | Comprehensive content (1000+ words) |
| Title | 15 pts | Optimal length (50-60 characters) |
| Meta Description | 15 pts | Optimal length (150-160 characters) |
| Heading Structure | 20 pts | Proper H2/H3 hierarchy |
| Keyword Usage | 15 pts | Natural density (0.5-2.5%) |
| Readability | 15 pts | Flesch reading ease score |

**Score Interpretation:**
- **70-100**: Excellent — ready to publish
- **50-69**: Good — minor optimizations recommended
- **0-49**: Needs work — review recommendations

---

## Deployment

### Railway (Recommended)

This project is configured for one-click Railway deployment:

1. Connect your GitHub repository to Railway
2. Set environment variables:
   - `FLASK_SECRET_KEY` (required)
   - `OPENAI_API_KEY` (required for AI features)
   - `DATABASE_URL` (optional — defaults to SQLite)

3. Deploy!

**Note**: For persistent data on Railway, attach a Volume or use Railway Postgres.

### Manual Deployment

```bash
gunicorn wsgi:app --bind 0.0.0.0:5000 --workers 2 --threads 4
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard with statistics |
| `/scrape` | GET, POST | Website scraper |
| `/scraped-content` | GET | View scraped content |
| `/generate` | GET, POST | Content generator |
| `/generate-topics` | POST | Generate topic ideas |
| `/generate-series` | POST | Generate content series |
| `/generated-content` | GET | View generated content |
| `/analyze` | POST | Analyze content for SEO |
| `/utm` | GET | UTM tool dashboard |
| `/utm/generate` | GET, POST | Generate tracked links |
| `/utm/library` | GET | Link library |
| `/utm/policy` | GET, POST | UTM policy settings |
| `/utm/channels` | GET, POST | Channel configuration |
| `/utm/export` | GET | Export links as CSV |
| `/api/stats` | GET | Statistics (JSON) |

---

## Roadmap

- [ ] Multi-model AI support (Claude, Gemini)
- [ ] WordPress/CMS integrations
- [ ] Content calendar and scheduling
- [ ] Advanced keyword research
- [ ] A/B headline testing
- [ ] Social media integration
- [ ] Multi-language support
- [ ] Team collaboration features

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## About Reverent Content Co.

We help businesses create content that connects. Rev Content Tools is our internal toolkit, now available to the content marketing community.

**Questions?** Open an issue or reach out at [reverentcontent.co](https://reverentcontent.co)

---

*Built with Flask, OpenAI, and a passion for great content.*
