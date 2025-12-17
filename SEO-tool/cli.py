#!/usr/bin/env python3
"""
Command-line interface for AI SEO Content Generator
"""

import argparse
import sys
from scraper import scrape_website
from content_generator import AIContentGenerator
from seo_analyzer import SEOAnalyzer
from models import Database
import json


def main():
    parser = argparse.ArgumentParser(
        description='AI SEO Content Generator - CLI Tool'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scrape command
    scrape_parser = subparsers.add_parser('scrape', help='Scrape a website')
    scrape_parser.add_argument('url', help='Website URL to scrape')
    scrape_parser.add_argument('--max-pages', type=int, default=100,
                              help='Maximum pages to scrape (default: 100)')

    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate content')
    generate_parser.add_argument('topic', help='Topic or title for the article')
    generate_parser.add_argument('--keywords', help='Comma-separated keywords')
    generate_parser.add_argument('--words', type=int, default=1500,
                                help='Target word count (default: 1500)')

    # Topics command
    topics_parser = subparsers.add_parser('topics', help='Generate topic ideas')
    topics_parser.add_argument('--count', type=int, default=10,
                              help='Number of topics (default: 10)')
    topics_parser.add_argument('--niche', help='Niche or industry')

    # Series command
    series_parser = subparsers.add_parser('series', help='Generate content series')
    series_parser.add_argument('topic', help='Main topic for the series')
    series_parser.add_argument('--count', type=int, default=5,
                              help='Number of posts (default: 5)')

    # List command
    list_parser = subparsers.add_parser('list', help='List content')
    list_parser.add_argument('type', choices=['scraped', 'generated'],
                           help='Type of content to list')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show statistics')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    if args.command == 'scrape':
        print(f"Scraping {args.url}...")
        num_pages = scrape_website(args.url, max_pages=args.max_pages)
        print(f"✓ Successfully scraped {num_pages} pages")

    elif args.command == 'generate':
        keywords = []
        if args.keywords:
            keywords = [k.strip() for k in args.keywords.split(',')]

        print(f"Generating content on: {args.topic}")
        generator = AIContentGenerator()
        content_id = generator.generate_and_save_content(
            topic=args.topic,
            keywords=keywords,
            word_count=args.words
        )

        if content_id:
            print(f"✓ Content generated successfully (ID: {content_id})")
        else:
            print("✗ Failed to generate content")
            sys.exit(1)

    elif args.command == 'topics':
        print(f"Generating {args.count} topic ideas...")
        generator = AIContentGenerator()
        topics = generator.generate_topic_ideas(
            num_topics=args.count,
            niche=args.niche
        )

        if topics:
            print(f"\n✓ Generated {len(topics)} topic ideas:\n")
            for i, topic in enumerate(topics, 1):
                print(f"{i}. {topic['title']}")
                print(f"   {topic['description']}")
                print(f"   Keywords: {', '.join(topic['target_keywords'])}\n")
        else:
            print("✗ Failed to generate topics")
            sys.exit(1)

    elif args.command == 'series':
        print(f"Generating content series on: {args.topic}")
        generator = AIContentGenerator()
        content_ids = generator.generate_content_series(
            main_topic=args.topic,
            num_posts=args.count
        )

        if content_ids:
            print(f"✓ Generated {len(content_ids)} articles")
            for content_id in content_ids:
                print(f"   - ID: {content_id}")
        else:
            print("✗ Failed to generate series")
            sys.exit(1)

    elif args.command == 'list':
        db = Database()
        if args.type == 'scraped':
            content = db.get_all_scraped_content()
            print(f"\nScraped Content ({len(content)} pages):\n")
            for item in content:
                print(f"• {item.title or 'No Title'}")
                print(f"  URL: {item.url}")
                print(f"  Words: {item.word_count or 0}\n")
        else:
            content = db.get_all_generated_content()
            print(f"\nGenerated Content ({len(content)} articles):\n")
            for item in content:
                print(f"• {item.title}")
                print(f"  ID: {item.id}")
                print(f"  Words: {item.word_count or 0}")
                if item.seo_score:
                    print(f"  SEO Score: {item.seo_score}/100")
                print()

    elif args.command == 'stats':
        db = Database()
        session = db.get_session()
        try:
            from models import ScrapedContent, GeneratedContent

            scraped_count = session.query(ScrapedContent).count()
            generated_count = session.query(GeneratedContent).count()
            domains = session.query(ScrapedContent.domain).distinct().all()
            unique_domains = len([d[0] for d in domains if d[0]])

            print("\nStatistics:")
            print(f"  Scraped Pages: {scraped_count}")
            print(f"  Generated Articles: {generated_count}")
            print(f"  Unique Domains: {unique_domains}\n")
        finally:
            session.close()


if __name__ == '__main__':
    main()
