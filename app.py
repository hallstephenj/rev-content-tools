from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
import json
from config import Config
from scraper import scrape_website
from content_generator import AIContentGenerator
from seo_analyzer import SEOAnalyzer
from models import Database, User
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db = Database()
seo_analyzer = SEOAnalyzer()


@login_manager.user_loader
def load_user(user_id):
    return db.get_user_by_id(int(user_id))


# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = db.authenticate_user(username, password)
        if user:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            error = 'Invalid username or password'
    
    return render_template('login.html', error=error)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    error = None
    username = ''
    email = ''
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if len(username) < 3:
            error = 'Username must be at least 3 characters'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters'
        elif db.get_user_by_username(username):
            error = 'Username already taken'
        elif db.get_user_by_email(email):
            error = 'Email already registered'
        else:
            user_id = db.create_user(username, email, password)
            if user_id:
                user = db.get_user_by_id(user_id)
                login_user(user)
                return redirect(url_for('index'))
            else:
                error = 'Failed to create account'
    
    return render_template('signup.html', error=error, username=username, email=email)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Main app routes
@app.route('/')
@login_required
def index():
    """Home page"""
    stats = get_stats()
    return render_template('index.html', stats=stats)


@app.route('/campaign')
@login_required
def campaign():
    """Campaign Tool - Coming Soon"""
    return render_template('coming_soon.html', 
        title='Campaign Tool',
        tool_name='Campaign Tool',
        tool_id='campaign',
        avatar='CT'
    )


@app.route('/account')
@login_required
def account():
    """Backward-compat redirect to global Settings"""
    return redirect(url_for('settings'))


@app.route('/scrape', methods=['GET', 'POST'])
@login_required
def scrape():
    """Scrape website page"""
    if request.method == 'POST':
        url = request.form.get('url')
        max_pages = int(request.form.get('max_pages', 100))
        skip_existing = request.form.get('skip_existing') == 'on'

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Start scraping in background thread with user_id
        user_id = current_user.id
        thread = threading.Thread(
            target=scrape_website,
            args=(url, max_pages, skip_existing, user_id)
        )
        thread.start()

        return jsonify({
            'message': 'Scraping started',
            'url': url,
            'max_pages': max_pages,
            'skip_existing': skip_existing
        })

    return render_template('scrape.html')


@app.route('/analyze')
@login_required
def analyze():
    """Analyze page with various SEO analysis tools"""
    from urllib.parse import urlparse
    content = db.get_all_scraped_content(user_id=current_user.id)
    
    subdir_counts = {}
    for item in content:
        parsed = urlparse(item.url)
        path_parts = parsed.path.strip('/').split('/')
        if path_parts and path_parts[0]:
            subdir = '/' + path_parts[0] + '/'
            subdir_counts[subdir] = subdir_counts.get(subdir, 0) + 1

    major_subdirs = sorted([s for s, c in subdir_counts.items() if c >= 3])
    minor_subdirs = sorted([s for s, c in subdir_counts.items() if c < 3])
    total_pages = len(content)

    return render_template(
        'analyze.html',
        major_subdirs=major_subdirs,
        minor_subdirs=minor_subdirs,
        subdir_counts=subdir_counts,
        total_pages=total_pages
    )


@app.route('/api/analyze-clusters', methods=['POST'])
@login_required
def api_analyze_clusters():
    """Analyze article titles to surface implicit topic clusters"""
    subdirectory = request.form.get('subdirectory', '').strip()
    
    if subdirectory == 'all':
        subdirectory = None

    try:
        generator = AIContentGenerator(user_id=current_user.id)
        result = generator.analyze_implicit_clusters(subdirectory=subdirectory)

        if result:
            return jsonify({
                'success': True,
                'pillars': result['pillars'],
                'analysis': result['analysis']
            })
        else:
            return jsonify({'error': 'No scraped content found for the selected filter.'}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        error_msg = str(e)
        if 'context_length_exceeded' in error_msg.lower() or 'token' in error_msg.lower():
            error_msg = 'Too many articles to analyze at once. Try selecting a smaller subdirectory.'
        return jsonify({'error': error_msg}), 500


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    def mask_secret(value: str) -> str:
        if not value:
            return ''
        prefix = value[:3]
        suffix = value[-4:] if len(value) >= 4 else value
        return f"{prefix}…{suffix}"

    user_id = current_user.id

    if request.method == 'POST':
        api_key = (request.form.get('openai_api_key') or '').strip()
        clear_key = request.form.get('clear_openai_api_key') == 'on'
        brand_voice = (request.form.get('brand_voice') or '').strip()

        if clear_key or not api_key:
            db.delete_setting('OPENAI_API_KEY', user_id=user_id)
        else:
            db.set_setting('OPENAI_API_KEY', api_key, user_id=user_id)

        if brand_voice:
            db.set_setting('BRAND_VOICE', brand_voice, user_id=user_id)
        else:
            db.delete_setting('BRAND_VOICE', user_id=user_id)

        return redirect(url_for('settings', saved=1))

    stored_key = db.get_setting('OPENAI_API_KEY', user_id=user_id)
    env_key = Config.OPENAI_API_KEY
    brand_voice = db.get_setting('BRAND_VOICE', '', user_id=user_id)

    active_key = stored_key or env_key
    key_source = 'database' if stored_key else ('env' if env_key else None)

    saved = request.args.get('saved')

    return render_template(
        'settings.html',
        saved=saved,
        openai_key_masked=mask_secret(active_key) if active_key else None,
        openai_key_source=key_source,
        has_db_key=stored_key is not None,
        brand_voice=brand_voice,
    )


@app.route('/scraped-content')
@login_required
def scraped_content():
    """View scraped content"""
    from urllib.parse import urlparse
    content = db.get_all_scraped_content(user_id=current_user.id)

    subdir_counts = {}
    for item in content:
        parsed = urlparse(item.url)
        path_parts = parsed.path.strip('/').split('/')
        if path_parts and path_parts[0]:
            subdir = '/' + path_parts[0] + '/'
            subdir_counts[subdir] = subdir_counts.get(subdir, 0) + 1

    major_subdirs = sorted([s for s, c in subdir_counts.items() if c >= 3])
    minor_subdirs = sorted([s for s, c in subdir_counts.items() if c < 3])

    return render_template(
        'scraped_content.html',
        content=content,
        major_subdirs=major_subdirs,
        minor_subdirs=minor_subdirs,
        subdir_counts=subdir_counts
    )


@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    """Generate content page"""
    if request.method == 'POST':
        topic = request.form.get('topic')
        keywords = request.form.get('keywords', '').split(',')
        keywords = [k.strip() for k in keywords if k.strip()]
        word_count = int(request.form.get('word_count', 1500))
        custom_instructions = (request.form.get('custom_instructions') or '').strip()
        
        context_ids_str = request.form.get('context_ids', '')
        context_ids = [int(id.strip()) for id in context_ids_str.split(',') if id.strip().isdigit()]

        if not topic:
            return jsonify({'error': 'Title is required'}), 400

        try:
            generator = AIContentGenerator(user_id=current_user.id)
            content_id = generator.generate_and_save_content(
                topic=topic,
                keywords=keywords,
                word_count=word_count,
                custom_instructions=custom_instructions,
                context_ids=context_ids if context_ids else None
            )

            if content_id:
                return jsonify({
                    'success': True,
                    'content_id': content_id,
                    'title': topic,
                    'message': 'Content generated successfully'
                })
            else:
                return jsonify({'error': 'Failed to generate content'}), 500

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    from urllib.parse import urlparse
    content = db.get_all_scraped_content(user_id=current_user.id)
    subdir_counts = {}
    for item in content:
        parsed = urlparse(item.url)
        path_parts = parsed.path.strip('/').split('/')
        if path_parts and path_parts[0]:
            subdir = '/' + path_parts[0] + '/'
            subdir_counts[subdir] = subdir_counts.get(subdir, 0) + 1

    major_subdirs = sorted([s for s, c in subdir_counts.items() if c >= 3])
    minor_subdirs = sorted([s for s, c in subdir_counts.items() if c < 3])
    total_pages = len(content)

    return render_template(
        'generate.html',
        major_subdirs=major_subdirs,
        minor_subdirs=minor_subdirs,
        subdir_counts=subdir_counts,
        total_pages=total_pages
    )


@app.route('/api/search-content', methods=['GET'])
@login_required
def search_content():
    """Search scraped content for context picker"""
    query = request.args.get('q', '')
    limit = int(request.args.get('limit', 20))
    
    results = db.search_scraped_content(query, limit=limit, user_id=current_user.id)
    
    return jsonify({
        'results': [
            {
                'id': item.id,
                'title': item.title or '(No title)',
                'url': item.url,
                'domain': item.domain,
                'word_count': item.word_count,
                'keywords': item.keywords,
                'meta_description': (item.meta_description or '')[:150]
            }
            for item in results
        ]
    })


@app.route('/generate-topics', methods=['POST'])
@login_required
def generate_topics():
    """Generate topic ideas"""
    num_topics = int(request.form.get('num_topics', 10))
    niche = request.form.get('niche', '')

    try:
        generator = AIContentGenerator(user_id=current_user.id)
        topics = generator.generate_topic_ideas(
            num_topics=num_topics,
            niche=niche if niche else None
        )

        return jsonify({'topics': topics})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generate-series', methods=['POST'])
@login_required
def generate_series():
    """Generate a series of related posts"""
    main_topic = request.form.get('main_topic')
    num_posts = int(request.form.get('num_posts', 5))

    if not main_topic:
        return jsonify({'error': 'Main topic is required'}), 400

    try:
        generator = AIContentGenerator(user_id=current_user.id)
        thread = threading.Thread(
            target=generator.generate_content_series,
            args=(main_topic, num_posts)
        )
        thread.start()

        return jsonify({
            'message': f'Generating {num_posts} posts on "{main_topic}"',
            'status': 'started'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generate-topic-clusters', methods=['POST'])
@login_required
def generate_topic_clusters():
    """Generate topic cluster strategy from scraped content"""
    num_samples = int(request.form.get('num_samples', 50))
    subdirectory = request.form.get('subdirectory', '').strip()
    
    if subdirectory == 'all':
        subdirectory = None

    try:
        generator = AIContentGenerator(user_id=current_user.id)
        result = generator.generate_topic_clusters(num_samples=num_samples, subdirectory=subdirectory)

        if result:
            return jsonify({
                'success': True,
                'cluster_id': result['id'],
                'clusters': result['content']
            })
        else:
            return jsonify({'error': 'Failed to generate topic clusters. Ensure you have scraped content.'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generated-content')
@login_required
def generated_content():
    """View all generated content"""
    content = db.get_all_generated_content(user_id=current_user.id)
    topic_clusters = db.get_all_topic_clusters(user_id=current_user.id)
    return render_template('generated_content.html', content=content, topic_clusters=topic_clusters)


@app.route('/topic-cluster/<int:cluster_id>')
@login_required
def view_topic_cluster(cluster_id):
    """View specific topic cluster"""
    cluster = db.get_topic_cluster_by_id(cluster_id, user_id=current_user.id)
    if not cluster:
        return "Topic cluster not found", 404
    return render_template('view_topic_cluster.html', cluster=cluster)


@app.route('/generated/<int:content_id>')
@login_required
def view_generated(content_id):
    """View specific generated content"""
    session = db.get_session()
    try:
        from models import GeneratedContent
        content = session.query(GeneratedContent).filter_by(id=content_id, user_id=current_user.id).first()

        if not content:
            return "Content not found", 404

        try:
            keywords = json.loads(content.keywords) if content.keywords else []
        except:
            keywords = []

        seo_report = seo_analyzer.generate_seo_report(
            content=content.content,
            title=content.title,
            meta_description=content.meta_description or '',
            keywords=keywords
        )

        return render_template('view_generated.html', content=content, seo_report=seo_report)
    finally:
        session.close()


@app.route('/api/seo-analyze', methods=['POST'])
@login_required
def seo_analyze():
    """Analyze content for SEO"""
    content = request.form.get('content', '')
    title = request.form.get('title', '')
    keywords = request.form.get('keywords', '').split(',')
    keywords = [k.strip() for k in keywords if k.strip()]

    report = seo_analyzer.generate_seo_report(
        content=content,
        title=title,
        keywords=keywords
    )

    return jsonify(report)


@app.route('/api/stats')
@login_required
def api_stats():
    """Get statistics API"""
    stats = get_stats()
    return jsonify(stats)


def get_stats():
    """Get application statistics for current user"""
    session = db.get_session()
    try:
        from models import ScrapedContent, GeneratedContent

        user_id = current_user.id if current_user.is_authenticated else None

        scraped_query = session.query(ScrapedContent)
        generated_query = session.query(GeneratedContent)
        
        if user_id:
            scraped_query = scraped_query.filter_by(user_id=user_id)
            generated_query = generated_query.filter_by(user_id=user_id)

        scraped_count = scraped_query.count()
        generated_count = generated_query.count()

        domains = scraped_query.with_entities(ScrapedContent.domain).distinct().all()
        unique_domains = len([d[0] for d in domains if d[0]])

        return {
            'scraped_pages': scraped_count,
            'generated_articles': generated_count,
            'unique_domains': unique_domains
        }
    finally:
        session.close()


# ============== UTM Tool Routes ==============

@app.route('/utm')
@login_required
def utm_index():
    """UTM Tool home page"""
    stats = db.get_utm_stats(current_user.id)
    recent_links = db.search_tracked_links(current_user.id, limit=5)
    channels = db.get_channel_defaults(current_user.id)
    return render_template('utm/index.html', stats=stats, recent_links=recent_links, channels=channels)


@app.route('/utm/policy', methods=['GET', 'POST'])
@login_required
def utm_policy():
    """UTM policy configuration"""
    if request.method == 'POST':
        # Parse form data
        sources = request.form.get('allowed_sources', '').strip()
        mediums = request.form.get('allowed_mediums', '').strip()
        campaigns = request.form.get('allowed_campaigns', '').strip()
        require_content = 1 if request.form.get('require_content') == 'on' else 0
        require_term = 1 if request.form.get('require_term') == 'on' else 0
        naming = request.form.get('naming_convention', 'lowercase-hyphens')
        
        # Convert to JSON arrays
        sources_json = json.dumps([s.strip() for s in sources.split('\n') if s.strip()]) if sources else '[]'
        mediums_json = json.dumps([m.strip() for m in mediums.split('\n') if m.strip()]) if mediums else '[]'
        campaigns_json = json.dumps([c.strip() for c in campaigns.split('\n') if c.strip()]) if campaigns else '[]'
        
        db.save_utm_policy(
            user_id=current_user.id,
            allowed_sources=sources_json,
            allowed_mediums=mediums_json,
            allowed_campaigns=campaigns_json,
            require_content=require_content,
            require_term=require_term,
            naming_convention=naming
        )
        
        # Log the change
        db.add_utm_audit_log(
            user_id=current_user.id,
            action='policy_updated',
            entity_type='policy',
            changed_by=current_user.username
        )
        
        return redirect(url_for('utm_policy', saved=1))
    
    policy = db.get_utm_policy(current_user.id)
    
    # Parse JSON arrays back to newline-separated strings for the form
    sources_list = []
    mediums_list = []
    campaigns_list = []
    
    if policy:
        try:
            sources_list = json.loads(policy.allowed_sources or '[]')
            mediums_list = json.loads(policy.allowed_mediums or '[]')
            campaigns_list = json.loads(policy.allowed_campaigns or '[]')
        except:
            pass
    
    return render_template('utm/policy.html',
        policy=policy,
        sources='\n'.join(sources_list),
        mediums='\n'.join(mediums_list),
        campaigns='\n'.join(campaigns_list),
        saved=request.args.get('saved')
    )


@app.route('/utm/channels', methods=['GET', 'POST'])
@login_required
def utm_channels():
    """Manage channel defaults"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            channel_name = request.form.get('channel_name', '').strip()
            default_source = request.form.get('default_source', '').strip()
            default_medium = request.form.get('default_medium', '').strip()
            
            if channel_name and default_source and default_medium:
                db.add_channel_default(current_user.id, channel_name, default_source, default_medium)
                db.add_utm_audit_log(
                    user_id=current_user.id,
                    action='created',
                    entity_type='channel',
                    changed_by=current_user.username,
                    new_value=json.dumps({'channel': channel_name, 'source': default_source, 'medium': default_medium})
                )
        
        elif action == 'delete':
            channel_id = request.form.get('channel_id')
            if channel_id:
                db.delete_channel_default(int(channel_id), current_user.id)
        
        return redirect(url_for('utm_channels'))
    
    channels = db.get_channel_defaults(current_user.id)
    return render_template('utm/channels.html', channels=channels)


@app.route('/utm/generate', methods=['GET', 'POST'])
@login_required
def utm_generate():
    """Generate a new tracked link"""
    from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
    
    if request.method == 'POST':
        canonical_url = request.form.get('canonical_url', '').strip()
        utm_source = request.form.get('utm_source', '').strip()
        utm_medium = request.form.get('utm_medium', '').strip()
        utm_campaign = request.form.get('utm_campaign', '').strip()
        utm_content = request.form.get('utm_content', '').strip() or None
        utm_term = request.form.get('utm_term', '').strip() or None
        channel = request.form.get('channel', '').strip() or None
        asset_name = request.form.get('asset_name', '').strip() or None
        description = request.form.get('description', '').strip() or None
        
        # Validate required fields
        if not canonical_url or not utm_source or not utm_medium or not utm_campaign:
            return jsonify({'error': 'URL, source, medium, and campaign are required'}), 400
        
        # Apply naming convention
        policy = db.get_utm_policy(current_user.id)
        naming = policy.naming_convention if policy else 'lowercase-hyphens'
        
        def apply_naming(value):
            if not value:
                return value
            if naming == 'lowercase-hyphens':
                return value.lower().replace(' ', '-').replace('_', '-')
            elif naming == 'lowercase-underscores':
                return value.lower().replace(' ', '_').replace('-', '_')
            elif naming == 'lowercase':
                return value.lower().replace(' ', '')
            return value
        
        utm_source = apply_naming(utm_source)
        utm_medium = apply_naming(utm_medium)
        utm_campaign = apply_naming(utm_campaign)
        if utm_content:
            utm_content = apply_naming(utm_content)
        if utm_term:
            utm_term = apply_naming(utm_term)
        
        # Build the full URL
        params = {
            'utm_source': utm_source,
            'utm_medium': utm_medium,
            'utm_campaign': utm_campaign
        }
        if utm_content:
            params['utm_content'] = utm_content
        if utm_term:
            params['utm_term'] = utm_term
        
        # Parse the canonical URL and add UTM params
        parsed = urlparse(canonical_url)
        existing_params = parse_qs(parsed.query)
        existing_params.update(params)
        
        new_query = urlencode(existing_params, doseq=True)
        full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))
        
        # Save to database
        link_id = db.add_tracked_link(
            user_id=current_user.id,
            canonical_url=canonical_url,
            utm_source=utm_source,
            utm_medium=utm_medium,
            utm_campaign=utm_campaign,
            utm_content=utm_content,
            utm_term=utm_term,
            full_url=full_url,
            channel=channel,
            asset_name=asset_name,
            description=description,
            created_by=current_user.username
        )
        
        if link_id:
            db.add_utm_audit_log(
                user_id=current_user.id,
                action='created',
                entity_type='link',
                entity_id=link_id,
                changed_by=current_user.username
            )
            return jsonify({
                'success': True,
                'link_id': link_id,
                'full_url': full_url
            })
        else:
            return jsonify({'error': 'Failed to save link'}), 500
    
    # GET request - show the form
    channels = db.get_channel_defaults(current_user.id)
    policy = db.get_utm_policy(current_user.id)
    
    # Parse allowed values for dropdowns
    sources = []
    mediums = []
    campaigns = []
    if policy:
        try:
            sources = json.loads(policy.allowed_sources or '[]')
            mediums = json.loads(policy.allowed_mediums or '[]')
            campaigns = json.loads(policy.allowed_campaigns or '[]')
        except:
            pass
    
    return render_template('utm/generate.html',
        channels=channels,
        policy=policy,
        sources=sources,
        mediums=mediums,
        campaigns=campaigns
    )


@app.route('/utm/library')
@login_required
def utm_library():
    """View link library"""
    query = request.args.get('q', '')
    channel = request.args.get('channel', '')
    campaign = request.args.get('campaign', '')
    
    links = db.search_tracked_links(
        user_id=current_user.id,
        query=query if query else None,
        channel=channel if channel else None,
        campaign=campaign if campaign else None
    )
    
    channels = db.get_channel_defaults(current_user.id)
    stats = db.get_utm_stats(current_user.id)
    
    return render_template('utm/library.html',
        links=links,
        channels=channels,
        stats=stats,
        query=query,
        selected_channel=channel,
        selected_campaign=campaign
    )


@app.route('/utm/link/<int:link_id>')
@login_required
def utm_view_link(link_id):
    """View a specific link"""
    link = db.get_tracked_link_by_id(link_id, current_user.id)
    if not link:
        return "Link not found", 404
    return render_template('utm/view_link.html', link=link)


@app.route('/utm/link/<int:link_id>/delete', methods=['POST'])
@login_required
def utm_delete_link(link_id):
    """Delete a tracked link"""
    link = db.get_tracked_link_by_id(link_id, current_user.id)
    if link:
        db.add_utm_audit_log(
            user_id=current_user.id,
            action='deleted',
            entity_type='link',
            entity_id=link_id,
            changed_by=current_user.username,
            old_value=json.dumps({'url': link.full_url, 'campaign': link.utm_campaign})
        )
        db.delete_tracked_link(link_id, current_user.id)
    return redirect(url_for('utm_library'))


@app.route('/utm/export')
@login_required
def utm_export():
    """Export links as CSV"""
    import csv
    from io import StringIO
    from flask import Response
    
    links = db.get_all_tracked_links(current_user.id)
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Header row
    writer.writerow([
        'ID', 'Canonical URL', 'Full URL', 'Source', 'Medium', 'Campaign',
        'Content', 'Term', 'Channel', 'Asset Name', 'Description',
        'Created By', 'Created At'
    ])
    
    # Data rows
    for link in links:
        writer.writerow([
            link.id,
            link.canonical_url,
            link.full_url,
            link.utm_source,
            link.utm_medium,
            link.utm_campaign,
            link.utm_content or '',
            link.utm_term or '',
            link.channel or '',
            link.asset_name or '',
            link.description or '',
            link.created_by or '',
            link.created_at.strftime('%Y-%m-%d %H:%M:%S') if link.created_at else ''
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=utm_links_export.csv'}
    )


@app.route('/utm/audit')
@login_required
def utm_audit():
    """View audit log"""
    logs = db.get_utm_audit_logs(current_user.id)
    return render_template('utm/audit.html', logs=logs)


@app.route('/api/utm/channel-defaults/<int:channel_id>')
@login_required
def api_channel_defaults(channel_id):
    """Get channel defaults for auto-fill"""
    session = db.get_session()
    try:
        from models import ChannelDefault
        channel = session.query(ChannelDefault).filter_by(id=channel_id, user_id=current_user.id).first()
        if channel:
            return jsonify({
                'source': channel.default_source,
                'medium': channel.default_medium
            })
        return jsonify({'error': 'Channel not found'}), 404
    finally:
        session.close()


# ============== CDJ Tool Routes ==============

@app.route('/cdj')
@login_required
def cdj_index():
    """CDJ Tool home page"""
    wizard_completed = db.cdj_wizard_completed(current_user.id)

    if wizard_completed:
        market_context = db.get_market_context(current_user.id)
        segments = db.get_customer_segments(current_user.id)

        segment_count = len(segments)
        primary_count = sum(1 for s in segments if s.is_primary)
        secondary_count = segment_count - primary_count

        return render_template('cdj/index.html',
            wizard_completed=True,
            market_context=market_context,
            segments=segments,
            segment_count=segment_count,
            primary_count=primary_count,
            secondary_count=secondary_count
        )
    else:
        return render_template('cdj/index.html', wizard_completed=False)


@app.route('/cdj/wizard/start')
@login_required
def cdj_wizard_start():
    """Start or restart the CDJ wizard"""
    return redirect(url_for('cdj_wizard_step', step=1))


@app.route('/cdj/wizard/<int:step>', methods=['GET', 'POST'])
@login_required
def cdj_wizard_step(step):
    """Handle wizard steps"""
    if step < 1 or step > 7:
        return redirect(url_for('cdj_wizard_step', step=1))

    # Step 1: Market Context
    if step == 1:
        if request.method == 'POST':
            industry_category = request.form.get('industry_category', '').strip()
            business_model = request.form.get('business_model', '').strip()
            purchase_size_range = request.form.get('purchase_size_range', '').strip()

            if industry_category and business_model and purchase_size_range:
                db.save_market_context(
                    current_user.id,
                    industry_category,
                    business_model,
                    purchase_size_range
                )
                return redirect(url_for('cdj_wizard_step', step=2))

        market_context = db.get_market_context(current_user.id)
        return render_template('cdj/wizard.html', step=1, market_context=market_context)

    # Step 2: Define Segments
    elif step == 2:
        if request.method == 'POST':
            segment_name = request.form.get('segment_name', '').strip()
            is_primary = 1 if request.form.get('is_primary') == '1' else 0

            if segment_name:
                db.create_customer_segment(current_user.id, segment_name, is_primary)
                return redirect(url_for('cdj_wizard_step', step=2))

        market_context = db.get_market_context(current_user.id)
        segments = db.get_customer_segments(current_user.id)
        return render_template('cdj/wizard.html', step=2, market_context=market_context, segments=segments)

    # Steps 3-7: Per-segment data collection
    else:
        segments = db.get_customer_segments(current_user.id)

        if not segments:
            return redirect(url_for('cdj_wizard_step', step=2))

        # Determine which segment we're working on based on session or first incomplete
        segment_index = int(request.args.get('segment_index', 0))
        if segment_index >= len(segments):
            segment_index = 0

        current_segment = segments[segment_index]

        if request.method == 'POST':
            segment_id = int(request.form.get('segment_id'))
            update_data = {}

            # Step 3: Segment Definition
            if step == 3:
                update_data['description'] = request.form.get('description', '').strip()
                update_data['core_jtbd'] = request.form.get('core_jtbd', '').strip()
                update_data['primary_problem'] = request.form.get('primary_problem', '').strip()

            # Step 4: Economic Reality
            elif step == 4:
                update_data['purchasing_power'] = request.form.get('purchasing_power', '').strip()
                update_data['budget_ownership'] = request.form.get('budget_ownership', '').strip()
                update_data['price_sensitivity'] = request.form.get('price_sensitivity', '').strip()

            # Step 5: Decision Drivers
            elif step == 5:
                update_data['decision_criteria_1'] = request.form.get('decision_criteria_1', '').strip()
                update_data['decision_criteria_2'] = request.form.get('decision_criteria_2', '').strip()
                update_data['decision_criteria_3'] = request.form.get('decision_criteria_3', '').strip()
                update_data['emotional_driver'] = request.form.get('emotional_driver', '').strip()
                update_data['rational_driver'] = request.form.get('rational_driver', '').strip()

            # Step 6: Objections & Friction
            elif step == 6:
                update_data['primary_objection'] = request.form.get('primary_objection', '').strip()
                update_data['secondary_objection'] = request.form.get('secondary_objection', '').strip()
                update_data['biggest_blocker'] = request.form.get('biggest_blocker', '').strip()

            # Step 7: Decision Journey
            elif step == 7:
                update_data['trigger_moment'] = request.form.get('trigger_moment', '').strip()
                update_data['evaluation_behavior'] = request.form.get('evaluation_behavior', '').strip()
                update_data['decision_ending_factor'] = request.form.get('decision_ending_factor', '').strip()

            db.update_customer_segment(segment_id, current_user.id, **update_data)

            # Determine next step
            if step == 7:
                # Move to next segment or complete
                if segment_index < len(segments) - 1:
                    return redirect(url_for('cdj_wizard_step', step=3, segment_index=segment_index + 1))
                else:
                    return redirect(url_for('cdj_index'))
            else:
                return redirect(url_for('cdj_wizard_step', step=step + 1, segment_index=segment_index))

        return render_template('cdj/wizard.html',
            step=step,
            current_segment=current_segment,
            segment_index=segment_index,
            total_segments=len(segments)
        )


@app.route('/cdj/wizard/2/delete/<int:segment_id>', methods=['POST'])
@login_required
def cdj_wizard_delete_segment(segment_id):
    """Delete a segment during wizard"""
    db.delete_customer_segment(segment_id, current_user.id)
    return redirect(url_for('cdj_wizard_step', step=2))


@app.route('/cdj/market-context', methods=['GET', 'POST'])
@login_required
def cdj_market_context():
    """View and edit market context"""
    if request.method == 'POST':
        industry_category = request.form.get('industry_category', '').strip()
        business_model = request.form.get('business_model', '').strip()
        purchase_size_range = request.form.get('purchase_size_range', '').strip()

        if industry_category and business_model and purchase_size_range:
            db.save_market_context(
                current_user.id,
                industry_category,
                business_model,
                purchase_size_range
            )
            return redirect(url_for('cdj_market_context', saved=1))

    market_context = db.get_market_context(current_user.id)
    saved = request.args.get('saved')

    return render_template('cdj/market_context.html',
        market_context=market_context,
        saved=saved
    )


@app.route('/cdj/segments')
@login_required
def cdj_segments():
    """List all customer segments"""
    segments = db.get_customer_segments(current_user.id)
    return render_template('cdj/segments.html', segments=segments)


@app.route('/cdj/segment/new', methods=['GET', 'POST'])
@login_required
def cdj_segment_new():
    """Create a new customer segment"""
    if request.method == 'POST':
        segment_name = request.form.get('segment_name', '').strip()

        if not segment_name:
            return render_template('cdj/segment.html',
                segment=None,
                error='Segment name is required'
            )

        is_primary = 1 if request.form.get('is_primary') == '1' else 0

        # Create the segment
        segment_id = db.create_customer_segment(current_user.id, segment_name, is_primary)

        if segment_id:
            # Update with all the other fields
            update_data = {
                'description': request.form.get('description', '').strip() or None,
                'core_jtbd': request.form.get('core_jtbd', '').strip() or None,
                'primary_problem': request.form.get('primary_problem', '').strip() or None,
                'purchasing_power': request.form.get('purchasing_power', '').strip() or None,
                'budget_ownership': request.form.get('budget_ownership', '').strip() or None,
                'price_sensitivity': request.form.get('price_sensitivity', '').strip() or None,
                'decision_criteria_1': request.form.get('decision_criteria_1', '').strip() or None,
                'decision_criteria_2': request.form.get('decision_criteria_2', '').strip() or None,
                'decision_criteria_3': request.form.get('decision_criteria_3', '').strip() or None,
                'emotional_driver': request.form.get('emotional_driver', '').strip() or None,
                'rational_driver': request.form.get('rational_driver', '').strip() or None,
                'primary_objection': request.form.get('primary_objection', '').strip() or None,
                'secondary_objection': request.form.get('secondary_objection', '').strip() or None,
                'biggest_blocker': request.form.get('biggest_blocker', '').strip() or None,
                'trigger_moment': request.form.get('trigger_moment', '').strip() or None,
                'evaluation_behavior': request.form.get('evaluation_behavior', '').strip() or None,
                'decision_ending_factor': request.form.get('decision_ending_factor', '').strip() or None,
            }

            db.update_customer_segment(segment_id, current_user.id, **update_data)

            return redirect(url_for('cdj_segment_view', segment_id=segment_id, saved=1, is_new=1))
        else:
            return render_template('cdj/segment.html',
                segment=None,
                error='Failed to create segment'
            )

    return render_template('cdj/segment.html', segment=None)


@app.route('/cdj/segment/<int:segment_id>', methods=['GET', 'POST'])
@login_required
def cdj_segment_view(segment_id):
    """View and edit a customer segment"""
    segment = db.get_customer_segment_by_id(segment_id, current_user.id)

    if not segment:
        return "Segment not found", 404

    if request.method == 'POST':
        # Update all fields
        is_primary = 1 if request.form.get('is_primary') == '1' else 0

        update_data = {
            'segment_name': request.form.get('segment_name', '').strip(),
            'is_primary': is_primary,
            'description': request.form.get('description', '').strip() or None,
            'core_jtbd': request.form.get('core_jtbd', '').strip() or None,
            'primary_problem': request.form.get('primary_problem', '').strip() or None,
            'purchasing_power': request.form.get('purchasing_power', '').strip() or None,
            'budget_ownership': request.form.get('budget_ownership', '').strip() or None,
            'price_sensitivity': request.form.get('price_sensitivity', '').strip() or None,
            'decision_criteria_1': request.form.get('decision_criteria_1', '').strip() or None,
            'decision_criteria_2': request.form.get('decision_criteria_2', '').strip() or None,
            'decision_criteria_3': request.form.get('decision_criteria_3', '').strip() or None,
            'emotional_driver': request.form.get('emotional_driver', '').strip() or None,
            'rational_driver': request.form.get('rational_driver', '').strip() or None,
            'primary_objection': request.form.get('primary_objection', '').strip() or None,
            'secondary_objection': request.form.get('secondary_objection', '').strip() or None,
            'biggest_blocker': request.form.get('biggest_blocker', '').strip() or None,
            'trigger_moment': request.form.get('trigger_moment', '').strip() or None,
            'evaluation_behavior': request.form.get('evaluation_behavior', '').strip() or None,
            'decision_ending_factor': request.form.get('decision_ending_factor', '').strip() or None,
        }

        db.update_customer_segment(segment_id, current_user.id, **update_data)

        return redirect(url_for('cdj_segment_view', segment_id=segment_id, saved=1))

    saved = request.args.get('saved')
    is_new = request.args.get('is_new')

    return render_template('cdj/segment.html',
        segment=segment,
        saved=saved,
        is_new=is_new
    )


@app.route('/cdj/segment/<int:segment_id>/delete', methods=['POST'])
@login_required
def cdj_segment_delete(segment_id):
    """Delete a customer segment"""
    db.delete_customer_segment(segment_id, current_user.id)
    return redirect(url_for('cdj_segments'))


if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))

    # Local/dev convenience: default to debug unless FLASK_ENV=production.
    debug_env = os.environ.get('FLASK_DEBUG')
    if debug_env is None:
        debug = os.environ.get('FLASK_ENV', 'development') != 'production'
    else:
        debug = debug_env.strip().lower() in ('1', 'true', 'yes', 'on')

    app.run(debug=debug, host=host, port=port)
