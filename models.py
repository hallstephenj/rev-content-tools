from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from config import Config
import hashlib
import hmac

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

Base = declarative_base()

def _check_password_hash_compat(pwhash: str, password: str) -> bool:
    """
    Compatibility wrapper around Werkzeug password hashes.

    Werkzeug 3 defaults to `scrypt`, but some Python builds (notably the macOS
    Command Line Tools Python linked against LibreSSL) may not provide
    `hashlib.scrypt`, which breaks `werkzeug.security.check_password_hash`.

    - For pbkdf2 hashes, delegate to Werkzeug directly.
    - For scrypt hashes, use hashlib.scrypt when available, otherwise fall back
      to `cryptography`'s Scrypt implementation.
    """
    if not pwhash:
        return False

    try:
        method, salt, hashval = pwhash.split("$", 2)
    except ValueError:
        # Not a valid Werkzeug hash format.
        return False

    if method.startswith("scrypt") and not hasattr(hashlib, "scrypt"):
        # Parse method: "scrypt" or "scrypt:n:r:p"
        parts = method.split(":")
        if len(parts) == 1:
            n, r, p = 2**15, 8, 1
        elif len(parts) == 4:
            try:
                n, r, p = map(int, parts[1:])
            except ValueError:
                return False
        else:
            return False

        try:
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        except Exception:
            # Can't verify legacy scrypt hashes without either hashlib.scrypt or cryptography.
            return False

        salt_b = salt.encode("utf-8")
        password_b = password.encode("utf-8")

        # Werkzeug/CPython default dklen for hashlib.scrypt is 64 when not specified.
        kdf = Scrypt(salt=salt_b, length=64, n=n, r=r, p=p)
        derived = kdf.derive(password_b).hex()
        return hmac.compare_digest(derived, hashval)

    # For pbkdf2, or scrypt when hashlib.scrypt is available, use Werkzeug.
    return check_password_hash(pwhash, password)


class User(Base, UserMixin):
    """User model for authentication"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scraped_content = relationship('ScrapedContent', backref='user', lazy=True)
    generated_content = relationship('GeneratedContent', backref='user', lazy=True)
    topic_clusters = relationship('TopicCluster', backref='user', lazy=True)
    settings = relationship('AppSetting', backref='user', lazy=True)

    def set_password(self, password):
        # Use PBKDF2 explicitly to avoid relying on hashlib.scrypt, which is
        # missing in some Python builds (see _check_password_hash_compat).
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        return _check_password_hash_compat(self.password_hash, password)

    def __repr__(self):
        return f"<User(username='{self.username}')>"


class ScrapedContent(Base):
    """Model for storing scraped website content"""
    __tablename__ = 'scraped_content'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    url = Column(String(500), nullable=False)
    title = Column(String(500))
    content = Column(Text, nullable=False)
    meta_description = Column(Text)
    keywords = Column(Text)
    word_count = Column(Integer)
    scraped_at = Column(DateTime, default=datetime.utcnow)
    domain = Column(String(255))

    def __repr__(self):
        return f"<ScrapedContent(url='{self.url}', title='{self.title}')>"


class GeneratedContent(Base):
    """Model for storing AI-generated content"""
    __tablename__ = 'generated_content'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=False)
    keywords = Column(Text)
    meta_description = Column(Text)
    word_count = Column(Integer)
    seo_score = Column(Float)
    source_urls = Column(Text)
    generated_at = Column(DateTime, default=datetime.utcnow)
    topic = Column(String(500))

    def __repr__(self):
        return f"<GeneratedContent(title='{self.title}', seo_score={self.seo_score})>"


class TopicCluster(Base):
    """Model for storing topic cluster strategies"""
    __tablename__ = 'topic_clusters'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=False)
    subdirectory = Column(String(255))
    num_samples = Column(Integer)
    generated_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<TopicCluster(title='{self.title}')>"


class AppSetting(Base):
    """Simple key/value settings store for app configuration."""
    __tablename__ = 'app_settings'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    key = Column(String(255), nullable=False)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AppSetting(key='{self.key}')>"


# ============== UTM Tool Models ==============

class UTMPolicy(Base):
    """UTM taxonomy rules and allowed values"""
    __tablename__ = 'utm_policies'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    # JSON: {"sources": [...], "mediums": [...], "campaigns": [...]}
    allowed_sources = Column(Text)  # JSON array of allowed source values
    allowed_mediums = Column(Text)  # JSON array of allowed medium values
    allowed_campaigns = Column(Text)  # JSON array of allowed campaign values
    require_content = Column(Integer, default=0)  # 1 = required, 0 = optional
    require_term = Column(Integer, default=0)
    naming_convention = Column(String(50), default='lowercase-hyphens')  # lowercase-hyphens, lowercase-underscores, etc.
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<UTMPolicy(user_id={self.user_id})>"


class ChannelDefault(Base):
    """Channel to source/medium default mappings"""
    __tablename__ = 'channel_defaults'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    channel_name = Column(String(100), nullable=False)  # e.g., "LinkedIn", "Newsletter"
    default_source = Column(String(100), nullable=False)  # e.g., "linkedin"
    default_medium = Column(String(100), nullable=False)  # e.g., "social"
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ChannelDefault(channel='{self.channel_name}')>"


class TrackedLink(Base):
    """Link library storing all generated UTM links"""
    __tablename__ = 'tracked_links'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # The canonical/base URL
    canonical_url = Column(String(2000), nullable=False)
    
    # UTM parameters
    utm_source = Column(String(255), nullable=False)
    utm_medium = Column(String(255), nullable=False)
    utm_campaign = Column(String(255), nullable=False)
    utm_content = Column(String(255))
    utm_term = Column(String(255))
    
    # The full generated URL with UTMs
    full_url = Column(Text, nullable=False)
    
    # Optional short link
    short_url = Column(String(500))
    
    # Metadata
    channel = Column(String(100))  # The channel this was created for
    description = Column(Text)  # Optional description/notes
    asset_name = Column(String(500))  # Name of the asset this points to
    
    # Tracking
    created_by = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Usage tracking (JSON array of where this link is used)
    usage_references = Column(Text)  # JSON: [{"type": "post", "id": 123, "name": "..."}]

    def __repr__(self):
        return f"<TrackedLink(campaign='{self.utm_campaign}', source='{self.utm_source}')>"


class UTMAuditLog(Base):
    """Audit trail for UTM changes"""
    __tablename__ = 'utm_audit_log'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    action = Column(String(50), nullable=False)  # created, updated, deleted, policy_changed
    entity_type = Column(String(50), nullable=False)  # link, policy, channel
    entity_id = Column(Integer)
    
    # What changed
    old_value = Column(Text)  # JSON of old state
    new_value = Column(Text)  # JSON of new state
    
    # Who and when
    changed_by = Column(String(100))
    changed_at = Column(DateTime, default=datetime.utcnow)
    
    # Downstream impact
    affected_items = Column(Text)  # JSON: list of affected link IDs, etc.

    def __repr__(self):
        return f"<UTMAuditLog(action='{self.action}', entity='{self.entity_type}')>"


# ============== CDJ Tool Models ==============

class MarketContext(Base):
    """Global market context - one per user"""
    __tablename__ = 'cdj_market_context'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    # Step 1: Market Context (GLOBAL)
    industry_category = Column(String(500))
    business_model = Column(String(100))  # B2B, B2C, hybrid
    purchase_size_range = Column(String(200))

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<MarketContext(user_id={self.user_id}, industry='{self.industry_category}')>"


class CustomerSegment(Base):
    """Customer segment with all decision journey data"""
    __tablename__ = 'cdj_customer_segments'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    # Step 2: Segment identification
    segment_name = Column(String(255), nullable=False)
    is_primary = Column(Integer, default=0)  # 1 = primary, 0 = secondary

    # Step 3: Segment Definition
    description = Column(Text)  # One-paragraph description
    core_jtbd = Column(Text)  # Job-to-be-done
    primary_problem = Column(Text)

    # Step 4: Economic Reality
    purchasing_power = Column(String(255))
    budget_ownership = Column(String(255))
    price_sensitivity = Column(String(100))  # High, Medium, Low

    # Step 5: Decision Drivers
    decision_criteria_1 = Column(String(500))
    decision_criteria_2 = Column(String(500))
    decision_criteria_3 = Column(String(500))
    emotional_driver = Column(Text)
    rational_driver = Column(Text)

    # Step 6: Objections & Friction
    primary_objection = Column(Text)
    secondary_objection = Column(Text)
    biggest_blocker = Column(Text)

    # Step 7: Decision Journey
    trigger_moment = Column(Text)
    evaluation_behavior = Column(Text)
    decision_ending_factor = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<CustomerSegment(name='{self.segment_name}', primary={self.is_primary})>"


# ============== GTM Tool Models ==============

class GTMCampaign(Base):
    """Go-To-Market Campaign - main campaign record"""
    __tablename__ = 'gtm_campaigns'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    # Step 1: Campaign Type & Intent
    campaign_type = Column(String(100))  # report, webinar, tool, video, launch, other
    primary_goal = Column(String(100))  # lead_gen, pipeline, education, activation, authority

    # Step 2: Content Title
    primary_title = Column(String(500))
    working_title = Column(String(500))

    # Step 3: Subtitle
    subtitle = Column(Text)

    # Step 4: Formal Campaign Name
    internal_campaign_name = Column(String(500))
    campaign_code = Column(String(100))

    # Step 6: Campaign Overview
    overview_paragraph_1 = Column(Text)  # Context + problem
    overview_paragraph_2 = Column(Text)  # What this delivers

    # Step 7: Logistics (for webinars, launches, live events)
    event_date = Column(String(100))
    event_time = Column(String(100))
    event_timezone = Column(String(100))
    event_duration = Column(String(100))

    # Step 8: Key Messages
    key_message_relevance = Column(Text)  # What's happening right now that makes this relevant?
    key_message_why_now = Column(Text)  # Why does this matter now?
    key_message_takeaway = Column(Text)  # What will someone walk away with?
    key_message_questions = Column(Text)  # What questions will this answer?

    # Step 9: Distribution Channels
    channels_owned = Column(Text)  # JSON array
    channels_earned = Column(Text)  # JSON array
    channels_paid = Column(Text)  # JSON array

    # Step 11: Calls to Action
    primary_cta = Column(String(500))
    secondary_cta = Column(String(500))
    post_conversion_step = Column(Text)

    # Wizard tracking
    current_step = Column(Integer, default=1)
    wizard_completed = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    contributors = relationship('GTMContributor', backref='campaign', lazy=True, cascade='all, delete-orphan')
    personas = relationship('GTMPersona', backref='campaign', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"<GTMCampaign(title='{self.primary_title}', type='{self.campaign_type}')>"


class GTMContributor(Base):
    """Contributors/Guests for a GTM Campaign (Step 5)"""
    __tablename__ = 'gtm_contributors'

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('gtm_campaigns.id'), nullable=False)

    name = Column(String(255), nullable=False)
    title = Column(String(255))
    organization = Column(String(255))
    role = Column(String(100))  # host, guest, expert

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<GTMContributor(name='{self.name}', role='{self.role}')>"


class GTMPersona(Base):
    """Audience Personas for a GTM Campaign (Step 10)"""
    __tablename__ = 'gtm_personas'

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('gtm_campaigns.id'), nullable=False)

    # Link to CDJ segment (optional)
    cdj_segment_id = Column(Integer, ForeignKey('cdj_customer_segments.id'), nullable=True)

    persona_name = Column(String(255), nullable=False)
    core_pain = Column(Text)
    messaging_angle = Column(Text)
    objection_to_address = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<GTMPersona(name='{self.persona_name}')>"


class Database:
    """Database manager"""

    def __init__(self, database_url=None):
        self.database_url = database_url or Config.DATABASE_URL
        self.engine = create_engine(self.database_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self):
        """Get a new database session"""
        return self.Session()

    # User methods
    def create_user(self, username, email, password):
        """Create a new user"""
        session = self.get_session()
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            session.add(user)
            session.commit()
            return user.id
        except Exception as e:
            session.rollback()
            print(f"Error creating user: {e}")
            return None
        finally:
            session.close()

    def get_user_by_id(self, user_id):
        """Get user by ID"""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                session.expunge(user)
            return user
        finally:
            session.close()

    def get_user_by_username(self, username):
        """Get user by username"""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(username=username).first()
            if user:
                session.expunge(user)
            return user
        finally:
            session.close()

    def get_user_by_email(self, email):
        """Get user by email"""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(email=email).first()
            if user:
                session.expunge(user)
            return user
        finally:
            session.close()

    def authenticate_user(self, username, password):
        """Authenticate user and return user object if valid"""
        session = self.get_session()
        try:
            user = session.query(User).filter_by(username=username).first()
            if user and user.check_password(password):
                # Opportunistic migration: if the stored hash is a legacy scrypt
                # hash (which may not be supported by the current Python build),
                # rehash to pbkdf2 after a successful login.
                if (user.password_hash or "").startswith("scrypt:"):
                    user.set_password(password)
                    session.commit()
                session.expunge(user)
                return user
            return None
        finally:
            session.close()

    # Scraped content methods (now with user filtering)
    def add_scraped_content(self, url, title, content, meta_description=None,
                           keywords=None, word_count=None, domain=None, user_id=None):
        """Add scraped content to database"""
        session = self.get_session()
        try:
            existing = session.query(ScrapedContent).filter_by(url=url, user_id=user_id).first()
            if existing:
                existing.title = title
                existing.content = content
                existing.meta_description = meta_description
                existing.keywords = keywords
                existing.word_count = word_count
                existing.scraped_at = datetime.utcnow()
            else:
                scraped = ScrapedContent(
                    url=url,
                    title=title,
                    content=content,
                    meta_description=meta_description,
                    keywords=keywords,
                    word_count=word_count,
                    domain=domain,
                    user_id=user_id
                )
                session.add(scraped)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error adding scraped content: {e}")
            return False
        finally:
            session.close()

    def add_generated_content(self, title, content, keywords=None, meta_description=None,
                             word_count=None, seo_score=None, source_urls=None, topic=None, user_id=None):
        """Add generated content to database"""
        session = self.get_session()
        try:
            generated = GeneratedContent(
                title=title,
                content=content,
                keywords=keywords,
                meta_description=meta_description,
                word_count=word_count,
                seo_score=seo_score,
                source_urls=source_urls,
                topic=topic,
                user_id=user_id
            )
            session.add(generated)
            session.commit()
            return generated.id
        except Exception as e:
            session.rollback()
            print(f"Error adding generated content: {e}")
            return None
        finally:
            session.close()

    def get_all_scraped_content(self, user_id=None):
        """Get all scraped content for a user"""
        session = self.get_session()
        try:
            query = session.query(ScrapedContent)
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.all()
        finally:
            session.close()

    def get_all_generated_content(self, user_id=None):
        """Get all generated content for a user"""
        session = self.get_session()
        try:
            query = session.query(GeneratedContent)
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.order_by(GeneratedContent.generated_at.desc()).all()
        finally:
            session.close()

    def add_topic_cluster(self, title, content, subdirectory=None, num_samples=None, user_id=None):
        """Add a topic cluster to database"""
        session = self.get_session()
        try:
            cluster = TopicCluster(
                title=title,
                content=content,
                subdirectory=subdirectory,
                num_samples=num_samples,
                user_id=user_id
            )
            session.add(cluster)
            session.commit()
            return cluster.id
        except Exception as e:
            session.rollback()
            print(f"Error adding topic cluster: {e}")
            return None
        finally:
            session.close()

    def get_all_topic_clusters(self, user_id=None):
        """Get all topic clusters for a user"""
        session = self.get_session()
        try:
            query = session.query(TopicCluster)
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.order_by(TopicCluster.generated_at.desc()).all()
        finally:
            session.close()

    def get_topic_cluster_by_id(self, cluster_id, user_id=None):
        """Get a topic cluster by ID"""
        session = self.get_session()
        try:
            query = session.query(TopicCluster).filter_by(id=cluster_id)
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.first()
        finally:
            session.close()

    def get_scraped_by_domain(self, domain, user_id=None):
        """Get scraped content by domain"""
        session = self.get_session()
        try:
            query = session.query(ScrapedContent).filter_by(domain=domain)
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.all()
        finally:
            session.close()

    def url_exists(self, url, user_id=None):
        """Check if a URL already exists in the scraped content database"""
        session = self.get_session()
        try:
            query = session.query(ScrapedContent).filter_by(url=url)
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.first() is not None
        finally:
            session.close()

    def search_scraped_content(self, query, limit=20, user_id=None):
        """Search scraped content by matching query terms"""
        session = self.get_session()
        try:
            base_query = session.query(ScrapedContent)
            if user_id:
                base_query = base_query.filter_by(user_id=user_id)
            
            if not query or not query.strip():
                return base_query.order_by(ScrapedContent.scraped_at.desc()).limit(limit).all()
            
            terms = [t.strip().lower() for t in query.replace(',', ' ').split() if t.strip()]
            results = base_query.all()
            
            scored = []
            for item in results:
                score = 0
                searchable = ' '.join([
                    (item.title or '').lower(),
                    (item.keywords or '').lower(),
                    (item.meta_description or '').lower(),
                    (item.content or '')[:500].lower()
                ])
                for term in terms:
                    if term in searchable:
                        if term in (item.title or '').lower():
                            score += 3
                        elif term in (item.keywords or '').lower():
                            score += 2
                        else:
                            score += 1
                if score > 0:
                    scored.append((score, item))
            
            scored.sort(key=lambda x: x[0], reverse=True)
            return [item for score, item in scored[:limit]]
        finally:
            session.close()

    def get_scraped_by_ids(self, ids, user_id=None):
        """Get scraped content by list of IDs"""
        session = self.get_session()
        try:
            if not ids:
                return []
            query = session.query(ScrapedContent).filter(ScrapedContent.id.in_(ids))
            if user_id:
                query = query.filter_by(user_id=user_id)
            return query.all()
        finally:
            session.close()

    def get_scraped_by_subdirectory(self, subdirectory, user_id=None):
        """Get scraped content filtered by subdirectory"""
        session = self.get_session()
        try:
            query = session.query(ScrapedContent)
            if user_id:
                query = query.filter_by(user_id=user_id)
            all_content = query.all()
            
            if not subdirectory:
                return all_content
            
            filtered = []
            for item in all_content:
                from urllib.parse import urlparse
                parsed = urlparse(item.url)
                path = parsed.path
                if path.startswith(subdirectory) or path.startswith(subdirectory.rstrip('/')):
                    filtered.append(item)
            return filtered
        finally:
            session.close()

    def get_setting(self, key, default=None, user_id=None):
        """Get a setting value by key."""
        session = self.get_session()
        try:
            query = session.query(AppSetting).filter_by(key=key)
            if user_id:
                query = query.filter_by(user_id=user_id)
            setting = query.first()
            return setting.value if setting and setting.value is not None else default
        finally:
            session.close()

    def set_setting(self, key, value, user_id=None):
        """Create/update a setting value by key."""
        session = self.get_session()
        try:
            query = session.query(AppSetting).filter_by(key=key)
            if user_id:
                query = query.filter_by(user_id=user_id)
            setting = query.first()
            
            if setting:
                setting.value = value
                setting.updated_at = datetime.utcnow()
            else:
                session.add(AppSetting(key=key, value=value, user_id=user_id))
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error saving setting {key}: {e}")
            return False
        finally:
            session.close()

    def delete_setting(self, key, user_id=None):
        """Delete a setting by key."""
        session = self.get_session()
        try:
            query = session.query(AppSetting).filter_by(key=key)
            if user_id:
                query = query.filter_by(user_id=user_id)
            setting = query.first()
            if setting:
                session.delete(setting)
                session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error deleting setting {key}: {e}")
            return False
        finally:
            session.close()

    # ============== UTM Tool Methods ==============

    def get_utm_policy(self, user_id):
        """Get UTM policy for a user"""
        session = self.get_session()
        try:
            return session.query(UTMPolicy).filter_by(user_id=user_id).first()
        finally:
            session.close()

    def save_utm_policy(self, user_id, allowed_sources=None, allowed_mediums=None,
                        allowed_campaigns=None, require_content=0, require_term=0,
                        naming_convention='lowercase-hyphens'):
        """Create or update UTM policy"""
        session = self.get_session()
        try:
            policy = session.query(UTMPolicy).filter_by(user_id=user_id).first()
            if policy:
                policy.allowed_sources = allowed_sources
                policy.allowed_mediums = allowed_mediums
                policy.allowed_campaigns = allowed_campaigns
                policy.require_content = require_content
                policy.require_term = require_term
                policy.naming_convention = naming_convention
                policy.updated_at = datetime.utcnow()
            else:
                policy = UTMPolicy(
                    user_id=user_id,
                    allowed_sources=allowed_sources,
                    allowed_mediums=allowed_mediums,
                    allowed_campaigns=allowed_campaigns,
                    require_content=require_content,
                    require_term=require_term,
                    naming_convention=naming_convention
                )
                session.add(policy)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error saving UTM policy: {e}")
            return False
        finally:
            session.close()

    def get_channel_defaults(self, user_id):
        """Get all channel defaults for a user"""
        session = self.get_session()
        try:
            return session.query(ChannelDefault).filter_by(user_id=user_id).order_by(ChannelDefault.channel_name).all()
        finally:
            session.close()

    def add_channel_default(self, user_id, channel_name, default_source, default_medium):
        """Add a new channel default"""
        session = self.get_session()
        try:
            channel = ChannelDefault(
                user_id=user_id,
                channel_name=channel_name,
                default_source=default_source,
                default_medium=default_medium
            )
            session.add(channel)
            session.commit()
            return channel.id
        except Exception as e:
            session.rollback()
            print(f"Error adding channel default: {e}")
            return None
        finally:
            session.close()

    def update_channel_default(self, channel_id, user_id, channel_name, default_source, default_medium):
        """Update a channel default"""
        session = self.get_session()
        try:
            channel = session.query(ChannelDefault).filter_by(id=channel_id, user_id=user_id).first()
            if channel:
                channel.channel_name = channel_name
                channel.default_source = default_source
                channel.default_medium = default_medium
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error updating channel default: {e}")
            return False
        finally:
            session.close()

    def delete_channel_default(self, channel_id, user_id):
        """Delete a channel default"""
        session = self.get_session()
        try:
            channel = session.query(ChannelDefault).filter_by(id=channel_id, user_id=user_id).first()
            if channel:
                session.delete(channel)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error deleting channel default: {e}")
            return False
        finally:
            session.close()

    def add_tracked_link(self, user_id, canonical_url, utm_source, utm_medium, utm_campaign,
                         full_url, utm_content=None, utm_term=None, short_url=None,
                         channel=None, description=None, asset_name=None, created_by=None):
        """Add a new tracked link to the library"""
        session = self.get_session()
        try:
            link = TrackedLink(
                user_id=user_id,
                canonical_url=canonical_url,
                utm_source=utm_source,
                utm_medium=utm_medium,
                utm_campaign=utm_campaign,
                utm_content=utm_content,
                utm_term=utm_term,
                full_url=full_url,
                short_url=short_url,
                channel=channel,
                description=description,
                asset_name=asset_name,
                created_by=created_by
            )
            session.add(link)
            session.commit()
            return link.id
        except Exception as e:
            session.rollback()
            print(f"Error adding tracked link: {e}")
            return None
        finally:
            session.close()

    def get_all_tracked_links(self, user_id):
        """Get all tracked links for a user"""
        session = self.get_session()
        try:
            return session.query(TrackedLink).filter_by(user_id=user_id).order_by(TrackedLink.created_at.desc()).all()
        finally:
            session.close()

    def get_tracked_link_by_id(self, link_id, user_id):
        """Get a specific tracked link"""
        session = self.get_session()
        try:
            return session.query(TrackedLink).filter_by(id=link_id, user_id=user_id).first()
        finally:
            session.close()

    def search_tracked_links(self, user_id, query=None, channel=None, campaign=None, 
                             date_from=None, date_to=None, limit=100):
        """Search tracked links with filters"""
        session = self.get_session()
        try:
            base_query = session.query(TrackedLink).filter_by(user_id=user_id)
            
            if channel:
                base_query = base_query.filter_by(channel=channel)
            if campaign:
                base_query = base_query.filter(TrackedLink.utm_campaign.ilike(f'%{campaign}%'))
            if date_from:
                base_query = base_query.filter(TrackedLink.created_at >= date_from)
            if date_to:
                base_query = base_query.filter(TrackedLink.created_at <= date_to)
            if query:
                search = f'%{query}%'
                base_query = base_query.filter(
                    (TrackedLink.canonical_url.ilike(search)) |
                    (TrackedLink.utm_campaign.ilike(search)) |
                    (TrackedLink.asset_name.ilike(search)) |
                    (TrackedLink.description.ilike(search))
                )
            
            return base_query.order_by(TrackedLink.created_at.desc()).limit(limit).all()
        finally:
            session.close()

    def delete_tracked_link(self, link_id, user_id):
        """Delete a tracked link"""
        session = self.get_session()
        try:
            link = session.query(TrackedLink).filter_by(id=link_id, user_id=user_id).first()
            if link:
                session.delete(link)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error deleting tracked link: {e}")
            return False
        finally:
            session.close()

    def add_utm_audit_log(self, user_id, action, entity_type, entity_id=None,
                          old_value=None, new_value=None, changed_by=None, affected_items=None):
        """Add an audit log entry"""
        session = self.get_session()
        try:
            log = UTMAuditLog(
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                old_value=old_value,
                new_value=new_value,
                changed_by=changed_by,
                affected_items=affected_items
            )
            session.add(log)
            session.commit()
            return log.id
        except Exception as e:
            session.rollback()
            print(f"Error adding audit log: {e}")
            return None
        finally:
            session.close()

    def get_utm_audit_logs(self, user_id, limit=100):
        """Get audit logs for a user"""
        session = self.get_session()
        try:
            return session.query(UTMAuditLog).filter_by(user_id=user_id).order_by(UTMAuditLog.changed_at.desc()).limit(limit).all()
        finally:
            session.close()

    def get_utm_stats(self, user_id):
        """Get UTM link statistics"""
        session = self.get_session()
        try:
            total_links = session.query(TrackedLink).filter_by(user_id=user_id).count()

            # Get unique campaigns
            campaigns = session.query(TrackedLink.utm_campaign).filter_by(user_id=user_id).distinct().count()

            # Get unique channels
            channels = session.query(TrackedLink.channel).filter_by(user_id=user_id).filter(TrackedLink.channel.isnot(None)).distinct().count()

            return {
                'total_links': total_links,
                'unique_campaigns': campaigns,
                'unique_channels': channels
            }
        finally:
            session.close()

    # ============== CDJ Tool Methods ==============

    def get_market_context(self, user_id):
        """Get market context for a user"""
        session = self.get_session()
        try:
            return session.query(MarketContext).filter_by(user_id=user_id).first()
        finally:
            session.close()

    def save_market_context(self, user_id, industry_category, business_model, purchase_size_range):
        """Create or update market context"""
        session = self.get_session()
        try:
            context = session.query(MarketContext).filter_by(user_id=user_id).first()
            if context:
                context.industry_category = industry_category
                context.business_model = business_model
                context.purchase_size_range = purchase_size_range
                context.updated_at = datetime.utcnow()
            else:
                context = MarketContext(
                    user_id=user_id,
                    industry_category=industry_category,
                    business_model=business_model,
                    purchase_size_range=purchase_size_range
                )
                session.add(context)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error saving market context: {e}")
            return False
        finally:
            session.close()

    def get_customer_segments(self, user_id):
        """Get all customer segments for a user"""
        session = self.get_session()
        try:
            return session.query(CustomerSegment).filter_by(user_id=user_id).order_by(CustomerSegment.is_primary.desc(), CustomerSegment.segment_name).all()
        finally:
            session.close()

    def get_customer_segment_by_id(self, segment_id, user_id):
        """Get a specific customer segment"""
        session = self.get_session()
        try:
            return session.query(CustomerSegment).filter_by(id=segment_id, user_id=user_id).first()
        finally:
            session.close()

    def create_customer_segment(self, user_id, segment_name, is_primary=0):
        """Create a new customer segment"""
        session = self.get_session()
        try:
            segment = CustomerSegment(
                user_id=user_id,
                segment_name=segment_name,
                is_primary=is_primary
            )
            session.add(segment)
            session.commit()
            return segment.id
        except Exception as e:
            session.rollback()
            print(f"Error creating customer segment: {e}")
            return None
        finally:
            session.close()

    def update_customer_segment(self, segment_id, user_id, **kwargs):
        """Update a customer segment with any fields"""
        session = self.get_session()
        try:
            segment = session.query(CustomerSegment).filter_by(id=segment_id, user_id=user_id).first()
            if segment:
                for key, value in kwargs.items():
                    if hasattr(segment, key):
                        setattr(segment, key, value)
                segment.updated_at = datetime.utcnow()
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error updating customer segment: {e}")
            return False
        finally:
            session.close()

    def delete_customer_segment(self, segment_id, user_id):
        """Delete a customer segment"""
        session = self.get_session()
        try:
            segment = session.query(CustomerSegment).filter_by(id=segment_id, user_id=user_id).first()
            if segment:
                session.delete(segment)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error deleting customer segment: {e}")
            return False
        finally:
            session.close()

    def cdj_wizard_completed(self, user_id):
        """Check if CDJ wizard has been completed (has market context and at least one segment)"""
        session = self.get_session()
        try:
            has_context = session.query(MarketContext).filter_by(user_id=user_id).first() is not None
            has_segments = session.query(CustomerSegment).filter_by(user_id=user_id).count() > 0
            return has_context and has_segments
        finally:
            session.close()

    # ============== GTM Tool Methods ==============

    def create_gtm_campaign(self, user_id):
        """Create a new GTM campaign and return its ID"""
        session = self.get_session()
        try:
            campaign = GTMCampaign(user_id=user_id)
            session.add(campaign)
            session.commit()
            return campaign.id
        except Exception as e:
            session.rollback()
            print(f"Error creating GTM campaign: {e}")
            return None
        finally:
            session.close()

    def get_gtm_campaign(self, campaign_id, user_id):
        """Get a GTM campaign by ID"""
        session = self.get_session()
        try:
            campaign = session.query(GTMCampaign).filter_by(id=campaign_id, user_id=user_id).first()
            if campaign:
                session.expunge(campaign)
            return campaign
        finally:
            session.close()

    def get_gtm_campaigns(self, user_id):
        """Get all GTM campaigns for a user"""
        session = self.get_session()
        try:
            return session.query(GTMCampaign).filter_by(user_id=user_id).order_by(GTMCampaign.updated_at.desc()).all()
        finally:
            session.close()

    def get_current_gtm_campaign(self, user_id):
        """Get the most recent incomplete GTM campaign, or None"""
        session = self.get_session()
        try:
            campaign = session.query(GTMCampaign).filter_by(
                user_id=user_id, wizard_completed=0
            ).order_by(GTMCampaign.updated_at.desc()).first()
            if campaign:
                session.expunge(campaign)
            return campaign
        finally:
            session.close()

    def update_gtm_campaign(self, campaign_id, user_id, **kwargs):
        """Update a GTM campaign with arbitrary fields"""
        session = self.get_session()
        try:
            campaign = session.query(GTMCampaign).filter_by(id=campaign_id, user_id=user_id).first()
            if campaign:
                for key, value in kwargs.items():
                    if hasattr(campaign, key):
                        setattr(campaign, key, value)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error updating GTM campaign: {e}")
            return False
        finally:
            session.close()

    def delete_gtm_campaign(self, campaign_id, user_id):
        """Delete a GTM campaign"""
        session = self.get_session()
        try:
            campaign = session.query(GTMCampaign).filter_by(id=campaign_id, user_id=user_id).first()
            if campaign:
                session.delete(campaign)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error deleting GTM campaign: {e}")
            return False
        finally:
            session.close()

    # GTM Contributors
    def add_gtm_contributor(self, campaign_id, name, title=None, organization=None, role=None):
        """Add a contributor to a GTM campaign"""
        session = self.get_session()
        try:
            contributor = GTMContributor(
                campaign_id=campaign_id,
                name=name,
                title=title,
                organization=organization,
                role=role
            )
            session.add(contributor)
            session.commit()
            return contributor.id
        except Exception as e:
            session.rollback()
            print(f"Error adding GTM contributor: {e}")
            return None
        finally:
            session.close()

    def get_gtm_contributors(self, campaign_id):
        """Get all contributors for a campaign"""
        session = self.get_session()
        try:
            return session.query(GTMContributor).filter_by(campaign_id=campaign_id).all()
        finally:
            session.close()

    def delete_gtm_contributor(self, contributor_id, campaign_id):
        """Delete a contributor"""
        session = self.get_session()
        try:
            contributor = session.query(GTMContributor).filter_by(id=contributor_id, campaign_id=campaign_id).first()
            if contributor:
                session.delete(contributor)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error deleting GTM contributor: {e}")
            return False
        finally:
            session.close()

    # GTM Personas
    def add_gtm_persona(self, campaign_id, persona_name, core_pain=None, messaging_angle=None, 
                        objection_to_address=None, cdj_segment_id=None):
        """Add a persona to a GTM campaign"""
        session = self.get_session()
        try:
            persona = GTMPersona(
                campaign_id=campaign_id,
                persona_name=persona_name,
                core_pain=core_pain,
                messaging_angle=messaging_angle,
                objection_to_address=objection_to_address,
                cdj_segment_id=cdj_segment_id
            )
            session.add(persona)
            session.commit()
            return persona.id
        except Exception as e:
            session.rollback()
            print(f"Error adding GTM persona: {e}")
            return None
        finally:
            session.close()

    def get_gtm_personas(self, campaign_id):
        """Get all personas for a campaign"""
        session = self.get_session()
        try:
            return session.query(GTMPersona).filter_by(campaign_id=campaign_id).all()
        finally:
            session.close()

    def update_gtm_persona(self, persona_id, campaign_id, **kwargs):
        """Update a persona"""
        session = self.get_session()
        try:
            persona = session.query(GTMPersona).filter_by(id=persona_id, campaign_id=campaign_id).first()
            if persona:
                for key, value in kwargs.items():
                    if hasattr(persona, key):
                        setattr(persona, key, value)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error updating GTM persona: {e}")
            return False
        finally:
            session.close()

    def delete_gtm_persona(self, persona_id, campaign_id):
        """Delete a persona"""
        session = self.get_session()
        try:
            persona = session.query(GTMPersona).filter_by(id=persona_id, campaign_id=campaign_id).first()
            if persona:
                session.delete(persona)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            print(f"Error deleting GTM persona: {e}")
            return False
        finally:
            session.close()

    def get_completed_gtm_campaigns(self, user_id):
        """Get all completed GTM campaigns for a user"""
        session = self.get_session()
        try:
            return session.query(GTMCampaign).filter_by(
                user_id=user_id, wizard_completed=1
            ).order_by(GTMCampaign.updated_at.desc()).all()
        finally:
            session.close()
