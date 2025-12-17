from openai import OpenAI
import json
import random
from config import Config
from models import Database
import re


class AIContentGenerator:
    """AI-powered content generator using existing website content"""

    def __init__(self, api_key=None, user_id=None):
        self.db = Database()
        self.user_id = user_id
        stored_key = self.db.get_setting('OPENAI_API_KEY', user_id=user_id)
        self.api_key = api_key or stored_key or Config.OPENAI_API_KEY
        if not self.api_key:
            raise ValueError('OpenAI API key is required. Set it in Settings or in the OPENAI_API_KEY env var.')

        # OpenAI Python SDK v1.x client
        self.client = OpenAI(api_key=self.api_key)

    def get_random_content_samples(self, num_samples=5, domain=None):
        """Get random samples of scraped content for context"""
        if domain:
            all_content = self.db.get_scraped_by_domain(domain, user_id=self.user_id)
        else:
            all_content = self.db.get_all_scraped_content(user_id=self.user_id)

        if not all_content:
            return []

        # Get random samples
        sample_size = min(num_samples, len(all_content))
        samples = random.sample(all_content, sample_size)

        return samples

    def build_context_from_samples(self, samples, max_words=3000):
        """Build context string from content samples"""
        context_parts = []
        total_words = 0

        for sample in samples:
            # Add title and content
            content_text = f"Title: {sample.title}\n\n{sample.content}"
            words = len(content_text.split())

            if total_words + words > max_words:
                break

            context_parts.append(content_text)
            total_words += words

        return "\n\n---\n\n".join(context_parts)

    def generate_topic_ideas(self, num_topics=10, domain=None, niche=None):
        """Generate topic ideas based on existing content"""
        samples = self.get_random_content_samples(num_samples=10, domain=domain)

        if not samples:
            return []

        context = self.build_context_from_samples(samples)

        niche_prompt = f" in the {niche} niche" if niche else ""

        # Load brand voice from settings
        brand_voice = self.db.get_setting('BRAND_VOICE', '', user_id=self.user_id)
        brand_block = ""
        if brand_voice:
            brand_block = f"\n\nBRAND VOICE & STYLE:\n{brand_voice}\n\nEnsure topic suggestions align with this brand voice.\n"

        prompt = f"""Based on the following content from a website{niche_prompt}, generate {num_topics} new blog post topic ideas that:
1. Align with the website's existing content themes
2. Would attract the target audience
3. Are optimized for SEO and search traffic
4. Cover related but new angles
{brand_block}
Existing content:

{context}

Generate {num_topics} compelling blog post topics as a JSON array with the following format:
[
  {{
    \"title\": \"Blog post title\",
    \"description\": \"Brief description of what the post would cover\",
    \"target_keywords\": [\"keyword1\", \"keyword2\", \"keyword3\"]
  }}
]

Return ONLY the JSON array, no additional text."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a professional content strategist and SEO expert."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.8,
                max_tokens=2000,
            )

            result = (response.choices[0].message.content or "").strip()

            # Extract JSON from response
            json_match = re.search(r"\[.*\]", result, re.DOTALL)
            if json_match:
                topics = json.loads(json_match.group(0))
                return topics

            return []

        except Exception as e:
            print(f"Error generating topics: {e}")
            return []

    def generate_content(self, topic, keywords=None, word_count=1500, domain=None, custom_instructions=None, context_ids=None):
        """Generate SEO-optimized content on a given topic"""
        # Use specific content if IDs provided, otherwise random samples
        if context_ids:
            samples = self.db.get_scraped_by_ids(context_ids, user_id=self.user_id)
            print(f"Using {len(samples)} user-selected content pieces as context")
        else:
            samples = self.get_random_content_samples(num_samples=5, domain=domain)

        if not samples:
            print("Warning: No existing content found. Generating without context.")
            context = "No existing content available."
        else:
            context = self.build_context_from_samples(samples)

        keywords_str = ", ".join(keywords) if keywords else "relevant keywords"

        # Load brand voice from settings
        brand_voice = self.db.get_setting('BRAND_VOICE', '', user_id=self.user_id)
        brand_block = ""
        if brand_voice:
            brand_block = f"\n\nBRAND VOICE & STYLE:\n{brand_voice}\n"

        custom_block = ""
        if custom_instructions:
            custom_block = f"\n\nCUSTOM INSTRUCTIONS:\n{custom_instructions}\n"

        prompt = f"""You are writing a high-quality, SEO-optimized blog post for a website.
{brand_block}

EXISTING CONTENT STYLE AND CONTEXT:
{context}

ASSIGNMENT:
Write a comprehensive blog post with the following specifications:
- Title (USE EXACTLY AS PROVIDED): {topic}
- Target word count: {word_count} words
- Target keywords: {keywords_str}
- Match the writing style and tone of the existing content
- Include natural keyword integration
- Write in a way that provides genuine value to readers
- Use proper headings (H2, H3) to structure the content
- Include an engaging introduction and strong conclusion

IMPORTANT: The title field in your response MUST be exactly "{topic}" - do not modify, rephrase, or "optimize" it.
{custom_block}
Return the content in the following JSON format:
{{
  \"title\": \"{topic}\",
  \"meta_description\": \"Compelling meta description (150-160 characters)\",
  \"content\": \"Full article content in markdown format\",
  \"keywords\": [\"keyword1\", \"keyword2\", \"keyword3\"],
  \"outline\": [\"Main section 1\", \"Main section 2\", \"Main section 3\"]
}}

Return ONLY the JSON object, no additional text."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert content writer and SEO specialist who creates high-quality, engaging content.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=4000,
            )

            result = (response.choices[0].message.content or "").strip()

            # Extract JSON from response
            json_match = re.search(r"\{.*\}", result, re.DOTALL)
            if json_match:
                content_data = json.loads(json_match.group(0))
                # Force the title to be exactly what the user provided
                content_data["title"] = topic
                return content_data

            return None

        except Exception as e:
            print(f"Error generating content: {e}")
            return None

    def generate_and_save_content(self, topic, keywords=None, word_count=1500, domain=None, custom_instructions=None, context_ids=None):
        """Generate content and save it to the database"""
        print(f"Generating content for topic: {topic}")

        content_data = self.generate_content(topic, keywords, word_count, domain, custom_instructions, context_ids)

        if not content_data:
            print("Failed to generate content")
            return None

        # Calculate word count
        actual_word_count = len(content_data["content"].split())

        # Get source URLs
        samples = self.get_random_content_samples(num_samples=5, domain=domain)
        source_urls = json.dumps([s.url for s in samples])

        # Save to database
        content_id = self.db.add_generated_content(
            title=content_data["title"],
            content=content_data["content"],
            keywords=json.dumps(content_data.get("keywords", [])),
            meta_description=content_data.get("meta_description", ""),
            word_count=actual_word_count,
            source_urls=source_urls,
            topic=topic,
            user_id=self.user_id,
        )

        print(f"Content generated successfully! ID: {content_id}")
        return content_id

    def improve_existing_content(self, content_id):
        """Improve existing content with SEO suggestions"""
        # This would analyze and suggest improvements
        # Implementation for future enhancement
        pass

    def generate_content_series(self, main_topic, num_posts=5, domain=None):
        """Generate a series of related blog posts"""
        print(f"Generating {num_posts} related posts on: {main_topic}")

        # First, generate topic ideas
        topics = self.generate_topic_ideas(num_topics=num_posts, domain=domain, niche=main_topic)

        if not topics:
            print("Failed to generate topics")
            return []

        generated_ids = []
        for topic_data in topics:
            content_id = self.generate_and_save_content(
                topic=topic_data["title"],
                keywords=topic_data.get("target_keywords", []),
                domain=domain,
            )
            if content_id:
                generated_ids.append(content_id)

        print(f"\nGenerated {len(generated_ids)} posts successfully!")
        return generated_ids

    def generate_topic_clusters(self, num_samples=50, subdirectory=None):
        """Generate topic cluster strategy based on scraped content"""
        print("Generating topic clusters from scraped content...")
        if subdirectory:
            print(f"Filtering to subdirectory: {subdirectory}")

        # Get content, optionally filtered by subdirectory
        if subdirectory:
            all_content = self.db.get_scraped_by_subdirectory(subdirectory, user_id=self.user_id)
        else:
            all_content = self.db.get_all_scraped_content(user_id=self.user_id)
            
        if not all_content:
            print("No scraped content available")
            return None

        print(f"Found {len(all_content)} pages to analyze")

        # Build context from titles, keywords, and meta descriptions
        sample_size = min(num_samples, len(all_content))
        samples = random.sample(all_content, sample_size)

        content_summary = []
        for item in samples:
            entry = f"Title: {item.title or '(No title)'}"
            if item.keywords:
                entry += f"\nKeywords: {item.keywords}"
            if item.meta_description:
                entry += f"\nDescription: {item.meta_description}"
            if item.content:
                # First 300 chars of content
                entry += f"\nExcerpt: {item.content[:300]}..."
            content_summary.append(entry)

        scraped_content = "\n\n---\n\n".join(content_summary)

        system_prompt = """You are a senior SEO + content strategist.
Your task is to infer the site's core business, audience, and authority themes from raw scraped content, then construct high-leverage topic clusters."""

        user_prompt = f"""INPUT:
I will paste scraped website content below (mixed pages, unstructured, noisy).

TASK:

1. Infer the primary business model, ICP, and core value proposition.

2. Identify recurring semantic themes and intent patterns.

3. Build exactly 5 topic clusters optimized for:
   - topical authority
   - long-term search demand
   - internal linking coherence

OUTPUT FORMAT (STRICT):

For each cluster, provide:

- **Cluster Name** (concise, non-buzzword)
- **Core Search Intent** (1 sentence)
- **Pillar Page Topic** (broad, evergreen)
- **6–10 Supporting Content Topics** (specific, long-tail, non-overlapping)
- **Internal Linking Logic** (how pillar ↔ supports reinforce each other)

CONSTRAINTS:

- Do not invent offerings not implied by the content
- Prefer educational + commercial-adjacent intent
- Avoid generic marketing language
- Assume content must scale to 50–100 total pages over time

OUTPUT STYLE:

- Clean markdown
- No preamble, no explanation, no filler

BEGIN after the content.

---

SCRAPED CONTENT:

{scraped_content}"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.7,
                max_tokens=4000,
            )

            result = (response.choices[0].message.content or "").strip()
            
            # Save to database
            title = f"Topic Clusters - {subdirectory or 'All'}"
            if subdirectory:
                title = f"Topic Clusters - {subdirectory}"
            else:
                title = "Topic Clusters - All Pages"
            
            cluster_id = self.db.add_topic_cluster(
                title=title,
                content=result,
                subdirectory=subdirectory,
                num_samples=sample_size,
                user_id=self.user_id
            )
            
            print(f"Topic cluster saved with ID: {cluster_id}")
            return {"id": cluster_id, "content": result}

        except Exception as e:
            print(f"Error generating topic clusters: {e}")
            return None

    def analyze_implicit_clusters(self, subdirectory=None):
        """Analyze article titles to surface implicit topic clusters"""
        print("Analyzing implicit topic clusters from titles...")
        if subdirectory:
            print(f"Filtering to subdirectory: {subdirectory}")

        # Get content, optionally filtered by subdirectory
        if subdirectory:
            all_content = self.db.get_scraped_by_subdirectory(subdirectory, user_id=self.user_id)
        else:
            all_content = self.db.get_all_scraped_content(user_id=self.user_id)
            
        if not all_content:
            print("No scraped content available")
            return None

        print(f"Found {len(all_content)} articles")

        # Build list of titles (limit to 500 to avoid token limits)
        titles = [item.title for item in all_content if item.title]
        if len(titles) > 500:
            print(f"Truncating from {len(titles)} to 500 titles")
            titles = titles[:500]
        
        print(f"Analyzing {len(titles)} article titles")
        titles_text = "\n".join([f"- {title}" for title in titles])

        system_prompt = """You are a senior SEO strategist and information architect.

Your task is to infer topical structure and search intent from article titles alone. You do not assume access to body content. You reason strictly from phrasing, semantic overlap, and implied intent.

Your goals are to:

1. Identify core themes already covered
2. Group articles into clear topical clusters that reflect how search engines model topical authority
3. Detect duplication, fragmentation, and cannibalization
4. Propose pillar-content opportunities where multiple weak or narrow posts should consolidate into one authoritative page

Constraints:

- Use plain, search-intent-aligned language, not internal or brand-specific jargon
- Prefer fewer, stronger clusters over many weak ones
- Do not invent topics not clearly implied by the titles
- Be decisive: every article must belong to a cluster, even if imperfectly
- Think like Google: prioritize clarity, hierarchy, and topical depth over cleverness"""

        user_prompt = f"""Analyze the following article titles and surface the implicit topic clusters.

ARTICLE TITLES:
{titles_text}

REQUIRED OUTPUT FORMAT:

1. First, provide exactly 10 CONTENT PILLARS as a JSON array. Each pillar should be a short, descriptive phrase (2-5 words) representing a core topic. Format:
```json
["Pillar 1", "Pillar 2", "Pillar 3", "Pillar 4", "Pillar 5", "Pillar 6", "Pillar 7", "Pillar 8", "Pillar 9", "Pillar 10"]
```

2. Then provide your full analysis in markdown format including:
- Cluster groupings with article assignments
- Duplication/cannibalization issues detected
- Pillar consolidation opportunities
- Gaps or underserved topics

Begin with the JSON array, then the markdown analysis."""

        try:
            print("Sending request to OpenAI...")
            response = self.client.chat.completions.create(
                model="gpt-4o",  # Use gpt-4o for larger context window
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.6,
                max_tokens=4000,
            )

            result = (response.choices[0].message.content or "").strip()
            print(f"Received response ({len(result)} chars)")
            
            # Extract pillars from JSON array
            json_match = re.search(r'\[[\s\S]*?\]', result)
            pillars = []
            if json_match:
                try:
                    pillars = json.loads(json_match.group(0))
                    print(f"Extracted {len(pillars)} pillars")
                except Exception as parse_err:
                    print(f"Failed to parse pillars JSON: {parse_err}")
                    pillars = []
            
            # Extract analysis (everything after the JSON)
            analysis = result
            if json_match:
                analysis = result[json_match.end():].strip()
                # Remove markdown code fence if present
                analysis = re.sub(r'^```\s*', '', analysis)
            
            return {"pillars": pillars, "analysis": analysis}

        except Exception as e:
            print(f"Error analyzing clusters: {e}")
            import traceback
            traceback.print_exc()
            raise  # Re-raise so the route can show the actual error
