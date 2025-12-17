import re
from collections import Counter
import math


class SEOAnalyzer:
    """SEO analysis and optimization tools"""

    def __init__(self):
        self.stop_words = set([
            'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
            'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'that', 'the',
            'to', 'was', 'will', 'with', 'the', 'this', 'but', 'they', 'have',
            'had', 'what', 'when', 'where', 'who', 'which', 'why', 'how'
        ])

    def extract_keywords(self, text, num_keywords=10):
        """Extract top keywords from text"""
        # Convert to lowercase and extract words
        words = re.findall(r'\b[a-z]{3,}\b', text.lower())

        # Filter out stop words
        filtered_words = [w for w in words if w not in self.stop_words]

        # Count frequency
        word_freq = Counter(filtered_words)

        # Get top keywords
        top_keywords = word_freq.most_common(num_keywords)

        return [(word, count) for word, count in top_keywords]

    def calculate_keyword_density(self, text, keyword):
        """Calculate keyword density"""
        text_lower = text.lower()
        keyword_lower = keyword.lower()

        keyword_count = text_lower.count(keyword_lower)
        total_words = len(text.split())

        if total_words == 0:
            return 0

        density = (keyword_count / total_words) * 100
        return round(density, 2)

    def analyze_readability(self, text):
        """Calculate readability scores"""
        # Count sentences
        sentences = re.split(r'[.!?]+', text)
        sentence_count = len([s for s in sentences if s.strip()])

        # Count words
        words = text.split()
        word_count = len(words)

        # Count syllables (simplified)
        syllable_count = sum(self.count_syllables(word) for word in words)

        if sentence_count == 0 or word_count == 0:
            return {
                'flesch_reading_ease': 0,
                'avg_words_per_sentence': 0,
                'avg_syllables_per_word': 0
            }

        # Flesch Reading Ease
        avg_sentence_length = word_count / sentence_count
        avg_syllables_per_word = syllable_count / word_count

        flesch_score = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)

        return {
            'flesch_reading_ease': round(flesch_score, 2),
            'avg_words_per_sentence': round(avg_sentence_length, 2),
            'avg_syllables_per_word': round(avg_syllables_per_word, 2)
        }

    def count_syllables(self, word):
        """Count syllables in a word (simplified)"""
        word = word.lower()
        vowels = 'aeiouy'
        syllable_count = 0
        previous_was_vowel = False

        for char in word:
            is_vowel = char in vowels
            if is_vowel and not previous_was_vowel:
                syllable_count += 1
            previous_was_vowel = is_vowel

        # Adjust for silent e
        if word.endswith('e'):
            syllable_count -= 1

        # Ensure at least one syllable
        if syllable_count == 0:
            syllable_count = 1

        return syllable_count

    def analyze_headings(self, content):
        """Analyze heading structure in markdown content"""
        headings = {
            'h1': re.findall(r'^# (.+)$', content, re.MULTILINE),
            'h2': re.findall(r'^## (.+)$', content, re.MULTILINE),
            'h3': re.findall(r'^### (.+)$', content, re.MULTILINE),
            'h4': re.findall(r'^#### (.+)$', content, re.MULTILINE),
        }

        return {
            'h1_count': len(headings['h1']),
            'h2_count': len(headings['h2']),
            'h3_count': len(headings['h3']),
            'h4_count': len(headings['h4']),
            'total_headings': sum(len(h) for h in headings.values()),
            'headings': headings
        }

    def calculate_seo_score(self, content, title='', meta_description='', keywords=None):
        """Calculate overall SEO score (0-100)"""
        score = 0
        max_score = 100

        # Word count (20 points)
        word_count = len(content.split())
        if word_count >= 1500:
            score += 20
        elif word_count >= 1000:
            score += 15
        elif word_count >= 500:
            score += 10
        elif word_count >= 300:
            score += 5

        # Title length (15 points)
        if title:
            title_len = len(title)
            if 50 <= title_len <= 60:
                score += 15
            elif 40 <= title_len <= 70:
                score += 10

        # Meta description (15 points)
        if meta_description:
            desc_len = len(meta_description)
            if 150 <= desc_len <= 160:
                score += 15
            elif 120 <= desc_len <= 170:
                score += 10

        # Headings structure (20 points)
        heading_analysis = self.analyze_headings(content)
        if heading_analysis['h2_count'] >= 3:
            score += 10
        if heading_analysis['h3_count'] >= 2:
            score += 5
        if heading_analysis['total_headings'] >= 5:
            score += 5

        # Keyword usage (15 points)
        if keywords:
            for keyword in keywords[:3]:  # Check top 3 keywords
                density = self.calculate_keyword_density(content, keyword)
                if 0.5 <= density <= 2.5:  # Ideal keyword density
                    score += 5

        # Readability (15 points)
        readability = self.analyze_readability(content)
        flesch_score = readability['flesch_reading_ease']
        if flesch_score >= 60:  # Easy to read
            score += 15
        elif flesch_score >= 50:
            score += 10
        elif flesch_score >= 30:
            score += 5

        return min(score, max_score)

    def generate_seo_report(self, content, title='', meta_description='', keywords=None):
        """Generate comprehensive SEO report"""
        word_count = len(content.split())
        extracted_keywords = self.extract_keywords(content)
        readability = self.analyze_readability(content)
        heading_analysis = self.analyze_headings(content)
        seo_score = self.calculate_seo_score(content, title, meta_description, keywords)

        report = {
            'seo_score': seo_score,
            'word_count': word_count,
            'title_length': len(title) if title else 0,
            'meta_description_length': len(meta_description) if meta_description else 0,
            'top_keywords': extracted_keywords,
            'readability': readability,
            'headings': heading_analysis,
            'recommendations': []
        }

        # Generate recommendations
        if word_count < 300:
            report['recommendations'].append("Content is too short. Aim for at least 300 words.")
        elif word_count < 1000:
            report['recommendations'].append("Consider expanding content to 1000+ words for better SEO.")

        if not title or len(title) < 40:
            report['recommendations'].append("Add a descriptive title between 50-60 characters.")

        if not meta_description or len(meta_description) < 120:
            report['recommendations'].append("Add a compelling meta description (150-160 characters).")

        if heading_analysis['h2_count'] < 3:
            report['recommendations'].append("Add more H2 headings to improve content structure.")

        if readability['flesch_reading_ease'] < 50:
            report['recommendations'].append("Content may be difficult to read. Simplify sentences.")

        if keywords:
            for keyword in keywords[:3]:
                density = self.calculate_keyword_density(content, keyword)
                if density < 0.5:
                    report['recommendations'].append(f"Keyword '{keyword}' is underused. Current density: {density}%")
                elif density > 2.5:
                    report['recommendations'].append(f"Keyword '{keyword}' is overused. Current density: {density}%")

        return report

    def suggest_improvements(self, content, target_keywords=None):
        """Suggest specific improvements for content"""
        report = self.generate_seo_report(content, keywords=target_keywords)

        suggestions = {
            'score': report['seo_score'],
            'improvements': []
        }

        # Add specific, actionable suggestions
        if report['word_count'] < 1000:
            suggestions['improvements'].append({
                'type': 'length',
                'priority': 'high',
                'suggestion': f"Expand content from {report['word_count']} to at least 1000 words",
                'impact': 'High impact on SEO'
            })

        if report['headings']['h2_count'] < 3:
            suggestions['improvements'].append({
                'type': 'structure',
                'priority': 'medium',
                'suggestion': "Add more H2 headings to break up content",
                'impact': 'Improves readability and SEO'
            })

        if target_keywords:
            for keyword in target_keywords:
                density = self.calculate_keyword_density(content, keyword)
                if density == 0:
                    suggestions['improvements'].append({
                        'type': 'keywords',
                        'priority': 'high',
                        'suggestion': f"Add target keyword '{keyword}' to content",
                        'impact': 'Critical for ranking'
                    })

        return suggestions
