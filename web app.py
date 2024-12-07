from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, g
from pymongo import MongoClient
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import datetime
import dns.resolver
import whois
from transformers import pipeline
from openai import OpenAI
import re
import os
from functools import lru_cache

app = Flask(__name__)
app.secret_key = 'Enter The Desired Secret Key Here'

# MongoDB connection URIs for different clusters
MONGODB_URIS = {
    'phish_links_domains': "Enter The Connection URI Here or Request Me For The Master Connection URI",
    'phishing_urls': "Enter The Connection URI Here or Request Me For The Master Connection URI"
}

#openai api 
openai_api_key = 'Enter The API Key for Pretrained AI-Model Here'

# Database and Collection Configuration
DB_CONFIG = {
    'phishing_urls_cluster': {
        'database': 'phish_defender',
        'collections': {
            'urls': 'phishing_urls'  # For newly analyzed URLs
        }
    },
    'phish_links_domains_cluster': {
        'database': 'phish_defender',
        'collections': {
            'phishing_domains': 'phishing_domains',  # Known phishing domains
            'phishing_links': 'phishing_links',      # Known phishing URLs/links
            's_domains': 's_domains',                # Safe domains
            's_links': 's_links'                     # Safe URLs/links
        }
    }
}

# Initialize MongoDB connections
try:
    # Initialize clients for both clusters
    links_domains_client = MongoClient(MONGODB_URIS['phish_links_domains'])
    urls_client = MongoClient(MONGODB_URIS['phishing_urls'])
    
    # Set up database references
    phish_links_domains_db = links_domains_client['phish_defender']
    urls_db = urls_client['phishing_urls']
    legacy_urls_db = urls_client['phish_defender']
    
    # Set up collection references
    # Collections from phish_links_domains cluster
    domains_collection = phish_links_domains_db['phishing_domains']
    links_collection = phish_links_domains_db['phishing_links']
    safe_domains_collection = phish_links_domains_db['s_domains']
    safe_links_collection = phish_links_domains_db['s_links']
    
    # Collections from phishing_urls cluster
    urls_collection = urls_db['phishing_urls']          # New analysis results
    legacy_urls_collection = legacy_urls_db['phishing_urls']  # Legacy data
    
    print("Successfully connected to all MongoDB clusters!")
except Exception as e:
    print(f"Error connecting to MongoDB clusters: {e}")
    raise

def get_db_connections():
    """Initialize database connections if they don't exist"""
    if 'db_connections' not in g:
        try:
            # Initialize clients
            g.urls_client = MongoClient(MONGODB_URIS['phishing_urls'])
            g.links_domains_client = MongoClient(MONGODB_URIS['phish_links_domains'])
            
            # Set up database references
            # 1. Phishing URLs cluster databases
            g.phish_defender_db = g.urls_client['phish_defender']  # For legacy data
            g.phishing_urls_db = g.urls_client['phishing_urls']    # For new analysis
            
            # 2. Phish Links & Domains cluster database
            g.links_domains_db = g.links_domains_client['phish_defender']
            
            # Set up collection references
            # Phishing URLs collections
            g.legacy_urls = g.phish_defender_db['phishing_urls']   # Legacy analyzed URLs
            g.analyzed_urls = g.phishing_urls_db['phishing_urls']  # New analyzed URLs
            
            # Known phishing/safe collections
            g.phishing_domains = g.links_domains_db['phishing_domains']
            g.phishing_links = g.links_domains_db['phishing_links']
            g.safe_domains = g.links_domains_db['s_domains']
            g.safe_links = g.links_domains_db['s_links']
            
            # Store clients for cleanup
            g.db_connections = {
                'urls': g.urls_client,
                'links_domains': g.links_domains_client
            }
            
            print("Successfully connected to all MongoDB clusters!")
            
        except Exception as e:
            print(f"Error connecting to MongoDB clusters: {str(e)}")
            raise

def create_mongodb_indexes():
    """Create necessary indexes for all collections"""
    try:
        # Indexes for URLs collection - changed from website to url
        g.urls_collection.create_index([("url", 1)], unique=True, sparse=True)
        g.urls_collection.create_index([("domain", 1)], sparse=True)
        g.urls_collection.create_index([("result", 1)], sparse=True)
        g.urls_collection.create_index([("analysis_date", -1)], sparse=True)

        # Indexes for phishing domains collection
        g.phishing_domains.create_index([("domain", 1)], unique=True, sparse=True)
        g.phishing_domains.create_index([("last_seen", -1)], sparse=True)

        # Indexes for phishing links collection
        g.phishing_links.create_index([("url", 1)], unique=True, sparse=True)
        g.phishing_links.create_index([("last_seen", -1)], sparse=True)

        # Indexes for safe domains collection
        g.safe_domains.create_index([("domain", 1)], unique=True, sparse=True)
        g.safe_domains.create_index([("last_seen", -1)], sparse=True)

        # Indexes for safe links collection
        g.safe_links.create_index([("url", 1)], unique=True, sparse=True)
        g.safe_links.create_index([("last_seen", -1)], sparse=True)

        print("MongoDB indexes created successfully")
    except Exception as e:
        print(f"Error creating MongoDB indexes: {str(e)}")
        raise

# Initialize AI models
try:
    classifier = pipeline("text-classification", model="distilbert-base-uncased")
    print("AI models initialized successfully")
except Exception as e:
    print(f"Error initializing AI models: {e}")
    classifier = None

def store_analysis_result(url, domain, is_phishing, analysis_data):
    """Store analysis results in appropriate collections"""
    try:
        current_time = datetime.datetime.utcnow()
        
        # 1. Store in new analysis collection (phishing_urls.phishing_urls)
        analysis_doc = {
            "url": url,
            "domain": domain,
            "result": 1 if is_phishing else 0,
            "risk_score": analysis_data.get('risk_score', 0),
            "features": analysis_data.get('features', {}),
            "dns_checks": analysis_data.get('dns_checks', []),
            "content_analysis": analysis_data.get('content_analysis', ''),
            "analysis_date": current_time
        }
        
        g.analyzed_urls.update_one(
            {"url": url},
            {"$set": analysis_doc},
            upsert=True
        )
        
        # 2. Update appropriate known/safe collections
        if is_phishing:
            # Remove from safe collections if present
            if domain:
                g.safe_domains.delete_one({"domain": domain})
            g.safe_links.delete_one({"url": url})
            
            # Add to phishing collections
            if domain:
                g.phishing_domains.update_one(
                    {"domain": domain},
                    {"$set": {
                        "domain": domain,
                        "date_added": current_time,
                        "last_checked": current_time,
                        "verified": True,
                        "source": "analysis"
                    }},
                    upsert=True
                )
            
            g.phishing_links.update_one(
                {"url": url},
                {"$set": {
                    "url": url,
                    "date_added": current_time,
                    "last_checked": current_time,
                    "verified": True,
                    "source": "analysis"
                }},
                upsert=True
            )
        else:
            # Remove from phishing collections if present
            if domain:
                g.phishing_domains.delete_one({"domain": domain})
            g.phishing_links.delete_one({"url": url})
            
            # Add to safe collections
            if domain:
                g.safe_domains.update_one(
                    {"domain": domain},
                    {"$set": {
                        "domain": domain,
                        "last_seen": current_time
                    }},
                    upsert=True
                )
            
            g.safe_links.update_one(
                {"url": url},
                {"$set": {
                    "url": url,
                    "last_seen": current_time
                }},
                upsert=True
            )
            
    except Exception as e:
        print(f"Error storing analysis result: {str(e)}")
        raise

def migrate_null_websites():
    """Migrate any documents with null website fields"""
    try:
        # Find all documents with null website field
        null_docs = g.urls_collection.find({"website": None})
        
        for doc in null_docs:
            # If URL exists, use it as website
            if "url" in doc:
                g.urls_collection.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"website": doc["url"]}}
                )
            else:
                # If no URL exists, delete the invalid document
                g.urls_collection.delete_one({"_id": doc["_id"]})
                
        print("Null website migration completed")
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        raise

def get_stats():
    """Get comprehensive statistics from all collections"""
    try:
        # 1. Stats from URL collections
        urls_stats = {
            'total': {
                'legacy': g.legacy_urls.count_documents({}),  # Legacy analysis results
                'new': g.analyzed_urls.count_documents({})    # New analysis results
            },
            'unsafe': {
                'legacy': g.legacy_urls.count_documents({"result": 1}),
                'new': g.analyzed_urls.count_documents({"result": 1})
            },
            'safe': {
                'legacy': g.legacy_urls.count_documents({"result": 0}),
                'new': g.analyzed_urls.count_documents({"result": 0})
            },
            'combined': {
                'total': g.legacy_urls.count_documents({}) + g.analyzed_urls.count_documents({}),
                'unsafe': g.legacy_urls.count_documents({"result": 1}) + g.analyzed_urls.count_documents({"result": 1}),
                'safe': g.legacy_urls.count_documents({"result": 0}) + g.analyzed_urls.count_documents({"result": 0})
            }
        }
        
        # 2. Stats from known phishing collections
        phishing_stats = {
            'domains': g.phishing_domains.count_documents({}),
            'links': g.phishing_links.count_documents({})
        }
        
        # 3. Stats from safe collections
        safe_stats = {
            'domains': g.safe_domains.count_documents({}),
            'links': g.safe_links.count_documents({})
        }
        
        # 4. Combined domain stats
        domains_stats = {
            'total': phishing_stats['domains'] + safe_stats['domains'],
            'unsafe': phishing_stats['domains'],
            'safe': safe_stats['domains']
        }
        
        # 5. Combined link stats
        links_stats = {
            'total': phishing_stats['links'] + safe_stats['links'],
            'unsafe': phishing_stats['links'],
            'safe': safe_stats['links']
        }
        
        return urls_stats, domains_stats, links_stats
        
    except Exception as e:
        print(f"Error getting stats: {str(e)}")
        raise

def check_url_in_all_collections(url, domain):
    """Check URL/domain across all collections in all databases"""
    try:
        # Dictionary to store all findings
        findings = {
            'legacy_analysis': None,
            'new_analysis': None,
            'phishing_domain': None,
            'phishing_link': None,
            'safe_domain': None,
            'safe_link': None
        }
        
        # 1. Check legacy analyzed URLs (phish_defender.phishing_urls)
        result = g.legacy_urls.find_one({"url": url})
        if result:
            findings['legacy_analysis'] = {
                "result": result.get("result"),
                "created_date": result.get("created_date")
            }

        # 2. Check new analyzed URLs (phishing_urls.phishing_urls)
        result = g.analyzed_urls.find_one({"url": url})
        if result:
            findings['new_analysis'] = {
                "result": result.get("result"),
                "risk_score": result.get("risk_score"),
                "analysis_date": result.get("analysis_date")
            }

        # 3. Check known phishing domain
        if domain:
            result = g.phishing_domains.find_one({"domain": domain})
            if result:
                findings['phishing_domain'] = {
                    "date_added": result.get("date_added"),
                    "last_checked": result.get("last_checked"),
                    "verified": result.get("verified", False)
                }

        # 4. Check known phishing URL
        result = g.phishing_links.find_one({"url": url})
        if result:
            findings['phishing_link'] = {
                "date_added": result.get("date_added"),
                "last_checked": result.get("last_checked"),
                "verified": result.get("verified", False)
            }

        # 5. Check safe domain
        if domain:
            result = g.safe_domains.find_one({"domain": domain})
            if result:
                findings['safe_domain'] = {
                    "last_seen": result.get("last_seen")
                }

        # 6. Check safe URL
        result = g.safe_links.find_one({"url": url})
        if result:
            findings['safe_link'] = {
                "last_seen": result.get("last_seen")
            }

        # Determine final result based on findings priority
        if findings['phishing_domain'] or findings['phishing_link']:
            return {"result": 1, "source": "known_phishing"}, "verified_phishing"
            
        if findings['safe_domain'] or findings['safe_link']:
            return {"result": 0, "source": "known_safe"}, "verified_safe"
            
        if findings['new_analysis']:
            return findings['new_analysis'], "recent_analysis"
            
        if findings['legacy_analysis']:
            return findings['legacy_analysis'], "legacy_analysis"

        return None, None

    except Exception as e:
        print(f"Error checking collections: {str(e)}")
        raise

class PhishingAnalyzer:

    def __init__(self):
        self.client = OpenAI(api_key=openai_api_key)
        self.openai_client = OpenAI(api_key=openai_api_key)

    def analyze_url(self, url):
        """Complete URL analysis"""
        try:
            features = self.extract_url_features(url)
            domain = urlparse(url).netloc
            dns_checks = self.check_dns_records(domain)
            content_analysis = self.analyze_content(url)
            
            risk_score = self.calculate_risk_score(features, dns_checks, content_analysis)
            
            return {
                'url': url,
                'domain': domain,
                'features': features,
                'dns_checks': dns_checks,
                'content_analysis': content_analysis,
                'risk_score': risk_score,
                'is_phishing': risk_score > 0.5
            }
        except Exception as e:
            print(f"Error analyzing URL: {str(e)}")
            return None

    @staticmethod
    def check_domain_info(domain):
        """Check domain information with timeout"""
        try:
            import socket
            socket.setdefaulttimeout(2)
            w = whois.whois(domain)
            return w
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {str(e)}")
            return None

    def extract_url_features(self, url):
        """Extract features from URL for analysis"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            features = {
                'length': len(url),
                'num_dots': url.count('.'),
                'has_ip': bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
                'has_suspicious_words': bool(re.search(r'login|account|secure|banking|verify', url.lower())),
                'is_https': parsed_url.scheme == 'https',
                'has_suspicious_tld': parsed_url.netloc.split('.')[-1] in ['xyz', 'tk', 'ml', 'ga', 'cf'],
                'subdomain_count': len(parsed_url.netloc.split('.')) - 2 if len(parsed_url.netloc.split('.')) > 2 else 0,
                'url_length_suspicious': len(url) > 100,
                'domain_age': -1  # Default value
            }

            # Add domain age with corrected WHOIS lookup
            if domain:
                whois_info = self.check_domain_info(domain)  # Use the static method
                if whois_info and whois_info.creation_date:
                    creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
                    features['domain_age'] = (datetime.datetime.now() - creation_date).days

            return features
        except Exception as e:
            print(f"Error extracting features: {e}")
            return None

    def analyze_content(self, url):
        """Analyze webpage content using GPT"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, timeout=5, headers=headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract relevant content
                text_content = soup.get_text()[:1500]
                forms = soup.find_all('form')
                inputs = soup.find_all('input')
                links = soup.find_all('a')
                
                analysis_text = f"""
                Analyze this webpage for phishing indicators:
                Text Content: {text_content[:500]}...
                Forms: {len(forms)}
                Input Fields: {len(inputs)}
                Links: {len(links)}
                URL: {url}
                """
                
                # Use the instance's OpenAI client
                response = self.openai_client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert analyzing webpages for phishing indicators."},
                        {"role": "user", "content": analysis_text}
                    ]
                )
                return response.choices[0].message.content
            
            return f"Could not fetch page content. Status code: {response.status_code}"
        except requests.exceptions.RequestException as e:
            return f"Error fetching content: {str(e)}"
        except Exception as e:
            return f"Error analyzing content: {str(e)}"

    def check_dns_records(self, domain):
        """Check DNS records for suspicious patterns"""
        suspicious_patterns = []
        try:
            # Set timeout for DNS queries
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            # Check various DNS record types
            record_types = ['A', 'MX', 'NS', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    records = dns.resolver.resolve(domain, record_type)
                    
                    if record_type == 'A':
                        # Check if IP is in suspicious ranges
                        for record in records:
                            ip = str(record)
                            if any(ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.']):
                                suspicious_patterns.append(f"Suspicious private IP address: {ip}")
                    
                    elif record_type == 'MX':
                        # Check for suspicious mail servers
                        for record in records:
                            mx_domain = str(record.exchange).lower()
                            if any(word in mx_domain for word in ['tempmail', 'temporary', 'disposable']):
                                suspicious_patterns.append(f"Suspicious mail server: {mx_domain}")
                    
                    elif record_type == 'NS':
                        # Check for suspicious nameservers
                        for record in records:
                            ns_domain = str(record).lower()
                            if any(word in ns_domain for word in ['free', 'temp', 'dynamic']):
                                suspicious_patterns.append(f"Suspicious nameserver: {ns_domain}")

                except dns.resolver.Timeout:
                    suspicious_patterns.append(f"{record_type} record lookup timed out")
                    continue
                except dns.resolver.NXDOMAIN:
                    suspicious_patterns.append(f"Domain does not exist")
                    continue
                except dns.resolver.NoAnswer:
                    suspicious_patterns.append(f"No {record_type} records found")
                    continue
                except Exception as e:
                    suspicious_patterns.append(f"Error checking {record_type} records: {str(e)}")
                    continue

            return suspicious_patterns

        except Exception as e:
            return [f"DNS check error: {str(e)}"]

    def calculate_risk_score(self, features, dns_checks, content_analysis):
        """Calculate comprehensive risk score"""
        risk_score = 0
        
        # URL feature based scoring
        if features:
            if features['has_ip']: risk_score += 0.3
            if features['has_suspicious_words']: risk_score += 0.2
            if not features['is_https']: risk_score += 0.2
            if features['domain_age'] < 30 and features['domain_age'] != -1: risk_score += 0.3
            if features['has_suspicious_tld']: risk_score += 0.2
            if features['subdomain_count'] > 2: risk_score += 0.1
            if features['url_length_suspicious']: risk_score += 0.1
        
        # DNS checks based scoring
        if dns_checks:
            for check in dns_checks:
                if 'suspicious' in check.lower(): risk_score += 0.1
                if 'error' in check.lower(): risk_score += 0.05
                if 'new' in check.lower(): risk_score += 0.15
        
        # Content analysis based scoring
        if content_analysis:
            suspicious_terms = ['password', 'credit card', 'login', 'verify', 'account']
            for term in suspicious_terms:
                if term in content_analysis.lower():
                    risk_score += 0.1
        
        # Cap the risk score at 1.0
        return min(risk_score, 1.0)
    
    def store_analysis_result(self, analysis_data):
        """Store analysis results in appropriate collections"""
        try:
            # Prepare document for storage
            doc = {
                "url": analysis_data['url'],
                "domain": analysis_data['domain'],
                "result": 1 if analysis_data['is_phishing'] else 0,
                "risk_score": analysis_data['risk_score'],
                "features": analysis_data['features'],
                "dns_checks": analysis_data['dns_checks'],
                "content_analysis": analysis_data['content_analysis'],
                "analysis_date": datetime.datetime.utcnow()
            }
            
            # Store in appropriate collections
            if analysis_data['is_phishing']:
                # Store in phishing collections
                if analysis_data['domain']:
                    g.phishing_domains.update_one(
                        {"domain": analysis_data['domain']},
                        {"$set": {
                            "domain": analysis_data['domain'],
                            "last_seen": datetime.datetime.utcnow()
                        }},
                        upsert=True
                    )
                
                g.phishing_links.update_one(
                    {"url": analysis_data['url']},
                    {"$set": {
                        "url": analysis_data['url'],
                        "last_seen": datetime.datetime.utcnow()
                    }},
                    upsert=True
                )
            else:
                # Store in safe collections
                if analysis_data['domain']:
                    g.safe_domains.update_one(
                        {"domain": analysis_data['domain']},
                        {"$set": {
                            "domain": analysis_data['domain'],
                            "last_seen": datetime.datetime.utcnow()
                        }},
                        upsert=True
                    )
                
                g.safe_links.update_one(
                    {"url": analysis_data['url']},
                    {"$set": {
                        "url": analysis_data['url'],
                        "last_seen": datetime.datetime.utcnow()
                    }},
                    upsert=True
                )
            
            # Store complete analysis in urls collection
            g.urls_collection.insert_one(doc)
            
        except Exception as e:
            print(f"Error storing analysis result: {str(e)}")
            raise
    
    def analyze_email(self, email_content):
        """Analyze email content for phishing indicators"""
        try:
            # Extract URLs from email
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
            
            # Analyze content using GPT
            content_analysis = self.analyze_email_content(email_content)
            
            # Analyze each URL found
            url_analysis = []
            for url in urls:
                url_result = self.analyze_url(url)
                if url_result:
                    url_analysis.append(url_result)
            
            # Calculate overall threat score
            threat_indicators = {
                'suspicious_urls': sum(1 for url in url_analysis if url['is_phishing']),
                'urgent_language': bool(re.search(r'urgent|immediate|suspended|cancelled|verify', email_content, re.I)),
                'sensitive_info_request': bool(re.search(r'password|credit.?card|ssn|social.?security', email_content, re.I)),
                'suspicious_sender': bool(re.search(r'@.*\.(tk|ml|cf|ga|gq)$', email_content, re.I)),
                'pressure_tactics': bool(re.search(r'within \d+ hours?|limited time|act now', email_content, re.I))
            }
            
            threat_score = sum([
                0.3 if threat_indicators['suspicious_urls'] > 0 else 0,
                0.2 if threat_indicators['urgent_language'] else 0,
                0.2 if threat_indicators['sensitive_info_request'] else 0,
                0.15 if threat_indicators['suspicious_sender'] else 0,
                0.15 if threat_indicators['pressure_tactics'] else 0
            ])
            
            return {
                'content_analysis': content_analysis,
                'urls_found': urls,
                'url_analysis': url_analysis,
                'threat_indicators': threat_indicators,
                'threat_score': threat_score,
                'is_phishing': threat_score > 0.5,
                'analysis_date': datetime.datetime.utcnow()
            }
            
        except Exception as e:
            print(f"Error analyzing email: {str(e)}")
            raise

class ContentAnalyzer:
    def __init__(self):
        self.url_analyzer = PhishingAnalyzer()
        self.client = OpenAI(api_key=openai_api_key)
        self.openai_client = OpenAI(api_key=openai_api_key)

    def analyze_email(self, email_content):
        """Analyze email content for phishing indicators"""
        try:
            # Extract URLs from email
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
            
            # Analyze content using GPT
            content_analysis = self.analyze_email_content(email_content)
            
            # Calculate threat indicators
            threat_indicators = {
                'suspicious_urls': len([url for url in urls if any(suspicious in url.lower() for suspicious in ['.tk', '.ml', '.cf', '.ga', '.gq', 'netflix', 'secure', 'login', 'verify'])]),
                'urgent_language': bool(re.search(r'urgent|immediate|suspended|cancelled|verify|suspension|restricted|limited', email_content, re.I)),
                'sensitive_info_request': bool(re.search(r'password|credit.?card|billing|payment|verify', email_content, re.I)),
                'suspicious_sender': bool(re.search(r'(@.*\.(tk|ml|cf|ga|gq)$)|(@.*netflix)', email_content, re.I)),
                'pressure_tactics': bool(re.search(r'within \d+ hours?|immediate|urgent|limited time|expire|suspend', email_content, re.I)),
                'impersonation': bool(re.search(r'netflix|security team|customer service|support', email_content, re.I))
            }
            
            # Calculate threat level (0-1)
            threat_level = sum([
                0.3 if threat_indicators['suspicious_urls'] > 0 else 0,
                0.2 if threat_indicators['urgent_language'] else 0,
                0.2 if threat_indicators['sensitive_info_request'] else 0,
                0.15 if threat_indicators['suspicious_sender'] else 0,
                0.15 if threat_indicators['pressure_tactics'] else 0,
                0.2 if threat_indicators['impersonation'] else 0
            ])
            
            # Analyze each URL found
            url_analysis = []
            for url in urls:
                analysis = self.url_analyzer.analyze_url(url)
                if analysis:
                    url_analysis.append({
                        'url': url,
                        'risk_score': analysis.get('risk_score', 0),
                        'is_phishing': analysis.get('is_phishing', False),
                        'features': analysis.get('features', {}),
                    })
            
            # Get threat level text
            threat_level_text = self.get_threat_level_text(threat_level)
            
            # Prepare findings based on indicators
            findings = []
            if threat_indicators['suspicious_urls']:
                findings.append({
                    'description': f"Found {threat_indicators['suspicious_urls']} suspicious URLs",
                    'severity': 'high'
                })
            if threat_indicators['urgent_language']:
                findings.append({
                    'description': "Uses urgent or threatening language",
                    'severity': 'medium'
                })
            if threat_indicators['sensitive_info_request']:
                findings.append({
                    'description': "Requests sensitive information",
                    'severity': 'high'
                })
            if threat_indicators['suspicious_sender']:
                findings.append({
                    'description': "Suspicious sender email domain",
                    'severity': 'high'
                })
            if threat_indicators['pressure_tactics']:
                findings.append({
                    'description': "Uses pressure tactics",
                    'severity': 'medium'
                })
            if threat_indicators['impersonation']:
                findings.append({
                    'description': "Attempts to impersonate a legitimate service",
                    'severity': 'high'
                })
            
            return {
                'content_analysis': {
                    'findings': findings,
                    'detailed': content_analysis
                },
                'urls_found': urls,
                'url_analysis': url_analysis,
                'threat_indicators': threat_indicators,
                'threat_level': threat_level,
                'threat_level_text': threat_level_text,
                'is_phishing': threat_level > 0.5,
                'analysis_date': datetime.datetime.utcnow()
            }
            
        except Exception as e:
            print(f"Error analyzing email: {str(e)}")
            raise

    def get_threat_level_text(self, threat_level):
        """Convert threat level to descriptive text"""
        if threat_level >= 0.7:
            return "High Risk - Likely Phishing Attempt"
        elif threat_level >= 0.4:
            return "Medium Risk - Suspicious Content"
        else:
            return "Low Risk - Likely Safe"

    def analyze_email_content(self, content):
        """Analyze email content using GPT"""
        try:
            prompt = f"""Analyze this email for phishing indicators. Consider:
            1. Urgency or threats
            2. Grammar and spelling
            3. Suspicious links
            4. Requests for sensitive information
            5. Impersonation attempts

            Email content:
            {content}
            """
            
            # Use the instance's OpenAI client instead of creating a new one
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing emails for phishing attempts."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error analyzing email content: {str(e)}"

analyzer = PhishingAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api_instructions')
def api_instructions():
    return render_template('api.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        url_to_check = request.form['url']
        domain = urlparse(url_to_check).netloc
        
        result, source = check_url_in_all_collections(url_to_check, domain)
        
        if result:
            is_phishing = bool(result.get('result', 0))
            return render_template('result.html', url=url_to_check, is_phishing=is_phishing, show_analyze_button=False,source=source)
        
        return render_template('result.html', url=url_to_check, is_phishing=None, show_analyze_button=True)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.form['url']
        domain = urlparse(url).netloc
        
        # Perform analysis
        features = analyzer.extract_url_features(url)
        dns_checks = analyzer.check_dns_records(domain)
        content_analysis = analyzer.analyze_content(url)
        
        # Calculate risk score
        risk_score = analyzer.calculate_risk_score(features, dns_checks, content_analysis)
        is_phishing = risk_score > 0.5
        
        # Prepare analysis document
        analysis_doc = {
            "url": url,
            "domain": domain,
            "result": 1 if is_phishing else 0,
            "risk_score": risk_score,
            "features": features,
            "dns_checks": dns_checks,
            "content_analysis": content_analysis,
            "analysis_date": datetime.datetime.utcnow()
        }
        
        # Store results in appropriate collections
        store_analysis_result(url, domain, is_phishing, analysis_doc)
        
        return render_template(
            'analysis.html',
            url=url,
            is_phishing=is_phishing,
            risk_score=risk_score,
            features=features,
            dns_checks=dns_checks,
            content_analysis=content_analysis
        )
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/check_content', methods=['POST'])
def check_content():
    content_type = request.form['type']  # 'url' or 'email'
    content = request.form['content']
    
    try:
        if content_type == 'url':
            url = content
            domain = urlparse(url).netloc
            
            # Check existing collections
            result, source = check_url_in_all_collections(url, domain)
            
            if result:
                is_phishing = bool(result.get('result', 0))
                return render_template('result.html', url=url, is_phishing=is_phishing, show_analyze_button=False, source=source)
            
            return render_template('result.html', url=url, is_phishing=None, show_analyze_button=True)
                                
        elif content_type == 'email':
            analyzer = ContentAnalyzer()
            analysis_result = analyzer.analyze_email(content)
            
            return render_template('email_analysis.html', content=content, analysis=analysis_result)
                                
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/stats')
def stats():
    """Route handler for statistics page"""
    try:
        urls_stats, domains_stats, links_stats = get_stats()
        
        # Get recent detections from both URL collections
        recent_detections = []
        
        # Get from new analysis collection
        recent_new = list(g.analyzed_urls.find(
            {"result": 1},
            {"url": 1, "risk_score": 1, "analysis_date": 1}
        ).sort("analysis_date", -1).limit(10))
        
        # Get from legacy collection
        recent_legacy = list(g.legacy_urls.find(
            {"result": 1},
            {"url": 1, "created_date": 1}
        ).sort("created_date", -1).limit(10))
        
        # Process new analysis detections
        for item in recent_new:
            recent_detections.append({
                'url': item['url'],
                'risk_score': item.get('risk_score', 'N/A'),
                'date': item.get('analysis_date', ''),
                'source': 'Recent Analysis'
            })
        
        # Process legacy detections
        for item in recent_legacy:
            recent_detections.append({
                'url': item['url'],
                'risk_score': 'N/A',  # Legacy entries don't have risk scores
                'date': item.get('created_date', ''),
                'source': 'Legacy Database'
            })
        
        # Sort combined results by date
        recent_detections.sort(key=lambda x: x['date'] if x['date'] else datetime.datetime.min, reverse=True)
        recent_detections = recent_detections[:20]  # Keep only the 20 most recent
        
        return render_template(
            'stats.html',
            urls_stats=urls_stats['combined'],  # Use combined stats for display
            domains_stats=domains_stats,
            links_stats=links_stats,
            recent_detections=recent_detections
        )
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/report', methods=['POST'])
def report_phishing():
    try:
        url = request.form['url']
        report_type = request.form.get('type', 'phishing')  # 'phishing' or 'safe'
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        domain = urlparse(url).netloc
        
        # Store report in appropriate collection
        report_doc = {
            "url": url,
            "domain": domain,
            "result": 1 if report_type == 'phishing' else 0,
            "reported_date": datetime.datetime.utcnow(),
            "source": "user_report"
        }
        
        urls_collection.insert_one(report_doc)
        
        flash('Thank you for reporting! Your submission helps protect others.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error submitting report: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/check', methods=['POST'])
def api_check_url():
    """API endpoint for checking URLs and email content"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request data"}), 400

        # Handle email content analysis
        if 'email_content' in data:
            email_content = data['email_content']
            analyzer = ContentAnalyzer()
            analysis_result = analyzer.analyze_email(email_content)
            return jsonify(analysis_result)

        # Handle URL analysis
        if 'url' not in data:
            return jsonify({"error": "Missing URL parameter"}), 400
            
        url = data['url']
        domain = urlparse(url).netloc
        
        # Check URL in all collections
        findings = {
            'legacy_analysis': None,
            'new_analysis': None,
            'phishing_domain': None,
            'phishing_link': None,
            'safe_domain': None,
            'safe_link': None
        }

        # 1. Check legacy analyzed URLs (phish_defender.phishing_urls)
        result = g.legacy_urls.find_one({"url": url}, {"_id": 0})
        if result:
            findings['legacy_analysis'] = {
                "result": result.get("result"),
                "created_date": result.get("created_date")
            }

        # 2. Check new analyzed URLs (phishing_urls.phishing_urls)
        result = g.analyzed_urls.find_one({"url": url}, {"_id": 0})
        if result:
            findings['new_analysis'] = {
                "result": result.get("result"),
                "risk_score": result.get("risk_score"),
                "analysis_date": result.get("analysis_date")
            }

        # 3. Check known phishing domain
        if domain:
            result = g.phishing_domains.find_one({"domain": domain}, {"_id": 0})
            if result:
                findings['phishing_domain'] = {
                    "date_added": result.get("date_added"),
                    "last_checked": result.get("last_checked")
                }

        # 4. Check known phishing URL
        result = g.phishing_links.find_one({"url": url}, {"_id": 0})
        if result:
            findings['phishing_link'] = {
                "date_added": result.get("date_added"),
                "last_checked": result.get("last_checked")
            }

        # 5. Check safe domain
        if domain:
            result = g.safe_domains.find_one({"domain": domain}, {"_id": 0})
            if result:
                findings['safe_domain'] = {
                    "last_seen": result.get("last_seen")
                }

        # 6. Check safe URL
        result = g.safe_links.find_one({"url": url}, {"_id": 0})
        if result:
            findings['safe_link'] = {
                "last_seen": result.get("last_seen")
            }

        # If found in any collection, return the result
        if any(findings.values()):
            # Determine final result based on findings priority
            is_phishing = bool(
                findings['phishing_domain'] or 
                findings['phishing_link'] or 
                (findings['new_analysis'] and findings['new_analysis'].get('result') == 1) or
                (findings['legacy_analysis'] and findings['legacy_analysis'].get('result') == 1)
            )
            
            return jsonify({
                "url": url,
                "is_phishing": is_phishing,
                "findings": findings,
                "source": "database_check"
            })

        # If URL not found, perform new analysis
        features = analyzer.extract_url_features(url)
        dns_checks = analyzer.check_dns_records(domain)
        content_analysis = analyzer.analyze_content(url)
        
        risk_score = analyzer.calculate_risk_score(features, dns_checks, content_analysis)
        is_phishing = risk_score > 0.5
        
        analysis_result = {
            "url": url,
            "domain": domain,
            "is_phishing": is_phishing,
            "risk_score": risk_score,
            "features": features,
            "dns_checks": dns_checks,
            "content_analysis": content_analysis,
            "analysis_date": datetime.datetime.utcnow()
        }
        
        # Store in all appropriate collections
        store_analysis_result(url, domain, is_phishing, analysis_result)
        
        return jsonify(analysis_result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report', methods=['POST'])
def api_report():
    """API endpoint for reporting URLs or email content"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request data"}), 400

        current_time = datetime.datetime.utcnow()

        # Handle email report
        if 'email_content' in data:
            email_content = data['email_content']
            report_type = data.get('type', 'phishing')
            
            # Extract URLs from email
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
            
            # Store email report
            email_report = {
                "content": email_content,
                "urls_found": urls,
                "result": 1 if report_type == 'phishing' else 0,
                "reported_date": current_time,
                "source": "api_report"
            }
            
            # Store in appropriate collections
            g.analyzed_urls.insert_one(email_report)
            
            # Also store extracted URLs
            for url in urls:
                domain = urlparse(url).netloc
                url_report = {
                    "url": url,
                    "domain": domain,
                    "result": 1 if report_type == 'phishing' else 0,
                    "reported_date": current_time,
                    "source": "email_report"
                }
                store_analysis_result(url, domain, report_type == 'phishing', url_report)

            return jsonify({
                "message": "Email report submitted successfully",
                "urls_found": len(urls),
                "status": "success"
            })

        # Handle URL report
        if 'url' not in data:
            return jsonify({"error": "Missing URL parameter"}), 400
            
        url = data['url']
        report_type = data.get('type', 'phishing')
        domain = urlparse(url).netloc
        
        report_doc = {
            "url": url,
            "domain": domain,
            "result": 1 if report_type == 'phishing' else 0,
            "reported_date": current_time,
            "source": "api_report"
        }
        
        # Store in all appropriate collections
        store_analysis_result(url, domain, report_type == 'phishing', report_doc)
        
        return jsonify({
            "message": "URL report submitted successfully",
            "status": "success"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="404 - Page Not Found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="500 - Internal Server Error"), 500

def cleanup_connections():
    """Clean up MongoDB connections"""
    try:
        links_domains_client.close()
        urls_client.close()
        print("MongoDB connections closed successfully")
    except Exception as e:
        print(f"Error closing MongoDB connections: {e}")

@app.before_request
def before_request():
    """Set up database connections before each request"""
    get_db_connections()

@app.teardown_appcontext
def teardown_db(exception=None):
    """Clean up database connections"""
    db_connections = g.pop('db_connections', None)
    
    if db_connections:
        for client in db_connections.values():
            try:
                client.close()
            except Exception as e:
                print(f"Error closing MongoDB connection: {str(e)}")

def create_app():
    """Create and configure the Flask application"""
    with app.app_context():
        try:
            # Initialize MongoDB connections
            get_db_connections()
            
            # Create indexes only if they don't exist
            if not g.urls_collection.index_information():
                create_mongodb_indexes()
            
            print("Application initialized successfully")
        except Exception as e:
            print(f"Error during initialization: {str(e)}")
    
    return app

if __name__ == '__main__':
    try:
        app = create_app()
        app.run(debug=True)
    except Exception as e:
        print(f"Error starting application: {str(e)}")