#!/usr/bin/env python3
"""
Vulnet ML Model - Data Collection Script
Collects training data from Alexa Top 1M domains and generates malicious samples
"""

import pandas as pd
import json
import time
import os
from urllib.parse import urlparse
import random
import re
from collections import Counter
import math

class VulnetDataCollector:
    def __init__(self):
        # Simple data collector for Alexa CSV processing
        self.training_data = []
        
        print(f"Data Collector initialized:")
        print(f"Direct Alexa CSV processing mode")
        print(f"No external API dependencies")
    
    def load_alexa_top_1m(self, csv_path):
        """Load Alexa Top 1M domains"""
        print(f"Loading Alexa Top 1M from {csv_path}")
        df = pd.read_csv(csv_path, names=['rank', 'domain'])
        print(f"Loaded {len(df)} domains")
        return df
    
    def generate_suspicious_domains(self, count):
        """Generate suspicious domain patterns for testing"""
        patterns = []
        
        # Brand impersonation patterns
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'adobe']
        suspicious_words = ['security', 'update', 'verification', 'suspended', 'locked', 'support']
        tlds = ['.com', '.net', '.org', '.info', '.biz', '.xyz', '.tk']
        
        for _ in range(count // 3):
            brand = random.choice(brands)
            word = random.choice(suspicious_words)
            tld = random.choice(tlds)
            
            # Various suspicious patterns
            patterns.extend([
                f"{brand}-{word}{tld}",
                f"{brand}{word}{tld}",
                f"{word}-{brand}{tld}",
                f"{brand}.{word}{tld}",
                f"secure-{brand}{tld}"
            ])
        
        # High-entropy random domains
        for _ in range(count // 3):
            length = random.randint(8, 15)
            domain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=length))
            tld = random.choice(tlds)
            patterns.append(f"{domain}{tld}")
        
        # Typosquatting patterns
        popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple']
        for _ in range(count // 3):
            original = random.choice(popular_domains)
            # Insert character
            pos = random.randint(1, len(original)-1)
            char = random.choice('abcdefghijklmnopqrstuvwxyz')
            typo = original[:pos] + char + original[pos:]
            tld = random.choice(tlds)
            patterns.append(f"{typo}{tld}")
        
        return list(set(patterns))[:count]  # Remove duplicates and limit
    
    def extract_basic_features(self, url, domain):
        """Extract basic features for training"""
        try:
            parsed = urlparse(url)
            
            return {
                'url_length': len(url),
                'domain_length': len(domain),
                'subdomain_count': len(parsed.hostname.split('.')) - 2 if parsed.hostname else 0,
                'has_hyphens': 1 if '-' in domain else 0,
                'has_numbers': 1 if any(c.isdigit() for c in domain) else 0,
                'is_https': 1 if url.startswith('https://') else 0,
                'has_port': 1 if parsed.port else 0,
                'entropy': self.calculate_entropy(domain),
                'suspicious_words': self.count_suspicious_words(domain),
                'brand_similarity': self.check_brand_similarity(domain)
            }
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return {}
    
    def calculate_entropy(self, text):
        """Calculate domain entropy"""
        if not text:
            return 0
            
        counts = Counter(text)
        total = len(text)
        entropy = 0
        
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
            
        return entropy
    
    def count_suspicious_words(self, text):
        """Count suspicious words in text"""
        suspicious = ['security', 'update', 'verify', 'suspended', 'locked', 'urgent', 'immediate']
        text_lower = text.lower()
        return sum(1 for word in suspicious if word in text_lower)
    
    def check_brand_similarity(self, domain):
        """Check similarity to popular brands"""
        brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal']
        domain_lower = domain.lower()
        
        for brand in brands:
            if brand in domain_lower and f"{brand}.com" not in domain_lower:
                return 1
                
        return 0
    
    def save_training_data(self, filepath):
        """Save collected training data"""
        # Add summary statistics
        legitimate_count = sum(1 for sample in self.training_data if sample['label'] == 0)
        malicious_count = sum(1 for sample in self.training_data if sample['label'] == 1)
        
        summary = {
            'total_samples': len(self.training_data),
            'legitimate_samples': legitimate_count,
            'malicious_samples': malicious_count,
            'collection_date': pd.Timestamp.now().isoformat(),
            'collection_method': 'direct_alexa_csv'
        }
        
        final_data = {
            'summary': summary,
            'samples': self.training_data
        }
        
        with open(filepath, 'w') as f:
            json.dump(final_data, f, indent=2)
        
        print(f"Saved training data to {filepath}")
        print(f"Summary: {legitimate_count} legitimate, {malicious_count} malicious")

    def create_direct_training_data(self, alexa_csv_path, num_legitimate=10000, num_malicious=5000):
        """Create training data directly from Alexa CSV without external API"""
        print(f"Creating training data directly from Alexa CSV")
        print(f"Target: {num_legitimate} legitimate + {num_malicious} malicious samples")
        
        # Load Alexa data
        alexa_df = self.load_alexa_top_1m(alexa_csv_path)
        
        # Create legitimate samples from Alexa (these are known good domains)
        print(f"Processing legitimate domains from Alexa Top 1M...")
        legitimate_samples = self.create_legitimate_samples_fast(alexa_df, num_legitimate)
        
        # Generate malicious/suspicious patterns
        print(f"Generating malicious domain patterns...")
        malicious_samples = self.create_malicious_samples_fast(num_malicious)
        
        # Combine all samples
        all_samples = legitimate_samples + malicious_samples
        random.shuffle(all_samples)  # Shuffle for better training
        
        print(f"Created {len(all_samples)} total training samples")
        print(f"Legitimate: {len(legitimate_samples)} samples")
        print(f"Malicious: {len(malicious_samples)} samples")
        
        return all_samples
    
    def create_legitimate_samples_fast(self, alexa_df, num_samples):
        """Create legitimate samples from Alexa data without API calls"""
        samples = []
        
        # Sample from different ranking tiers for diversity
        sample_indices = []
        
        # Top 1000 (25%)
        top_1k = alexa_df[alexa_df['rank'] <= 1000]
        sample_indices.extend(top_1k.sample(n=min(num_samples//4, len(top_1k))).index.tolist())
        
        # Top 10k (25%)
        top_10k = alexa_df[(alexa_df['rank'] > 1000) & (alexa_df['rank'] <= 10000)]
        sample_indices.extend(top_10k.sample(n=min(num_samples//4, len(top_10k))).index.tolist())
        
        # Top 100k (25%)
        top_100k = alexa_df[(alexa_df['rank'] > 10000) & (alexa_df['rank'] <= 100000)]
        sample_indices.extend(top_100k.sample(n=min(num_samples//4, len(top_100k))).index.tolist())
        
        # Remaining from full dataset (25%)
        remaining_needed = num_samples - len(sample_indices)
        if remaining_needed > 0:
            remaining = alexa_df[~alexa_df.index.isin(sample_indices)]
            sample_indices.extend(remaining.sample(n=min(remaining_needed, len(remaining))).index.tolist())
        
        # Create samples
        for idx in sample_indices[:num_samples]:
            row = alexa_df.iloc[idx]
            domain = row['domain'].strip()
            
            sample = {
                'url': f"https://{domain}",
                'domain': domain,
                'alexa_rank': int(row['rank']),
                'label': 0,  # Legitimate
                'threat_data': {},  # Empty - will be simulated during training
                'features': self.extract_basic_features(f"https://{domain}", domain),
                'source': 'alexa_legitimate'
            }
            samples.append(sample)
            
            if len(samples) % 1000 == 0:
                print(f"Created {len(samples)}/{num_samples} legitimate samples")
        
        return samples
    
    def create_malicious_samples_fast(self, num_samples):
        """Generate malicious domain patterns for training"""
        samples = []
        
        # Generate diverse malicious patterns
        patterns = self.generate_suspicious_domains(num_samples)
        
        for i, domain in enumerate(patterns[:num_samples]):
            sample = {
                'url': f"https://{domain}",
                'domain': domain,
                'alexa_rank': None,
                'label': 1,  # Malicious
                'threat_data': {},  # Empty - will be simulated during training
                'features': self.extract_basic_features(f"https://{domain}", domain),
                'source': 'generated_malicious'
            }
            samples.append(sample)
            
            if (i + 1) % 1000 == 0:
                print(f"Created {i + 1}/{num_samples} malicious samples")
        
        return samples

def main():
    """Streamlined data collection from Alexa CSV"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnet Fast Data Collector - Direct from Alexa CSV')
    parser.add_argument('--alexa-csv', default='alexa.csv',
                       help='Path to Alexa Top 1M CSV file')
    parser.add_argument('--legitimate', type=int, default=10000,
                       help='Number of legitimate samples (default: 10000)')
    parser.add_argument('--malicious', type=int, default=5000,
                       help='Number of malicious samples (default: 5000)')
    parser.add_argument('--output', default='training_data.json',
                       help='Output training data file')
    
    args = parser.parse_args()
    
    # Check if Alexa CSV exists
    alexa_csv_path = os.path.join(os.path.dirname(__file__), args.alexa_csv)
    if not os.path.exists(alexa_csv_path):
        print(f"Alexa CSV file not found: {alexa_csv_path}")
        print(f"Please place the Alexa Top 1M CSV file as '{args.alexa_csv}' in the scripts folder")
        print(f"Download from: https://s3.amazonaws.com/alexa-static/top-1m.csv.zip")
        return
    
    # Initialize fast collector (no API needed)
    collector = VulnetDataCollector()
    
    print(f"Fast Training Data Creation Mode")
    print(f"Source: {alexa_csv_path}")
    print(f"Target: {args.legitimate + args.malicious} total samples")
    print(f"No external API calls needed!")
    
    # Create training data directly
    training_samples = collector.create_direct_training_data(
        alexa_csv_path, 
        args.legitimate, 
        args.malicious
    )
    
    # Save training data
    collector.training_data = training_samples
    collector.save_training_data(args.output)
    
    print(f"\nFast data collection complete!")
    print(f"Output: {args.output}")
    print(f"Ready for optimized training!")
    print(f"Next: python optimized_trainer.py --data {args.output}")

if __name__ == "__main__":
    main()
