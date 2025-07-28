#!/usr/bin/env python3
"""
Vulnet ML Model - Optimized High-Performance Trainer
Fast training with full dataset support and professional quality
"""

import json
import numpy as np
import os
import sys
import time
from urllib.parse import urlparse
import re
from collections import Counter
import math
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

class OptimizedVulnetTrainer:
    def __init__(self, use_multiprocessing=True):
        self.use_multiprocessing = use_multiprocessing
        self.cpu_count = multiprocessing.cpu_count()
        
        # Optimized feature extraction patterns (pre-compiled for speed)
        self.suspicious_words = set([
            'verify', 'suspended', 'urgent', 'click', 'immediately',
            'limited', 'time', 'act', 'now', 'winner', 'prize',
            'free', 'money', 'guaranteed', 'secret', 'exclusive',
            'security', 'update', 'confirm', 'locked'
        ])
        
        self.brands = set([
            'paypal', 'amazon', 'google', 'microsoft', 'apple',
            'facebook', 'netflix', 'adobe', 'dropbox', 'linkedin'
        ])
        
        # Pre-compiled regex patterns for speed
        self.ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
        self.number_pattern = re.compile(r'\d')
        
        print(f"   Optimized Vulnet Trainer initialized")
        print(f"   CPU cores available: {self.cpu_count}")
        print(f"   Multiprocessing: {'Enabled' if use_multiprocessing else 'Disabled'}")
    
    def load_training_data(self, data_file):
        """Load training data from JSON format only"""
        print(f"Loading training data from {data_file}")
        start_time = time.time()
        
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        samples = data.get('samples', [])
        load_time = time.time() - start_time
        
        print(f"Loaded {len(samples)} samples in {load_time:.2f}s")
        return samples
    
    def extract_features_batch(self, samples):
        """Extract features using optimized batch processing"""
        print(f"Extracting features from {len(samples)} samples...")
        start_time = time.time()
        
        if self.use_multiprocessing and len(samples) > 1000:
            # Use multiprocessing for large datasets
            chunk_size = max(100, len(samples) // (self.cpu_count * 4))
            chunks = [samples[i:i+chunk_size] for i in range(0, len(samples), chunk_size)]
            
            print(f"Using {len(chunks)} chunks across {self.cpu_count} processes")
            
            with ProcessPoolExecutor(max_workers=self.cpu_count) as executor:
                chunk_results = list(executor.map(self._process_chunk, chunks))
            
            # Combine results
            features_list = []
            labels = []
            for chunk_features, chunk_labels in chunk_results:
                features_list.extend(chunk_features)
                labels.extend(chunk_labels)
        else:
            # Single-threaded for smaller datasets
            features_list, labels = self._process_chunk(samples)
        
        extract_time = time.time() - start_time
        print(f"Feature extraction completed in {extract_time:.2f}s")
        print(f"Features per second: {len(features_list)/extract_time:.0f}")
        
        return np.array(features_list), np.array(labels)
    
    def _process_chunk(self, samples):
        """Process a chunk of samples (for multiprocessing)"""
        features_list = []
        labels = []
        
        for sample in samples:
            try:
                features = self._extract_25_features_optimized(sample)
                if features and len(features) == 25:
                    features_list.append(features)
                    labels.append(sample['label'])
            except Exception:
                continue  # Skip problematic samples silently for speed
        
        return features_list, labels
    
    def _extract_25_features_optimized(self, sample):
        """Optimized 25-feature extraction"""
        url = sample['url']
        domain = sample['domain']
        threat_data = sample.get('threat_data', {})
        alexa_rank = sample.get('alexa_rank')
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or domain
            
            # URL structure features (8) - vectorized operations
            url_len = len(url)
            domain_len = len(domain)
            subdomains = hostname.split('.')
            subdomain_count = max(0, len(subdomains) - 2)
            
            has_hyphens = 1 if '-' in domain else 0
            has_numbers = 1 if self.number_pattern.search(domain) else 0
            is_ip = 1 if self.ip_pattern.match(domain) else 0
            is_https = 1 if url.startswith('https://') else 0
            has_port = 1 if parsed.port else 0
            
            # Normalize
            url_length = min(1, url_len / 200)
            domain_length = min(1, domain_len / 50)
            subdomain_count_norm = min(1, subdomain_count / 5)
            
            # Page content features (8) - optimized simulation
            domain_lower = domain.lower()
            script_count = min(1, self._fast_content_sim(domain, 'scripts'))
            form_count = min(1, self._fast_content_sim(domain, 'forms'))
            link_count = min(1, self._fast_content_sim(domain, 'links'))
            image_count = min(1, self._fast_content_sim(domain, 'images'))
            iframe_count = min(1, self._fast_content_sim(domain, 'iframes'))
            
            # Fast keyword checks
            login_keywords = {'login', 'account', 'signin', 'password'}
            has_password_field = 1 if any(kw in domain_lower for kw in login_keywords) else 0
            has_login_form = 1 if any(kw in domain_lower for kw in {'login', 'signin', 'auth'}) else 0
            external_domains = min(1, self._fast_content_sim(domain, 'external'))
            
            # Behavioral features (3) - fast simulation
            redirect_count = min(1, self._fast_behavioral_sim(threat_data))
            load_time = min(1, np.random.uniform(0.1, 0.5))  # Simulated
            error_count = min(1, self._fast_error_sim(threat_data))
            
            # Advanced analysis features (6) - optimized
            entropic_domain = self._fast_entropy(domain)
            suspicious_words = self._fast_suspicious_words(domain_lower)
            brand_imitation = self._fast_brand_check(url, domain)
            social_engineering = self._fast_social_engineering(domain_lower)
            threat_score = self._fast_threat_score(threat_data)
            alexa_score = self._fast_alexa_score(alexa_rank)
            
            return [
                # URL structure (8)
                url_length, domain_length, subdomain_count_norm, has_hyphens,
                has_numbers, is_ip, is_https, has_port,
                # Page content (8)
                script_count, form_count, link_count, image_count,
                iframe_count, has_password_field, has_login_form, external_domains,
                # Behavioral (3)
                redirect_count, load_time, error_count,
                # Advanced analysis (6)
                entropic_domain, suspicious_words, brand_imitation,
                social_engineering, threat_score, alexa_score
            ]
            
        except Exception:
            return None
    
    def _fast_content_sim(self, domain, content_type):
        """Fast content simulation"""
        base = hash(domain + content_type) % 100 / 100
        return base * 0.5  # Normalized
    
    def _fast_behavioral_sim(self, threat_data):
        """Fast behavioral simulation"""
        if threat_data and threat_data.get('detected_urls'):
            return min(1, len(threat_data['detected_urls']) / 10)
        return np.random.uniform(0, 0.2)
    
    def _fast_error_sim(self, threat_data):
        """Fast error simulation"""
        if threat_data and threat_data.get('response_code') != 1:
            return 0.3
        return np.random.uniform(0, 0.1)
    
    def _fast_entropy(self, domain):
        """Fast entropy calculation"""
        if not domain or len(domain) < 3:
            return 0
        chars = domain.replace('.', '')
        if len(chars) < 2:
            return 0
        unique_ratio = len(set(chars)) / len(chars)
        return min(1, unique_ratio * 1.5)  # Approximation
    
    def _fast_suspicious_words(self, text):
        """Fast suspicious word detection"""
        matches = sum(1 for word in self.suspicious_words if word in text)
        return min(1, matches / 5)
    
    def _fast_brand_check(self, url, domain):
        """Fast brand imitation check"""
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        for brand in self.brands:
            if brand in domain_lower:
                # Quick legitimacy check
                if f"{brand}.com" in url_lower or f"www.{brand}" in url_lower:
                    return 0
                return 0.8
        return 0
    
    def _fast_social_engineering(self, text):
        """Fast social engineering detection"""
        tactics = {'urgent', 'immediate', 'suspended', 'verify', 'security', 'update'}
        matches = sum(1 for tactic in tactics if tactic in text)
        return min(1, matches / 8)
    
    def _fast_threat_score(self, threat_data):
        """Fast threat score calculation"""
        if not threat_data:
            return 0.5
        
        detected_urls = threat_data.get('detected_urls', [])
        detected_count = len(detected_urls)
        
        if detected_count >= 3:
            return min(1, 0.6 + (detected_count / 20) * 0.4)
        elif detected_count > 0:
            return detected_count / 10 * 0.5
        return 0.1
    
    def _fast_alexa_score(self, alexa_rank):
        """Fast Alexa score calculation"""
        if not alexa_rank:
            return 0.6
        
        if alexa_rank <= 1000:
            return 0.05
        elif alexa_rank <= 10000:
            return 0.1
        elif alexa_rank <= 100000:
            return 0.2
        elif alexa_rank <= 1000000:
            return 0.3
        return 0.7
    
    def train_optimized_model(self, X, y):
        """Train model with optimized parameters for speed"""
        print(f"Training optimized model...")
        print(f"Dataset: {len(X)} samples, {X.shape[1] if len(X) > 0 else 0} features")
        
        if len(X) == 0:
            raise ValueError("No training data available")
        
        start_time = time.time()
        
        # Convert to numpy arrays if needed
        X = np.array(X)
        y = np.array(y)
        
        legitimate_count = np.sum(y == 0)
        malicious_count = np.sum(y == 1)
        print(f"Legitimate: {legitimate_count} samples")
        print(f"Malicious:  {malicious_count} samples")
        
        # Fast train/test split (80/20)
        split_idx = int(0.8 * len(X))
        indices = np.random.permutation(len(X))
        
        train_idx = indices[:split_idx]
        test_idx = indices[split_idx:]
        
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        # Fast standardization (simplified)
        X_mean = np.mean(X_train, axis=0)
        X_std = np.std(X_train, axis=0)
        X_std[X_std == 0] = 1  # Prevent division by zero
        
        X_train_scaled = (X_train - X_mean) / X_std
        X_test_scaled = (X_test - X_mean) / X_std
        
        # Optimized logistic regression with fast solver
        weights, bias = self._fast_logistic_regression(X_train_scaled, y_train)
        
        # Fast evaluation
        train_pred = self._predict(X_train_scaled, weights, bias)
        test_pred = self._predict(X_test_scaled, weights, bias)
        
        train_accuracy = np.mean((train_pred > 0.5) == y_train)
        test_accuracy = np.mean((test_pred > 0.5) == y_test)
        
        train_time = time.time() - start_time
        
        print(f"Training completed in {train_time:.2f}s")
        print(f"Train accuracy: {train_accuracy:.3f}")
        print(f"Test accuracy:  {test_accuracy:.3f}")
        print(f"Samples/second: {len(X)/train_time:.0f}")
        
        return {
            'weights': weights.tolist(),
            'bias': float(bias),
            'scaler_mean': X_mean.tolist(),
            'scaler_std': X_std.tolist(),
            'train_accuracy': float(train_accuracy),
            'test_accuracy': float(test_accuracy),
            'training_time': train_time,
            'samples_processed': len(X)
        }
    
    def _fast_logistic_regression(self, X, y, learning_rate=0.01, epochs=500):
        """Fast logistic regression implementation"""
        # Add bias term
        X_bias = np.column_stack([np.ones(len(X)), X])
        
        # Initialize weights
        weights = np.random.normal(0, 0.01, X_bias.shape[1])
        
        # Vectorized gradient descent
        for epoch in range(epochs):
            # Forward pass
            z = X_bias.dot(weights)
            predictions = 1 / (1 + np.exp(-np.clip(z, -500, 500)))
            
            # Gradient calculation
            gradient = X_bias.T.dot(predictions - y) / len(y)
            weights -= learning_rate * gradient
            
            # Early stopping if converged
            if epoch > 50 and epoch % 50 == 0:
                loss = -np.mean(y * np.log(predictions + 1e-8) + (1 - y) * np.log(1 - predictions + 1e-8))
                if loss < 0.1:  # Good enough convergence
                    break
        
        return weights[1:], weights[0]  # weights, bias
    
    def _predict(self, X, weights, bias):
        """Fast prediction"""
        z = X.dot(weights) + bias
        return 1 / (1 + np.exp(-np.clip(z, -500, 500)))
    
    def export_optimized_model(self, model_data, filepath='vulnet_optimized_model.json'):
        """Export optimized model"""
        feature_names = [
            'url_length', 'domain_length', 'subdomain_count', 'has_hyphens',
            'has_numbers', 'is_ip', 'is_https', 'has_port',
            'script_count', 'form_count', 'link_count', 'image_count',
            'iframe_count', 'has_password_field', 'has_login_form', 'external_domains',
            'redirect_count', 'load_time', 'error_count',
            'entropic_domain', 'suspicious_words', 'brand_imitation',
            'social_engineering', 'threat_score', 'alexa_score'
        ]
        
        export_data = {
            **model_data,
            'feature_names': feature_names,
            'model_type': 'optimized_logistic_regression',
            'training_method': 'high_performance_batch',
            'version': '2.0',
            'timestamp': time.time()
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Optimized model saved to {filepath}")
        print(f"Accuracy: {model_data['test_accuracy']:.1%}")
        print(f"Training time: {model_data['training_time']:.2f}s")
        print(f"Samples processed: {model_data['samples_processed']:,}")

def main():
    """High-performance training pipeline"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnet Optimized High-Performance Trainer')
    parser.add_argument('--data', default='training_data.json', 
                       help='Training data JSON file from data_collector.py')
    parser.add_argument('--no-multiprocessing', action='store_true',
                       help='Disable multiprocessing (for debugging)')
    parser.add_argument('--output', default='vulnet_optimized_model.json',
                       help='Output model file')
    parser.add_argument('--samples', type=int, default=None,
                       help='Max samples to use for training (optional limit)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.data):
        print(f"Training data file not found: {args.data}")
        print("Run data_collector.py first to collect training data")
        return
    
    print(f"Vulnet Optimized Trainer")
    print(f"Data source: {args.data}")
    if args.samples:
        print(f"Max samples: {args.samples}")
    print(f"Output: {args.output}")
    
    # Initialize optimized trainer
    trainer = OptimizedVulnetTrainer(use_multiprocessing=not args.no_multiprocessing)
    
    # Load and process data
    training_samples = trainer.load_training_data(args.data)
    
    if not training_samples:
        print("No training samples found")
        return
    
    # Limit samples if requested
    if args.samples and len(training_samples) > args.samples:
        import random
        training_samples = random.sample(training_samples, args.samples)
        print(f"Limited to {args.samples} samples for training")
    
    # Extract features using optimized batch processing
    X, y = trainer.extract_features_batch(training_samples)
    
    if len(X) == 0:
        print("No valid features extracted")
        return
    
    # Train optimized model
    model_data = trainer.train_optimized_model(X, y)
    
    # Export model
    trainer.export_optimized_model(model_data, args.output)
    
    print(f"\nHigh-performance training complete!")
    print(f"Model file: {args.output}")
    print(f"Ready for extension integration")

if __name__ == "__main__":
    main()
