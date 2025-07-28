# Vulnet Security Scanner

A browser extension that analyzes website security by checking SSL certificates, form encryption, tracking scripts, and potential scam indicators. The extension provides security scores and recommendations based on technical analysis performed locally in the browser.

## Overview

This extension scans websites you visit and evaluates their security using JavaScript-based analysis. It checks SSL certificates, detects mixed content, analyzes forms for HTTPS usage, identifies tracking scripts, and looks for common phishing patterns. All analysis happens locally without sending data to external servers.

## Features

### Connection Security
- Checks SSL certificate validity and expiration dates
- Detects mixed content (HTTP resources on HTTPS pages)
- Validates certificate chains and identifies self-signed certificates
- Reports on TLS protocol versions and cipher suites

### Form Security
- Identifies forms that submit data over HTTP instead of HTTPS
- Checks for proper input validation and security attributes
- Detects password fields without proper protection
- Analyzes form submission methods and encryption

### Privacy Analysis
- Detects tracking scripts from known analytics and advertising domains
- Identifies social media widgets that may track users
- Finds tracking pixels (1x1 images used for monitoring)
- Reports on third-party domains loading resources

### Scam Detection
- Analyzes URLs for suspicious patterns and known phishing indicators
- Checks domain reputation using local pattern matching
- Identifies suspicious domain characteristics (unusual TLDs, random strings)
- Detects content patterns commonly used in phishing attempts

### AI Analysis
- Uses a pre-trained model to classify threats based on multiple factors
- Combines technical indicators with pattern recognition
- Provides confidence scores for threat assessments 

## Technical Implementation

The extension is built using Manifest V3 and consists of several JavaScript modules that analyze different security aspects.

### Architecture
- **Content Scripts**: Injected into web pages to analyze DOM, resources, and network requests
- **Service Worker**: Handles background tasks and coordinates between components
- **Popup Interface**: Displays security analysis results and detailed breakdowns
- **Security Modules**: Specialized modules for SSL, forms, privacy, and scam detection

### Analysis Methods
Security analysis is performed using DOM inspection, network resource enumeration, and pattern matching against known threat indicators. The extension reads certificate information through browser APIs and analyzes page structure for security issues.

### Scoring System
Each security category receives a score from 0-100 based on specific criteria:
- Connection Security: SSL validity, protocol strength, mixed content presence
- Form Safety: HTTPS usage, validation attributes, security headers
- Privacy Protection: Number and type of tracking scripts detected
- Scam Detection: Domain reputation, URL patterns, content analysis
- Overall score is calculated as weighted average of individual categories

## Installation

1. Download or clone the extension files
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable Developer Mode using the toggle in the top right
4. Click "Load unpacked" and select the extension directory
5. The Vulnet icon will appear in your browser toolbar

The extension requires permissions for active tab access (to analyze visited websites) and storage (to cache security data).

## Usage

After installation, the extension automatically analyzes each website you visit. Click the Vulnet icon in your browser toolbar to view security analysis results.

### Security Reports
The popup displays scores for different security categories:
- **Connection Security**: SSL certificate validity and encryption status
- **Form Safety**: Whether forms use HTTPS and have proper validation
- **Privacy Protection**: Tracking scripts and social widgets detected
- **Scam Detection**: Domain reputation and URL pattern analysis

Scores range from 0-100, with higher scores indicating better security. Click "View Details" for specific findings and recommendations.

## Privacy

All security analysis is performed locally in your browser. No browsing data is transmitted to external servers. The extension does not collect personal information or track user behavior.

## Development

Built with JavaScript, HTML, and CSS using Manifest V3. The codebase is organized into modular security analysis components for SSL checking, form analysis, privacy protection, and scam detection.

