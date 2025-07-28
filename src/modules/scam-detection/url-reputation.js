/** URL reputation checker with local analysis */

class URLReputationChecker {
  constructor() {
    // Known suspicious TLDs (top-level domains)
    this.suspiciousTLDs = [
      '.tk', '.ml', '.cf', '.ga', '.top', '.click', '.download', '.stream',
      '.science', '.cricket', '.racing', '.review', '.party', '.work',
      '.men', '.date', '.faith', '.bid', '.trade', '.loan', '.win'
    ];

    // Common phishing keywords
    this.phishingKeywords = [
      'secure', 'verify', 'update', 'suspend', 'confirm', 'login',
      'signin', 'account', 'bank', 'paypal', 'amazon', 'apple',
      'microsoft', 'google', 'facebook', 'security', 'alert',
      'urgent', 'immediate', 'expire', 'limited', 'offer'
    ];

    // Suspicious URL patterns
    this.suspiciousPatterns = [
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
      /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./,    // Hyphenated domains (3+ segments)
      /[0-9]{8,}/,                           // Very long number sequences (8+)
      /[a-z]{25,}/,                          // Extremely long strings (25+)
      /xn--/,                                // Punycode (internationalized domains)
      /bit\.ly|tinyurl|t\.co|short/,         // URL shorteners
      /[il1|o0]{3,}/g                        // Multiple lookalike characters
    ];

    // Known legitimate domains (expanded gaming intelligence)
    this.trustedDomains = [
      // Major tech companies
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
      'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
      'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'discord.com',
      
      // Gaming platforms and stores
      'steam.com', 'epic.com', 'origin.com', 'battle.net', 'minecraft.net',
      'roblox.com', 'unity.com', 'unreal.com', 'twitch.tv', 'gog.com',
      'humblebundle.com', 'itch.io', 'gamejolt.com', 'newgrounds.com',
      
      // Gaming publishers and developers
      'activision.com', 'blizzard.com', 'ubisoft.com', 'ea.com', 'rockstargames.com',
      'bethesda.net', 'valve.com', 'riot.com', 'riotgames.com', 'leagueoflegends.com',
      
      // Gaming community and esports
      'teamspeak.com', 'mumble.info', 'curse.com', 'overwolf.com',
      'faceit.com', 'esl.com', 'majorleaguegaming.com',
      
      // Gaming content and streaming
      'gamespot.com', 'ign.com', 'polygon.com', 'kotaku.com', 'pcgamer.com',
      'gameinformer.com', 'eurogamer.net', 'destructoid.com',
      
      // Development and tech
      'codepen.io', 'glitch.com', 'repl.it', 'vercel.com', 'netlify.com',
      'heroku.com', 'aws.com', 'cloudflare.com', 'npm.com'
    ];

    // Gaming domain patterns (more comprehensive)
    this.gamingPatterns = [
      /\.(gg|io|me|tv)$/i,           // Gaming-friendly TLDs
      /game|gaming|esport|clan|guild|server/i,  // Gaming keywords
      /minecraft|steam|riot|league|csgo|dota/i,  // Game-specific
      /tournament|competition|match|arena/i       // Esports terms
    ];

    // Enhanced gaming TLD whitelist
    this.gamingTLDs = ['.gg', '.io', '.me', '.tv', '.co', '.net', '.org', '.itch'];

    // Gaming-specific trusted patterns
    this.trustedGamingPatterns = [
      /^[a-z0-9-]+\.(gg|io)$/i,      // Simple .gg/.io domains
      /^cities\.gg$/i,               // Specific known gaming domains
      /^[a-z0-9-]+\.minecraft\.net$/i, // Minecraft subdomains
      /^[a-z0-9-]+\.steam\.com$/i    // Steam subdomains
    ];

    // Domain age approximation (newer domains are riskier)
    this.suspiciousNewDomains = [
      // This would typically be populated from a domain age service
      // For demo purposes, we'll use pattern analysis
    ];
  }

  /**
   * Main URL reputation analysis function
   * @param {string} url - URL to analyze
   * @returns {Object} Comprehensive reputation report
   */
  async analyzeURLReputation(url) {
    console.log('🔍 Starting URL reputation analysis for:', url);

    const report = {
      score: 100,
      riskLevel: 'safe',
      
      // Detailed breakdown scores (like demo data)
      reputationScore: 100,
      domainScore: 100,
      patternScore: 100,
      trustScore: 100,
      phishingScore: 100,
      
      // Detailed breakdown descriptions
      reputationDetails: '',
      domainDetails: '',
      patternDetails: '',
      trustDetails: '',
      phishingDetails: '',
      
      // Technical analysis details
      issues: [],
      indicators: [],
      analysis: {
        domain: null,
        tld: null,
        isIP: false,
        isShortened: false,
        suspiciousPatterns: [],
        phishingIndicators: [],
        trustScore: 0
      },
      recommendations: []
    };

    try {
      const urlObj = new URL(url);
      report.analysis.domain = urlObj.hostname;
      report.analysis.tld = this.extractTLD(urlObj.hostname);

      // Enhanced gaming domain analysis
      const gamingAnalysis = this.analyzeGamingDomain(urlObj.hostname);
      
      // Step 1: Check if domain is trusted
      if (this.isTrustedDomain(urlObj.hostname)) {
        report.analysis.trustScore = 95;
        report.riskLevel = 'trusted';
        report.indicators.push('Recognized trusted domain');
        return this.generateReputationReport(report);
      }

      // Step 1.5: Gaming domain whitelist check
      if (gamingAnalysis.isLegitimateGaming) {
        report.analysis.trustScore = 85;
        report.riskLevel = 'trusted';
        report.indicators.push(`Legitimate gaming domain (${gamingAnalysis.reason})`);
        report.score = Math.max(report.score, 85);
        return this.generateReputationReport(report);
      }

      // Step 2: Check for IP address usage
      if (this.isIPAddress(urlObj.hostname)) {
        report.score -= 40;
        report.analysis.isIP = true;
        report.issues.push('Uses IP address instead of domain name');
        report.indicators.push(' IP Address: High risk indicator');
      }

      // Step 3: Analyze TLD reputation with gaming context
      const tldAnalysis = this.analyzeTLD(report.analysis.tld, gamingAnalysis.isGamingRelated);
      if (tldAnalysis.suspicious) {
        report.score -= tldAnalysis.penalty;
        report.issues.push(`Suspicious TLD: ${report.analysis.tld}`);
        report.indicators.push(` Suspicious domain extension: ${report.analysis.tld}`);
      }

      // Step 4: Check for URL shortening services
      if (this.isURLShortener(urlObj.hostname)) {
        report.score -= 25;
        report.analysis.isShortened = true;
        report.issues.push('URL shortening service detected');
        report.indicators.push('LINK Shortened URL: Cannot verify final destination');
      }

      // Step 5: Analyze domain patterns
      const patternAnalysis = this.analyzeURLPatterns(url);
      if (patternAnalysis.suspicious.length > 0) {
        report.score -= (patternAnalysis.suspicious.length * 15);
        report.analysis.suspiciousPatterns = patternAnalysis.suspicious;
        report.issues.push(...patternAnalysis.issues);
        report.indicators.push(...patternAnalysis.indicators);
      }

      // Step 6: Check for phishing keywords
      const phishingAnalysis = this.analyzePhishingIndicators(url);
      if (phishingAnalysis.indicators.length > 0) {
        report.score -= (phishingAnalysis.indicators.length * 20);
        report.analysis.phishingIndicators = phishingAnalysis.indicators;
        report.issues.push(...phishingAnalysis.issues);
        report.indicators.push(...phishingAnalysis.indicators);
      }

      // Step 7: Check for typosquatting
      const typosquattingAnalysis = this.analyzeTyposquatting(urlObj.hostname);
      if (typosquattingAnalysis.suspicious) {
        report.score -= 30;
        report.issues.push('Potential typosquatting detected');
        report.indicators.push(` Typosquatting: Similar to ${typosquattingAnalysis.similarTo}`);
      }

      // Step 8: Analyze URL structure
      const structureAnalysis = this.analyzeURLStructure(urlObj);
      if (structureAnalysis.suspicious) {
        report.score -= structureAnalysis.penalty;
        report.issues.push(...structureAnalysis.issues);
        report.indicators.push(...structureAnalysis.indicators);
      }

      // Step 9: Check subdomain depth
      const subdomainAnalysis = this.analyzeSubdomains(urlObj.hostname);
      if (subdomainAnalysis.excessive) {
        report.score -= 20;
        report.issues.push('Excessive subdomain depth');
        report.indicators.push(` Deep nesting: ${subdomainAnalysis.depth} levels`);
      }

      return this.generateReputationReport(report);

    } catch (error) {
      console.error('URL reputation analysis failed:', error);
      return {
        score: 0,
        riskLevel: 'error',
        issues: ['Unable to analyze URL'],
        indicators: [' Analysis failed'],
        userMessage: ' URL reputation check failed'
      };
    }
  }

  /**
   * Check if domain is in trusted whitelist
   * @param {string} hostname - Domain hostname
   * @returns {boolean} True if trusted
   */
  isTrustedDomain(hostname) {
    const domain = hostname.toLowerCase();
    return this.trustedDomains.some(trusted => 
      domain === trusted || domain.endsWith('.' + trusted)
    );
  }

  /**
   * Check if hostname is an IP address
   * @param {string} hostname - Hostname to check
   * @returns {boolean} True if IP address
   */
  isIPAddress(hostname) {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipPattern.test(hostname);
  }

  /**
   * Extract top-level domain from hostname
   * @param {string} hostname - Domain hostname
   * @returns {string} TLD (e.g., '.com', '.org')
   */
  extractTLD(hostname) {
    const parts = hostname.split('.');
    return parts.length > 1 ? '.' + parts[parts.length - 1] : '';
  }

  /**
   * Analyze if domain is gaming-related and legitimate
   */
  analyzeGamingDomain(hostname) {
    const analysis = {
      isGamingRelated: false,
      isLegitimateGaming: false,
      reason: null,
      confidence: 0
    };

    // Check trusted gaming patterns
    for (const pattern of this.trustedGamingPatterns) {
      if (pattern.test(hostname)) {
        analysis.isLegitimateGaming = true;
        analysis.reason = 'Matches trusted gaming pattern';
        analysis.confidence = 90;
        return analysis;
      }
    }

    // Check gaming domain patterns
    for (const pattern of this.gamingPatterns) {
      if (pattern.test(hostname)) {
        analysis.isGamingRelated = true;
        analysis.confidence += 20;
      }
    }

    // Check for gaming TLD with reasonable domain name
    const tld = this.extractTLD(hostname);
    if (this.gamingTLDs.includes(tld)) {
      analysis.isGamingRelated = true;
      
      // Simple domain name on gaming TLD = likely legitimate
      const domainParts = hostname.split('.');
      if (domainParts.length <= 3 && domainParts[0].length >= 3 && domainParts[0].length <= 20) {
        if (!/[0-9]{4,}/.test(domainParts[0])) { // No long number sequences
          analysis.isLegitimateGaming = true;
          analysis.reason = `Simple domain on gaming TLD (${tld})`;
          analysis.confidence = 75;
        }
      }
    }

    return analysis;
  }

  /**
   * Analyze TLD reputation with gaming context
   */
  analyzeTLD(tld, isGamingRelated = false) {
    const suspicious = this.suspiciousTLDs.includes(tld.toLowerCase());
    const isGamingTLD = this.gamingTLDs.includes(tld.toLowerCase());
    
    // Reduce penalty for gaming-related domains
    let penalty = 0;
    if (suspicious && !isGamingTLD) {
      penalty = isGamingRelated ? 15 : 25; // Lower penalty for gaming domains
    }
    
    return {
      suspicious: suspicious && !isGamingTLD,
      penalty: penalty,
      category: isGamingTLD ? 'gaming' : (suspicious ? 'suspicious' : 'standard'),
      isGaming: isGamingTLD
    };
  }

  /**
   * Check if domain is a URL shortening service
   * @param {string} hostname - Domain hostname
   * @returns {boolean} True if URL shortener
   */
  isURLShortener(hostname) {
    const shorteners = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link',
      'ow.ly', 'buff.ly', 'is.gd', 'tiny.cc', 'rebrand.ly'
    ];
    return shorteners.includes(hostname.toLowerCase());
  }

  /**
   * Analyze URL for suspicious patterns
   * @param {string} url - URL to analyze
   * @returns {Object} Pattern analysis results
   */
  analyzeURLPatterns(url) {
    const result = {
      suspicious: [],
      issues: [],
      indicators: []
    };

    // Check if this is a known gaming domain first
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const tld = this.extractTLD(hostname);
      
      // If it's a trusted gaming domain, be much more lenient
      const isGamingDomain = this.gamingTLDs.includes(tld) || 
                            hostname.includes('game') || 
                            hostname.includes('esports') ||
                            this.trustedDomains.some(trusted => hostname.includes(trusted));
      
      this.suspiciousPatterns.forEach((pattern, index) => {
        if (pattern.test(url)) {
          result.suspicious.push(pattern);
          
          switch (index) {
            case 0: // IP address
              result.issues.push('Uses IP address instead of domain');
              result.indicators.push(' Direct IP access detected');
              break;
            case 1: // Hyphenated domains (3+ segments)
              // Be more lenient with gaming domains
              if (!isGamingDomain) {
                result.issues.push('Hyphenated domain name');
                result.indicators.push(' Unusual domain structure');
              }
              break;
            case 2: // Very long numbers (8+)
              result.issues.push('Contains very long number sequences');
              result.indicators.push('NUMBERS Suspicious number patterns');
              break;
            case 3: // Extremely long strings (25+)
              // Only flag if it's really excessive and not a gaming domain
              if (!isGamingDomain) {
                result.issues.push('Contains extremely long text strings');
                result.indicators.push(' Unusual URL length');
              }
              break;
            case 4: // Punycode
              result.issues.push('Internationalized domain (punycode)');
              result.indicators.push('GLOBAL IDN domain detected');
              break;
            case 5: // URL shorteners
              result.issues.push('URL shortening service');
              result.indicators.push('LINK Shortened URL');
              break;
            case 6: // Multiple lookalike characters
              result.issues.push('Contains multiple lookalike characters');
              result.indicators.push(' Character spoofing detected');
              break;
          }
        }
      });
      
    } catch (error) {
      // If URL parsing fails, apply all patterns normally
      this.suspiciousPatterns.forEach((pattern, index) => {
        if (pattern.test(url)) {
          result.suspicious.push(pattern);
          
          switch (index) {
            case 0: // IP address
              result.issues.push('Uses IP address instead of domain');
              result.indicators.push(' Direct IP access detected');
              break;
            case 1: // Hyphenated domains
              result.issues.push('Hyphenated domain name');
              result.indicators.push(' Unusual domain structure');
              break;
            case 2: // Long numbers
              result.issues.push('Contains long number sequences');
              result.indicators.push('NUMBERS Suspicious number patterns');
              break;
            case 3: // Long strings
              result.issues.push('Contains very long text strings');
              result.indicators.push(' Unusual URL length');
              break;
            case 4: // Punycode
              result.issues.push('Internationalized domain (punycode)');
              result.indicators.push('GLOBAL IDN domain detected');
              break;
            case 5: // URL shorteners
              result.issues.push('URL shortening service');
              result.indicators.push('LINK Shortened URL');
              break;
            case 6: // Lookalike characters
              result.issues.push('Contains lookalike characters');
              result.indicators.push(' Character spoofing detected');
              break;
          }
        }
      });
    }

    return result;
  }

  /**
   * Analyze URL for phishing indicators
   * @param {string} url - URL to analyze
   * @returns {Object} Phishing analysis results
   */
  analyzePhishingIndicators(url) {
    const result = {
      indicators: [],
      issues: [],
      score: 0
    };

    const urlLower = url.toLowerCase();
    
    this.phishingKeywords.forEach(keyword => {
      if (urlLower.includes(keyword)) {
        result.indicators.push(` Phishing keyword: "${keyword}"`);
        result.issues.push(`Contains phishing-related term: ${keyword}`);
        result.score += 10;
      }
    });

    // Check for multiple keywords (higher risk)
    if (result.indicators.length > 2) {
      result.issues.push('Multiple phishing keywords detected');
      result.indicators.push(' High phishing risk: Multiple suspicious terms');
    }

    return result;
  }

  /**
   * Analyze for typosquatting attempts
   * @param {string} hostname - Domain to analyze
   * @returns {Object} Typosquatting analysis
   */
  analyzeTyposquatting(hostname) {
    const result = {
      suspicious: false,
      similarTo: null,
      confidence: 0
    };

    // Check against trusted domains for similarity
    for (const trusted of this.trustedDomains) {
      const similarity = this.calculateStringSimilarity(hostname, trusted);
      if (similarity > 0.8 && similarity < 1.0) {
        result.suspicious = true;
        result.similarTo = trusted;
        result.confidence = similarity;
        break;
      }
    }

    return result;
  }

  /**
   * Calculate string similarity using Levenshtein distance
   * @param {string} str1 - First string
   * @param {string} str2 - Second string
   * @returns {number} Similarity ratio (0-1)
   */
  calculateStringSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) return 1.0;
    
    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  /**
   * Calculate Levenshtein distance between two strings
   * @param {string} str1 - First string
   * @param {string} str2 - Second string
   * @returns {number} Edit distance
   */
  levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }

  /**
   * Analyze URL structure for suspicious elements
   * @param {URL} urlObj - Parsed URL object
   * @returns {Object} Structure analysis
   */
  analyzeURLStructure(urlObj) {
    const result = {
      suspicious: false,
      penalty: 0,
      issues: [],
      indicators: []
    };

    // Check for suspicious paths
    if (urlObj.pathname.includes('..')) {
      result.suspicious = true;
      result.penalty += 20;
      result.issues.push('Path traversal patterns detected');
      result.indicators.push(' Directory traversal attempt');
    }

    // Check for encoded characters
    if (urlObj.href.includes('%') && decodeURIComponent(urlObj.href) !== urlObj.href) {
      result.suspicious = true;
      result.penalty += 15;
      result.issues.push('URL encoding detected');
      result.indicators.push('ENCODED Encoded URL elements');
    }

    // Check for suspicious query parameters
    const suspiciousParams = ['exec', 'cmd', 'eval', 'system', 'shell'];
    const queryString = urlObj.search.toLowerCase();
    
    suspiciousParams.forEach(param => {
      if (queryString.includes(param)) {
        result.suspicious = true;
        result.penalty += 25;
        result.issues.push(`Suspicious parameter: ${param}`);
        result.indicators.push(` Dangerous parameter: ${param}`);
      }
    });

    return result;
  }

  /**
   * Analyze subdomain depth and structure
   * @param {string} hostname - Domain hostname
   * @returns {Object} Subdomain analysis
   */
  analyzeSubdomains(hostname) {
    const parts = hostname.split('.');
    const depth = parts.length - 2; // Subtract domain and TLD
    
    return {
      depth: depth,
      excessive: depth > 3,
      subdomains: parts.slice(0, -2)
    };
  }

  /**
   * Generate final reputation report with user-friendly messaging
   * @param {Object} report - Raw analysis report
   * @returns {Object} Formatted reputation report
   */
  generateReputationReport(report) {
    // Generate detailed breakdown analysis first
    this.generateDetailedReputationAnalysis(report);
    
    // Calculate overall score from breakdown scores
    report.score = Math.round((
      report.reputationScore * 0.25 +
      report.domainScore * 0.25 +
      report.patternScore * 0.20 +
      report.trustScore * 0.20 +
      report.phishingScore * 0.10
    ));

    // Bonus points for gaming domains that aren't in main trusted list
    try {
      const urlObj = new URL(report.analysis?.domain || '');
      const hostname = urlObj.hostname || report.analysis?.domain || '';
      const tld = this.extractTLD(hostname);
      
      // Boost score for legitimate gaming TLDs and gaming-related domains
      if (this.gamingTLDs.includes(tld) && !this.isTrustedDomain(hostname)) {
        // Give gaming domains benefit of the doubt
        report.score = Math.min(100, report.score + 15);
        
        if (hostname.includes('cities') || hostname.includes('game') || hostname.includes('esports')) {
          report.score = Math.min(100, report.score + 10); // Additional bonus for obvious gaming domains
        }
      }
      
      // Don't penalize gaming domains as heavily for minor issues
      if (this.gamingTLDs.includes(tld) && report.score >= 65) {
        report.score = Math.min(100, report.score + 10);
      }
      
    } catch (error) {
      // Continue with normal processing if URL parsing fails
    }

    // Determine final risk level
    if (report.score >= 80) {
      report.riskLevel = report.riskLevel === 'trusted' ? 'trusted' : 'safe';
    } else if (report.score >= 60) {
      report.riskLevel = 'moderate';
    } else if (report.score >= 40) {
      report.riskLevel = 'high';
    } else {
      report.riskLevel = 'dangerous';
    }

    // Generate user-friendly message
    const messages = {
      trusted: ' Trusted domain with good reputation',
      safe: ' No significant reputation issues detected',
      moderate: ' Some reputation concerns identified',
      high: ' Multiple reputation issues detected',
      dangerous: ' High-risk domain - exercise extreme caution'
    };

    report.userMessage = messages[report.riskLevel];

    // Generate recommendations
    report.recommendations = this.generateRecommendations(report);

    // Add summary statistics
    report.summary = {
      totalIssues: report.issues.length,
      riskFactors: report.indicators.length,
      trustLevel: report.riskLevel,
      domainAge: 'Unknown', // Would require external service
      reputation: report.analysis.trustScore || report.score
    };

    // Ensure score doesn't go below 0
    report.score = Math.max(0, report.score);

    return report;
  }

  /**
   * Generate detailed reputation analysis with breakdown scores
   */
  generateDetailedReputationAnalysis(report) {
    const domain = report.analysis.domain || '';
    const issues = report.issues.length;
    
    // Start each category at 100 and deduct points for specific issues
    report.reputationScore = 100;
    report.domainScore = 100;
    report.patternScore = 100;
    report.trustScore = 100;
    report.phishingScore = 100;

    // Analyze overall reputation based on total issues
    if (report.riskLevel === 'trusted') {
      report.reputationScore = 100;
      report.reputationDetails = '✅ Trusted domain with excellent reputation';
    } else {
      // Deduct points based on issue count
      const reputationPenalty = Math.min(issues * 15, 60); // Max 60 point penalty
      report.reputationScore = Math.max(40, 100 - reputationPenalty);
      
      if (issues === 0) {
        report.reputationDetails = '✅ No reputation issues detected';
      } else if (issues <= 2) {
        report.reputationDetails = `⚠️ ${issues} minor reputation issue(s)`;
      } else {
        report.reputationDetails = `❌ ${issues} reputation issue(s) detected`;
      }
    }

    // Analyze domain quality - start at 100, deduct for specific issues
    if (this.isTrustedDomain(domain)) {
      report.domainScore = 100;
      report.domainDetails = '✅ Recognized trusted domain';
    } else {
      if (report.analysis.isIP) {
        report.domainScore -= 70; // Major penalty for IP usage
        report.domainDetails = '❌ Uses IP address instead of domain';
      } else if (this.suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        // Check if it's a gaming domain to reduce penalty
        const tld = this.extractTLD(domain);
        const isGamingTLD = this.gamingTLDs.includes(tld);
        const penalty = isGamingTLD ? 15 : 50; // Reduced penalty for gaming TLDs
        report.domainScore -= penalty;
        report.domainDetails = isGamingTLD ? '⚠️ Gaming domain with unusual TLD' : '⚠️ Uses suspicious top-level domain';
      } else {
        report.domainDetails = '✅ Standard domain structure';
      }
      report.domainScore = Math.max(30, report.domainScore); // Minimum score
    }

    // Analyze URL patterns - start at 100, deduct for each pattern
    const suspiciousPatterns = report.analysis.suspiciousPatterns.length;
    if (suspiciousPatterns > 0) {
      const patternPenalty = Math.min(suspiciousPatterns * 30, 60); // Max 60 point penalty
      report.patternScore -= patternPenalty;
      report.patternScore = Math.max(40, report.patternScore);
    }
    
    if (suspiciousPatterns === 0) {
      report.patternDetails = '✅ No suspicious URL patterns';
    } else if (suspiciousPatterns === 1) {
      report.patternDetails = '⚠️ 1 suspicious pattern detected';
    } else {
      report.patternDetails = `❌ ${suspiciousPatterns} suspicious patterns detected`;
    }

    // Analyze trust indicators - calculate based on analysis
    if (report.riskLevel === 'trusted') {
      report.analysis.trustScore = 95;
    } else if (this.isTrustedDomain(domain)) {
      report.analysis.trustScore = 90;
    } else {
      // Calculate trust score based on various factors
      let trustScore = 70; // Base score for unknown domains
      
      // Boost for gaming domains
      const tld = this.extractTLD(domain);
      if (this.gamingTLDs.includes(tld)) {
        trustScore += 15;
      }
      
      // Reduce for suspicious indicators
      if (report.analysis.isIP) trustScore -= 40;
      if (report.analysis.isShortened) trustScore -= 25;
      if (suspiciousPatterns > 0) trustScore -= (suspiciousPatterns * 10);
      
      report.analysis.trustScore = Math.max(0, Math.min(100, trustScore));
    }
    
    // Set trust score and details
    if (report.analysis.trustScore >= 90) {
      report.trustScore = 100;
      report.trustDetails = '✅ High trust indicators';
    } else if (report.analysis.trustScore >= 70) {
      report.trustScore = 80;
      report.trustDetails = '✅ Moderate trust indicators';
    } else if (report.analysis.trustScore >= 50) {
      report.trustScore = 60;
      report.trustDetails = '⚠️ Limited trust indicators';
    } else {
      report.trustScore = Math.max(30, Math.round(report.analysis.trustScore));
      report.trustDetails = '❌ Low trust indicators';
    }

    // Analyze phishing indicators - start at 100, deduct for each indicator
    const phishingCount = report.analysis.phishingIndicators.length;
    if (phishingCount > 0) {
      const phishingPenalty = Math.min(phishingCount * 35, 70); // Max 70 point penalty
      report.phishingScore -= phishingPenalty;
      report.phishingScore = Math.max(30, report.phishingScore);
    }
    
    if (phishingCount === 0) {
      report.phishingDetails = '✅ No phishing indicators';
    } else if (phishingCount === 1) {
      report.phishingDetails = '⚠️ 1 potential phishing indicator';
    } else {
      report.phishingDetails = `❌ ${phishingCount} phishing indicators detected`;
    }

    // Generate enhanced recommendations
    this.generateEnhancedReputationRecommendations(report);
  }

  /**
   * Generate enhanced reputation recommendations
   */
  generateEnhancedReputationRecommendations(report) {
    const recommendations = [];
    
    if (report.score >= 90) {
      recommendations.push('✅ Excellent domain reputation');
    } else {
      if (report.domainScore < 70) {
        recommendations.push('Verify domain authenticity before proceeding');
      }
      if (report.patternScore < 70) {
        recommendations.push('URL contains suspicious patterns - exercise caution');
      }
      if (report.trustScore < 70) {
        recommendations.push('Limited trust indicators - verify site legitimacy');
      }
      if (report.phishingScore < 70) {
        recommendations.push('Potential phishing indicators detected - be very cautious');
      }
    }

    report.recommendations = recommendations;
  }

  /**
   * Generate security recommendations based on reputation analysis
   * @param {Object} report - Reputation report
   * @returns {Array} Array of recommendations
   */
  generateRecommendations(report) {
    const recommendations = [];

    switch (report.riskLevel) {
      case 'dangerous':
        recommendations.push(' DO NOT enter personal information on this site');
        recommendations.push(' DO NOT download files from this domain');
        recommendations.push(' Consider leaving this website immediately');
        break;

      case 'high':
        recommendations.push(' Exercise extreme caution on this website');
        recommendations.push(' Verify the website URL carefully');
        recommendations.push(' Do not enter sensitive information');
        break;

      case 'moderate':
        recommendations.push(' Be cautious with personal data');
        recommendations.push(' Verify website authenticity before proceeding');
        recommendations.push(' Use additional security measures');
        break;

      case 'safe':
        recommendations.push(' Website appears legitimate');
        recommendations.push(' Continue with normal security practices');
        break;

      case 'trusted':
        recommendations.push(' Trusted domain with good reputation');
        recommendations.push(' Safe to use with confidence');
        break;
    }

    // Add specific recommendations based on issues found
    if (report.analysis.isIP) {
      recommendations.push(' IP addresses often indicate suspicious activity');
    }
    
    if (report.analysis.isShortened) {
      recommendations.push('LINK Shortened URLs hide the real destination');
    }
    
    if (report.analysis.phishingIndicators.length > 0) {
      recommendations.push(' Phishing indicators detected - verify legitimacy');
    }

    return recommendations;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = URLReputationChecker;
} else {
  window.URLReputationChecker = URLReputationChecker;
} 