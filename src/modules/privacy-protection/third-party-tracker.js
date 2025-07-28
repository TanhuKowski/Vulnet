/** Third party tracker detection with domain intelligence */

class ThirdPartyTracker {
  constructor() {
    this.trackerDomains = [
      'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
      'facebook.com', 'facebook.net', 'fbcdn.net',
      'twitter.com', 'twimg.com',
      'amazon-adsystem.com', 'googlesyndication.com',
      'scorecardresearch.com', 'quantserve.com',
      'addthis.com', 'sharethis.com',
      'hotjar.com', 'crazyegg.com',
      'mixpanel.com', 'segment.com',
      // Add more comprehensive tracker list
      'googleapis.com', 'gstatic.com', 'ggpht.com',
      'youtube.com', 'ytimg.com',
      'linkedin.com', 'licdn.com',
      'instagram.com', 'cdninstagram.com',
      'pinterest.com', 'pinimg.com',
      'snapchat.com', 'snap.com',
      'tiktok.com', 'musical.ly',
      'amazon.com', 'ssl-images-amazon.com',
      'microsoft.com', 'live.com', 'outlook.com',
      'yahoo.com', 'yimg.com',
      'reddit.com', 'redd.it',
      'tumblr.com',
      // Ad networks
      'adsystem.com', 'adsensecustomsearchads.com',
      'googleadservices.com', 'googlesyndication.com',
      // Analytics services
      'chartbeat.com', 'newrelic.com', 'pingdom.net',
      'optimizely.com', 'adobe.com'
    ];

    // Trusted domains that should get higher base scores
    this.trustedDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'facebook.com', 'netflix.com', 'youtube.com', 'wikipedia.org',
      'github.com', 'stackoverflow.com', 'mozilla.org'
    ];

    // Known CDN and infrastructure domains (not tracking)
    this.infrastructureDomains = [
      'cloudflare.com', 'amazonaws.com', 'akamai.net', 'fastly.com',
      'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
      'bootstrapcdn.com', 'fontawesome.com', 'googleapis.com'
    ];
  }

  /**
   * Analyze privacy tracking on the current page with domain intelligence
   * @returns {Promise<Object>} Privacy analysis results
   */
  async analyzePrivacyTracking() {
    try {
      const analysis = {
        score: 100,
        status: 'safe',
        
        // Detailed breakdown scores (like demo data)
        privacyScore: 100,
        trackingScore: 100,
        cookieScore: 100,
        resourceScore: 100,
        socialScore: 100,
        
        // Detailed breakdown descriptions
        privacyDetails: '',
        trackingDetails: '',
        cookieDetails: '',
        resourceDetails: '',
        socialDetails: '',
        
        // Technical details
        trackingScripts: [],
        trackingPixels: [],
        socialWidgets: [],
        recommendations: [],

        // NEW: Domain intelligence
        domainIntelligence: await this.analyzeDomainIntelligence()
      };

      // Analyze tracking scripts with domain context
      await this.detectTrackingScripts(analysis);
      
      // Analyze tracking pixels
      this.detectTrackingPixels(analysis);
      
      // Analyze social media widgets
      this.detectSocialWidgets(analysis);
      
      // Generate detailed breakdown analysis with domain context
      this.generateDetailedPrivacyAnalysis(analysis);
      
      // Calculate overall score from breakdown scores with domain weighting
      analysis.score = this.calculateIntelligentScore(analysis);

      // Enhanced debug: Show why score is what it is
      if (analysis.trackingScripts.length === 0 && analysis.score < 95) {
        console.warn('🔍 Privacy Debug - Clean detection but low score:');
        console.warn(`  Domain: ${window.location.hostname}`);
        console.warn(`  Domain Trust Level: ${analysis.domainIntelligence.trustLevel}`);
        console.warn(`  Privacy Score: ${analysis.privacyScore} (25% weight) - ${analysis.privacyDetails}`);
        console.warn(`  Tracking Score: ${analysis.trackingScore} (25% weight) - ${analysis.trackingDetails}`);
        console.warn(`  Cookie Score: ${analysis.cookieScore} (20% weight) - ${analysis.cookieDetails}`);
        console.warn(`  Resource Score: ${analysis.resourceScore} (15% weight) - ${analysis.resourceDetails}`);
        console.warn(`  Social Score: ${analysis.socialScore} (15% weight) - ${analysis.socialDetails}`);
        console.warn(`  Final Score: ${analysis.score}`);
        console.warn(`  Elements Detected:`, {
          trackingScripts: analysis.trackingScripts,
          pixels: analysis.trackingPixels,
          social: analysis.socialWidgets
        });
      }

      return analysis;
      
    } catch (error) {
      console.error('❌ Privacy tracking analysis failed:', error);
      return {
        score: 70,
        status: 'error',
        trackingScripts: [],
        trackingPixels: [],
        socialWidgets: [],
        recommendations: ['Privacy analysis failed - manual review recommended'],
        error: error.message,
        domainIntelligence: { trustLevel: 'unknown', details: 'Analysis failed' }
      };
    }
  }

  /**
   * Analyze domain intelligence (age, popularity, reputation)
   * @returns {Promise<Object>} Domain intelligence data
   */
  async analyzeDomainIntelligence() {
    const hostname = window.location.hostname;
    const domain = hostname.replace(/^www\./, ''); // Remove www prefix
    
    const intelligence = {
      domain: domain,
      trustLevel: 'unknown',
      estimatedAge: 'unknown',
      popularityRank: 'unknown',
      details: [],
      baseScoreModifier: 0 // Will adjust final score based on domain trust
    };

    try {
      // Check if it's a well-known trusted domain
      if (this.trustedDomains.some(trusted => domain.includes(trusted) || trusted.includes(domain))) {
        intelligence.trustLevel = 'high';
        intelligence.estimatedAge = '10+ years';
        intelligence.popularityRank = 'top_1000';
        intelligence.baseScoreModifier = +10; // Boost score for trusted domains
        intelligence.details.push('✅ Well-known trusted domain');
      }
      // Check for suspicious patterns
      else if (this.isSuspiciousDomain(domain)) {
        intelligence.trustLevel = 'low';
        intelligence.estimatedAge = 'unknown/recent';
        intelligence.popularityRank = 'unknown';
        intelligence.baseScoreModifier = -15; // Penalize suspicious domains
        intelligence.details.push('⚠️ Domain has suspicious characteristics');
      }
      // Check domain structure for age estimation
      else {
        const ageEstimate = this.estimateDomainAge(domain);
        const popularityEstimate = this.estimatePopularity(domain);
        
        intelligence.estimatedAge = ageEstimate.age;
        intelligence.popularityRank = popularityEstimate.rank;
        intelligence.trustLevel = this.calculateTrustLevel(ageEstimate, popularityEstimate);
        intelligence.baseScoreModifier = this.calculateScoreModifier(intelligence.trustLevel);
        intelligence.details = [...ageEstimate.indicators, ...popularityEstimate.indicators];
      }

      // Add context about why domain intelligence matters
      intelligence.explanation = this.explainDomainIntelligence(intelligence);

    } catch (error) {
      intelligence.details.push('❌ Domain analysis failed');
      intelligence.explanation = 'Unable to assess domain reputation - scoring may be less accurate';
    }

    return intelligence;
  }

  /**
   * Check if domain has suspicious characteristics
   */
  isSuspiciousDomain(domain) {
    const suspiciousPatterns = [
      /\d{4,}/, // Many numbers (like phishing domains)
      /[.-]{2,}/, // Multiple consecutive dots/dashes
      /-{3,}/, // Multiple dashes
      /\.(tk|ml|ga|cf)$/, // Free/suspicious TLDs
      /bit\.ly|tinyurl|t\.co/, // URL shorteners (could be suspicious)
      /[0-9]+[a-z]+[0-9]+/, // Mixed numbers and letters
      /secure.*login|bank.*login|verify.*account/i // Phishing keywords
    ];

    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  /**
   * Estimate domain age based on structure and patterns
   */
  estimateDomainAge(domain) {
    const indicators = [];
    let ageScore = 0;

    // Short, clean domains are often older
    if (domain.length <= 8 && !domain.includes('-')) {
      ageScore += 3;
      indicators.push('📅 Short domain suggests established presence');
    }

    // Common TLDs for established sites
    if (domain.endsWith('.com') || domain.endsWith('.org') || domain.endsWith('.net')) {
      ageScore += 2;
      indicators.push('🌐 Traditional TLD suggests established site');
    }

    // New/suspicious TLDs
    if (domain.match(/\.(xyz|info|biz|tk|ml|ga|cf)$/)) {
      ageScore -= 2;
      indicators.push('⚠️ New/unusual TLD may indicate recent registration');
    }

    // Domain structure analysis
    if (domain.includes('-')) {
      ageScore -= 1;
      indicators.push('➖ Hyphenated domain (common in newer sites)');
    }

    // Estimate age category
    let age = 'unknown';
    if (ageScore >= 4) age = '5+ years (estimated)';
    else if (ageScore >= 2) age = '2-5 years (estimated)';
    else if (ageScore >= 0) age = '1-2 years (estimated)';
    else age = 'Recent/unknown (estimated)';

    return { age, indicators, score: ageScore };
  }

  /**
   * Estimate domain popularity based on common patterns
   */
  estimatePopularity(domain) {
    const indicators = [];
    let popularityScore = 0;

    // Well-known patterns
    const popularPatterns = [
      { pattern: /news|blog|shop|store|web/, score: 1, desc: 'Common website type' },
      { pattern: /api|cdn|static/, score: 2, desc: 'Technical infrastructure domain' },
      { pattern: /support|help|docs/, score: 1, desc: 'Support/documentation site' }
    ];

    popularPatterns.forEach(({ pattern, score, desc }) => {
      if (pattern.test(domain)) {
        popularityScore += score;
        indicators.push(`🔍 ${desc}`);
      }
    });

    // Simple heuristics for popularity
    let rank = 'unknown';
    if (this.trustedDomains.some(trusted => domain.includes(trusted))) {
      rank = 'top_1000 (estimated)';
    } else if (popularityScore >= 2) {
      rank = 'moderate_traffic (estimated)';
    } else {
      rank = 'low_traffic (estimated)';
    }

    return { rank, indicators, score: popularityScore };
  }

  /**
   * Calculate overall trust level from age and popularity
   */
  calculateTrustLevel(ageEstimate, popularityEstimate) {
    const totalScore = ageEstimate.score + popularityEstimate.score;
    
    if (totalScore >= 4) return 'moderate';
    if (totalScore >= 2) return 'low_moderate';
    if (totalScore >= 0) return 'low';
    return 'very_low';
  }

  /**
   * Calculate score modifier based on trust level
   */
  calculateScoreModifier(trustLevel) {
    const modifiers = {
      'high': +10,          // Well-known trusted domains
      'moderate': +5,       // Established-looking domains
      'low_moderate': 0,    // Neutral
      'low': -3,           // Some concerns
      'very_low': -8,      // Multiple red flags
      'unknown': -5        // Default penalty for unknown domains
    };

    return modifiers[trustLevel] || -5;
  }

  /**
   * Explain domain intelligence impact
   */
  explainDomainIntelligence(intelligence) {
    const explanations = {
      'high': 'Well-established, trusted domain with strong reputation',
      'moderate': 'Domain appears established with good indicators',
      'low_moderate': 'Domain has mixed indicators - moderate confidence',
      'low': 'Domain has some concerning characteristics',
      'very_low': 'Domain shows multiple suspicious indicators',
      'unknown': 'Unable to verify domain reputation and age'
    };

    return explanations[intelligence.trustLevel] || 'Domain trust assessment inconclusive';
  }
  /**
   * Detect tracking scripts on the page with intelligence
   */
  async detectTrackingScripts(analysis) {
    const scripts = document.querySelectorAll('script[src]');
    const currentDomain = window.location.hostname;
    
    scripts.forEach((script, index) => {
      try {
        const url = new URL(script.src);
        const domain = url.hostname;
        
        // Skip same-domain scripts
        if (domain === currentDomain) {
          return;
        }

        // Skip infrastructure/CDN domains (not tracking)
        if (this.infrastructureDomains.some(infra => domain.includes(infra))) {
          return;
        }
        
        // Check against known tracker domains with stricter matching
        const isTracker = this.trackerDomains.some(tracker => {
          // Exact match only for more precision
          return domain === tracker || domain.endsWith('.' + tracker);
        });
        
        if (isTracker) {
          analysis.trackingScripts.push({
            domain: domain,
            url: script.src,
            type: this.identifyTrackerType(domain),
            element: 'script'
          });
        }
        
        // Check for specific tracking patterns (more conservative)
        if (this.hasTrackingPatterns(script.src)) {
          // Avoid duplicates
          const alreadyDetected = analysis.trackingScripts.some(t => t.url === script.src);
          if (!alreadyDetected) {
            analysis.trackingScripts.push({
              domain: domain,
              url: script.src,
              type: 'analytics',
              element: 'script',
              pattern: 'url_pattern'
            });
          }
        }
        
      } catch (error) {
        // Invalid URL, skip
      }
    });
    
    // Also check inline scripts for tracking code (more conservative)
    const inlineScripts = document.querySelectorAll('script:not([src])');
    
    inlineScripts.forEach((script, index) => {
      const content = script.textContent;
      if (content && content.length > 100) { // Only check substantial scripts
        if (this.hasTrackingCode(content)) {
          analysis.trackingScripts.push({
            domain: 'inline',
            type: 'inline_tracking',
            element: 'script',
            pattern: 'inline_code'
          });
        }
      }
    });
  }

  /**
   * Detect tracking pixels
   */
  detectTrackingPixels(analysis) {
    const images = document.querySelectorAll('img');
    
    images.forEach(img => {
      // Check for 1x1 pixel images (common for tracking)
      if ((img.width === 1 && img.height === 1) || 
          (img.naturalWidth === 1 && img.naturalHeight === 1)) {
        
        try {
          const url = new URL(img.src);
          const domain = url.hostname;
          
          analysis.trackingPixels.push({
            domain: domain,
            url: img.src,
            type: 'tracking_pixel',
            dimensions: `${img.width}x${img.height}`
          });
          
        } catch (error) {
          // Invalid URL, skip
        }
      }
    });
  }

  /**
   * Detect social media widgets
   */
  detectSocialWidgets(analysis) {
    const socialPatterns = [
      { name: 'Facebook', patterns: ['facebook.com', 'fb.com', 'fbcdn.net'] },
      { name: 'Twitter', patterns: ['twitter.com', 'twimg.com', 't.co'] },
      { name: 'LinkedIn', patterns: ['linkedin.com', 'licdn.com'] },
      { name: 'Instagram', patterns: ['instagram.com', 'cdninstagram.com'] },
      { name: 'YouTube', patterns: ['youtube.com', 'ytimg.com', 'googlevideo.com'] }
    ];
    
    const iframes = document.querySelectorAll('iframe');
    const scripts = document.querySelectorAll('script[src]');
    
    [...iframes, ...scripts].forEach(element => {
      try {
        const url = element.src;
        if (!url) return;
        
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        socialPatterns.forEach(social => {
          if (social.patterns.some(pattern => domain.includes(pattern))) {
            analysis.socialWidgets.push({
              platform: social.name,
              domain: domain,
              url: url,
              type: element.tagName.toLowerCase()
            });
          }
        });
        
      } catch (error) {
        // Invalid URL, skip
      }
    });
  }

  /**
   * Generate detailed privacy analysis with breakdown scores
   */
  generateDetailedPrivacyAnalysis(analysis) {
    // Analyze overall privacy protection starting with perfect score and deducting for issues
    const totalTrackers = analysis.trackingScripts.length + analysis.trackingPixels.length + analysis.socialWidgets.length;
    
    // Start with perfect privacy score and deduct for actual issues
    analysis.privacyScore = 100;
    let privacyPenalties = [];
    
    if (totalTrackers > 0) {
      const baseTrackerPenalty = Math.min(totalTrackers * 8, 40); // 8 points per tracker, max 40
      analysis.privacyScore -= baseTrackerPenalty;
      privacyPenalties.push(`-${baseTrackerPenalty} for ${totalTrackers} tracker(s)`);
    }
    
    analysis.privacyScore = Math.max(0, analysis.privacyScore);
    
    if (totalTrackers === 0) {
      analysis.privacyDetails = '✅ No tracking detected - excellent privacy protection';
    } else {
      analysis.privacyDetails = `⚠️ Privacy score: ${analysis.privacyScore}/100 (${privacyPenalties.join(', ')})`;
    }

    // Analyze tracking scripts starting at 100 and deducting for specific issues
    const trackingCount = analysis.trackingScripts.length;
    const knownAnalyticsTrackers = analysis.trackingScripts.filter(t => 
      t.domain.includes('google-analytics') || t.domain.includes('googletagmanager')
    ).length;
    const advertisingTrackers = analysis.trackingScripts.filter(t => 
      t.domain.includes('doubleclick') || t.domain.includes('googlesyndication') || t.domain.includes('facebook')
    ).length;
    
    analysis.trackingScore = 100;
    let trackingPenalties = [];
    
    if (advertisingTrackers > 0) {
      const adPenalty = Math.min(advertisingTrackers * 25, 75); // 25 points per advertising tracker, max 75
      analysis.trackingScore -= adPenalty;
      trackingPenalties.push(`-${adPenalty} for ${advertisingTrackers} advertising tracker(s)`);
    }
    
    const analyticsOnlyTrackers = trackingCount - advertisingTrackers;
    if (analyticsOnlyTrackers > 0) {
      const analyticsPenalty = Math.min(analyticsOnlyTrackers * 10, 50); // 10 points per analytics tracker, max 50
      analysis.trackingScore -= analyticsPenalty;
      trackingPenalties.push(`-${analyticsPenalty} for ${analyticsOnlyTrackers} analytics tracker(s)`);
    }
    
    analysis.trackingScore = Math.max(0, analysis.trackingScore);
    
    if (trackingCount === 0) {
      analysis.trackingDetails = '✅ No tracking scripts detected';
    } else {
      analysis.trackingDetails = `Tracking score: ${analysis.trackingScore}/100 (${trackingPenalties.join(', ')})`;
    }

    // Set cookie and resource scores to 100 (removed features)
    analysis.cookieScore = 100;
    analysis.cookieDetails = '✅ Cookie analysis disabled';
    
    analysis.resourceScore = 100;
    analysis.resourceDetails = '✅ External resource analysis disabled';

    // Analyze social media widgets starting at 100 and deducting for cross-platform tracking
    const socialCount = analysis.socialWidgets.length;
    const socialPlatforms = [...new Set(analysis.socialWidgets.map(w => w.platform))].length;
    
    analysis.socialScore = 100;
    let socialPenalties = [];
    
    if (socialCount > 0) {
      const socialPenalty = Math.min(socialCount * 18, 72); // 18 points per social widget, max 72
      analysis.socialScore -= socialPenalty;
      socialPenalties.push(`-${socialPenalty} for ${socialCount} social widget(s)`);
      
      if (socialPlatforms > 1) {
        const platformPenalty = Math.min((socialPlatforms - 1) * 10, 28); // Extra penalty for multiple platforms, max 28
        analysis.socialScore -= platformPenalty;
        socialPenalties.push(`-${platformPenalty} for ${socialPlatforms} different platform(s)`);
      }
    }
    
    analysis.socialScore = Math.max(0, analysis.socialScore);
    
    if (socialCount === 0) {
      analysis.socialDetails = '✅ No social media widgets detected';
    } else {
      analysis.socialDetails = `Social score: ${analysis.socialScore}/100 (${socialPenalties.join(', ')})`;
    }

    // Determine overall status based on final calculated score
    const finalScore = this.calculateIntelligentScore(analysis);
    if (finalScore >= 80) {
      analysis.status = 'safe';
    } else if (finalScore >= 60) {
      analysis.status = 'warning';
    } else {
      analysis.status = 'dangerous';
    }

    // Generate enhanced recommendations
    this.generateEnhancedPrivacyRecommendations(analysis);
  }

  /**
   * Calculate intelligent score with domain context
   */
  calculateIntelligentScore(analysis) {
    // Base calculation
    const baseScore = Math.round((
      analysis.privacyScore * 0.25 +
      analysis.trackingScore * 0.25 +
      analysis.cookieScore * 0.20 +
      analysis.resourceScore * 0.15 +
      analysis.socialScore * 0.15
    ));

    // Apply domain intelligence modifier
    const domainModifier = analysis.domainIntelligence.baseScoreModifier;
    const adjustedScore = Math.max(0, Math.min(100, baseScore + domainModifier));

    // Add explanation for domain adjustment
    if (domainModifier !== 0) {
      analysis.domainAdjustment = {
        baseScore: baseScore,
        modifier: domainModifier,
        finalScore: adjustedScore,
        reason: analysis.domainIntelligence.explanation
      };
    }

    return adjustedScore;
  }

  /**
   * Calculate overall privacy impact score based on tracking types and intensity
   */
  /**
   * Generate enhanced privacy recommendations with stricter criteria
   */
  generateEnhancedPrivacyRecommendations(analysis) {
    const recommendations = [];
    
    // Only truly excellent privacy gets positive recommendation
    if (analysis.score >= 95) {
      recommendations.push('✅ Excellent privacy protection - no significant tracking detected');
    } else if (analysis.score >= 75) {
      recommendations.push('⚠️ Good privacy but some tracking present');
    } else {
      // More actionable recommendations for privacy concerns
      if (analysis.trackingScore < 60) {
        recommendations.push('🛡️ High tracking detected - use privacy tools like uBlock Origin');
      }
      if (analysis.cookieScore < 60) {
        recommendations.push('🍪 Block third-party cookies in browser settings');
      }
      if (analysis.resourceScore < 60) {
        recommendations.push('🔗 Many tracking resources - consider using a privacy-focused browser');
      }
      if (analysis.socialScore < 60) {
        recommendations.push('📱 Social widgets are tracking you across websites');
      }
      
      // General privacy recommendations for poor scores
      if (analysis.score < 50) {
        recommendations.push('🚨 Poor privacy protection - consider using Tor Browser for sensitive activities');
        recommendations.push('⚠️ Your browsing behavior is likely being profiled');
      }
    }

    analysis.recommendations = recommendations;
  }

  /**
   * Identify tracker type based on domain
   */
  identifyTrackerType(domain) {
    if (domain.includes('google-analytics') || domain.includes('googletagmanager')) {
      return 'analytics';
    } else if (domain.includes('facebook') || domain.includes('fb')) {
      return 'social';
    } else if (domain.includes('doubleclick') || domain.includes('googlesyndication')) {
      return 'advertising';
    } else if (domain.includes('hotjar') || domain.includes('crazyegg')) {
      return 'heatmap';
    } else if (domain.includes('mixpanel') || domain.includes('segment')) {
      return 'analytics';
    } else {
      return 'unknown';
    }
  }

  /**
   * Check if URL has tracking patterns (more specific to reduce false positives)
   */
  hasTrackingPatterns(url) {
    const trackingPatterns = [
      /google-analytics\.com/i,    // Google Analytics (specific)
      /googletagmanager\.com/i,    // Google Tag Manager (specific)
      /doubleclick\.net/i,         // DoubleClick (specific)
      /facebook\.com.*tr\?/i,      // Facebook tracking (specific)
      /googlesyndication\.com/i,   // Google Ads (specific)
      /analytics\.js/i,            // Analytics scripts (specific)
      /gtag\/js/i,                 // Google gtag (specific)
      /gtm\.js/i,                  // Google Tag Manager (specific)
      /fbevents\.js/i,             // Facebook events (specific)
      /track.*pixel/i,             // Tracking pixels (specific)
      /beacon.*collect/i,          // Beacon collection (specific)
      /conversion.*track/i,        // Conversion tracking (specific)
      /segment\.com.*analytics/i,  // Segment analytics (specific)
      /mixpanel\.com.*track/i,     // Mixpanel tracking (specific)
      /hotjar\.com.*identify/i     // Hotjar tracking (specific)
    ];
    
    return trackingPatterns.some(pattern => pattern.test(url));
  }

  /**
   * Check if script content has tracking code (more specific to reduce false positives)
   */
  hasTrackingCode(content) {
    const trackingPatterns = [
      /ga\(['"`]send/i,                  // Google Analytics send calls (specific)
      /gtag\(['"`]config/i,              // Google gtag config (specific)
      /gtag\(['"`]event/i,               // Google gtag events (specific)
      /fbq\(['"`]init/i,                 // Facebook pixel init (specific)
      /fbq\(['"`]track/i,                // Facebook pixel track (specific)
      /_gaq\.push/i,                     // Google Analytics queue (specific)
      /GoogleAnalyticsObject.*ga/i,      // GA object assignment (specific)
      /google-analytics\.com.*collect/i, // GA collect calls (specific)
      /googletagmanager\.com.*gtm/i,     // GTM specific calls
      /mixpanel\.track\(/i,              // Mixpanel track calls (specific)
      /segment\.track\(/i,               // Segment track calls (specific)
      /analytics\.track\(/i,             // Analytics track calls (specific)
      /hotjar\.hj\(/i,                   // Hotjar specific calls
      /_hjSettings.*hjid/i,              // Hotjar settings (specific)
      /dataLayer\.push.*event/i,         // Data layer events (specific)
      /window\.ga.*create/i,             // GA create calls (specific)
      /fbevents\.js.*facebook/i          // Facebook events script (specific)
    ];
    
    return trackingPatterns.some(pattern => pattern.test(content));
  }
}

// Make class available globally
window.ThirdPartyTracker = ThirdPartyTracker;
