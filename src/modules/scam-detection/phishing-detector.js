/** Phishing detection module */

class PhishingDetector {
  constructor() {
    this.suspiciousDomains = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
      'ow.ly', 'is.gd', 'buff.ly', 'short.link'
    ];
    
    this.phishingKeywords = [
      'urgent', 'immediate', 'verify', 'suspended', 'locked',
      'click here', 'act now', 'limited time', 'expires',
      'winner', 'congratulations', 'prize', 'lottery',
      'security alert', 'account compromise', 'unusual activity'
    ];
    
    this.legitimateDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
      'stackoverflow.com', 'wikipedia.org', 'reddit.com'
    ];
  }

  /** Detect phishing indicators
   * @returns {Promise<Object>} Analysis results
   */
  async detectPhishingIndicators() {
    try {
      const analysis = {
        score: 100,
        status: 'safe',
        riskLevel: 'safe',
        indicators: [],
        urlAnalysis: {},
        contentAnalysis: {},
        formAnalysis: {},
        recommendations: []
      };

      // URL analysis
      this.analyzeURL(analysis);
      
      // Content analysis
      this.analyzeContent(analysis);
      
      // Form analysis
      this.analyzeForms(analysis);
      
      // Structure analysis
      this.analyzePageStructure(analysis);
      
      // Calculate risk score
      this.calculatePhishingScore(analysis);

      return analysis;
      
    } catch (error) {
      console.error('❌ Phishing detection failed:', error);
      return {
        score: 70,
        status: 'error',
        riskLevel: 'unknown',
        indicators: [],
        urlAnalysis: {},
        contentAnalysis: {},
        formAnalysis: {},
        recommendations: ['Phishing analysis failed - manual review recommended'],
        error: error.message
      };
    }
  }

  /** Analyze URL for suspicious patterns */
  analyzeURL(analysis) {
    const url = window.location.href;
    const hostname = window.location.hostname;
    const protocol = window.location.protocol;
    
    analysis.urlAnalysis = {
      url: url,
      hostname: hostname,
      protocol: protocol,
      isIP: /^\d+\.\d+\.\d+\.\d+/.test(hostname),
      hasSubdomain: hostname.split('.').length > 2,
      urlLength: url.length,
      hasHttps: protocol === 'https:',
      suspiciousChars: (url.match(/[-_.~!*'();:@&=+$,/?#[\]]/g) || []).length
    };
    
    // Check for IP address instead of domain
    if (analysis.urlAnalysis.isIP) {
      analysis.indicators.push({
        type: 'url_suspicious',
        severity: 'high',
        description: 'Website uses IP address instead of domain name',
        indicator: 'ip_address'
      });
    }
    
    // Check for suspicious domain
    if (this.suspiciousDomains.some(domain => hostname.includes(domain))) {
      analysis.indicators.push({
        type: 'url_suspicious',
        severity: 'medium',
        description: 'URL uses URL shortening service',
        indicator: 'url_shortener'
      });
    }
    
    // Check for no HTTPS on forms
    if (!analysis.urlAnalysis.hasHttps && document.querySelector('form')) {
      analysis.indicators.push({
        type: 'security',
        severity: 'high',
        description: 'Forms present but no HTTPS encryption',
        indicator: 'insecure_forms'
      });
    }
    
    // Check for very long URLs (potential obfuscation)
    if (url.length > 200) {
      analysis.indicators.push({
        type: 'url_suspicious',
        severity: 'medium',
        description: 'Unusually long URL may indicate obfuscation',
        indicator: 'long_url'
      });
    }
    
    // Check for excessive special characters
    if (analysis.urlAnalysis.suspiciousChars > 20) {
      analysis.indicators.push({
        type: 'url_suspicious',
        severity: 'medium',
        description: 'URL contains many special characters',
        indicator: 'special_chars'
      });
    }
    
    // Check for domain spoofing patterns
    this.checkDomainSpoofing(analysis, hostname);
  }

  /**
   * Check for domain spoofing attempts
   */
  checkDomainSpoofing(analysis, hostname) {
    const spoofingPatterns = [
      { pattern: /g[o0][o0]gle/i, legitimate: 'google.com' },
      { pattern: /micr[o0]s[o0]ft/i, legitimate: 'microsoft.com' },
      { pattern: /amaz[o0]n/i, legitimate: 'amazon.com' },
      { pattern: /[a4]pple/i, legitimate: 'apple.com' },
      { pattern: /f[a4]ceb[o0][o0]k/i, legitimate: 'facebook.com' },
      { pattern: /p[a4]yp[a4]l/i, legitimate: 'paypal.com' }
    ];
    
    spoofingPatterns.forEach(spoof => {
      if (spoof.pattern.test(hostname) && !hostname.includes(spoof.legitimate)) {
        analysis.indicators.push({
          type: 'domain_spoofing',
          severity: 'high',
          description: `Domain may be spoofing ${spoof.legitimate}`,
          indicator: 'domain_spoofing',
          legitimate: spoof.legitimate
        });
      }
    });
  }

  /**
   * Analyze page content for phishing keywords
   */
  analyzeContent(analysis) {
    const textContent = document.body ? document.body.innerText.toLowerCase() : '';
    const title = document.title.toLowerCase();
    
    analysis.contentAnalysis = {
      textLength: textContent.length,
      title: document.title,
      hasPhishingKeywords: false,
      keywordCount: 0,
      urgencyWords: 0,
      socialEngineering: 0
    };
    
    // Check for phishing keywords
    let keywordCount = 0;
    let urgencyWords = 0;
    let socialEngineering = 0;
    
    this.phishingKeywords.forEach(keyword => {
      const regex = new RegExp(keyword, 'gi');
      const matches = (textContent.match(regex) || []).length + (title.match(regex) || []).length;
      
      if (matches > 0) {
        keywordCount += matches;
        
        // Categorize keywords
        if (['urgent', 'immediate', 'expires', 'act now', 'limited time'].includes(keyword)) {
          urgencyWords += matches;
        }
        
        if (['verify', 'suspended', 'locked', 'security alert', 'compromise'].includes(keyword)) {
          socialEngineering += matches;
        }
      }
    });
    
    analysis.contentAnalysis.keywordCount = keywordCount;
    analysis.contentAnalysis.urgencyWords = urgencyWords;
    analysis.contentAnalysis.socialEngineering = socialEngineering;
    analysis.contentAnalysis.hasPhishingKeywords = keywordCount > 0;
    
    // Add indicators based on keyword analysis
    if (urgencyWords > 2) {
      analysis.indicators.push({
        type: 'content_suspicious',
        severity: 'medium',
        description: 'Multiple urgency words detected',
        indicator: 'urgency_language',
        count: urgencyWords
      });
    }
    
    if (socialEngineering > 1) {
      analysis.indicators.push({
        type: 'content_suspicious',
        severity: 'high',
        description: 'Social engineering language detected',
        indicator: 'social_engineering',
        count: socialEngineering
      });
    }
    
    if (keywordCount > 5) {
      analysis.indicators.push({
        type: 'content_suspicious',
        severity: 'medium',
        description: 'High concentration of phishing keywords',
        indicator: 'phishing_keywords',
        count: keywordCount
      });
    }
  }

  /**
   * Analyze forms for credential harvesting
   */
  analyzeForms(analysis) {
    const forms = document.querySelectorAll('form');
    
    analysis.formAnalysis = {
      formCount: forms.length,
      hasPasswordField: false,
      hasEmailField: false,
      hasLoginForm: false,
      suspiciousForms: []
    };
    
    forms.forEach((form, index) => {
      const formData = {
        index: index,
        action: form.action || '',
        method: form.method || 'get',
        hasPassword: !!form.querySelector('input[type="password"]'),
        hasEmail: !!form.querySelector('input[type="email"], input[name*="email"]'),
        hasHiddenFields: form.querySelectorAll('input[type="hidden"]').length,
        fieldCount: form.querySelectorAll('input, select, textarea').length
      };
      
      analysis.formAnalysis.hasPasswordField = analysis.formAnalysis.hasPasswordField || formData.hasPassword;
      analysis.formAnalysis.hasEmailField = analysis.formAnalysis.hasEmailField || formData.hasEmail;
      analysis.formAnalysis.hasLoginForm = analysis.formAnalysis.hasLoginForm || (formData.hasPassword && formData.hasEmail);
      
      // Check for suspicious form characteristics
      if (formData.hasPassword || formData.hasEmail) {
        // Check if form submits to external domain
        try {
          if (formData.action) {
            const actionUrl = new URL(formData.action, window.location.href);
            const currentDomain = window.location.hostname;
            
            if (actionUrl.hostname !== currentDomain) {
              analysis.indicators.push({
                type: 'form_suspicious',
                severity: 'high',
                description: `Login form submits to external domain: ${actionUrl.hostname}`,
                indicator: 'external_form_action',
                form: index
              });
              analysis.formAnalysis.suspiciousForms.push(formData);
            }
          }
        } catch (error) {
          // Invalid URL in action - silently continue
        }
        
        // Check for HTTP submission of sensitive data
        if (window.location.protocol === 'http:') {
          analysis.indicators.push({
            type: 'form_suspicious',
            severity: 'high',
            description: 'Sensitive form on insecure HTTP connection',
            indicator: 'insecure_form',
            form: index
          });
        }
        
        // Check for excessive hidden fields (could indicate malicious intent)
        if (formData.hasHiddenFields > 5) {
          analysis.indicators.push({
            type: 'form_suspicious',
            severity: 'medium',
            description: `Form has excessive hidden fields (${formData.hasHiddenFields})`,
            indicator: 'excessive_hidden_fields',
            form: index
          });
        }
      }
    });
  }

  /**
   * Analyze page structure for suspicious elements
   */
  analyzePageStructure(analysis) {
    // Check for hidden iframes
    const iframes = document.querySelectorAll('iframe');
    const hiddenIframes = Array.from(iframes).filter(iframe => {
      const style = window.getComputedStyle(iframe);
      return style.display === 'none' || 
             style.visibility === 'hidden' || 
             style.opacity === '0' ||
             (iframe.width === '0' && iframe.height === '0');
    });
    
    if (hiddenIframes.length > 0) {
      analysis.indicators.push({
        type: 'structure_suspicious',
        severity: 'medium',
        description: 'Hidden iframes detected',
        indicator: 'hidden_iframes',
        count: hiddenIframes.length
      });
    }
    
    // Check for favicon spoofing
    const favicon = document.querySelector('link[rel*="icon"]');
    if (favicon && favicon.href) {
      try {
        const faviconUrl = new URL(favicon.href);
        if (faviconUrl.hostname !== window.location.hostname) {
          analysis.indicators.push({
            type: 'structure_suspicious',
            severity: 'low',
            description: 'Favicon loaded from external domain',
            indicator: 'external_favicon',
            domain: faviconUrl.hostname
          });
        }
      } catch (error) {
        // Invalid favicon URL
      }
    }
    
    // Check for popup/overlay patterns
    const popupSelectors = [
      '.popup', '.modal', '.overlay', '.lightbox',
      '[style*="position: fixed"]', '[style*="position:fixed"]'
    ];
    
    let popupCount = 0;
    popupSelectors.forEach(selector => {
      popupCount += document.querySelectorAll(selector).length;
    });
    
    if (popupCount > 3) {
      analysis.indicators.push({
        type: 'structure_suspicious',
        severity: 'low',
        description: 'Multiple popup/modal elements detected',
        indicator: 'multiple_popups',
        count: popupCount
      });
    }
  }

  /**
   * Calculate overall phishing risk score
   */
  calculatePhishingScore(analysis) {
    let score = 100;
    
    // Apply penalties based on indicators
    analysis.indicators.forEach(indicator => {
      switch (indicator.severity) {
        case 'high':
          score -= 25;
          break;
        case 'medium':
          score -= 15;
          break;
        case 'low':
          score -= 5;
          break;
      }
    });
    
    // Additional penalties
    if (analysis.urlAnalysis.isIP) score -= 30;
    if (analysis.contentAnalysis.socialEngineering > 2) score -= 20;
    if (analysis.formAnalysis.hasLoginForm && !analysis.urlAnalysis.hasHttps) score -= 25;
    
    // Ensure score doesn't go below 0
    score = Math.max(0, score);
    
    analysis.score = score;
    
    // Determine risk level
    if (score >= 80) {
      analysis.riskLevel = 'safe';
      analysis.status = 'safe';
    } else if (score >= 60) {
      analysis.riskLevel = 'warning';
      analysis.status = 'warning';
    } else if (score >= 40) {
      analysis.riskLevel = 'suspicious';
      analysis.status = 'dangerous';
    } else {
      analysis.riskLevel = 'dangerous';
      analysis.status = 'dangerous';
    }
    
    // Generate recommendations
    this.generatePhishingRecommendations(analysis);
  }

  /**
   * Generate phishing recommendations
   */
  generatePhishingRecommendations(analysis) {
    const recommendations = [];
    
    if (analysis.riskLevel === 'dangerous') {
      recommendations.push('⚠️ High phishing risk - avoid entering personal information');
      recommendations.push('🚫 Do not provide passwords or financial details');
      recommendations.push('🔍 Verify website authenticity through official channels');
    } else if (analysis.riskLevel === 'suspicious') {
      recommendations.push('⚠️ Suspicious indicators detected - exercise caution');
      recommendations.push('🔍 Verify website legitimacy before proceeding');
    } else if (analysis.riskLevel === 'warning') {
      recommendations.push('⚠️ Some concerns detected - be cautious with sensitive information');
    } else {
      recommendations.push('✅ No major phishing indicators detected');
    }
    
    // Specific recommendations based on indicators
    if (analysis.urlAnalysis.isIP) {
      recommendations.push('🔍 Website uses IP address - verify legitimacy');
    }
    
    if (!analysis.urlAnalysis.hasHttps && analysis.formAnalysis.hasPasswordField) {
      recommendations.push('🔒 Insecure connection for password forms - avoid login');
    }
    
    if (analysis.contentAnalysis.socialEngineering > 0) {
      recommendations.push('🧠 Social engineering tactics detected - think critically');
    }
    
    analysis.recommendations = recommendations;
  }
}

// Make class available globally
window.PhishingDetector = PhishingDetector;
