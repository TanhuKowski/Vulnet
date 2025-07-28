/** Mixed content security detector */

class MixedContentDetector {
  constructor() {
    // Define resource types and their security impact
    this.activeContentTypes = ['script', 'stylesheet', 'iframe', 'object', 'embed'];
    this.passiveContentTypes = ['img', 'audio', 'video', 'source'];
    this.mixedContentFound = [];
  }

  /**
   * Main mixed content analysis function
   * Scans the current page for HTTP resources on HTTPS sites
   * @returns {Object} Mixed content security report
   */
  async detectMixedContent() {
    console.log(' Starting mixed content detection...');
    
    // Only analyze HTTPS pages (mixed content only applies here)
    if (window.location.protocol !== 'https:') {
      return {
        score: 100,
        status: 'not-applicable',
        message: 'Mixed content check not applicable for HTTP sites',
        userMessage: 'INFO: Mixed content check not applicable for HTTP sites',
        activeContent: [],
        passiveContent: []
      };
    }

    const report = {
      score: 100,
      status: 'secure',
      activeContent: [],    // High-risk HTTP resources
      passiveContent: [],   // Lower-risk HTTP resources
      totalIssues: 0,
      recommendations: []
    };

    // Step 1: Scan for active mixed content (scripts, stylesheets, etc.)
    const activeIssues = await this.scanActiveContent();
    if (activeIssues.length > 0) {
      report.score -= (activeIssues.length * 20); // Major penalty for active content
      report.status = 'insecure';
      report.activeContent = activeIssues;
      report.recommendations.push('Page loads insecure scripts - high security risk');
    }

    // Step 2: Scan for passive mixed content (images, media)
    const passiveIssues = await this.scanPassiveContent();
    if (passiveIssues.length > 0) {
      report.score -= (passiveIssues.length * 5); // Minor penalty for passive content
      if (report.status === 'secure') report.status = 'warning';
      report.passiveContent = passiveIssues;
      report.recommendations.push(`${passiveIssues.length} images/media loaded insecurely`);
    }

    // Step 3: Check for form submissions to HTTP endpoints
    const insecureFormIssues = await this.scanInsecureForms();
    if (insecureFormIssues.length > 0) {
      report.score -= (insecureFormIssues.length * 25); // High penalty for insecure forms
      report.status = 'insecure';
      report.activeContent.push(...insecureFormIssues);
      report.recommendations.push('Forms submit to insecure HTTP endpoints');
    }

    report.totalIssues = activeIssues.length + passiveIssues.length + insecureFormIssues.length;
    return this.generateMixedContentReport(report);
  }

  /**
   * Scan for active mixed content (high security risk)
   * Active content can execute code and compromise page security
   * @returns {Array} List of insecure active resources
   */
  async scanActiveContent() {
    const activeIssues = [];

    try {
      // Check all script tags for HTTP sources
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        if (script.src.startsWith('http://')) {
          activeIssues.push({
            type: 'script',
            url: script.src,
            element: script.outerHTML.substring(0, 100) + '...', // Truncate for display
            risk: 'high',
            description: 'JavaScript loaded over insecure connection'
          });
        }
      });

      // Check stylesheets for HTTP sources
      const stylesheets = document.querySelectorAll('link[rel="stylesheet"]');
      stylesheets.forEach(link => {
        if (link.href.startsWith('http://')) {
          activeIssues.push({
            type: 'stylesheet',
            url: link.href,
            element: link.outerHTML.substring(0, 100) + '...',
            risk: 'high',
            description: 'Stylesheet loaded over insecure connection'
          });
        }
      });

      // Check iframes for HTTP sources
      const iframes = document.querySelectorAll('iframe[src]');
      iframes.forEach(iframe => {
        if (iframe.src.startsWith('http://')) {
          activeIssues.push({
            type: 'iframe',
            url: iframe.src,
            element: iframe.outerHTML.substring(0, 100) + '...',
            risk: 'high',
            description: 'Embedded frame loaded over insecure connection'
          });
        }
      });

      // Check object and embed tags
      const objects = document.querySelectorAll('object[data], embed[src]');
      objects.forEach(obj => {
        const src = obj.data || obj.src;
        if (src && src.startsWith('http://')) {
          activeIssues.push({
            type: obj.tagName.toLowerCase(),
            url: src,
            element: obj.outerHTML.substring(0, 100) + '...',
            risk: 'high',
            description: 'Plugin content loaded over insecure connection'
          });
        }
      });

      // Check for WebSocket connections (ws:// instead of wss://)
      // Note: This is harder to detect programmatically, but we can check for common patterns
      const inlineScripts = document.querySelectorAll('script:not([src])');
      inlineScripts.forEach(script => {
        const content = script.textContent;
        if (content.includes('ws://')) {
          activeIssues.push({
            type: 'websocket',
            url: 'WebSocket connection detected',
            element: 'Inline script',
            risk: 'high',
            description: 'Insecure WebSocket connection (ws:// instead of wss://)'
          });
        }
      });

    } catch (error) {
      console.error('Error scanning active content:', error);
    }

    return activeIssues;
  }

  /**
   * Scan for passive mixed content (lower security risk)
   * Passive content cannot execute code but still poses privacy risks
   * @returns {Array} List of insecure passive resources
   */
  async scanPassiveContent() {
    const passiveIssues = [];

    try {
      // Check images for HTTP sources
      const images = document.querySelectorAll('img[src]');
      images.forEach(img => {
        if (img.src.startsWith('http://')) {
          passiveIssues.push({
            type: 'image',
            url: img.src,
            risk: 'medium',
            description: 'Image loaded over insecure connection'
          });
        }
      });

      // Check audio/video elements
      const mediaElements = document.querySelectorAll('audio[src], video[src]');
      mediaElements.forEach(media => {
        if (media.src.startsWith('http://')) {
          passiveIssues.push({
            type: media.tagName.toLowerCase(),
            url: media.src,
            risk: 'medium',
            description: 'Media file loaded over insecure connection'
          });
        }
      });

      // Check source elements within media tags
      const sources = document.querySelectorAll('source[src]');
      sources.forEach(source => {
        if (source.src.startsWith('http://')) {
          passiveIssues.push({
            type: 'source',
            url: source.src,
            risk: 'medium',
            description: 'Media source loaded over insecure connection'
          });
        }
      });

      // Check background images in CSS (requires style inspection)
      const elementsWithBg = document.querySelectorAll('*');
      elementsWithBg.forEach(element => {
        const style = window.getComputedStyle(element);
        const backgroundImage = style.backgroundImage;
        
        if (backgroundImage && backgroundImage !== 'none') {
          // Extract URL from CSS url() function
          const urlMatch = backgroundImage.match(/url\(['"]?(.*?)['"]?\)/);
          if (urlMatch && urlMatch[1].startsWith('http://')) {
            passiveIssues.push({
              type: 'background-image',
              url: urlMatch[1],
              risk: 'medium',
              description: 'Background image loaded over insecure connection'
            });
          }
        }
      });

    } catch (error) {
      console.error('Error scanning passive content:', error);
    }

    return passiveIssues;
  }

  /**
   * Scan for forms that submit to HTTP endpoints
   * @returns {Array} List of insecure form submissions
   */
  async scanInsecureForms() {
    const formIssues = [];

    try {
      const forms = document.querySelectorAll('form');
      forms.forEach((form, index) => {
        const action = form.action || window.location.href;
        
        if (action.startsWith('http://')) {
          formIssues.push({
            type: 'form',
            url: action,
            element: `Form #${index + 1}`,
            risk: 'high',
            description: 'Form submits data to insecure HTTP endpoint'
          });
        }
      });

    } catch (error) {
      console.error('Error scanning forms:', error);
    }

    return formIssues;
  }

  /**
   * Check for XMLHttpRequest or fetch requests to HTTP endpoints
   * Note: This is more complex to detect in real-time without intercepting
   * @returns {Array} List of insecure AJAX requests
   */
  async scanAjaxRequests() {
    const ajaxIssues = [];

    try {
      // This would require more advanced monitoring of network requests
      // For now, we'll check for common patterns in inline scripts
      const ajaxScripts = document.querySelectorAll('script:not([src])');
      
      ajaxScripts.forEach(script => {
        const content = script.textContent.toLowerCase();
        
        // Look for fetch or XMLHttpRequest patterns with HTTP URLs
        const httpPatterns = [
          /fetch\s*\(\s*['"`]http:\/\/[^'"`]+['"`]/,
          /xmlhttprequest\s*\(\s*.*http:\/\//,
          /ajax\s*\(\s*.*http:\/\//
        ];

        httpPatterns.forEach(pattern => {
          if (pattern.test(content)) {
            ajaxIssues.push({
              type: 'ajax',
              url: 'Detected in inline script',
              element: 'JavaScript AJAX request',
              risk: 'high',
              description: 'AJAX request to insecure HTTP endpoint detected'
            });
          }
        });
      });

    } catch (error) {
      console.error('Error scanning AJAX requests:', error);
    }

    return ajaxIssues;
  }

  /**
   * Generate user-friendly mixed content report
   * @param {Object} report - Raw mixed content analysis
   * @returns {Object} Formatted report for user display
   */
  generateMixedContentReport(report) {
    // Create user-friendly status messages
    if (report.totalIssues === 0) {
      report.userMessage = " No mixed content issues found";
    } else if (report.activeContent.length > 0) {
      report.userMessage = ` ${report.activeContent.length} high-risk mixed content issues`;
    } else {
      report.userMessage = ` ${report.passiveContent.length} mixed content warnings`;
    }

    // Add educational information for users
    report.explanation = "Mixed content occurs when secure (HTTPS) pages load insecure (HTTP) resources, which can compromise security.";

    // Add specific recommendations based on findings
    if (report.activeContent.length > 0) {
      report.recommendations.unshift(' Active mixed content detected - page security compromised');
    }

    if (report.passiveContent.length > 5) {
      report.recommendations.push('Consider enabling "Block all mixed content" in browser settings');
    }

    // Add summary statistics
    report.summary = {
      totalActiveIssues: report.activeContent.length,
      totalPassiveIssues: report.passiveContent.length,
      totalIssues: report.totalIssues,
      securityImpact: report.activeContent.length > 0 ? 'high' : 
                     report.passiveContent.length > 0 ? 'medium' : 'none'
    };

    // Ensure score doesn't go below 0
    report.score = Math.max(0, report.score);

    return report;
  }

  /**
   * Get detailed analysis of mixed content by type
   * @param {Array} mixedContentItems - Array of mixed content items
   * @returns {Object} Categorized analysis
   */
  categorizeMixedContent(mixedContentItems) {
    const categories = {
      scripts: [],
      stylesheets: [],
      images: [],
      media: [],
      iframes: [],
      forms: [],
      other: []
    };

    mixedContentItems.forEach(item => {
      switch (item.type) {
        case 'script':
          categories.scripts.push(item);
          break;
        case 'stylesheet':
          categories.stylesheets.push(item);
          break;
        case 'image':
          categories.images.push(item);
          break;
        case 'audio':
        case 'video':
        case 'source':
          categories.media.push(item);
          break;
        case 'iframe':
          categories.iframes.push(item);
          break;
        case 'form':
          categories.forms.push(item);
          break;
        default:
          categories.other.push(item);
      }
    });

    return categories;
  }

  /**
   * Get security recommendations based on mixed content findings
   * @param {Object} report - Mixed content report
   * @returns {Array} Array of actionable recommendations
   */
  getSecurityRecommendations(report) {
    const recommendations = [];

    if (report.activeContent.length > 0) {
      recommendations.push(' HIGH PRIORITY: Upgrade HTTP resources to HTTPS');
      recommendations.push('Consider this page compromised until fixed');
      recommendations.push('Avoid entering sensitive information');
    }

    if (report.passiveContent.length > 0) {
      recommendations.push(' MEDIUM PRIORITY: Update HTTP media resources to HTTPS');
      recommendations.push('Privacy may be compromised by insecure resources');
    }

    if (report.totalIssues > 10) {
      recommendations.push('Enable browser mixed content blocking');
      recommendations.push('Contact website administrator about security issues');
    }

    // Add educational recommendations
    recommendations.push('Look for "Not Secure" warnings in browser address bar');
    recommendations.push('Use browser developer tools to identify specific resources');

    return recommendations;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MixedContentDetector;
} else {
  window.MixedContentDetector = MixedContentDetector;
}