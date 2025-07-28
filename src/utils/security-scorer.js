/** Security scoring utility with ML enhancement */

class SecurityScorer {
  constructor() {
    // Score ranges
    this.SCORE_RANGES = {
      EXCELLENT: { min: 90, max: 100, label: 'Excellent', color: '#4CAF50', status: 'secure' },
      GOOD:      { min: 75, max: 89,  label: 'Good',      color: '#8BC34A', status: 'secure' },
      FAIR:      { min: 60, max: 74,  label: 'Fair',      color: '#FFC107', status: 'warning' },
      POOR:      { min: 40, max: 59,  label: 'Poor',      color: '#FF9800', status: 'warning' },
      DANGEROUS: { min: 0,  max: 39,  label: 'Dangerous', color: '#F44336', status: 'danger' }
    };

    // Category weights
    this.CATEGORY_WEIGHTS = {
      connectionSecurity: 0.30,    // SSL/HTTPS priority
      scamDetection: 0.25,        // Phishing protection
      formSafety: 0.20,           // Data protection
      privacyProtection: 0.15,    // Privacy matters
      codeSafety: 0.10            // Code safety
    };

    // Maximum penalty caps
    this.PENALTY_CAPS = {
      connectionSecurity: 70,
      scamDetection: 80,         // Critical for phishing
      formSafety: 60,
      privacyProtection: 50,
      codeSafety: 50
    };

    // ML configuration
    this.mlEnabled = true;
    this.mlModel = null; // ML model
    this.mlWeights = null;
    this.mlBias = null;
    this.scalerMean = null;
    this.scalerStd = null;
    this.alexaRankings = new Map();

    // Initialize fallback weights
    this.initializeOptimizedWeights();

    // Initialize scorer
    this.initialize().catch(error => {
      console.warn('⚠️ SecurityScorer async initialization failed:', error.message);
    });
  }

  /** Load trained ML model */
  async loadTrainedModel() {
    try {
      // Try to load the trained model
      let modelUrl;
      let response;
      let modelData;
      
      // Check if we're in an extension context and it's valid
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL && chrome.runtime.id) {
        try {
          modelUrl = chrome.runtime.getURL('training/scripts/vulnet_optimized_model.json');
          response = await fetch(modelUrl);
          modelData = await response.json();
        } catch (extensionError) {
          if (extensionError.message.includes('Extension context invalidated')) {
            console.log('🔧 Extension context invalidated during model loading, using optimized weights');
            return false;
          }
          throw extensionError;
        }
      } else {
        // Fallback: load from relative path if not in extension
        response = await fetch('/training/scripts/vulnet_optimized_model.json');
        modelData = await response.json();
      }
      
      // Load trained parameters
      this.mlWeights = modelData.weights;
      this.mlBias = modelData.bias;
      this.scalerMean = modelData.scaler_mean;
      this.scalerStd = modelData.scaler_std;
      this.mlModel = modelData;
      
      return true;
    } catch (error) {
      // Don't log extension context errors as warnings since they're expected
      if (error.message.includes('Extension context invalidated')) {
        console.log('🔧 Extension context invalidated, using optimized hardcoded weights');
      } else {
        console.warn('⚠️ Failed to load trained ML model:', error.message);
        console.log('📝 Using hardcoded optimized weights');
      }
      return false;
    }
  }

  /**
   * Initialize optimized ML weights with proper scaler parameters
   */
  initializeOptimizedWeights() {
    // Use optimized weights from the actual trained model 
    this.mlWeights = [
      0.09674557335637521, 0.09851092925512307, -0.1515825258122476, -0.12849174734222324,
      0.7287871870229434, 0.008468216739636833, -0.006505898704446008, 0.002748984041990436,
      -0.003817586128649673, -0.0034165738970325914, -9.008070482991725e-05, -0.0040192464393716,
      -0.001796697585674143, -0.01522303393433415, -0.0008778023507633844, -0.003663697620252503,
      0.0009700053576994969, 0.00234222375969925, -0.005203460088829578, 0.15882997982549635,
      -0.044897899780512486, 0.045047375566450235, 0.006877287864866426, -0.0027991944403503383,
      1.018441327899131
    ];
    
    this.mlBias = -0.7453114132085648;
    
    // Scaler parameters from training
    this.scalerMean = [
      34.67142857142857, 13.52857142857143, 0.8571428571428571, 2.6571428571428573,
      0.9714285714285714, 0.8571428571428571, 0.8857142857142857, 1.6285714285714286,
      14.228571428571429, 1.2857142857142858, 4.485714285714286, 23.2, 12.742857142857142,
      0.5428571428571428, 0.22857142857142856, 0.37142857142857144, 2.4285714285714284,
      7.428571428571429, 6.114285714285714, 39.08571428571429, 1084.8857142857142,
      0.05714285714285714, 0.22857142857142856, 2.0857142857142856, 0.5714285714285714
    ];
    
    this.scalerStd = [
      21.61940213847896, 5.992640726230837, 1.0690449676496976, 1.6559762717203478,
      1.5811388300841898, 0.35136306009596495, 0.31622776601683794, 1.4106736334760306,
      10.49524697863264, 1.1127167433055198, 4.184013201671795, 17.985554789925592,
      10.070158058105516, 0.49857113690718807, 0.4226182617407, 0.48507125007266594,
      2.2708185106778813, 3.4412280397839297, 7.311668154881696, 32.79918394153807,
      1089.8344009334824, 0.23570226039551584, 0.4226182617407, 2.5515247108307823,
      0.4953463221017075
    ];
  }

  setupOptimizedWeights() {
    // Initialize with highly optimized ML weights based on our training data
  }

  /**
   * Normalize features using trained scaler parameters
   */
  normalizeFeatures(features) {
    // Validate input features
    if (!features || !Array.isArray(features) || features.length === 0) {
      console.warn('⚠️ Invalid features array, using default features');
      features = new Array(25).fill(0.5); // Default neutral features
    }
    
    // Check if we have proper scaler parameters
    if (!this.scalerMean || !this.scalerStd || !Array.isArray(this.scalerMean) || !Array.isArray(this.scalerStd)) {
      console.log('📊 Using raw features (scaler parameters not available)');
      // Ensure we return exactly 25 features
      const normalizedFeatures = features.slice(0, 25);
      while (normalizedFeatures.length < 25) {
        normalizedFeatures.push(0.5);
      }
      return normalizedFeatures;
    }

    const normalizedFeatures = [];
    const targetLength = Math.min(features.length, this.scalerMean.length, 25);
    
    for (let i = 0; i < targetLength; i++) {
      const mean = this.scalerMean[i] || 0;
      const std = this.scalerStd[i] || 1;
      const feature = features[i] || 0; // Handle undefined features
      
      // Prevent division by zero
      const normalizedValue = std !== 0 ? (feature - mean) / std : feature - mean;
      normalizedFeatures[i] = normalizedValue;
    }
    
    // Fill remaining features with zeros if needed
    while (normalizedFeatures.length < 25) {
      normalizedFeatures.push(0);
    }
    
    return normalizedFeatures;
  }

  async initialize() {
    // Check if we already have weights from the constructor fallback
    if (this.mlWeights && this.scalerMean) {
      // Weights already loaded
    }
    
    if (this.mlEnabled) {
      try {
        const modelLoaded = await this.loadTrainedModel();
        
        try {
          await this.loadAlexaRankings();
        } catch (error) {
          console.warn('⚠️ Alexa rankings failed to load:', error.message);
        }
        
      } catch (error) {
        console.error('❌ SecurityScorer initialization error:', error);
        this.mlEnabled = false;
      }
    }
  }

  async loadAlexaRankings() {
    try {
      // Check if chrome runtime is available and valid
      if (chrome && chrome.runtime && !chrome.runtime.lastError && chrome.runtime.sendMessage) {
        // Check if extension context is still valid
        if (chrome.runtime.id) {
          const response = await chrome.runtime.sendMessage({
            type: 'GET_ALEXA_DATA'
          });
          
          if (response?.data && Array.isArray(response.data)) {
            response.data.forEach(item => {
              if (item.domain && item.rank) {
                this.alexaRankings.set(item.domain, parseInt(item.rank));
              }
            });
            console.log(`📊 Alexa rankings loaded: ${this.alexaRankings.size} domains`);
            return;
          }
        } else {
          console.log('📊 Extension context not available for Alexa rankings');
        }
      }
      
      // Fallback: initialize with empty rankings
      console.log('📊 Alexa rankings not available, continuing without them');
      
    } catch (error) {
      // Don't log extension context errors as warnings since they're expected
      if (error.message.includes('Extension context invalidated')) {
        console.log('📊 Extension context invalidated, skipping Alexa rankings');
      } else {
        console.warn('⚠️ Alexa rankings unavailable:', error.message);
      }
      // Don't disable ML just because Alexa rankings aren't available
    }
  }

  /**
   * MAIN SCORING FUNCTION
   * Calculate overall security score with proper methodology
   * 
   * @param {Object} categoryScores - Raw scores from each security category
   * @param {string} url - URL for context and ML enhancement
   * @param {Object} pageData - Additional page data for ML features
   * @returns {number} Final security score (0-100)
   */
  async calculateOverallScore(categoryScores, url = null, pageData = null) {
    console.log('🔢 Starting security score calculation...');
    
    // Step 1: Validate and normalize category scores
    const normalizedScores = this.normalizeCategoryScores(categoryScores);
    console.log('📝 Normalized category scores:', normalizedScores);
    
    // Step 2: Calculate weighted baseline score
    const baselineScore = this.calculateWeightedAverage(normalizedScores);
    console.log(`📊 Baseline weighted score: ${baselineScore}`);
    
    // Step 3: Apply ML enhancement (if enabled and data available)
    let finalScore = baselineScore;
    if (this.mlEnabled && url && pageData) {
      const mlAdjustment = await this.calculateMLAdjustment(url, pageData, baselineScore);
      finalScore = this.applyMLAdjustment(baselineScore, mlAdjustment);
      console.log(`🤖 ML adjustment: ${mlAdjustment > 0 ? '+' : ''}${mlAdjustment} -> Final: ${finalScore}`);
    }
    
    // Step 4: Ensure score is within valid bounds
    finalScore = this.boundScore(finalScore);
    
    console.log(`✅ Final security score: ${finalScore}/100 (${this.getScoreLabel(finalScore)})`);
    return finalScore;
  }

  /**
   * Normalize and validate category scores
   * Handles missing categories and invalid scores gracefully
   */
  normalizeCategoryScores(categoryScores) {
    const normalized = {};
    const defaults = {
      connectionSecurity: 70,  // Conservative default when SSL check fails
      scamDetection: 75,      // Assume safe when phishing check fails
      formSafety: 80,         // Assume secure when form check fails
      privacyProtection: 65,  // Assume some tracking when privacy check fails
      codeSafety: 75          // Assume safe when code check fails
    };

    Object.keys(this.CATEGORY_WEIGHTS).forEach(category => {
      const score = categoryScores[category];
      
      if (typeof score === 'number' && score >= 0 && score <= 100) {
        normalized[category] = score;
      } else {
        normalized[category] = defaults[category];
        console.warn(`⚠️ Using default score for ${category}: ${defaults[category]}`);
      }
    });

    return normalized;
  }

  /**
   * Calculate weighted average of category scores
   * Uses predefined weights that reflect security importance
   */
  calculateWeightedAverage(categoryScores) {
    let weightedSum = 0;
    let totalWeight = 0;

    Object.entries(this.CATEGORY_WEIGHTS).forEach(([category, weight]) => {
      const score = categoryScores[category];
      if (typeof score === 'number') {
        weightedSum += score * weight;
        totalWeight += weight;
      }
    });

    return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 50;
  }

  /**
   * Apply ML adjustment with proper bounds and confidence weighting
   */
  applyMLAdjustment(baselineScore, mlAdjustment) {
    const adjustedScore = baselineScore + mlAdjustment;
    
    // Ensure adjustment doesn't create unrealistic scores
    if (adjustedScore > baselineScore + 15) {
      return baselineScore + 15; // Cap positive adjustment
    }
    if (adjustedScore < baselineScore - 25) {
      return baselineScore - 25; // Cap negative adjustment
    }
    
    return Math.round(adjustedScore);
  }

  /**
   * Calculate ML-based score adjustment
   * Returns adjustment value (-25 to +15)
   */
  async calculateMLAdjustment(url, pageData, baselineScore) {
    try {
      // Extract normalized features
      const features = this.extractMLFeatures(url, pageData);
      
      // Get ML prediction
      const prediction = await this.predictWithML(features, url);
      
      // Convert threat probability to score adjustment
      let adjustment = 0;
      
      if (prediction.threatProbability > 0.8) {
        // Very high threat - large penalty
        adjustment = -Math.round((prediction.threatProbability - 0.5) * 50);
      } else if (prediction.threatProbability > 0.6) {
        // High threat - moderate penalty
        adjustment = -Math.round((prediction.threatProbability - 0.5) * 30);
      } else if (prediction.threatProbability < 0.3) {
        // Low threat - small bonus
        adjustment = Math.round((0.5 - prediction.threatProbability) * 20);
      } else {
        // Medium threat - small penalty
        adjustment = -Math.round((prediction.threatProbability - 0.4) * 15);
      }
      
      // Apply confidence weighting
      adjustment = Math.round(adjustment * prediction.confidence);
      
      // Final bounds check
      return Math.max(-25, Math.min(15, adjustment));
      
    } catch (error) {
      console.warn('🤖 ML adjustment failed:', error.message);
      return 0;
    }
  }

  /**
   * Extract properly normalized ML features
   */
  extractMLFeatures(url, pageData = {}) {
    try {
      const parsedUrl = new URL(url);
      const domain = parsedUrl.hostname;
      
      // URL structure features (8) - Properly normalized
      const urlLength = Math.min(1.0, url.length / 150);  // Cap at 150 chars
      const domainLength = Math.min(1.0, domain.length / 30); // Cap at 30 chars
      const subdomainCount = Math.min(1.0, Math.max(0, domain.split('.').length - 2) / 3);
      const hasHyphens = domain.includes('-') ? 1 : 0;
      const hasNumbers = /\d/.test(domain) ? 1 : 0;
      const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(domain) ? 1 : 0;
      const isHTTPS = url.startsWith('https://') ? 1 : 0;
      const hasPort = parsedUrl.port ? 1 : 0;
      
      // Content features (8) - Realistic thresholds
      const scriptCount = Math.min(1.0, (pageData.scriptCount || 0) / 15);
      const formCount = Math.min(1.0, (pageData.formCount || 0) / 3);
      const linkCount = Math.min(1.0, (pageData.linkCount || 0) / 50);
      const imageCount = Math.min(1.0, (pageData.imageCount || 0) / 25);
      const iframeCount = Math.min(1.0, (pageData.iframeCount || 0) / 2);
      const hasPasswordField = pageData.hasPasswordField ? 1 : 0;
      const hasLoginForm = pageData.hasLoginForm ? 1 : 0;
      const externalDomains = Math.min(1.0, (pageData.externalDomains || 0) / 5);
      
      // Behavioral features (3) - Proper defaults
      const redirectCount = Math.min(1.0, (pageData.redirectCount || 0) / 3);
      const loadTime = Math.min(1.0, Math.max(0.1, (pageData.loadTime || 2000)) / 8000);
      const errorCount = Math.min(1.0, (pageData.errorCount || 0) / 5);
      
      // Advanced analysis features (6)
      const entropyScore = this.calculateDomainEntropy(domain);
      const suspiciousWords = this.detectSuspiciousWords(url + ' ' + domain);
      const brandImitation = this.detectBrandImitation(url, domain);
      const socialEngineering = this.detectSocialEngineering(url + ' ' + domain);
      const vtScore = 0.5; // Placeholder for external reputation
      const alexaScore = this.getAlexaScore(domain);
      
      return [
        urlLength, domainLength, subdomainCount, hasHyphens,
        hasNumbers, isIP, isHTTPS, hasPort,
        scriptCount, formCount, linkCount, imageCount,
        iframeCount, hasPasswordField, hasLoginForm, externalDomains,
        redirectCount, loadTime, errorCount,
        entropyScore, suspiciousWords, brandImitation,
        socialEngineering, vtScore, alexaScore
      ];
      
    } catch (error) {
      console.warn('🔧 Feature extraction failed:', error.message);
      // Return safe defaults (neutral features)
      return new Array(25).fill(0.5);
    }
  }

  /**
   * ML prediction with trained model and proper normalization
   */
  async predictWithML(features, url) {
    try {
      const domain = new URL(url).hostname;
      const alexaScore = this.getAlexaScore(domain);
      
      // Update Alexa feature
      features[24] = alexaScore;
      
      // Normalize features using trained scaler parameters
      const normalizedFeatures = this.normalizeFeatures(features);
      
      // Calculate ML prediction using trained weights and bias
      const mlLogit = this.calculateLogit(normalizedFeatures);
      const mlProbability = this.sigmoid(mlLogit);
      
      // Combine ML with reputation sources (70% ML, 30% Alexa)
      const finalProbability = (mlProbability * 0.7) + (alexaScore * 0.3);
      
      const result = {
        threatProbability: Math.max(0, Math.min(1, finalProbability)),
        confidence: this.calculateConfidence(normalizedFeatures, finalProbability),
        alexaScore: alexaScore,
        mlPrediction: mlProbability,
        modelVersion: this.mlModel?.version || 'fallback',
        featuresNormalized: !!this.scalerMean
      };
      
      console.log('🤖 ML Prediction:', {
        threat: (result.threatProbability * 100).toFixed(1) + '%',
        confidence: (result.confidence * 100).toFixed(1) + '%',
        model: result.modelVersion
      });
      
      return result;
      
    } catch (error) {
      console.warn('🤖 ML prediction failed:', error.message);
      return { 
        threatProbability: 0.5, 
        confidence: 0.3,
        alexaScore: 0.5,
        mlPrediction: 0.5,
        modelVersion: 'error',
        featuresNormalized: false
      };
    }
  }

  /**
   * Calculate logistic regression output
   */
  calculateLogit(features) {
    // Validate inputs
    if (!features || !Array.isArray(features)) {
      console.warn('⚠️ Invalid features for logit calculation');
      return this.mlBias || 0;
    }
    
    if (!this.mlWeights || !Array.isArray(this.mlWeights)) {
      console.warn('⚠️ ML weights not available for logit calculation');
      return this.mlBias || 0;
    }
    
    let logit = this.mlBias || 0;
    const featureCount = Math.min(features.length, this.mlWeights.length);
    
    for (let i = 0; i < featureCount; i++) {
      const feature = features[i] || 0;
      const weight = this.mlWeights[i] || 0;
      logit += feature * weight;
    }
    
    return logit;
  }

  /**
   * Sigmoid activation function with overflow protection
   */
  sigmoid(x) {
    const clampedX = Math.max(-500, Math.min(500, x));
    return 1 / (1 + Math.exp(-clampedX));
  }

  /**
   * Calculate prediction confidence based on feature strength and certainty
   */
  calculateConfidence(features, prediction) {
    const certainty = Math.abs(prediction - 0.5) * 2;
    const featureStrength = features.reduce((sum, val) => sum + Math.abs(val - 0.5), 0) / features.length;
    const confidence = (certainty * 0.6) + (featureStrength * 0.4);
    return Math.min(0.95, Math.max(0.1, confidence));
  }

  /**
   * Get Alexa ranking score for domain reputation
   */
  getAlexaScore(domain) {
    if (!domain) return 0.5;
    
    // Remove www prefix for lookup
    const cleanDomain = domain.replace(/^www\./, '');
    const rank = this.alexaRankings.get(cleanDomain);
    
    if (!rank) return 0.4; // Unknown domain - slightly suspicious
    
    // Convert rank to score (lower rank = higher score)
    if (rank <= 1000) return 0.9;      // Top 1K sites
    if (rank <= 10000) return 0.8;     // Top 10K sites  
    if (rank <= 100000) return 0.7;    // Top 100K sites
    if (rank <= 500000) return 0.6;    // Top 500K sites
    if (rank <= 1000000) return 0.5;   // Top 1M sites
    return 0.4;                        // Outside top 1M
  }

  /**
   * Calculate domain entropy for randomness detection
   */
  calculateDomainEntropy(domain) {
    if (!domain || domain.length < 2) return 0;
    
    const chars = {};
    for (let char of domain.toLowerCase()) {
      chars[char] = (chars[char] || 0) + 1;
    }
    
    let entropy = 0;
    const length = domain.length;
    
    Object.values(chars).forEach(count => {
      const p = count / length;
      entropy -= p * Math.log2(p);
    });
    
    // Normalize to 0-1 range (typical domain entropy is 2-4)
    return Math.min(1, entropy / 4);
  }

  /**
   * Detect suspicious words in URL and domain
   */
  detectSuspiciousWords(text) {
    const suspiciousWords = [
      'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
      'bank', 'secure', 'account', 'verify', 'update', 'login',
      'free', 'winner', 'urgent', 'click', 'now', 'limited'
    ];
    
    const lowerText = text.toLowerCase();
    const matches = suspiciousWords.filter(word => lowerText.includes(word));
    
    // Return normalized score (0-1)
    return Math.min(1, matches.length / 3);
  }

  /**
   * Detect brand imitation patterns
   */
  detectBrandImitation(url, domain) {
    const brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'ebay', 'facebook'];
    const lowerDomain = domain.toLowerCase();
    
    let score = 0;
    
    brands.forEach(brand => {
      if (lowerDomain.includes(brand) && !lowerDomain.endsWith(brand + '.com')) {
        score += 0.3; // Brand name in suspicious context
      }
    });
    
    // Check for character substitution (e.g., 'o' -> '0')
    if (/[0-9]/.test(lowerDomain.replace(/\./g, ''))) {
      score += 0.2;
    }
    
    return Math.min(1, score);
  }

  /**
   * Detect social engineering patterns
   */
  detectSocialEngineering(text) {
    const urgencyWords = ['urgent', 'immediate', 'expires', 'limited', 'act now', 'verify now'];
    const actionWords = ['click here', 'download', 'install', 'update', 'confirm'];
    
    const lowerText = text.toLowerCase();
    let score = 0;
    
    urgencyWords.forEach(word => {
      if (lowerText.includes(word)) score += 0.2;
    });
    
    actionWords.forEach(word => {
      if (lowerText.includes(word)) score += 0.1;
    });
    
    return Math.min(1, score);
  }

  /**
   * Ensure score is within valid bounds
   */
  boundScore(score) {
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Get score label and color for UI display
   */
  getScoreLabel(score) {
    for (const [key, range] of Object.entries(this.SCORE_RANGES)) {
      if (score >= range.min && score <= range.max) {
        return range.label;
      }
    }
    return 'Unknown';
  }

  /**
   * Get score status for security assessment
   */
  getScoreStatus(score) {
    for (const range of Object.values(this.SCORE_RANGES)) {
      if (score >= range.min && score <= range.max) {
        return range.status;
      }
    }
    return 'unknown';
  }

  /**
   * Calculate individual category score with proper penalty application
   */
  calculateCategoryScore(baseScore, penalties, category) {
    const maxPenalty = this.PENALTY_CAPS[category] || 50;
    const totalPenalty = Math.min(maxPenalty, penalties.reduce((sum, p) => sum + p, 0));
    const finalScore = Math.max(20, baseScore - totalPenalty); // Never below 20
    
    console.log(`📊 ${category}: ${baseScore} - ${totalPenalty} = ${finalScore}`);
    return this.boundScore(finalScore);
  }

  /**
   * Generate comprehensive security report
   */
  generateSecurityReport(categoryScores, overallScore, url) {
    return {
      url: url,
      timestamp: new Date().toISOString(),
      overallScore: overallScore,
      overallStatus: this.getScoreStatus(overallScore),
      overallLabel: this.getScoreLabel(overallScore),
      categories: categoryScores,
      weights: this.CATEGORY_WEIGHTS,
      recommendations: this.generateRecommendations(categoryScores, overallScore)
    };
  }

  /**
   * Generate security recommendations based on scores
   */
  generateRecommendations(categoryScores, overallScore) {
    const recommendations = [];
    
    // Overall recommendations
    if (overallScore < 60) {
      recommendations.push('🚨 CRITICAL: Multiple security issues detected - exercise extreme caution');
    } else if (overallScore < 75) {
      recommendations.push('⚠️ WARNING: Some security concerns detected - review before proceeding');
    }
    
    // Category-specific recommendations
    if (categoryScores.connectionSecurity < 70) {
      recommendations.push('🔒 Connection security needs attention - check SSL/HTTPS configuration');
    }
    
    if (categoryScores.scamDetection < 60) {
      recommendations.push('🎣 Phishing/scam indicators detected - verify site authenticity');
    }
    
    if (categoryScores.formSafety < 70) {
      recommendations.push('📝 Form security issues detected - be cautious with personal information');
    }
    
    if (categoryScores.privacyProtection < 60) {
      recommendations.push('🛡️ Privacy concerns detected - consider using privacy tools');
    }
    
    if (categoryScores.codeSafety < 70) {
      recommendations.push('💻 Code security issues detected - potential malicious scripts');
    }
    
    return recommendations;
  }

  getAlexaScore(domain) {
    const rank = this.alexaRankings.get(domain);
    if (!rank) return 0.6; // Unknown domain
    
    if (rank <= 1000) return 0.05;
    if (rank <= 10000) return 0.1;
    if (rank <= 100000) return 0.2;
    if (rank <= 1000000) return 0.3;
    return 0.7;
  }

  // Feature extraction utilities
  calculateDomainEntropy(domain) {
    const chars = domain.replace(/\./g, '');
    const counts = {};
    for (const char of chars) {
      counts[char] = (counts[char] || 0) + 1;
    }
    
    let entropy = 0;
    const total = chars.length;
    for (const count of Object.values(counts)) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
    
    return Math.min(1, entropy / 4);
  }

  detectSuspiciousWords(text) {
    const suspicious = ['verify', 'suspended', 'urgent', 'click', 'immediately', 'limited', 'time', 'act', 'now'];
    const lowerText = text.toLowerCase();
    const matches = suspicious.filter(word => lowerText.includes(word)).length;
    return Math.min(1, matches / 5);
  }

  detectBrandImitation(url, domain) {
    const brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook'];
    const lowerUrl = url.toLowerCase();
    const lowerDomain = domain.toLowerCase();
    
    for (const brand of brands) {
      if ((lowerUrl.includes(brand) || lowerDomain.includes(brand)) && 
          !lowerDomain.includes(`${brand}.com`) && 
          !lowerDomain.includes(`${brand}.net`)) {
        return 0.8;
      }
    }
    return 0;
  }

  detectSocialEngineering(text) {
    const tactics = ['urgent', 'immediate', 'suspended', 'verify', 'security', 'update', 'confirm'];
    const lowerText = text.toLowerCase();
    const matches = tactics.filter(tactic => lowerText.includes(tactic)).length;
    return Math.min(1, matches / 8);
  }

  /**
   * Legacy calculateOverallScore for backward compatibility
   * @param {Object} categoryScores - Scores for each security category
   * @returns {number} Overall security score (0-100)
   */
  calculateOverallScoreSync(categoryScores) {
    let weightedSum = 0;
    let totalWeight = 0;

    // Calculate weighted average of valid category scores
    Object.entries(this.CATEGORY_WEIGHTS).forEach(([category, weight]) => {
      const score = categoryScores[category];
      
      // Only include categories that have valid scores
      if (typeof score === 'number' && score >= 0 && score <= 100) {
        weightedSum += score * weight;
        totalWeight += weight;
      }
    });

    // Return weighted average, or 0 if no valid scores
    return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
  }

  /**
   * Get risk level information based on security score
   * @param {number} score - Security score (0-100)
   * @returns {Object} Risk level details with color, icon, and label
   */
  getRiskLevel(score) {
    // Find the appropriate risk range for the score
    for (const [level, range] of Object.entries(this.SCORE_RANGES)) {
      if (score >= range.min && score <= range.max) {
        return {
          level: level.toLowerCase(),
          label: range.label,
          color: range.color,
          icon: range.icon,
          score: score
        };
      }
    }

    // Fallback to dangerous if score is invalid
    return {
      level: 'dangerous',
      label: 'Unknown',
      color: this.SCORE_RANGES.DANGEROUS.color,
      icon: this.SCORE_RANGES.DANGEROUS.icon,
      score: 0
    };
  }

  /**
   * Apply security penalty to a base score
   * @param {number} baseScore - Starting score (typically 100)
   * @param {string} penaltyType - Type of security issue
   * @param {number} multiplier - Penalty multiplier (default: 1)
   * @returns {number} Score after applying penalty
   */
  applyPenalty(baseScore, penaltyType, multiplier = 1) {
    const penalty = this.RISK_PENALTIES[penaltyType] || 0;
    const adjustedPenalty = penalty * multiplier;
    
    // Ensure score doesn't go below 0
    return Math.max(0, baseScore - adjustedPenalty);
  }

  /**
   * Generate user-friendly security summary
   * @param {number} score - Security score
   * @param {Array} issues - Array of security issues found
   * @returns {Object} User-friendly security summary
   */
  generateSecuritySummary(score, issues = []) {
    const riskLevel = this.getRiskLevel(score);
    
    return {
      score: score,
      riskLevel: riskLevel,
      userMessage: this.generateUserMessage(riskLevel, issues.length),
      recommendations: this.generateRecommendations(riskLevel, issues),
      criticalIssueCount: issues.filter(issue => this.isCriticalIssue(issue)).length,
      totalIssueCount: issues.length
    };
  }

  /**
   * Generate user-friendly message based on risk level
   * @param {Object} riskLevel - Risk level details
   * @param {number} issueCount - Number of issues found
   * @returns {string} User-friendly message
   */
  generateUserMessage(riskLevel, issueCount) {
    const messages = {
      excellent: `${riskLevel.icon} Excellent security - no issues detected`,
      good: `${riskLevel.icon} Good security practices`,
      fair: `${riskLevel.icon} Fair security - ${issueCount} minor concerns`,
      poor: `${riskLevel.icon} Poor security - ${issueCount} issues need attention`,
      dangerous: `${riskLevel.icon} Dangerous - ${issueCount} critical security issues`
    };

    return messages[riskLevel.level] || `${riskLevel.icon} Security assessment complete`;
  }

  /**
   * Generate security recommendations based on risk level
   * @param {Object} riskLevel - Risk level details
   * @param {Array} issues - Security issues found
   * @returns {Array} Array of user-friendly recommendations
   */
  generateRecommendations(riskLevel, issues) {
    const recommendations = [];

    switch (riskLevel.level) {
      case 'dangerous':
        recommendations.push(' Leave this website immediately');
        recommendations.push('Do not enter any personal information');
        recommendations.push('Report this site to your browser security team');
        break;

      case 'poor':
        recommendations.push(' Exercise extreme caution on this site');
        recommendations.push('Avoid entering sensitive information');
        recommendations.push('Verify the website authenticity');
        break;

      case 'fair':
        recommendations.push(' Be cautious with personal data');
        recommendations.push('Double-check the website URL');
        recommendations.push('Use additional security measures');
        break;

      case 'good':
        recommendations.push(' Site follows good security practices');
        recommendations.push('Continue with normal web safety habits');
        break;

      case 'excellent':
        recommendations.push(' Excellent security implementation');
        recommendations.push('Safe to use with confidence');
        break;
    }

    // Add issue-specific recommendations
    issues.forEach(issue => {
      const specificRec = this.getIssueSpecificRecommendation(issue);
      if (specificRec && !recommendations.includes(specificRec)) {
        recommendations.push(specificRec);
      }
    });

    return recommendations;
  }

  /**
   * Get specific recommendation for a security issue
   * @param {string} issue - Security issue description
   * @returns {string} Specific recommendation for the issue
   */
  getIssueSpecificRecommendation(issue) {
    const issueRecommendations = {
      'password form on http': ' Never enter passwords on HTTP sites',
      'mixed content': ' Check for "Not Secure" warnings in browser',
      'phishing indicators': ' Verify website URL carefully',
      'excessive tracking': ' Consider using privacy browser extensions',
      'suspicious scripts': ' Disable JavaScript if possible',
      'expired certificate': 'CERT Certificate has expired - verify legitimacy'
    };

    // Find matching recommendation
    for (const [keyword, recommendation] of Object.entries(issueRecommendations)) {
      if (issue.toLowerCase().includes(keyword)) {
        return recommendation;
      }
    }

    return null;
  }

  /**
   * Determine if a security issue is critical
   * @param {string} issue - Security issue description
   * @returns {boolean} True if issue is critical
   */
  isCriticalIssue(issue) {
    const criticalKeywords = [
      'password',
      'phishing',
      'malware',
      'dangerous',
      'critical',
      'expired certificate',
      'self-signed',
      'suspicious download'
    ];

    return criticalKeywords.some(keyword => 
      issue.toLowerCase().includes(keyword)
    );
  }

  /**
   * Format score for display with appropriate precision
   * @param {number} score - Raw security score
   * @returns {string} Formatted score for display
   */
  formatScore(score) {
    if (typeof score !== 'number' || isNaN(score)) {
      return 'N/A';
    }

    return Math.round(score).toString();
  }

  /**
   * Get security badge data for browser extension badge
   * @param {number} score - Security score
   * @returns {Object} Badge configuration
   */
  getBadgeData(score) {
    const riskLevel = this.getRiskLevel(score);
    
    return {
      text: riskLevel.icon,
      color: riskLevel.color,
      title: `Security Score: ${score}/100 (${riskLevel.label})`
    };
  }

  /**
   * Export security report data for external use
   * @param {Object} fullReport - Complete security report
   * @returns {Object} Exportable report data
   */
  exportReport(fullReport) {
    return {
      url: fullReport.url,
      domain: fullReport.domain,
      scanTimestamp: fullReport.scanTimestamp,
      overallScore: fullReport.overallScore,
      overallStatus: fullReport.overallStatus,
      riskLevel: this.getRiskLevel(fullReport.overallScore),
      categoryScores: Object.fromEntries(
        Object.entries(fullReport.categories).map(([category, data]) => [
          category,
          {
            score: data.score,
            status: data.status,
            issueCount: data.details ? Object.keys(data.details).length : 0
          }
        ])
      ),
      criticalIssues: fullReport.criticalIssues,
      recommendations: fullReport.recommendations,
      summary: this.generateSecuritySummary(fullReport.overallScore, fullReport.criticalIssues)
    };
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityScorer;
} else {
  window.SecurityScorer = SecurityScorer;
} 