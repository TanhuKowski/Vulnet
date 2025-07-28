/** Insecure forms detection module */

class InsecureFormsDetector {
  constructor() {
    this.securityRisks = {
      HTTP_PASSWORD: 'password_over_http',
      EXTERNAL_ACTION: 'external_form_action',
      NO_CSRF: 'missing_csrf_protection',
      AUTO_COMPLETE: 'autocomplete_enabled',
      HIDDEN_FIELDS: 'excessive_hidden_fields',
      WEAK_VALIDATION: 'weak_client_validation'
    };
  }

  /**
   * Analyze all forms on the page for security issues
   * @returns {Promise<Object>} Form security analysis results
   */
  async analyzeFormSecurity() {
    try {
      console.log('🔒 Analyzing form security...');
      
      const analysis = {
        score: 100,
        status: 'safe',
        
        // Detailed breakdown scores (like demo data)
        formSecurityScore: 100,
        encryptionScore: 100,
        validationScore: 100,
        protectionScore: 100,
        privacyScore: 100,
        
        // Detailed breakdown descriptions
        formSecurityDetails: '',
        encryptionDetails: '',
        validationDetails: '',
        protectionDetails: '',
        privacyDetails: '',
        
        // Technical details
        totalForms: 0,
        secureForms: 0,
        insecureForms: [],
        securityIssues: [],
        recommendations: []
      };

      // Get all forms on the page
      const forms = document.querySelectorAll('form');
      analysis.totalForms = forms.length;

      if (forms.length === 0) {
        console.log('✅ No forms found on page');
        analysis.formSecurityDetails = '✅ No forms detected';
        analysis.encryptionDetails = '✅ No encryption concerns';
        analysis.validationDetails = '✅ No validation concerns';
        analysis.protectionDetails = '✅ No protection concerns';
        analysis.privacyDetails = '✅ No privacy concerns';
        analysis.recommendations.push('No forms detected - no form security concerns');
        return analysis;
      }

      // Analyze each form
      let secureFormsCount = 0;
      forms.forEach((form, index) => {
        const formAnalysis = this.analyzeIndividualForm(form, index);
        
        if (formAnalysis.hasSecurityIssues) {
          analysis.insecureForms.push(formAnalysis);
          analysis.securityIssues.push(...formAnalysis.issues);
        } else {
          secureFormsCount++;
        }
      });

      analysis.secureForms = secureFormsCount;

      // Generate detailed breakdown analysis
      this.generateDetailedFormAnalysis(analysis, forms);

      // Calculate overall security score from breakdown scores
      analysis.score = Math.round((
        analysis.formSecurityScore * 0.30 +
        analysis.encryptionScore * 0.25 +
        analysis.validationScore * 0.20 +
        analysis.protectionScore * 0.15 +
        analysis.privacyScore * 0.10
      ));
      
      console.log('✅ Form security analysis completed:', {
        totalForms: analysis.totalForms,
        insecureForms: analysis.insecureForms.length,
        score: analysis.score
      });

      return analysis;
      
    } catch (error) {
      console.error('❌ Form security analysis failed:', error);
      return {
        score: 70,
        status: 'error',
        totalForms: 0,
        insecureForms: [],
        securityIssues: [],
        recommendations: ['Form security analysis failed - manual review recommended'],
        error: error.message
      };
    }
  }

  /**
   * Analyze individual form for security issues
   * @param {HTMLFormElement} form - Form element to analyze
   * @param {number} index - Form index on page
   * @returns {Object} Individual form analysis
   */
  analyzeIndividualForm(form, index) {
    const formAnalysis = {
      index: index,
      action: form.action || window.location.href,
      method: (form.method || 'get').toLowerCase(),
      hasPasswordField: false,
      hasEmailField: false,
      hasSecurityIssues: false,
      issues: [],
      riskLevel: 'low',
      fields: []
    };

    // Analyze form fields
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
      const fieldAnalysis = this.analyzeFormField(input);
      formAnalysis.fields.push(fieldAnalysis);
      
      if (fieldAnalysis.type === 'password') {
        formAnalysis.hasPasswordField = true;
      }
      
      if (fieldAnalysis.type === 'email' || fieldAnalysis.name.toLowerCase().includes('email')) {
        formAnalysis.hasEmailField = true;
      }
    });

    // Check for specific security issues
    this.checkPasswordOverHTTP(formAnalysis);
    this.checkExternalFormAction(formAnalysis);
    this.checkCSRFProtection(formAnalysis, form);
    this.checkAutoComplete(formAnalysis, form);
    this.checkHiddenFields(formAnalysis, form);
    this.checkClientSideValidation(formAnalysis, form);

    // Determine overall risk level
    this.determineFormRiskLevel(formAnalysis);

    return formAnalysis;
  }

  /**
   * Analyze individual form field
   * @param {HTMLInputElement} input - Input element to analyze
   * @returns {Object} Field analysis
   */
  analyzeFormField(input) {
    return {
      type: input.type || 'text',
      name: input.name || '',
      id: input.id || '',
      required: input.required,
      autocomplete: input.autocomplete,
      hasValidation: input.pattern || input.minLength || input.maxLength || input.min || input.max,
      placeholder: input.placeholder || ''
    };
  }

  /**
   * Check for password fields over HTTP
   */
  checkPasswordOverHTTP(formAnalysis) {
    if (formAnalysis.hasPasswordField && window.location.protocol === 'http:') {
      formAnalysis.hasSecurityIssues = true;
      formAnalysis.issues.push({
        type: this.securityRisks.HTTP_PASSWORD,
        severity: 'high',
        description: 'Password field transmitted over insecure HTTP connection',
        recommendation: 'Use HTTPS for all forms containing sensitive data'
      });
    }
  }

  /**
   * Check for external form actions
   */
  checkExternalFormAction(formAnalysis) {
    try {
      const actionUrl = new URL(formAnalysis.action, window.location.href);
      const currentDomain = window.location.hostname;
      
      if (actionUrl.hostname !== currentDomain) {
        formAnalysis.hasSecurityIssues = true;
        formAnalysis.issues.push({
          type: this.securityRisks.EXTERNAL_ACTION,
          severity: 'medium',
          description: `Form submits to external domain: ${actionUrl.hostname}`,
          recommendation: 'Verify the legitimacy of external form submissions'
        });
      }
    } catch (error) {
      // Invalid URL in action
    }
  }

  /**
   * Check for CSRF protection
   */
  checkCSRFProtection(formAnalysis, form) {
    // Look for common CSRF token patterns
    const csrfPatterns = [
      'csrf', 'token', '_token', 'authenticity_token',
      'csrfmiddlewaretoken', 'RequestVerificationToken'
    ];
    
    const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
    let hasCSRFToken = false;
    
    hiddenInputs.forEach(input => {
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      
      if (csrfPatterns.some(pattern => name.includes(pattern) || id.includes(pattern))) {
        hasCSRFToken = true;
      }
    });
    
    // Only flag as issue for forms that modify data
    if (!hasCSRFToken && formAnalysis.method === 'post' && 
        (formAnalysis.hasPasswordField || formAnalysis.hasEmailField)) {
      formAnalysis.hasSecurityIssues = true;
      formAnalysis.issues.push({
        type: this.securityRisks.NO_CSRF,
        severity: 'medium',
        description: 'Form lacks CSRF protection tokens',
        recommendation: 'Implement CSRF protection for data modification forms'
      });
    }
  }

  /**
   * Check autocomplete settings
   */
  checkAutoComplete(formAnalysis, form) {
    const sensitiveFields = form.querySelectorAll('input[type="password"], input[name*="credit"], input[name*="ssn"]');
    
    sensitiveFields.forEach(field => {
      if (field.autocomplete !== 'off' && field.autocomplete !== 'new-password') {
        formAnalysis.hasSecurityIssues = true;
        formAnalysis.issues.push({
          type: this.securityRisks.AUTO_COMPLETE,
          severity: 'low',
          description: `Sensitive field allows autocomplete: ${field.name || field.type}`,
          recommendation: 'Disable autocomplete for sensitive fields'
        });
      }
    });
  }

  /**
   * Check for excessive hidden fields
   */
  checkHiddenFields(formAnalysis, form) {
    const hiddenFields = form.querySelectorAll('input[type="hidden"]');
    
    if (hiddenFields.length > 10) {
      formAnalysis.hasSecurityIssues = true;
      formAnalysis.issues.push({
        type: this.securityRisks.HIDDEN_FIELDS,
        severity: 'low',
        description: `Form contains many hidden fields (${hiddenFields.length})`,
        recommendation: 'Review hidden fields for potential security risks'
      });
    }
  }

  /**
   * Check client-side validation
   */
  checkClientSideValidation(formAnalysis, form) {
    const requiredFields = form.querySelectorAll('input[required], select[required], textarea[required]');
    const fieldsWithValidation = form.querySelectorAll('input[pattern], input[minlength], input[maxlength]');
    
    // Check if form relies only on client-side validation
    if (requiredFields.length > 0 && fieldsWithValidation.length === 0) {
      formAnalysis.hasSecurityIssues = true;
      formAnalysis.issues.push({
        type: this.securityRisks.WEAK_VALIDATION,
        severity: 'low',
        description: 'Form may rely solely on client-side validation',
        recommendation: 'Implement server-side validation for all form inputs'
      });
    }
  }

  /**
   * Determine form risk level
   */
  determineFormRiskLevel(formAnalysis) {
    const highRiskIssues = formAnalysis.issues.filter(issue => issue.severity === 'high').length;
    const mediumRiskIssues = formAnalysis.issues.filter(issue => issue.severity === 'medium').length;
    const lowRiskIssues = formAnalysis.issues.filter(issue => issue.severity === 'low').length;
    
    if (highRiskIssues > 0) {
      formAnalysis.riskLevel = 'high';
    } else if (mediumRiskIssues > 1 || (mediumRiskIssues > 0 && lowRiskIssues > 2)) {
      formAnalysis.riskLevel = 'medium';
    } else if (mediumRiskIssues > 0 || lowRiskIssues > 3) {
      formAnalysis.riskLevel = 'low';
    } else {
      formAnalysis.riskLevel = 'minimal';
    }
  }

  /**
   * Generate detailed form security analysis with breakdown scores
   */
  generateDetailedFormAnalysis(analysis, forms) {
    // Analyze form security (overall form structure and count)
    // Base score on the security posture of existing forms
    if (analysis.totalForms === 0) {
      analysis.formSecurityScore = 100;
      analysis.formSecurityDetails = '✅ No forms detected';
    } else if (analysis.insecureForms.length === 0) {
      analysis.formSecurityScore = 95;
      analysis.formSecurityDetails = `✅ All ${analysis.totalForms} form(s) secure`;
    } else {
      // Calculate score based on severity of issues, not just count
      let totalPenalty = 0;
      analysis.securityIssues.forEach(issue => {
        switch(issue.severity) {
          case 'high': totalPenalty += 30; break;    // Critical issues
          case 'medium': totalPenalty += 15; break;  // Important issues
          case 'low': totalPenalty += 5; break;     // Minor issues
        }
      });
      
      analysis.formSecurityScore = Math.max(20, 100 - totalPenalty);
      analysis.formSecurityDetails = `⚠️ ${analysis.insecureForms.length}/${analysis.totalForms} form(s) have security issues (${analysis.securityIssues.length} total issues)`;
    }

    // Analyze encryption (HTTPS vs HTTP for password forms)
    // Focus specifically on password transmission security
    let hasHttpPasswordForms = false;
    let passwordFormsCount = 0;
    let sensitiveFormsCount = 0;
    
    forms.forEach(form => {
      const hasPassword = form.querySelector('input[type="password"]');
      const hasEmail = form.querySelector('input[type="email"]');
      const hasCreditCard = form.querySelector('input[name*="credit"], input[name*="card"], input[autocomplete*="cc-"]');
      
      if (hasPassword) {
        passwordFormsCount++;
        if (window.location.protocol === 'http:') {
          hasHttpPasswordForms = true;
        }
      }
      
      if (hasPassword || hasEmail || hasCreditCard) {
        sensitiveFormsCount++;
      }
    });

    if (passwordFormsCount === 0) {
      analysis.encryptionScore = 100;
      analysis.encryptionDetails = '✅ No password forms requiring encryption';
    } else if (!hasHttpPasswordForms) {
      analysis.encryptionScore = 100;
      analysis.encryptionDetails = `✅ All ${passwordFormsCount} password form(s) use HTTPS encryption`;
    } else {
      analysis.encryptionScore = 10; // Critical security failure
      analysis.encryptionDetails = `❌ Password form(s) transmitted over insecure HTTP`;
    }

    // Analyze validation (input validation and security requirements)
    // Check for proper validation patterns and security measures
    let totalInputs = 0;
    let validatedInputs = 0;
    let securePasswordFields = 0;
    let passwordFields = 0;

    forms.forEach(form => {
      const inputs = form.querySelectorAll('input, select, textarea');
      inputs.forEach(input => {
        totalInputs++;
        
        // Count inputs with any form of validation
        if (input.required || input.pattern || input.minLength || input.maxLength || 
            input.min || input.max || input.type === 'email' || input.type === 'url') {
          validatedInputs++;
        }
        
        // Check password field security
        if (input.type === 'password') {
          passwordFields++;
          if (input.minLength >= 8 || input.pattern) {
            securePasswordFields++;
          }
        }
      });
    });

    if (totalInputs === 0) {
      analysis.validationScore = 100;
      analysis.validationDetails = '✅ No input validation concerns';
    } else {
      const validationRatio = validatedInputs / totalInputs;
      let baseValidationScore = Math.round(validationRatio * 80 + 20); // 20-100 range
      
      // Apply penalty for weak password validation
      if (passwordFields > 0) {
        const passwordSecurityRatio = securePasswordFields / passwordFields;
        if (passwordSecurityRatio < 0.5) {
          baseValidationScore -= 20; // Significant penalty for weak password rules
        } else if (passwordSecurityRatio < 1.0) {
          baseValidationScore -= 10; // Moderate penalty for some weak passwords
        }
      }
      
      analysis.validationScore = Math.max(10, baseValidationScore);
      
      if (passwordFields > 0 && securePasswordFields === 0) {
        analysis.validationDetails = `⚠️ ${validatedInputs}/${totalInputs} inputs validated, but ${passwordFields} password field(s) lack security requirements`;
      } else if (validationRatio >= 0.8) {
        analysis.validationDetails = `✅ ${validatedInputs}/${totalInputs} inputs have proper validation`;
      } else {
        analysis.validationDetails = `⚠️ ${validatedInputs}/${totalInputs} inputs validated - consider adding more validation`;
      }
    }

    // Analyze protection (CSRF tokens and security headers)
    // Focus on forms that actually need protection (POST forms with sensitive data)
    let csrfProtectedForms = 0;
    let formsNeedingProtection = 0;

    forms.forEach(form => {
      const method = (form.method || 'get').toLowerCase();
      const hasPassword = form.querySelector('input[type="password"]');
      const hasEmail = form.querySelector('input[type="email"]');
      const hasHiddenInputs = form.querySelectorAll('input[type="hidden"]').length > 0;
      
      // Only POST forms with sensitive data need CSRF protection
      if (method === 'post' && (hasPassword || hasEmail || hasHiddenInputs)) {
        formsNeedingProtection++;
        
        const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
        const hasToken = Array.from(hiddenInputs).some(input => {
          const name = (input.name || '').toLowerCase();
          const id = (input.id || '').toLowerCase();
          return name.includes('token') || name.includes('csrf') || 
                 id.includes('token') || id.includes('csrf');
        });
        
        if (hasToken) csrfProtectedForms++;
      }
    });

    if (formsNeedingProtection === 0) {
      analysis.protectionScore = 100;
      analysis.protectionDetails = '✅ No forms requiring CSRF protection';
    } else {
      const protectionRatio = csrfProtectedForms / formsNeedingProtection;
      analysis.protectionScore = Math.round(protectionRatio * 80 + 20); // 20-100 range
      
      if (protectionRatio === 1) {
        analysis.protectionDetails = `✅ All ${formsNeedingProtection} sensitive form(s) have CSRF protection`;
      } else if (protectionRatio > 0) {
        analysis.protectionDetails = `⚠️ ${csrfProtectedForms}/${formsNeedingProtection} sensitive form(s) have CSRF protection`;
      } else {
        analysis.protectionDetails = `❌ ${formsNeedingProtection} sensitive form(s) lack CSRF protection`;
      }
    }

    // Analyze privacy (autocomplete and data collection patterns)
    // Focus on preventing credential theft and data leakage
    let sensitiveFieldsWithAutocompleteOff = 0;
    let totalSensitiveFields = 0;

    forms.forEach(form => {
      const sensitiveInputs = form.querySelectorAll(
        'input[type="password"], input[type="email"], input[name*="credit"], input[name*="ssn"], input[autocomplete*="cc-"]'
      );
      
      totalSensitiveFields += sensitiveInputs.length;
      
      sensitiveInputs.forEach(input => {
        // Check if autocomplete is explicitly disabled for sensitive fields
        if (input.autocomplete === 'off' || input.autocomplete === 'new-password' || 
            form.autocomplete === 'off') {
          sensitiveFieldsWithAutocompleteOff++;
        }
      });
    });

    if (totalSensitiveFields === 0) {
      analysis.privacyScore = 100;
      analysis.privacyDetails = '✅ No sensitive fields detected';
    } else {
      // Higher score when autocomplete is OFF for sensitive fields (better privacy)
      const privacyRatio = sensitiveFieldsWithAutocompleteOff / totalSensitiveFields;
      analysis.privacyScore = Math.round(privacyRatio * 70 + 30); // 30-100 range
      
      if (privacyRatio >= 0.8) {
        analysis.privacyDetails = `✅ ${sensitiveFieldsWithAutocompleteOff}/${totalSensitiveFields} sensitive fields properly disable autocomplete`;
      } else if (privacyRatio > 0) {
        analysis.privacyDetails = `⚠️ ${sensitiveFieldsWithAutocompleteOff}/${totalSensitiveFields} sensitive fields disable autocomplete`;
      } else {
        analysis.privacyDetails = `⚠️ ${totalSensitiveFields} sensitive field(s) allow autocomplete (privacy risk)`;
      }
    }

    // Determine overall status
    if (analysis.score >= 85) {
      analysis.status = 'safe';
    } else if (analysis.score >= 70) {
      analysis.status = 'warning';
    } else {
      analysis.status = 'dangerous';
    }

    // Generate recommendations
    this.generateEnhancedFormRecommendations(analysis);
  }

  /**
   * Generate enhanced form security recommendations
   */
  generateEnhancedFormRecommendations(analysis) {
    const recommendations = [];
    
    if (analysis.score >= 90) {
      recommendations.push('✅ Excellent form security implementation');
    } else {
      if (analysis.encryptionScore < 80) {
        recommendations.push('Use HTTPS for all password and sensitive forms');
      }
      if (analysis.validationScore < 80) {
        recommendations.push('Add stronger input validation and password requirements');
      }
      if (analysis.protectionScore < 80) {
        recommendations.push('Implement CSRF protection for POST forms');
      }
      if (analysis.privacyScore < 80) {
        recommendations.push('Disable autocomplete for sensitive fields');
      }
    }

    analysis.recommendations = recommendations;
  }

  /**
   * Calculate overall form security score (legacy method for compatibility)
   */
  calculateFormSecurityScore(analysis) {
    let score = 100;
    
    // Penalize based on form security issues
    analysis.securityIssues.forEach(issue => {
      switch (issue.severity) {
        case 'high':
          score -= 30;
          break;
        case 'medium':
          score -= 15;
          break;
        case 'low':
          score -= 5;
          break;
      }
    });
    
    // Additional penalties for high-risk scenarios
    const httpPasswordForms = analysis.insecureForms.filter(form => 
      form.issues.some(issue => issue.type === this.securityRisks.HTTP_PASSWORD)
    ).length;
    
    if (httpPasswordForms > 0) {
      score -= 25; // Extra penalty for HTTP password forms
    }
    
    // Ensure score doesn't go below 0
    score = Math.max(0, score);
    
    analysis.score = score;
    analysis.status = score >= 80 ? 'safe' : score >= 60 ? 'warning' : 'dangerous';
    
    // Generate recommendations
    this.generateFormRecommendations(analysis);
  }

  /**
   * Generate form security recommendations
   */
  generateFormRecommendations(analysis) {
    const recommendations = [];
    
    if (analysis.insecureForms.length === 0) {
      recommendations.push('✅ All forms follow good security practices');
    } else {
      recommendations.push(`⚠️ ${analysis.insecureForms.length} form(s) have security concerns`);
      
      // Specific recommendations based on issues
      const httpPasswordIssues = analysis.securityIssues.filter(issue => 
        issue.type === this.securityRisks.HTTP_PASSWORD
      ).length;
      
      if (httpPasswordIssues > 0) {
        recommendations.push('🔒 Critical: Use HTTPS for password forms');
      }
      
      const externalActionIssues = analysis.securityIssues.filter(issue => 
        issue.type === this.securityRisks.EXTERNAL_ACTION
      ).length;
      
      if (externalActionIssues > 0) {
        recommendations.push('🔍 Verify external form destinations');
      }
      
      const csrfIssues = analysis.securityIssues.filter(issue => 
        issue.type === this.securityRisks.NO_CSRF
      ).length;
      
      if (csrfIssues > 0) {
        recommendations.push('🛡️ CSRF protection recommended');
      }
    }
    
    // General security advice
    if (analysis.totalForms > 0) {
      recommendations.push('Always verify form legitimacy before entering sensitive data');
    }
    
    analysis.recommendations = recommendations;
  }
}

// Make class available globally
window.InsecureFormsDetector = InsecureFormsDetector;
