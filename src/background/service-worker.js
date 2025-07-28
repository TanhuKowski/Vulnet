/** Background service worker for security scanner */

class SecurityBackgroundService {
  constructor() {
    // Initialize service
    this.initializeService();
    
    // Tab security tracking
    this.tabSecurityStatus = new Map();
    
    // Setup message handlers
    this.setupMessageHandlers();
    
    // Setup tab handlers
    this.setupTabEventHandlers();
  }

  /** Initialize background service worker */
  initializeService() {
    console.log(' Security Scanner Background Service initialized');
    
    // Set default badge
    this.updateBadge('', '#666666', 'Website Security Scanner');
  }

  /**
   * Set up message handlers for communication with content scripts and popup
   */
  setupMessageHandlers() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      console.log('MESSAGE Background received message:', request.action);
      
      switch (request.action) {
        case 'securityScanComplete':
          this.handleSecurityScanComplete(request, sender);
          break;
          
        case 'updateBadge':
          this.handleBadgeUpdate(request, sender);
          break;
          
        case 'emergencyAlert':
          this.handleEmergencyAlert(request, sender);
          break;
          
        case 'getTabSecurityStatus':
          this.handleGetTabSecurityStatus(request, sender, sendResponse);
          break;
          
        case 'clearTabData':
          this.handleClearTabData(request, sender);
          break;
          
        default:
          console.log('UNKNOWN Unknown message action:', request.action);
      }
      
      // Keep message channel open for async responses
      return true;
    });
  }

  /**
   * Set up tab event handlers to manage security status
   */
  setupTabEventHandlers() {
    // Clear security data when tab is closed
    chrome.tabs.onRemoved.addListener((tabId) => {
      this.clearTabSecurityData(tabId);
    });

    // Update badge when active tab changes
    chrome.tabs.onActivated.addListener((activeInfo) => {
      this.updateBadgeForTab(activeInfo.tabId);
    });

    // Monitor tab URL changes
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.url) {
        // URL changed, clear previous security data
        this.clearTabSecurityData(tabId);
        this.updateBadge('', '#666666', 'Website Security Scanner');
      }
    });
  }

  /**
   * Handle security scan completion from content script
   * @param {Object} request - Message request with scan results
   * @param {Object} sender - Message sender information
   */
  handleSecurityScanComplete(request, sender) {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    console.log(` Security scan completed for tab ${tabId}`);
    
    // Store security status for this tab
    const securityData = {
      tabId: tabId,
      url: request.report.url,
      overallScore: request.report.overallScore,
      overallStatus: request.report.overallStatus,
      scanTimestamp: request.report.scanTimestamp,
      criticalIssues: request.report.criticalIssues || []
    };
    
    this.tabSecurityStatus.set(tabId, securityData);
    
    // Update badge for this tab if it's currently active
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id === tabId) {
        this.updateBadgeFromSecurityData(securityData);
      }
    });

    // Store detailed report in local storage
    this.storeSecurityReport(tabId, request.report);
  }

  /**
   * Handle badge update request from content script
   * @param {Object} request - Badge update request
   * @param {Object} sender - Message sender information
   */
  handleBadgeUpdate(request, sender) {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    // Update badge for specific tab
    this.updateBadge(
      request.badgeText || '',
      request.badgeColor || '#666666',
      request.title || 'Website Security Scanner',
      tabId
    );
  }

  /**
   * Handle emergency alert from content script
   * @param {Object} request - Emergency alert request
   * @param {Object} sender - Message sender information
   */
  handleEmergencyAlert(request, sender) {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    console.log(` Emergency alert received for tab ${tabId}:`, request.message);
    
    // Store emergency alert data
    const alertData = {
      tabId: tabId,
      severity: request.severity,
      message: request.message,
      timestamp: request.timestamp || Date.now(),
      url: sender.tab?.url
    };

    // Update tab security status with emergency flag
    if (this.tabSecurityStatus.has(tabId)) {
      const securityData = this.tabSecurityStatus.get(tabId);
      securityData.emergencyAlert = alertData;
      this.tabSecurityStatus.set(tabId, securityData);
    }

    // Update badge with emergency indicator
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id === tabId) {
        this.updateEmergencyBadge(request.severity, tabId);
      }
    });

    // Store emergency alert in local storage
    chrome.storage.local.set({
      [`emergency_alert_${tabId}`]: alertData,
      'last_emergency_alert': alertData
    });

    // For critical alerts, also try to show a notification
    if (request.severity === 'CRITICAL') {
      this.showCriticalNotification(request.message, sender.tab?.url);
    }
  }

  /**
   * Update badge with emergency styling
   * @param {string} severity - Alert severity
   * @param {number} tabId - Tab ID
   */
  updateEmergencyBadge(severity, tabId) {
    const emergencyBadges = {
      'CRITICAL': { text: '', color: '#F44336', title: ' CRITICAL SECURITY THREAT DETECTED!' },
      'HIGH': { text: '', color: '#FF9800', title: ' High Security Risk Detected' },
      'WARNING': { text: '', color: '#2196F3', title: ' Security Warning - Check Details' }
    };

    const badge = emergencyBadges[severity] || emergencyBadges['WARNING'];
    
    this.updateBadge(badge.text, badge.color, badge.title, tabId);

    // Make badge flash for critical alerts
    if (severity === 'CRITICAL') {
      this.flashBadge(tabId, badge);
    }
  }

  /**
   * Make badge flash for critical alerts
   * @param {number} tabId - Tab ID
   * @param {Object} badgeConfig - Badge configuration
   */
  flashBadge(tabId, badgeConfig) {
    let flashCount = 0;
    const maxFlashes = 6;
    
    const flashInterval = setInterval(() => {
      if (flashCount >= maxFlashes) {
        clearInterval(flashInterval);
        // Set final badge state
        this.updateBadge(badgeConfig.text, badgeConfig.color, badgeConfig.title, tabId);
        return;
      }

      // Alternate between emergency color and bright flash
      const isFlash = flashCount % 2 === 0;
      const color = isFlash ? '#FFFFFF' : badgeConfig.color;
      const text = isFlash ? '' : badgeConfig.text;
      
      this.updateBadge(text, color, badgeConfig.title, tabId);
      flashCount++;
    }, 300);
  }

  /**
   * Show critical notification
   * @param {string} message - Alert message
   * @param {string} url - Website URL
   */
  showCriticalNotification(message, url) {
    try {
      // Create a notification for critical alerts
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'src/assets/icons/icon48.png',
        title: ' CRITICAL SECURITY ALERT',
        message: message,
        contextMessage: `Website: ${url}`,
        priority: 2,
        requireInteraction: true
      }, (notificationId) => {
        if (chrome.runtime.lastError) {
          console.log('Notification permission not granted:', chrome.runtime.lastError);
        } else {
          console.log('Critical notification created:', notificationId);
        }
      });
    } catch (error) {
      console.error('Failed to create critical notification:', error);
    }
  }

  /**
   * Handle request for tab security status
   * @param {Object} request - Status request
   * @param {Object} sender - Message sender
   * @param {Function} sendResponse - Response callback
   */
  handleGetTabSecurityStatus(request, sender, sendResponse) {
    const tabId = request.tabId || sender.tab?.id;
    
    if (tabId && this.tabSecurityStatus.has(tabId)) {
      const securityData = this.tabSecurityStatus.get(tabId);
      sendResponse({
        success: true,
        securityData: securityData
      });
    } else {
      sendResponse({
        success: false,
        error: 'No security data available for tab'
      });
    }
  }

  /**
   * Handle request to clear tab data
   * @param {Object} request - Clear data request
   * @param {Object} sender - Message sender
   */
  handleClearTabData(request, sender) {
    const tabId = request.tabId || sender.tab?.id;
    
    if (tabId) {
      this.clearTabSecurityData(tabId);
    }
  }

  /**
   * Update extension badge
   * @param {string} text - Badge text
   * @param {string} color - Badge background color
   * @param {string} title - Tooltip title
   * @param {number} tabId - Optional specific tab ID
   */
  updateBadge(text, color, title, tabId = null) {
    try {
      const badgeOptions = {
        text: text
      };
      
      const colorOptions = {
        color: color
      };
      
      const titleOptions = {
        title: title
      };

      // If tabId specified, update badge for specific tab
      if (tabId) {
        badgeOptions.tabId = tabId;
        colorOptions.tabId = tabId;
        titleOptions.tabId = tabId;
      }

      // Update badge text
      chrome.action.setBadgeText(badgeOptions);
      
      // Update badge color
      chrome.action.setBadgeBackgroundColor(colorOptions);
      
      // Update badge title
      chrome.action.setTitle(titleOptions);

    } catch (error) {
      console.error(' Failed to update badge:', error);
    }
  }

  /**
   * Update badge based on security data
   * @param {Object} securityData - Security assessment data
   */
  updateBadgeFromSecurityData(securityData) {
    let badgeText = '';
    let badgeColor = '#666666';
    let title = 'Website Security Scanner';

    if (securityData) {
      const score = securityData.overallScore;
      const status = securityData.overallStatus;
      
      // Determine badge appearance based on security status
      if (status === 'dangerous' || score < 60) {
        badgeText = '!';
        badgeColor = '#F44336'; // Red
        title = `Security Issues Detected (${score}/100)`;
      } else if (status === 'warning' || score < 80) {
        badgeText = '!';
        badgeColor = '#FF9800'; // Orange
        title = `Security Concerns (${score}/100)`;
      } else {
        badgeText = 'VERIFIED';
        badgeColor = '#4CAF50'; // Green
        title = `Secure Website (${score}/100)`;
      }

      // Add critical issues count if present
      if (securityData.criticalIssues && securityData.criticalIssues.length > 0) {
        title += ` - ${securityData.criticalIssues.length} critical issues`;
      }
    }

    this.updateBadge(badgeText, badgeColor, title);
  }

  /**
   * Update badge for specific tab
   * @param {number} tabId - Tab ID to update badge for
   */
  updateBadgeForTab(tabId) {
    if (this.tabSecurityStatus.has(tabId)) {
      const securityData = this.tabSecurityStatus.get(tabId);
      this.updateBadgeFromSecurityData(securityData);
    } else {
      // No security data for this tab, show default badge
      this.updateBadge('', '#666666', 'Website Security Scanner');
    }
  }

  /**
   * Store detailed security report in local storage
   * @param {number} tabId - Tab ID
   * @param {Object} report - Security report data
   */
  storeSecurityReport(tabId, report) {
    try {
      const storageKey = `security_report_${tabId}`;
      const reportData = {
        ...report,
        storedAt: Date.now()
      };

      chrome.storage.local.set({
        [storageKey]: reportData
      }, () => {
        if (chrome.runtime.lastError) {
          console.error(' Failed to store security report:', chrome.runtime.lastError);
        } else {
          console.log(`CACHE Security report stored for tab ${tabId}`);
        }
      });

      // Clean up old reports (keep only last 10)
      this.cleanupOldReports();

    } catch (error) {
      console.error(' Failed to store security report:', error);
    }
  }

  /**
   * Clean up old security reports from storage
   */
  cleanupOldReports() {
    chrome.storage.local.get(null, (items) => {
      if (chrome.runtime.lastError) {
        console.error(' Failed to get storage items:', chrome.runtime.lastError);
        return;
      }

      // Find all security report keys
      const reportKeys = Object.keys(items).filter(key => 
        key.startsWith('security_report_')
      );

      // Sort by storage time (newest first)
      const sortedKeys = reportKeys.sort((a, b) => {
        const aTime = items[a]?.storedAt || 0;
        const bTime = items[b]?.storedAt || 0;
        return bTime - aTime;
      });

      // Keep only the 10 most recent reports
      const keysToDelete = sortedKeys.slice(10);

      if (keysToDelete.length > 0) {
        chrome.storage.local.remove(keysToDelete, () => {
          if (chrome.runtime.lastError) {
            console.error(' Failed to cleanup old reports:', chrome.runtime.lastError);
          } else {
            console.log(`CLEANUP Cleaned up ${keysToDelete.length} old security reports`);
          }
        });
      }
    });
  }

  /**
   * Clear security data for a specific tab
   * @param {number} tabId - Tab ID to clear data for
   */
  clearTabSecurityData(tabId) {
    // Remove from in-memory storage
    this.tabSecurityStatus.delete(tabId);

    // Remove from persistent storage
    const storageKey = `security_report_${tabId}`;
    chrome.storage.local.remove([storageKey], () => {
      if (chrome.runtime.lastError) {
        console.error(` Failed to clear tab data for ${tabId}:`, chrome.runtime.lastError);
      } else {
        console.log(` Cleared security data for tab ${tabId}`);
      }
    });
  }

  /**
   * Get security statistics across all tabs
   * @returns {Object} Security statistics
   */
  getSecurityStatistics() {
    const stats = {
      totalScannedTabs: this.tabSecurityStatus.size,
      safeTabs: 0,
      warningTabs: 0,
      dangerousTabs: 0,
      averageScore: 0
    };

    let totalScore = 0;

    this.tabSecurityStatus.forEach((securityData) => {
      const score = securityData.overallScore;
      const status = securityData.overallStatus;

      totalScore += score;

      if (status === 'safe') {
        stats.safeTabs++;
      } else if (status === 'warning') {
        stats.warningTabs++;
      } else {
        stats.dangerousTabs++;
      }
    });

    if (stats.totalScannedTabs > 0) {
      stats.averageScore = Math.round(totalScore / stats.totalScannedTabs);
    }

    return stats;
  }
}

// Initialize background service when service worker starts
const securityBackgroundService = new SecurityBackgroundService();

// Handle installation and updates
chrome.runtime.onInstalled.addListener((details) => {
  console.log(' Security Scanner Extension installed/updated:', details.reason);
  
  if (details.reason === 'install') {
    // First time installation
    console.log(' Welcome to Website Security Scanner!');
    
    // Set default badge
    securityBackgroundService.updateBadge('', '#666666', 'Website Security Scanner - Click to analyze current site');
    
    // Clear any existing storage
    chrome.storage.local.clear(() => {
      console.log('CLEANUP Cleared existing storage on fresh install');
    });
  } else if (details.reason === 'update') {
    // Extension updated
    console.log('Extension updated to version:', chrome.runtime.getManifest().version);
    
    // Clean up old data format if needed
    securityBackgroundService.cleanupOldReports();
  }
});

// Handle startup
chrome.runtime.onStartup.addListener(() => {
  console.log(' Browser started, Security Scanner service worker active');
  
  // Reset badge on browser startup
  securityBackgroundService.updateBadge('', '#666666', 'Website Security Scanner');
});

// Export for testing purposes
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityBackgroundService;
} 