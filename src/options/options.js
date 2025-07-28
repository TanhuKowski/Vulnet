/** Vulnet security extension options */

// Default settings
const DEFAULT_SETTINGS = {
  realTimeScanning: true,
  autoBlockThreats: true,
  notificationAlerts: true,
  threatSensitivity: 'medium',
  privacyProtection: 3,
  mlAnalysis: true,
  mlUpdates: true,
  cacheResults: true,
  anonymousStats: false
};

// Load settings on page load
document.addEventListener('DOMContentLoaded', loadSettings);

/** Load settings from storage */
async function loadSettings() {
  try {
    const result = await chrome.storage.sync.get(['vulnetSettings']);
    const settings = result.vulnetSettings || DEFAULT_SETTINGS;
    
    // Apply settings to UI
    document.getElementById('real-time-scanning').checked = settings.realTimeScanning;
    document.getElementById('auto-block-threats').checked = settings.autoBlockThreats;
    document.getElementById('notification-alerts').checked = settings.notificationAlerts;
    document.getElementById('threat-sensitivity').value = settings.threatSensitivity;
    document.getElementById('privacy-protection').value = settings.privacyProtection;
    document.getElementById('ml-analysis').checked = settings.mlAnalysis;
    document.getElementById('ml-updates').checked = settings.mlUpdates;
    document.getElementById('cache-results').checked = settings.cacheResults;
    document.getElementById('anonymous-stats').checked = settings.anonymousStats;
    
    updatePrivacyLevelText(settings.privacyProtection);
    
    console.log('Settings loaded successfully');
  } catch (error) {
    console.error('Failed to load settings:', error);
    showStatus('Failed to load settings', 'error');
  }
}

/**
 * Save settings to storage
 */
async function saveSettings() {
  try {
    const settings = {
      realTimeScanning: document.getElementById('real-time-scanning').checked,
      autoBlockThreats: document.getElementById('auto-block-threats').checked,
      notificationAlerts: document.getElementById('notification-alerts').checked,
      threatSensitivity: document.getElementById('threat-sensitivity').value,
      privacyProtection: parseInt(document.getElementById('privacy-protection').value),
      mlAnalysis: document.getElementById('ml-analysis').checked,
      mlUpdates: document.getElementById('ml-updates').checked,
      cacheResults: document.getElementById('cache-results').checked,
      anonymousStats: document.getElementById('anonymous-stats').checked
    };
    
    await chrome.storage.sync.set({ vulnetSettings: settings });
    
    // Notify background script of settings change
    chrome.runtime.sendMessage({
      action: 'settingsUpdated',
      settings: settings
    });
    
    showStatus('Settings saved successfully!', 'success');
    console.log('Settings saved:', settings);
    
  } catch (error) {
    console.error('Failed to save settings:', error);
    showStatus('Failed to save settings', 'error');
  }
}

/**
 * Update privacy level text
 */
function updatePrivacyLevelText(level) {
  const text = ['Minimal', 'Low', 'Medium', 'High', 'Maximum'][level - 1];
  document.getElementById('privacy-level-text').textContent = text;
}

/**
 * Show status message
 */
function showStatus(message, type) {
  const statusElement = document.getElementById('status');
  statusElement.textContent = message;
  statusElement.className = `status ${type}`;
  statusElement.style.display = 'block';
  
  setTimeout(() => {
    statusElement.style.display = 'none';
  }, 3000);
}

/**
 * Reset to defaults
 */
function resetToDefaults() {
  if (confirm('Are you sure you want to reset all settings to defaults?')) {
    // Apply defaults to UI
    Object.entries(DEFAULT_SETTINGS).forEach(([key, value]) => {
      const elementId = key.replace(/([A-Z])/g, '-$1').toLowerCase();
      const element = document.getElementById(elementId);
      
      if (element) {
        if (element.type === 'checkbox') {
          element.checked = value;
        } else {
          element.value = value;
        }
      }
    });
    
    updatePrivacyLevelText(DEFAULT_SETTINGS.privacyProtection);
    saveSettings();
  }
}

/**
 * Export settings
 */
async function exportSettings() {
  try {
    const result = await chrome.storage.sync.get(['vulnetSettings']);
    const settings = result.vulnetSettings || DEFAULT_SETTINGS;
    
    const dataStr = JSON.stringify(settings, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'vulnet-settings.json';
    link.click();
    
    URL.revokeObjectURL(url);
    showStatus('Settings exported successfully!', 'success');
    
  } catch (error) {
    console.error('Failed to export settings:', error);
    showStatus('Failed to export settings', 'error');
  }
}

/**
 * Import settings
 */
function importSettings() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  
  input.onchange = (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const settings = JSON.parse(e.target.result);
        
        // Validate settings structure
        const validKeys = Object.keys(DEFAULT_SETTINGS);
        const importedKeys = Object.keys(settings);
        
        if (!importedKeys.every(key => validKeys.includes(key))) {
          throw new Error('Invalid settings file format');
        }
        
        // Merge with defaults
        const mergedSettings = { ...DEFAULT_SETTINGS, ...settings };
        
        // Save and apply
        await chrome.storage.sync.set({ vulnetSettings: mergedSettings });
        await loadSettings();
        
        showStatus('Settings imported successfully!', 'success');
        
      } catch (error) {
        console.error('Failed to import settings:', error);
        showStatus('Failed to import settings: Invalid file', 'error');
      }
    };
    
    reader.readAsText(file);
  };
  
  input.click();
}

// Event listeners
document.getElementById('privacy-protection').addEventListener('input', (e) => {
  updatePrivacyLevelText(parseInt(e.target.value));
});

// Add keyboard shortcuts
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey || e.metaKey) {
    switch (e.key) {
      case 's':
        e.preventDefault();
        saveSettings();
        break;
      case 'r':
        e.preventDefault();
        resetToDefaults();
        break;
    }
  }
});

// Auto-save on change (debounced)
let saveTimeout;
function debouncedSave() {
  clearTimeout(saveTimeout);
  saveTimeout = setTimeout(saveSettings, 1000);
}

// Add change listeners to all inputs
document.querySelectorAll('input, select').forEach(element => {
  element.addEventListener('change', debouncedSave);
});

// Make functions globally available
window.saveSettings = saveSettings;
window.resetToDefaults = resetToDefaults;
window.exportSettings = exportSettings;
window.importSettings = importSettings;
