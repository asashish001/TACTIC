import { api } from './api.js?v=2';
import { showToast } from './ui.js';
import { updateUserUI } from './auth.js?v=1';

export function setupSettings() {
  const btnSaveSettings = document.getElementById('btn-save-settings');
  const inputThreshold = document.getElementById('setting-anomaly-threshold');
  const inputTimezone = document.getElementById('setting-timezone');
  const inputTimeWindow = document.getElementById('setting-time-window');
  const inputCrossCase = document.getElementById('setting-cross-case');

  window.loadSettings = async function () {
    updateUserUI();
    if (!inputThreshold) return;
    try {
      const data = await api('GET', '/api/settings');
      if (data) {
        inputThreshold.value = data.anomaly_threshold;
        inputTimezone.value = data.default_timezone;
        inputTimeWindow.value = data.correlation_time_window_seconds;
        if (inputCrossCase) inputCrossCase.checked = data.cross_case_correlation;
      }
    } catch (err) {
      console.error("Failed to load settings", err);
    }
  };

  if (btnSaveSettings) {
    btnSaveSettings.addEventListener('click', async () => {
      try {
        const payload = {
          anomaly_threshold: parseFloat(inputThreshold.value),
          default_timezone: inputTimezone.value || "UTC",
          correlation_time_window_seconds: parseInt(inputTimeWindow.value, 10),
          cross_case_correlation: inputCrossCase ? inputCrossCase.checked : true
        };
        await api('PUT', '/api/settings', payload);
        showToast("Settings saved successfully.", 'success');
      } catch (err) {
        showToast("Failed to save settings: " + err.message, 'error');
      }
    });
  }
}
