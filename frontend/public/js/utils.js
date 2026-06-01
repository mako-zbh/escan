// ============ Shared Utilities ============

const Utils = {
  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  },

  truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.slice(0, len) + '…' : String(str);
  },

  debounce(fn, ms) {
    let t;
    const debounced = (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
    debounced.cancel = () => clearTimeout(t);
    return debounced;
  },

  showToast(message, type = 'info', duration = 3500) {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span><span>${Utils.escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'toastOut 0.25s ease forwards';
      setTimeout(() => toast.remove(), 250);
    }, duration);
  },

  confirm(message) {
    return window.confirm(message);
  }
};
