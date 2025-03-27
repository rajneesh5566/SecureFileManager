/**
 * Main JavaScript for Secure File Management System
 */

// Wait for DOM content to be fully loaded before attaching event handlers
document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Auto-dismiss alerts after 5 seconds
    const autoAlerts = document.querySelectorAll('.alert-dismissible:not(.alert-danger)');
    autoAlerts.forEach(function(alert) {
        setTimeout(function() {
            const closeButton = alert.querySelector('.btn-close');
            if (closeButton) {
                closeButton.click();
            }
        }, 5000);
    });
    
    // Enhanced file input display
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(function(input) {
        input.addEventListener('change', function(e) {
            if (this.files && this.files.length > 0) {
                const fileName = this.files[0].name;
                const fileSize = this.files[0].size;
                
                // Find the nearest form-text element to display file info
                const formText = this.closest('.mb-3').querySelector('.form-text');
                if (formText) {
                    const fileSizeFormatted = formatFileSize(fileSize);
                    formText.innerHTML = `Selected: <strong>${fileName}</strong> (${fileSizeFormatted})`;
                }
            }
        });
    });
    
    // Password strength meter
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        const strengthIndicator = document.createElement('div');
        strengthIndicator.className = 'progress mt-2';
        strengthIndicator.innerHTML = '<div class="progress-bar" role="progressbar" style="width: 0%"></div>';
        
        passwordInput.parentNode.insertBefore(strengthIndicator, passwordInput.nextSibling);
        
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            const strength = calculatePasswordStrength(password);
            const progressBar = strengthIndicator.querySelector('.progress-bar');
            
            // Update progress bar
            progressBar.style.width = `${strength}%`;
            
            // Update color based on strength
            if (strength < 25) {
                progressBar.className = 'progress-bar bg-danger';
            } else if (strength < 50) {
                progressBar.className = 'progress-bar bg-warning';
            } else if (strength < 75) {
                progressBar.className = 'progress-bar bg-info';
            } else {
                progressBar.className = 'progress-bar bg-success';
            }
        });
    }
    
    // Copy to clipboard functionality
    const copyButtons = document.querySelectorAll('[data-copy]');
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy)
                    .then(() => {
                        // Show success indicator
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="bi bi-check"></i>';
                        
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                        }, 2000);
                    })
                    .catch(err => {
                        console.error('Failed to copy text: ', err);
                    });
            }
        });
    });
    
    // Format OTP input
    const otpInput = document.getElementById('otp_code');
    if (otpInput) {
        otpInput.addEventListener('input', function() {
            // Remove non-digit characters
            this.value = this.value.replace(/\D/g, '');
            
            // Limit to 6 digits
            if (this.value.length > 6) {
                this.value = this.value.slice(0, 6);
            }
            
            // Auto-submit when 6 digits are entered
            if (this.value.length === 6 && this.form) {
                setTimeout(() => {
                    this.form.submit();
                }, 300);
            }
        });
    }
});

/**
 * Calculate password strength on a scale of 0-100
 * 
 * @param {string} password - The password to evaluate
 * @return {number} - Strength score (0-100)
 */
function calculatePasswordStrength(password) {
    if (!password) return 0;
    
    let strength = 0;
    
    // Length contribution (up to 30 points)
    strength += Math.min(30, password.length * 3);
    
    // Character variety contribution
    if (/[A-Z]/.test(password)) strength += 15; // Uppercase
    if (/[a-z]/.test(password)) strength += 15; // Lowercase
    if (/[0-9]/.test(password)) strength += 15; // Numbers
    if (/[^A-Za-z0-9]/.test(password)) strength += 15; // Special characters
    
    // Penalize repeating characters
    const repeats = password.match(/(.)\1+/g);
    if (repeats) {
        strength -= repeats.length * 5;
    }
    
    // Ensure strength is between 0-100
    return Math.max(0, Math.min(100, strength));
}

/**
 * Format file size in human-readable format
 * 
 * @param {number} bytes - File size in bytes
 * @return {string} - Formatted size with units
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Show a confirmation dialog before form submission
 * 
 * @param {string} message - Confirmation message to display
 * @return {boolean} - True if confirmed, false otherwise
 */
function confirmAction(message) {
    return confirm(message || 'Are you sure you want to perform this action?');
}

/**
 * Handle file deletion confirmation
 * 
 * @param {Event} event - The click event
 * @param {string} filename - Name of the file to delete
 */
function confirmDelete(event, filename) {
    if (!confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) {
        event.preventDefault();
    }
}

/**
 * Handle shared access revocation confirmation
 * 
 * @param {Event} event - The click event
 * @param {string} username - Name of the user whose access will be revoked
 */
function confirmUnshare(event, username) {
    if (!confirm(`Are you sure you want to revoke access for ${username}?`)) {
        event.preventDefault();
    }
}

/**
 * Utility function for sanitizing input to prevent XSS
 * 
 * @param {string} text - Text to sanitize
 * @return {string} - Sanitized text
 */
function sanitizeHtml(text) {
    const element = document.createElement('div');
    element.textContent = text;
    return element.innerHTML;
}
