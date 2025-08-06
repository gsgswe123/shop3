// devtools-protection.js - Enhanced DevTools Protection System
"use strict";

/**
 * Enhanced DevTools Protection System
 * Provides comprehensive protection against unauthorized DevTools usage
 * Only allows admin users to use DevTools
 */
class DevToolsProtection {
    constructor() {
        this.isDevToolsOpen = false;
        this.checkInterval = null;
        this.protectedPages = ['account.html', 'index.html', 'product.html', 'cart.html', 'favorite.html'];
        this.warningCount = 0;
        this.maxWarnings = 3;
        this.isBlocked = false;
        this.threshold = 160;
        this.isInitialized = false;
        
        console.log('🛡️ DevTools Protection System initialized');
        this.init();
    }

    /**
     * Initialize the protection system
     */
    init() {
        if (this.isInitialized) return;
        
        console.log('🔄 Starting DevTools Protection...');
        
        // Check if protection should be enabled for this page
        if (this.shouldProtect()) {
            console.log('✅ Protection activated for current page');
            this.startProtection();
            this.addAntiDebugMethods();
            this.blockCommonShortcuts();
            this.addVisibilityChangeHandler();
            this.isInitialized = true;
        } else {
            console.log('ℹ️ No protection needed for this page');
        }
    }

    /**
     * Check if current page needs protection
     */
    shouldProtect() {
        const currentPage = window.location.pathname.split('/').pop() || 'index.html';
        const needsProtection = this.protectedPages.some(page => 
            currentPage.includes(page.replace('.html', ''))
        ) || currentPage === '' || currentPage === 'index.html';
        
        console.log(`📄 Current page: ${currentPage} | Protection needed: ${needsProtection}`);
        return needsProtection;
    }

    /**
     * Check if current user is admin
     */
    isAdmin() {
        try {
            // Check from main.js global variables first
            if (window.currentUser && window.currentUser.role === 'admin') {
                return true;
            }
            
            // Fallback to localStorage
            const user = JSON.parse(localStorage.getItem('gag_user') || '{}');
            return user && user.role === 'admin';
        } catch (error) {
            console.error('❌ Error checking admin status:', error);
            return false;
        }
    }

    /**
     * Start the protection monitoring
     */
    startProtection() {
        // Continuous DevTools detection
        this.checkInterval = setInterval(() => {
            this.detectDevTools();
        }, 500);

        console.log('✅ DevTools detection started');
    }

    /**
     * Detect if DevTools is open
     */
    detectDevTools() {
        if (this.isAdmin()) {
            // Admin is allowed - no restrictions
            return;
        }

        // Method 1: Window size difference
        const widthDiff = window.outerWidth - window.innerWidth;
        const heightDiff = window.outerHeight - window.innerHeight;
        
        if (widthDiff > this.threshold || heightDiff > this.threshold) {
            if (!this.isDevToolsOpen) {
                this.isDevToolsOpen = true;
                this.handleDevToolsDetected();
            }
        } else {
            this.isDevToolsOpen = false;
        }

        // Method 2: Console timing detection
        this.checkConsoleDebugging();
    }

    /**
     * Check for console debugging
     */
    checkConsoleDebugging() {
        if (this.isAdmin()) return;

        const start = performance.now();
        console.log(''); // Dummy log
        const end = performance.now();
        
        // If console.log is slower than normal -> DevTools is open
        if (end - start > 1) {
            this.handleDevToolsDetected();
        }
    }

    /**
     * Handle DevTools detection
     */
    handleDevToolsDetected() {
        if (this.isAdmin()) {
            console.log('👑 Admin detected - DevTools allowed');
            return;
        }

        this.warningCount++;
        
        // Clear console and show warning
        console.clear();
        console.log('%c🚫 CẢNH BÁO BẢO MẬT', 'color: red; font-size: 20px; font-weight: bold;');
        console.log('%cViệc mở Developer Tools không được phép!', 'color: red; font-size: 14px;');
        console.log(`%cCảnh báo ${this.warningCount}/${this.maxWarnings}`, 'color: orange; font-size: 12px;');

        // Show warning modal
        this.showWarningModal();

        if (this.warningCount >= this.maxWarnings) {
            this.blockAccess();
        }
    }

    /**
     * Show warning modal
     */
    showWarningModal() {
        if (this.isAdmin()) return;

        // Remove existing modal
        const existingModal = document.getElementById('devtools-warning-modal');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.id = 'devtools-warning-modal';
        modal.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.9);
                z-index: 99999;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                animation: fadeIn 0.3s ease;
            ">
                <div style="
                    background: white;
                    padding: 30px;
                    border-radius: 16px;
                    text-align: center;
                    max-width: 400px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                    animation: slideIn 0.3s ease;
                ">
                    <div style="color: #e74c3c; font-size: 48px; margin-bottom: 20px;">⚠️</div>
                    <h2 style="color: #e74c3c; margin-bottom: 15px; font-size: 24px;">CẢNH BÁO BẢO MẬT</h2>
                    <p style="color: #333; margin-bottom: 20px; line-height: 1.6; font-size: 16px;">
                        Việc mở Developer Tools không được phép trên trang này.<br>
                        <strong>Cảnh báo: ${this.warningCount}/${this.maxWarnings}</strong>
                    </p>
                    <button id="close-warning" style="
                        background: #e74c3c;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 8px;
                        cursor: pointer;
                        font-size: 16px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    " onmouseover="this.style.background='#c0392b'" onmouseout="this.style.background='#e74c3c'">Đã hiểu</button>
                </div>
            </div>
            <style>
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                @keyframes slideIn { from { transform: scale(0.8); opacity: 0; } to { transform: scale(1); opacity: 1; } }
            </style>
        `;

        document.body.appendChild(modal);

        // Auto close after 3 seconds
        setTimeout(() => {
            if (modal && modal.parentNode) modal.remove();
        }, 3000);

        // Close button handler
        const closeBtn = modal.querySelector('#close-warning');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                if (modal && modal.parentNode) modal.remove();
            });
        }
    }

    /**
     * Block access completely
     */
    blockAccess() {
        if (this.isAdmin()) return;

        this.isBlocked = true;
        
        console.log('🚫 Blocking access due to repeated violations');
        
        // Clear intervals
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }

        // Block entire page
        document.body.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                z-index: 999999;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                color: white;
                text-align: center;
            ">
                <div>
                    <div style="font-size: 72px; margin-bottom: 30px;">🚫</div>
                    <h1 style="font-size: 2.5rem; margin-bottom: 20px; font-weight: 700;">TRUY CẬP BỊ CHẶN</h1>
                    <p style="font-size: 1.2rem; margin-bottom: 30px; opacity: 0.9; line-height: 1.6;">
                        Bạn đã vi phạm chính sách bảo mật của website<br>
                        và bị chặn truy cập tạm thời
                    </p>
                    <p style="opacity: 0.7; font-size: 1rem;">Đang chuyển hướng về trang chủ...</p>
                </div>
            </div>
        `;

        // Redirect to home page after 2 seconds
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 2000);
    }

    /**
     * Block common shortcuts
     */
    blockCommonShortcuts() {
        console.log('⌨️ Blocking common shortcuts...');
        
        // Prevent keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyDown(e), { passive: false, capture: true });
        
        // Prevent right-click
        document.addEventListener('contextmenu', (e) => this.handleContextMenu(e), { passive: false, capture: true });
        
        // Prevent text selection
        document.addEventListener('selectstart', (e) => this.handleSelectStart(e), { passive: false, capture: true });
        
        console.log('✅ Shortcut blocking activated');
    }

    /**
     * Handle keyboard shortcuts
     */
    handleKeyDown(e) {
        if (this.isAdmin()) return;

        let blocked = false;
        let message = '';

        // Common DevTools shortcuts
        const shortcuts = {
            123: 'F12 không được phép!', // F12
            73: 'Ctrl+Shift+I không được phép!', // Ctrl+Shift+I
            85: 'Ctrl+U không được phép!', // Ctrl+U (View Source)
            83: 'Ctrl+S không được phép!', // Ctrl+S (Save)
            65: 'Ctrl+A không được phép!', // Ctrl+A (Select All)
            80: 'Ctrl+P không được phép!', // Ctrl+P (Print)
            67: 'Ctrl+Shift+C không được phép!' // Ctrl+Shift+C (Inspect Element)
        };

        if (e.ctrlKey && e.shiftKey && shortcuts[e.keyCode]) {
            blocked = true;
            message = shortcuts[e.keyCode];
        } else if (e.ctrlKey && shortcuts[e.keyCode]) {
            blocked = true;
            message = shortcuts[e.keyCode];
        } else if (shortcuts[e.keyCode]) {
            blocked = true;
            message = shortcuts[e.keyCode];
        }

        if (blocked) {
            e.preventDefault();
            e.stopPropagation();
            this.showQuickWarning(message);
            return false;
        }
    }

    /**
     * Handle right-click
     */
    handleContextMenu(e) {
        if (this.isAdmin()) return;

        e.preventDefault();
        e.stopPropagation();
        this.showQuickWarning('Chuột phải không được phép!');
        return false;
    }

    /**
     * Handle text selection
     */
    handleSelectStart(e) {
        if (this.isAdmin()) return;

        // Allow selection in input and textarea
        if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) {
            return;
        }

        e.preventDefault();
        e.stopPropagation();
        return false;
    }

    /**
     * Show quick warning message
     */
    showQuickWarning(message) {
        // Remove existing warning
        const existingWarning = document.getElementById('quick-warning');
        if (existingWarning) existingWarning.remove();

        // Create warning element
        const warning = document.createElement('div');
        warning.id = 'quick-warning';
        warning.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #e74c3c;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            z-index: 99999;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            animation: slideInWarning 0.3s ease;
            pointer-events: none;
            font-weight: 600;
            font-size: 14px;
        `;
        warning.textContent = message;

        // Add animation CSS if not exists
        if (!document.getElementById('warning-animation-style')) {
            const style = document.createElement('style');
            style.id = 'warning-animation-style';
            style.textContent = `
                @keyframes slideInWarning {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `;
            document.head.appendChild(style);
        }

        document.body.appendChild(warning);

        // Auto remove after 2 seconds
        setTimeout(() => {
            if (warning && warning.parentNode) {
                warning.remove();
            }
        }, 2000);
    }

    /**
     * Add anti-debug methods
     */
    addAntiDebugMethods() {
        if (this.isAdmin()) return;

        console.log('🔒 Adding anti-debug methods...');

        // Console clearing
        setInterval(() => {
            if (this.isAdmin()) return;
            
            console.clear();
            console.log('%cSTOP!', 'color: red; font-size: 50px; font-weight: bold;');
            console.log('%cĐây là tính năng dành cho Developer. Nếu bạn không phải admin, việc sử dụng có thể vi phạm bảo mật.', 'color: red; font-size: 16px;');
        }, 2000);

        // Debugger statement (limited to avoid performance issues)
        let debugCounter = 0;
        const debugInterval = setInterval(() => {
            if (this.isAdmin()) {
                clearInterval(debugInterval);
                return;
            }
            
            if (debugCounter < 10) {
                debugger;
                debugCounter++;
            } else {
                clearInterval(debugInterval);
            }
        }, 1000);
    }

    /**
     * Add visibility change handler
     */
    addVisibilityChangeHandler() {
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.isBlocked) {
                console.log('🚫 User returned to blocked tab - redirecting...');
                window.location.href = 'index.html';
            }
        });
    }

    /**
     * Destroy protection (admin only)
     */
    destroy() {
        if (!this.isAdmin()) {
            console.log('❌ Only admin can destroy protection');
            return false;
        }

        console.log('🗑️ Destroying DevTools protection...');
        
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
        
        // Remove event listeners
        document.removeEventListener('keydown', this.handleKeyDown);
        document.removeEventListener('contextmenu', this.handleContextMenu);
        document.removeEventListener('selectstart', this.handleSelectStart);
        
        this.isInitialized = false;
        
        console.log('✅ DevTools protection destroyed');
        return true;
    }
}

// =================================================================
// ADMIN MANAGEMENT CLASS
// =================================================================

class AdminDevToolsManager {
    /**
     * Enable DevTools for admin
     */
    static enableDevTools() {
        const user = window.currentUser || JSON.parse(localStorage.getItem('gag_user') || '{}');
        
        if (!user || user.role !== 'admin') {
            console.log('❌ Chỉ admin mới có thể kích hoạt DevTools');
            return false;
        }

        // Destroy protection
        if (window.devToolsProtection) {
            const destroyed = window.devToolsProtection.destroy();
            if (destroyed) {
                window.devToolsProtection = null;
                console.log('✅ DevTools đã được kích hoạt cho admin');
                console.log('🔧 Admin có thể sử dụng tất cả tính năng debug');
                return true;
            }
        }

        console.log('ℹ️ DevTools protection không hoạt động hoặc đã được tắt');
        return false;
    }

    /**
     * Disable DevTools protection (reinitialize)
     */
    static disableDevTools() {
        const user = window.currentUser || JSON.parse(localStorage.getItem('gag_user') || '{}');
        
        if (!user || user.role !== 'admin') {
            console.log('❌ Chỉ admin mới có thể tắt DevTools protection');
            return false;
        }

        // Reinitialize protection
        if (!window.devToolsProtection) {
            window.devToolsProtection = new DevToolsProtection();
            console.log('🛡️ DevTools protection đã được kích hoạt lại');
            return true;
        }

        console.log('ℹ️ DevTools protection đã đang hoạt động');
        return false;
    }

    /**
     * Get protection status
     */
    static getStatus() {
        const user = window.currentUser || JSON.parse(localStorage.getItem('gag_user') || '{}');
        const isAdmin = user && user.role === 'admin';
        const protectionActive = !!window.devToolsProtection;
        
        console.log('=== DEVTOOLS PROTECTION STATUS ===');
        console.log('User:', user?.name || 'Anonymous');
        console.log('Role:', user?.role || 'none');
        console.log('Is Admin:', isAdmin);
        console.log('Protection Active:', protectionActive);
        console.log('Can Use DevTools:', isAdmin);
        console.log('===============================');
        
        return {
            user,
            isAdmin,
            protectionActive,
            canUseDevTools: isAdmin
        };
    }
}

// =================================================================
// CONSOLE STYLING & MESSAGES
// =================================================================

function addConsoleStyles() {
    const user = window.currentUser || JSON.parse(localStorage.getItem('gag_user') || '{}');
    
    if (user && user.role === 'admin') {
        console.log('%c👑 ADMIN PANEL', 'background: linear-gradient(45deg, #667eea, #764ba2); color: white; padding: 10px 20px; border-radius: 10px; font-size: 16px; font-weight: bold;');
        console.log('%cChào mừng Admin! Bạn có thể sử dụng DevTools.', 'color: #4CAF50; font-size: 14px;');
        console.log('%cSử dụng AdminDevToolsManager.enableDevTools() để tắt protection hoàn toàn.', 'color: #2196F3; font-size: 12px;');
        console.log('%cSử dụng AdminDevToolsManager.getStatus() để xem trạng thái.', 'color: #2196F3; font-size: 12px;');
    } else {
        console.log('%c⚠️ CẢNH BÁO', 'background: #e74c3c; color: white; padding: 10px; border-radius: 5px; font-weight: bold;');
        console.log('%cTrang này được bảo vệ khỏi việc sử dụng DevTools trái phép.', 'color: #e74c3c; font-size: 14px;');
    }
}

// =================================================================
// INITIALIZATION FUNCTION
// =================================================================

function initDevToolsProtection() {
    console.log('🔄 Initializing DevTools Protection System...');
    
    const checkUser = () => {
        // Wait for main.js to load (may take 1-2 seconds)
        if (window.Utils && (window.currentUser !== undefined || Date.now() - startTime > 3000)) {
            console.log('🔍 User data available, proceeding with protection init...');
            console.log('👤 Current user role:', window.currentUser?.role || 'none');
            
            try {
                // Initialize protection system
                window.devToolsProtection = new DevToolsProtection();
                window.AdminDevToolsManager = AdminDevToolsManager;
                
                // Style console
                addConsoleStyles();
                
                console.log('✅ DevTools Protection initialized successfully');
            } catch (error) {
                console.error('❌ Failed to initialize DevTools Protection:', error);
            }
        } else {
            // Wait 200ms and try again
            setTimeout(checkUser, 200);
        }
    };

    const startTime = Date.now();
    checkUser();
}

// =================================================================
// AUTO INITIALIZATION
// =================================================================

// Initialize when DOM loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDevToolsProtection);
} else {
    // DOM already loaded
    setTimeout(initDevToolsProtection, 100);
}

// Also init when page becomes visible
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !window.devToolsProtection) {
        console.log('👁️ Page visible and no protection - reinitializing...');
        setTimeout(initDevToolsProtection, 500);
    }
});

// Export to window for debugging
window.initDevToolsProtection = initDevToolsProtection;

console.log('🛡️ DevTools Protection Script Loaded Successfully');
