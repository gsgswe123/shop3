// main.js - ENHANCED Authentication & Protection System
"use strict";

// =================================================================
// CONFIGURATION & GLOBAL VARIABLES
// =================================================================

const CONFIG = {
    API_BASE_URL: 'https://shop-4mlk.onrender.com/api/v1',
    STORAGE_KEYS: {
        TOKEN: 'gag_token',
        USER: 'gag_user',
        PRODUCTS: 'gag_products',
        BALANCE: 'gag_balance'
    },
    TOAST_DURATION: 3000,
    ANIMATION_DELAY: 0.08,
    MAX_IMAGE_SIZE: 5 * 1024 * 1024, // 5MB
    ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'],
    PRODUCT_VALIDATION: {
        TITLE_MIN: 5,
        TITLE_MAX: 100,
        DESC_MIN: 10,
        DESC_MAX: 500,
        PRICE_MIN: 1000,
        PRICE_MAX: 50000000
    },
    DEVTOOLS_PROTECTION: {
        ENABLED: true,
        WARNING_LIMIT: 3,
        DETECTION_INTERVAL: 500
    }
};

// Global state management
let currentUser = null;
let userBalance = 0;
let allProducts = [];
let isInitialized = false;
let devToolsProtection = null;

// =================================================================
// UTILITY CLASS
// =================================================================

class Utils {
    static formatPrice(price) {
        const num = typeof price === 'string' ? parseInt(price, 10) : price;
        if (isNaN(num)) return '0đ';
        return new Intl.NumberFormat('vi-VN').format(num) + 'đ';
    }

    static formatDate(date) {
        try {
            return new Date(date).toLocaleDateString('vi-VN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch {
            return 'N/A';
        }
    }

    static formatDateTime(date) {
        try {
            return new Date(date).toLocaleString('vi-VN');
        } catch {
            return 'N/A';
        }
    }

    static generateId() {
        return 'local_' + Date.now() + '_' + Math.random().toString(36).substr(2, 12);
    }

    static generateUserId(userData) {
        if (userData && userData._id) return userData._id.slice(-6);
        if (userData && userData.id) return userData.id.toString().slice(-6);
        if (userData && userData.email) {
            let hash = 0;
            for (let i = 0; i < userData.email.length; i++) {
                const char = userData.email.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
            }
            return Math.abs(hash).toString().slice(-6).padStart(6, '0');
        }
        return '000001';
    }

    static validateURL(url) {
        try {
            const parsed = new URL(url);
            return ['http:', 'https:'].includes(parsed.protocol);
        } catch {
            return false;
        }
    }

    static validateCard(number, serial) {
        const cardRegex = /^[0-9]{10,15}$/;
        const serialRegex = /^[0-9]{5,12}$/;
        return cardRegex.test(number) && serialRegex.test(serial);
    }

    static validatePassword(password) {
        return password && password.length >= 6;
    }

    static showToast(message, type = 'success', duration = CONFIG.TOAST_DURATION) {
        const container = this.getToastContainer();
        const toast = this.createToastElement(message, type);
        
        container.appendChild(toast);
        this.animateToast(toast, duration);
    }

    static getToastContainer() {
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            Object.assign(container.style, {
                position: 'fixed',
                top: '20px',
                right: '20px',
                zIndex: '10003',
                pointerEvents: 'none'
            });
            document.body.appendChild(container);
        }
        return container;
    }

    static createToastElement(message, type) {
        const toast = document.createElement('div');
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        
        const colors = {
            success: '#2a9d8f',
            error: '#dc3545',
            warning: '#f4a261',
            info: '#3b82f6'
        };

        toast.className = `toast toast-${type}`;
        toast.style.cssText = `
            background: ${colors[type]};
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            transform: translateX(120%);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 10px;
            max-width: 400px;
            backdrop-filter: blur(10px);
        `;

        toast.innerHTML = `
            <i class="fas ${icons[type]}" style="font-size: 16px;"></i>
            <span style="flex: 1;">${message}</span>
            <button onclick="this.parentElement.remove()" style="
                background: none; 
                border: none; 
                color: inherit; 
                cursor: pointer; 
                font-size: 18px; 
                padding: 0; 
                width: 20px; 
                height: 20px; 
                display: flex; 
                align-items: center; 
                justify-content: center;
                opacity: 0.7;
                transition: opacity 0.2s;
            " onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.7'">&times;</button>
        `;

        return toast;
    }

    static animateToast(toast, duration) {
        // Show toast
        setTimeout(() => {
            toast.style.transform = 'translateX(0)';
            toast.style.opacity = '1';
        }, 100);

        // Hide toast
        setTimeout(() => {
            toast.style.transform = 'translateX(120%)';
            toast.style.opacity = '0';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, 300);
        }, duration);
    }

    static showLoading(element, message = 'Đang tải...') {
        if (!element) return;
        
        const originalContent = element.innerHTML;
        element.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px; justify-content: center;">
                <div class="spinner" style="
                    width: 20px; 
                    height: 20px; 
                    border: 2px solid rgba(255,255,255,0.3); 
                    border-radius: 50%; 
                    border-top-color: white; 
                    animation: spin 1s linear infinite;
                "></div>
                <span>${message}</span>
            </div>
        `;
        element.disabled = true;
        
        return () => {
            element.innerHTML = originalContent;
            element.disabled = false;
        };
    }

    static showError(element, message = 'Có lỗi xảy ra.') {
        if (!element) return;
        
        const formGroup = element.closest('.form-group');
        if (formGroup) {
            formGroup.classList.add('has-error');
            const errorElement = formGroup.querySelector('.error-message');
            if (errorElement) {
                errorElement.textContent = message;
                errorElement.style.display = 'block';
            }
        }
    }

    static clearError(element) {
        if (!element) return;
        
        const formGroup = element.closest('.form-group');
        if (formGroup) {
            formGroup.classList.remove('has-error');
            const errorElement = formGroup.querySelector('.error-message');
            if (errorElement) {
                errorElement.style.display = 'none';
            }
        }
    }

    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    static togglePassword(inputId) {
        const input = document.getElementById(inputId);
        const icon = document.querySelector(`[onclick*="${inputId}"] i`);
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }
} 

// =================================================================
// API MANAGER
// =================================================================

class ApiManager {
    static getToken() {
        return localStorage.getItem(CONFIG.STORAGE_KEYS.TOKEN);
    }

    static async call(endpoint, method = 'GET', body = null, requireAuth = true) {
        const headers = {
            'Content-Type': 'application/json',
        };
        
        if (requireAuth) {
            const token = this.getToken();
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
        }
        
        const options = {
            method,
            headers,
            credentials: 'include'
        };
        
        if (body) {
            options.body = JSON.stringify(body);
        }
        
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}${endpoint}`, options);
            
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Phiên đăng nhập đã hết hạn');
                } else if (response.status === 403) {
                    throw new Error('Không có quyền truy cập');
                } else if (response.status === 404) {
                    throw new Error('Không tìm thấy dữ liệu');
                } else if (response.status >= 500) {
                    throw new Error('Lỗi máy chủ, vui lòng thử lại sau');
                }
            }
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Có lỗi xảy ra');
            }
            
            return data;
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    }

    static clearAuthData() {
        localStorage.removeItem(CONFIG.STORAGE_KEYS.TOKEN);
        localStorage.removeItem(CONFIG.STORAGE_KEYS.USER);
        localStorage.removeItem(CONFIG.STORAGE_KEYS.BALANCE);
    }

    // Product API methods
    static async createProduct(productData) {
        return await this.call('/products', 'POST', productData);
    }

    static async updateProduct(productId, productData) {
        return await this.call(`/products/${productId}`, 'PATCH', productData);
    }

    static async deleteProduct(productId) {
        return await this.call(`/products/${productId}`, 'DELETE');
    }

    static async getProducts() {
        return await this.call('/products', 'GET', null, false);
    }

    // User API methods
    static async getUserProfile() {
        return await this.call('/users/me');
    }

    static async getUserBalance() {
        return await this.call('/users/me/balance');
    }

    static async getUserTransactions() {
        return await this.call('/users/transactions');
    }

    static async updatePassword(passwordData) {
        return await this.call('/users/updateMyPassword', 'PATCH', passwordData);
    }

    static async depositMoney(depositData) {
        return await this.call('/users/deposit', 'POST', depositData);
    }
}

// =================================================================
// PERMISSION MANAGER
// =================================================================

class PermissionManager {
    static checkPostPermission() {
        if (!currentUser) {
            Utils.showToast('Vui lòng đăng nhập để thực hiện chức năng này', 'warning');
            return false;
        }
        
        if (currentUser.role === 'admin' || currentUser.role === 'moderator') {
            return true;
        }
        
        Utils.showToast('Bạn không có quyền thực hiện chức năng này', 'error');
        return false;
    }

    static checkDeletePermission(product) {
        if (!currentUser) {
            Utils.showToast('Vui lòng đăng nhập để thực hiện chức năng này', 'warning');
            return false;
        }
        
        if (currentUser.role === 'admin') {
            return true;
        }
        
        if (currentUser.role === 'moderator' && product.createdBy === currentUser._id) {
            return true;
        }
        
        Utils.showToast('Bạn không có quyền xóa sản phẩm này', 'error');
        return false;
    }

    static checkAdminPermission() {
        return currentUser && currentUser.role === 'admin';
    }

    static debugPermissions() {
        console.log('=== PERMISSION DEBUG ===');
        console.log('Current User:', currentUser);
        console.log('Can Post:', this.checkPostPermission());
        console.log('Is Admin:', this.checkAdminPermission());
        console.log('=======================');
    }
}

// =================================================================
// AUTH MANAGER
// =================================================================

class AuthManager {
    static async login(email, password, rememberMe = true) {
        try {
            const response = await ApiManager.call('/users/login', 'POST', {
                email,
                password
            }, false);

            const { token, user } = response.data;
            
            // Store auth data
            localStorage.setItem(CONFIG.STORAGE_KEYS.TOKEN, token);
            localStorage.setItem(CONFIG.STORAGE_KEYS.USER, JSON.stringify(user));
            
            // Update global state
            currentUser = user;
            
            // Load user balance
            await this.loadUserBalance();
            
            // Update UI
            await this.updateUIAfterLogin();
            
            Utils.showToast('Đăng nhập thành công!', 'success');
            
            return { success: true, user };
        } catch (error) {
            console.error('Login failed:', error);
            Utils.showToast(error.message || 'Đăng nhập thất bại', 'error');
            return { success: false, error: error.message };
        }
    }

    static async register(name, email, password, passwordConfirm) {
        try {
            const response = await ApiManager.call('/users/signup', 'POST', {
                name,
                email,
                password,
                passwordConfirm
            }, false);

            const { token, user } = response.data;
            
            // Store auth data
            localStorage.setItem(CONFIG.STORAGE_KEYS.TOKEN, token);
            localStorage.setItem(CONFIG.STORAGE_KEYS.USER, JSON.stringify(user));
            
            // Update global state
            currentUser = user;
            
            // Load user balance
            await this.loadUserBalance();
            
            // Update UI
            await this.updateUIAfterLogin();
            
            Utils.showToast('Đăng ký thành công!', 'success');
            
            return { success: true, user };
        } catch (error) {
            console.error('Registration failed:', error);
            Utils.showToast(error.message || 'Đăng ký thất bại', 'error');
            return { success: false, error: error.message };
        }
    }

    static logout() {
        // Clear auth data
        ApiManager.clearAuthData();
        
        // Reset global state
        currentUser = null;
        userBalance = 0;
        
        // Update UI
        this.updateUIAfterLogout();
        
        // Destroy DevTools protection
        if (devToolsProtection && typeof devToolsProtection.destroy === 'function') {
            devToolsProtection.destroy();
        }
        
        Utils.showToast('Đăng xuất thành công', 'success');
        
        // Redirect to home page
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 1000);
    }

    static async checkAutoLogin() {
        try {
            const token = ApiManager.getToken();
            if (!token) return false;

            const userData = await ApiManager.getUserProfile();
            currentUser = userData.data.user;
            
            // Load user balance
            await this.loadUserBalance();
            
            // Update UI
            await this.updateUIAfterLogin();
            
            console.log('Auto login successful');
            return true;
        } catch (error) {
            console.error('Auto login failed:', error);
            ApiManager.clearAuthData();
            return false;
        }
    }

    static async loadUserBalance() {
        try {
            const balanceData = await ApiManager.getUserBalance();
            userBalance = balanceData.data.balance || 0;
            localStorage.setItem(CONFIG.STORAGE_KEYS.BALANCE, userBalance.toString());
        } catch (error) {
            console.warn('Could not load user balance:', error);
            userBalance = 0;
        }
    }

    static getDisplayName(user) {
        return user ? (user.name || user.email || 'User') : 'User';
    }

    // 1. Sửa AuthManager.updateUIAfterLogin để cập nhật tên, role, body class, và render lại sản phẩm
    static async updateUIAfterLogin() {
        const userDropdown = document.getElementById('userDropdown');
        const loginButton = document.getElementById('loginButton');
        const userAvatar = document.getElementById('userAvatar');
        const userName = document.getElementById('userName');

        if (userDropdown) userDropdown.style.display = 'flex';
        if (loginButton) loginButton.style.display = 'none';

        if (userAvatar && userName) {
            const name = currentUser?.name || currentUser?.email || '';
            const firstLetter = name ? name[0].toUpperCase() : 'U';
            userAvatar.textContent = firstLetter;
            userName.textContent = name || 'User';
        }
        // Cập nhật body class admin-user
        if (currentUser && currentUser.role === 'admin') {
            document.body.classList.add('admin-user');
        } else {
            document.body.classList.remove('admin-user');
        }
        // Render lại sản phẩm
        if (window.ProductManager && ProductManager.loadProducts) {
            await ProductManager.loadProducts();
            const grid = document.getElementById('productsGrid');
            if (grid) ProductManager.renderProductsBasic(window.allProducts, grid);
        }
        // Update floating buttons
        if (window.FloatingButtonsManager) {
            window.FloatingButtonsManager.update();
        }
    }

    // 2. Sửa updateUIAfterLogout để cập nhật body class
    static updateUIAfterLogout() {
        const userDropdown = document.getElementById('userDropdown');
        const loginButton = document.getElementById('loginButton');
        if (userDropdown) userDropdown.style.display = 'none';
        if (loginButton) loginButton.style.display = 'flex';
        document.body.classList.remove('admin-user');
        // Render lại sản phẩm (ẩn các nút admin nếu có)
        if (window.ProductManager && ProductManager.loadProducts) {
            ProductManager.loadProducts().then(() => {
                const grid = document.getElementById('productsGrid');
                if (grid) ProductManager.renderProductsBasic(window.allProducts, grid);
            });
        }
        // Update floating buttons
        if (window.FloatingButtonsManager) {
            window.FloatingButtonsManager.update();
        }
    }
} 

// =================================================================
// UI CONTROLLER
// =================================================================

class UIController {
    static init() {
        this.initAuthModal();
        this.initEventListeners();
    }

    static initAuthModal() {
        const modalHTML = `
            <div id="authModal" class="modal" style="display: none;">
                <div class="modal-content">
                    <button class="modal-close" onclick="UIController.hideAuthModal()">&times;</button>
                    
                    <div class="auth-tabs">
                        <button class="auth-tab active" data-tab="login">Đăng Nhập</button>
                        <button class="auth-tab" data-tab="register">Đăng Ký</button>
                    </div>
                    
                    <div id="loginTab" class="auth-tab-content active">
                        <form id="loginForm">
                            <div class="form-group">
                                <label for="loginEmail">Email</label>
                                <input type="email" id="loginEmail" required>
                            </div>
                            <div class="form-group password-group">
                                <label for="loginPassword">Mật khẩu</label>
                                <input type="password" id="loginPassword" required>
                                <span class="password-toggle" onclick="Utils.togglePassword('loginPassword')">
                                    <i class="fas fa-eye"></i>
                                </span>
                            </div>
                            <button type="submit" class="btn btn-primary">Đăng Nhập</button>
                        </form>
                    </div>
                    
                    <div id="registerTab" class="auth-tab-content">
                        <form id="registerForm">
                            <div class="form-group">
                                <label for="registerName">Họ và tên</label>
                                <input type="text" id="registerName" required>
                            </div>
                            <div class="form-group">
                                <label for="registerEmail">Email</label>
                                <input type="email" id="registerEmail" required>
                            </div>
                            <div class="form-group password-group">
                                <label for="registerPassword">Mật khẩu</label>
                                <input type="password" id="registerPassword" required minlength="6">
                                <span class="password-toggle" onclick="Utils.togglePassword('registerPassword')">
                                    <i class="fas fa-eye"></i>
                                </span>
                            </div>
                            <div class="form-group password-group">
                                <label for="registerPasswordConfirm">Nhập lại mật khẩu</label>
                                <input type="password" id="registerPasswordConfirm" required>
                                <span class="password-toggle" onclick="Utils.togglePassword('registerPasswordConfirm')">
                                    <i class="fas fa-eye"></i>
                                </span>
                            </div>
                            <button type="submit" class="btn btn-primary">Đăng Ký</button>
                        </form>
                    </div>
                </div>
            </div>
        `;

        // Add modal to body if not exists
        if (!document.getElementById('authModal')) {
            document.body.insertAdjacentHTML('beforeend', modalHTML);
        }

        this.initLoginForm();
        this.initRegisterForm();
    }

    static initLoginForm() {
        const form = document.getElementById('loginForm');
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value;
            
            if (!email || !password) {
                Utils.showToast('Vui lòng nhập đầy đủ thông tin', 'warning');
                return;
            }

            const submitBtn = form.querySelector('button[type="submit"]');
            const resetLoading = Utils.showLoading(submitBtn, 'Đang đăng nhập...');

            try {
                const result = await AuthManager.login(email, password);
                if (result.success) {
                    this.hideAuthModal();
                    form.reset();
                }
            } catch (error) {
                console.error('Login error:', error);
            } finally {
                resetLoading();
            }
        });
    }

    static initRegisterForm() {
        const form = document.getElementById('registerForm');
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const name = document.getElementById('registerName').value.trim();
            const email = document.getElementById('registerEmail').value.trim();
            const password = document.getElementById('registerPassword').value;
            const passwordConfirm = document.getElementById('registerPasswordConfirm').value;
            
            if (!name || !email || !password || !passwordConfirm) {
                Utils.showToast('Vui lòng nhập đầy đủ thông tin', 'warning');
                return;
            }

            if (password !== passwordConfirm) {
                Utils.showToast('Mật khẩu nhập lại không khớp', 'error');
                return;
            }

            const submitBtn = form.querySelector('button[type="submit"]');
            const resetLoading = Utils.showLoading(submitBtn, 'Đang đăng ký...');

            try {
                const result = await AuthManager.register(name, email, password, passwordConfirm);
                if (result.success) {
                    this.hideAuthModal();
                    form.reset();
                }
            } catch (error) {
                console.error('Registration error:', error);
            } finally {
                resetLoading();
            }
        });
    }

    static initEventListeners() {
        // Auth tab switching
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('auth-tab')) {
                const tab = e.target.dataset.tab;
                this.switchAuthTab(tab);
            }
        });

        // Login button click
        const loginBtn = document.getElementById('loginButton');
        if (loginBtn) {
            loginBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.showAuthModal('login');
            });
        }

        // Logout functionality
        document.addEventListener('click', (e) => {
            if (e.target.closest('[onclick*="logout"]') || e.target.closest('[onclick*="AuthManager.logout"]')) {
                e.preventDefault();
                AuthManager.logout();
            }
        });
    }

    static showAuthModal(tab = 'login') {
        const modal = document.getElementById('authModal');
        if (modal) {
            modal.style.display = 'flex';
            this.switchAuthTab(tab);
        }
    }

    static hideAuthModal() {
        const modal = document.getElementById('authModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    static switchAuthTab(tab) {
        // Update tab buttons
        document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
        
        // Update tab content
        document.querySelectorAll('.auth-tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(tab + 'Tab').classList.add('active');
    }
}

// =================================================================
// FLOATING BUTTONS MANAGER
// =================================================================

class FloatingButtonsManager {
    static init() {
        this.addStyles();
        this.create();
    }

    static addStyles() {
        const styleId = 'floating-buttons-styles';
        if (document.getElementById(styleId)) return;

        const styles = `
            .floating-buttons {
                position: fixed;
                bottom: 30px;
                right: 30px;
                z-index: 1000;
                display: flex;
                flex-direction: column;
                gap: 15px;
            }

            .floating-button {
                width: 60px;
                height: 60px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                text-decoration: none;
                color: white;
                font-size: 24px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }

            .floating-button::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                transition: left 0.6s;
            }

            .floating-button:hover::before {
                left: 100%;
            }

            .floating-button:hover {
                transform: scale(1.1) translateY(-5px);
                box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            }

            .messenger-button {
                background: linear-gradient(135deg, #0084ff, #006ce7);
                animation: pulse 3s ease-in-out infinite;
            }

            .post-button {
                background: linear-gradient(135deg, #e63946, #d62839);
                display: none;
            }

            .post-button.show {
                display: flex;
            }

            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }

            .floating-button .tooltip {
                position: absolute;
                right: 75px;
                top: 50%;
                transform: translateY(-50%);
                background: rgba(0, 0, 0, 0.9);
                color: white;
                padding: 8px 12px;
                border-radius: 6px;
                font-size: 12px;
                white-space: nowrap;
                opacity: 0;
                visibility: hidden;
                transition: all 0.3s ease;
                pointer-events: none;
            }

            .floating-button:hover .tooltip {
                opacity: 1;
                visibility: visible;
            }

            .floating-button .tooltip::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 100%;
                margin-top: -4px;
                border: 4px solid transparent;
                border-left-color: rgba(0, 0, 0, 0.9);
            }

            @media (max-width: 768px) {
                .floating-buttons {
                    bottom: 20px;
                    right: 20px;
                }

                .floating-button {
                    width: 50px;
                    height: 50px;
                    font-size: 20px;
                }

                .floating-button .tooltip {
                    display: none;
                }
            }
        `;

        const styleElement = document.createElement('style');
        styleElement.id = styleId;
        styleElement.textContent = styles;
        document.head.appendChild(styleElement);
    }

    static create() {
        const containerId = 'floating-buttons-container';
        let container = document.getElementById(containerId);
        
        if (!container) {
            container = document.createElement('div');
            container.id = containerId;
            container.className = 'floating-buttons';
            document.body.appendChild(container);
        }

        this.createMessengerButton();
        this.createPostButton();
    }

    static createMessengerButton() {
        const container = document.getElementById('floating-buttons-container');
        if (!container || container.querySelector('.messenger-button')) return;

        const messengerBtn = document.createElement('a');
        messengerBtn.href = 'https://www.messenger.com/e2ee/t/6933504863440412';
        messengerBtn.target = '_blank';
        messengerBtn.className = 'floating-button messenger-button';
        messengerBtn.innerHTML = `
            <i class="fab fa-facebook-messenger"></i>
            <div class="tooltip">Chat với chúng tôi</div>
        `;

        container.appendChild(messengerBtn);
    }

    static createPostButton() {
        const container = document.getElementById('floating-buttons-container');
        if (!container || container.querySelector('.post-button')) return;

        const postBtn = document.createElement('button');
        postBtn.className = 'floating-button post-button';
        postBtn.innerHTML = `
            <i class="fas fa-plus"></i>
            <div class="tooltip">Đăng sản phẩm</div>
        `;
        postBtn.onclick = () => {
            if (PermissionManager.checkPostPermission()) {
                // Handle post product logic
                Utils.showToast('Tính năng đăng sản phẩm sẽ sớm ra mắt!', 'info');
            }
        };

        container.appendChild(postBtn);
    }

    static update() {
        const postButton = document.querySelector('.post-button');
        if (postButton) {
            if (currentUser && (currentUser.role === 'admin' || currentUser.role === 'moderator')) {
                postButton.classList.add('show');
            } else {
                postButton.classList.remove('show');
            }
        }
    }
}

// =================================================================
// PRODUCT MANAGER
// =================================================================

class ProductManager {
    static async loadProducts() {
        try {
            const response = await ApiManager.getProducts();
            allProducts = response.data.products || [];
            
            // Store in localStorage for offline access
            localStorage.setItem(CONFIG.STORAGE_KEYS.PRODUCTS, JSON.stringify(allProducts));
            
            return allProducts;
        } catch (error) {
            console.error('Failed to load products:', error);
            
            // Try to load from localStorage
            const cached = localStorage.getItem(CONFIG.STORAGE_KEYS.PRODUCTS);
            if (cached) {
                allProducts = JSON.parse(cached);
                return allProducts;
            }
            
            return [];
        }
    }

    // 3. Sửa ProductManager.renderProductsBasic để hiển thị thông báo nếu không có sản phẩm
    static renderProductsBasic(products, container) {
        if (!container) return;
        if (!products || products.length === 0) {
            container.innerHTML = '<div class="no-products-found">Chưa có sản phẩm nào.</div>';
            return;
        }
        container.innerHTML = products.map(product => this.createBasicProductCard(product)).join('');
    }

    static createBasicProductCard(product) {
        return `
            <div class="product-card" data-product-id="${product._id || product.id}">
                <div class="product-image">
                    <img src="${product.image || 'placeholder.jpg'}" alt="${product.title}" loading="lazy">
                </div>
                <div class="product-info">
                    <h3 class="product-title">${product.title}</h3>
                    <p class="product-description">${product.description}</p>
                    <div class="product-price">${Utils.formatPrice(product.price)}</div>
                    <button class="btn btn-primary" onclick="ProductManager.addToCart('${product._id || product.id}')">
                        Thêm vào giỏ
                    </button>
                </div>
            </div>
        `;
    }

    static async createProduct(productData) {
        if (!PermissionManager.checkPostPermission()) return;

        try {
            const response = await ApiManager.createProduct(productData);
            Utils.showToast('Sản phẩm đã được tạo thành công!', 'success');
            return response;
        } catch (error) {
            console.error('Create product failed:', error);
            Utils.showToast(error.message || 'Tạo sản phẩm thất bại', 'error');
            throw error;
        }
    }

    static async updateProduct(productId, productData) {
        if (!PermissionManager.checkPostPermission()) return;

        try {
            const response = await ApiManager.updateProduct(productId, productData);
            Utils.showToast('Sản phẩm đã được cập nhật!', 'success');
            return response;
        } catch (error) {
            console.error('Update product failed:', error);
            Utils.showToast(error.message || 'Cập nhật sản phẩm thất bại', 'error');
            throw error;
        }
    }

    static async deleteProduct(productId) {
        if (!PermissionManager.checkDeletePermission({ createdBy: productId })) return;

        if (!confirm('Bạn có chắc chắn muốn xóa sản phẩm này?')) return;

        try {
            await ApiManager.deleteProduct(productId);
            Utils.showToast('Sản phẩm đã được xóa!', 'success');
            
            // Remove from local array
            allProducts = allProducts.filter(p => p._id !== productId);
            localStorage.setItem(CONFIG.STORAGE_KEYS.PRODUCTS, JSON.stringify(allProducts));
        } catch (error) {
            console.error('Delete product failed:', error);
            Utils.showToast(error.message || 'Xóa sản phẩm thất bại', 'error');
        }
    }

    static addToCart(productId) {
        if (!currentUser) {
            Utils.showToast('Vui lòng đăng nhập để thêm vào giỏ hàng', 'warning');
            return;
        }

        // Simple cart implementation
        let cart = JSON.parse(localStorage.getItem('gag_cart') || '[]');
        const existingItem = cart.find(item => item.productId === productId);
        
        if (existingItem) {
            existingItem.quantity += 1;
        } else {
            cart.push({ productId, quantity: 1 });
        }
        
        localStorage.setItem('gag_cart', JSON.stringify(cart));
        Utils.showToast('Đã thêm vào giỏ hàng!', 'success');
    }
}

// =================================================================
// CART MANAGER
// =================================================================

class CartManager {
    async get() {
        return JSON.parse(localStorage.getItem('gag_cart') || '[]');
    }

    async add(productId, quantity = 1) {
        let cart = await this.get();
        const existingItem = cart.find(item => item.productId === productId);
        
        if (existingItem) {
            existingItem.quantity += quantity;
        } else {
            cart.push({ productId, quantity });
        }
        
        localStorage.setItem('gag_cart', JSON.stringify(cart));
        await this.updateCount();
    }

    async updateCount() {
        const cart = await this.get();
        const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
        
        // Update cart count display if exists
        const cartCountElements = document.querySelectorAll('.cart-count');
        cartCountElements.forEach(el => {
            el.textContent = totalItems;
            el.style.display = totalItems > 0 ? 'block' : 'none';
        });
    }
}

// =================================================================
// FAVORITES MANAGER
// =================================================================

class FavoritesManager {
    async get() {
        return JSON.parse(localStorage.getItem('gag_favorites') || '[]');
    }

    async add(productId) {
        let favorites = await this.get();
        if (!favorites.includes(productId)) {
            favorites.push(productId);
            localStorage.setItem('gag_favorites', JSON.stringify(favorites));
        }
    }

    async remove(productId) {
        let favorites = await this.get();
        favorites = favorites.filter(id => id !== productId);
        localStorage.setItem('gag_favorites', JSON.stringify(favorites));
    }

    async updateStatus(productId, isFavorite) {
        if (isFavorite) {
            await this.add(productId);
        } else {
            await this.remove(productId);
        }
    }
}

// =================================================================
// MAIN APPLICATION CLASS
// =================================================================

class MainApp {
    static async init() {
        console.log('🚀 Initializing MainApp...');
        
        try {
            // Initialize UI
            UIController.init();
            
            // Initialize floating buttons
            FloatingButtonsManager.init();
            
            // Check auto login
            await AuthManager.checkAutoLogin();
            
            // Load products
            await ProductManager.loadProducts();
            
            // Initialize DevTools protection
            if (CONFIG.DEVTOOLS_PROTECTION.ENABLED) {
                this.initDevToolsProtection();
            }
            
            // Setup event handlers
            this.setupFilterHandlers();
            
            // Mark as initialized
            isInitialized = true;
            
            console.log('✅ MainApp initialized successfully');
            
            // Expose global functions
            this.exposeGlobalFunctions();
            
        } catch (error) {
            console.error('❌ MainApp initialization failed:', error);
        }
    }

    static initDevToolsProtection() {
        try {
            // Load devtools protection script
            if (typeof DevToolsProtection !== 'undefined') {
                devToolsProtection = new DevToolsProtection();
                console.log('🛡️ DevTools protection initialized');
            } else {
                console.log('⚠️ DevTools protection script not loaded');
            }
        } catch (error) {
            console.error('❌ Failed to initialize DevTools protection:', error);
        }
    }

    static setupFilterHandlers() {
        // Add filter functionality if needed
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const category = e.target.dataset.category;
                this.filterProducts(category);
            });
        });
    }

    static filterProducts(category) {
        const products = allProducts.filter(product => 
            category === 'all' || product.category === category
        );
        
        const container = document.querySelector('.products-container');
        if (container) {
            ProductManager.renderProductsBasic(products, container);
        }
    }

    static exposeGlobalFunctions() {
        // Expose necessary functions for account.html and other pages
        window.currentUser = currentUser;
        window.userBalance = userBalance;
        window.Utils = Utils;
        window.ApiManager = ApiManager;
        window.AuthManager = AuthManager;
        window.ProductManager = ProductManager;
        window.CartManager = CartManager;
        window.FavoritesManager = FavoritesManager;
        
        // Expose callApi function for account.html
        window.callApi = ApiManager.call.bind(ApiManager);
        
        // Expose logout function
        window.logout = AuthManager.logout.bind(AuthManager);
        window.logoutUser = AuthManager.logout.bind(AuthManager);
        
        console.log('🌐 Global functions exposed');
    }
}

// =================================================================
// INITIALIZATION
// =================================================================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        MainApp.init();
    });
} else {
    // DOM already loaded
    setTimeout(() => {
        MainApp.init();
    }, 100);
}

// Initialize when page becomes visible
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !isInitialized) {
        setTimeout(() => {
            MainApp.init();
        }, 500);
    }
});

// Export for external use
window.MainApp = MainApp;

console.log('📦 Main.js loaded successfully'); 

// Modal Đăng Sản Phẩm
window.showAddProductModal = function() {
    const modal = document.getElementById('addProductModal');
    if (modal) modal.classList.add('show');
};
window.hideAddProductModal = function() {
    const modal = document.getElementById('addProductModal');
    if (modal) modal.classList.remove('show');
};

(function initAddProductModal() {
    const form = document.getElementById('addProductForm');
    if (!form) return;
    // Char count
    const titleInput = document.getElementById('productTitle');
    const descInput = document.getElementById('productDescription');
    const titleCount = document.getElementById('titleCharCount');
    const descCount = document.getElementById('descCharCount');
    if (titleInput && titleCount) {
        titleInput.addEventListener('input', () => {
            titleCount.textContent = `${titleInput.value.length}/100 ký tự`;
        });
    }
    if (descInput && descCount) {
        descInput.addEventListener('input', () => {
            descCount.textContent = `${descInput.value.length}/500 ký tự`;
        });
    }
    // Image preview
    const imageInput = document.getElementById('productImage');
    const imagePreview = document.getElementById('imagePreview');
    if (imageInput && imagePreview) {
        imageInput.addEventListener('change', () => {
            imagePreview.innerHTML = '';
            const file = imageInput.files[0];
            if (file) {
                const url = URL.createObjectURL(file);
                imagePreview.innerHTML = `<img src="${url}" style="max-width:100%;max-height:180px;border-radius:8px;">`;
            }
        });
    }
    // Submit
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitBtn = document.getElementById('submitAddProductBtn');
        const resetLoading = window.Utils && Utils.showLoading ? Utils.showLoading(submitBtn, 'Đang đăng...') : () => {};
        try {
            // Validate
            const title = titleInput.value.trim();
            const description = descInput.value.trim();
            const price = parseInt(document.getElementById('productPrice').value, 10);
            const note = document.getElementById('productNote').value.trim();
            let imageUrl = '';
            if (!title || title.length < 5) throw new Error('Tên sản phẩm phải từ 5 ký tự');
            if (!description || description.length < 10) throw new Error('Mô tả phải từ 10 ký tự');
            if (!price || price < 1000) throw new Error('Giá sản phẩm không hợp lệ');
            // Upload ảnh nếu có
            const file = imageInput.files[0];
            if (file) {
                if (!['image/jpeg','image/jpg','image/png','image/webp'].includes(file.type)) throw new Error('Chỉ chấp nhận ảnh JPG, PNG, WEBP');
                if (file.size > 5*1024*1024) throw new Error('Ảnh tối đa 5MB');
                imageUrl = await uploadImageToImgbb(file);
            }
            // Gọi API tạo sản phẩm
            const productData = { title, description, price, image: imageUrl, note };
            const res = await window.ProductManager.createProduct(productData);
            window.hideAddProductModal();
            form.reset();
            if (imagePreview) imagePreview.innerHTML = '';
            if (window.ProductManager && ProductManager.loadProducts) {
                await ProductManager.loadProducts();
                // Render lại sản phẩm nếu có grid
                const grid = document.getElementById('productsGrid');
                if (grid) ProductManager.renderProductsBasic(window.allProducts, grid);
            }
        } catch (err) {
            if (window.Utils && Utils.showToast) Utils.showToast(err.message || 'Đăng sản phẩm thất bại', 'error');
        } finally {
            resetLoading();
        }
    });
    // Đóng modal khi bấm nền tối
    document.getElementById('addProductModal').addEventListener('click', function(e) {
        if (e.target === this) window.hideAddProductModal();
    });
})();

// Hàm upload ảnh lên imgbb miễn phí (hoặc có thể thay bằng API backend nếu có)
async function uploadImageToImgbb(file) {
    const apiKey = '1b7e2e2e2e2e2e2e2e2e2e2e2e2e2e2e'; // Thay bằng key thật nếu cần
    const formData = new FormData();
    formData.append('image', file);
    const res = await fetch(`https://api.imgbb.com/1/upload?key=${apiKey}`, {
        method: 'POST',
        body: formData
    });
    const data = await res.json();
    if (!data.success) throw new Error('Upload ảnh thất bại');
    return data.data.url;
}

// Sửa FloatingButtonsManager để mở modal đăng sản phẩm
FloatingButtonsManager.createPostButton = function() {
    const container = document.getElementById('floating-buttons-container');
    if (!container || container.querySelector('.post-button')) return;
    const postBtn = document.createElement('button');
    postBtn.className = 'floating-button post-button';
    postBtn.innerHTML = `
        <i class="fas fa-plus"></i>
        <div class="tooltip">Đăng sản phẩm</div>
    `;
    postBtn.onclick = () => {
        if (PermissionManager.checkPostPermission()) {
            window.showAddProductModal();
        }
    };
    container.appendChild(postBtn);
}; 
