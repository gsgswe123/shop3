// script.js - FIXED UI Controller for Index Page
"use strict";

// =================================================================
// CONFIGURATION
// =================================================================

const UI_CONFIG = {
    ANIMATION_DELAY: 0.08,
    TOAST_DURATION: 3000,
    DEBOUNCE_DELAY: 300,
    MAX_PRODUCT_TITLE: 100,
    MAX_PRODUCT_DESC: 500,
    MIN_PRODUCT_PRICE: 1000,
    MAX_PRODUCT_PRICE: 50000000
};

// =================================================================
// ENHANCED PRODUCT MODAL MANAGER (COMPLETELY FIXED)
// =================================================================

const ProductModal = {
    modal: null,
    isSubmitting: false,

    /**
     * Tạo và khởi tạo modal nếu chưa tồn tại
     */
    init() {
        if (this.modal) return;

        console.log('🎯 Initializing ProductModal...');

        const modalElement = document.createElement('div');
        modalElement.id = 'addProductModal';
        modalElement.className = 'modal';
        modalElement.innerHTML = `
            <div class="modal-content add-product-modal-content">
                <button class="modal-close" aria-label="Đóng">×</button>
                <h2 class="modal-title"><i class="fas fa-plus-circle"></i> Đăng Sản Phẩm Mới</h2>
                <form id="addProductForm" class="add-product-form">
                    <div class="form-grid-2col">
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-tag"></i> Tên sản phẩm 
                                <span class="required">*</span>
                                <span class="char-count" id="titleCharCount">0/${UI_CONFIG.MAX_PRODUCT_TITLE}</span>
                            </label>
                            <input type="text" id="productTitle" class="form-input" required 
                                   maxlength="${UI_CONFIG.MAX_PRODUCT_TITLE}" 
                                   placeholder="Nhập tên sản phẩm...">
                        </div>
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-hashtag"></i> Badge/Tag
                            </label>
                            <select id="productBadge" class="form-input">
                                <option value="">-- Không có --</option>
                                <option value="HOT">🔥 HOT</option>
                                <option value="SALE">💰 SALE</option>
                                <option value="NEW">✨ NEW</option>
                                <option value="BEST">⭐ BEST</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-money-bill-wave"></i> Giá bán 
                                <span class="required">*</span>
                            </label>
                            <input type="number" id="productPrice" class="form-input" required 
                                   min="${UI_CONFIG.MIN_PRODUCT_PRICE}" 
                                   max="${UI_CONFIG.MAX_PRODUCT_PRICE}"
                                   step="1000" placeholder="0">
                        </div>
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-users"></i> Số lượng đã bán
                            </label>
                            <input type="number" id="productSales" class="form-input" 
                                   min="0" value="0" placeholder="0">
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-align-left"></i> Mô tả sản phẩm 
                            <span class="required">*</span>
                            <span class="char-count" id="descCharCount">0/${UI_CONFIG.MAX_PRODUCT_DESC}</span>
                        </label>
                        <textarea id="productDescription" class="form-textarea" required 
                                  maxlength="${UI_CONFIG.MAX_PRODUCT_DESC}"
                                  placeholder="Mô tả chi tiết về sản phẩm..."></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-image"></i> URL Hình ảnh 
                            <span class="required">*</span>
                        </label>
                        <input type="url" id="productImage" class="form-input" required 
                               placeholder="https://example.com/image.jpg">
                        <div id="imagePreview" class="image-preview"></div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-link"></i> Link sản phẩm 
                            <span class="required">*</span>
                        </label>
                        <input type="url" id="productLink" class="form-input" required 
                               placeholder="https://example.com/product">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" id="cancelProductBtn">
                            <i class="fas fa-times"></i><span>Hủy</span>
                        </button>
                        <button type="submit" class="btn btn-success" id="submitProductBtn">
                            <i class="fas fa-plus"></i><span>Đăng sản phẩm</span>
                            <div class="spinner" style="display: none;"></div>
                        </button>
                    </div>
                </form>
            </div>
        `;
        document.body.appendChild(modalElement);
        this.modal = modalElement;

        // Attach event listeners
        this.attachEventListeners();
        this.setupFormValidation();
        
        console.log('✅ ProductModal initialized successfully');
    },

    /**
     * Gắn các event listeners cho modal
     */
    attachEventListeners() {
        this.modal.querySelector('.modal-close').addEventListener('click', () => this.hide());
        this.modal.querySelector('#cancelProductBtn').addEventListener('click', () => this.hide());
        this.modal.addEventListener('click', (e) => { 
            if (e.target === this.modal) this.hide(); 
        });
        this.modal.querySelector('#addProductForm').addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Image URL preview with debouncing
        const imageInput = this.modal.querySelector('#productImage');
        imageInput.addEventListener('blur', (e) => {
            this.previewImage(e.target.value);
        });

        // Real-time image preview with debouncing
        imageInput.addEventListener('input', window.Utils?.debounce((e) => {
            this.previewImage(e.target.value);
        }, 500) || (() => {}));
    },

    /**
     * Thiết lập validation cho form
     */
    setupFormValidation() {
        const titleInput = this.modal.querySelector('#productTitle');
        const descInput = this.modal.querySelector('#productDescription');
        const titleCount = this.modal.querySelector('#titleCharCount');
        const descCount = this.modal.querySelector('#descCharCount');

        // Character count for title
        titleInput.addEventListener('input', (e) => {
            const count = e.target.value.length;
            titleCount.textContent = `${count}/${UI_CONFIG.MAX_PRODUCT_TITLE}`;
            titleCount.style.color = count > UI_CONFIG.MAX_PRODUCT_TITLE * 0.9 ? '#ef4444' : '#6b7280';
        });

        // Character count for description
        descInput.addEventListener('input', (e) => {
            const count = e.target.value.length;
            descCount.textContent = `${count}/${UI_CONFIG.MAX_PRODUCT_DESC}`;
            descCount.style.color = count > UI_CONFIG.MAX_PRODUCT_DESC * 0.9 ? '#ef4444' : '#6b7280';
        });

        // Price formatting and validation
        const priceInput = this.modal.querySelector('#productPrice');
        priceInput.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            if (!isNaN(value)) {
                e.target.style.color = value < UI_CONFIG.MIN_PRODUCT_PRICE || value > UI_CONFIG.MAX_PRODUCT_PRICE ? '#ef4444' : '';
            }
        });

        // Price formatting on blur
        priceInput.addEventListener('blur', (e) => {
            const value = parseInt(e.target.value);
            if (!isNaN(value)) {
                e.target.value = value;
            }
        });
    },

    /**
     * Preview hình ảnh từ URL
     */
    previewImage(url) {
        const preview = this.modal.querySelector('#imagePreview');
        
        if (!url || !window.Utils?.validateURL(url)) {
            preview.innerHTML = '';
            return;
        }

        preview.innerHTML = `
            <div style="text-align: center; margin: 1rem 0;">
                <div style="position: relative; display: inline-block;">
                    <img src="${url}" alt="Preview" 
                         style="max-width: 200px; max-height: 200px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); transition: opacity 0.3s; opacity: 0;" 
                         onload="this.style.opacity='1'; this.nextElementSibling.style.display='none';"
                         onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                    <div style="display: none; color: #ef4444; font-size: 0.9rem; padding: 20px; border: 2px dashed #ef4444; border-radius: 8px;">
                        <i class="fas fa-exclamation-triangle"></i> Không thể tải hình ảnh
                    </div>
                </div>
                <p style="color: #6b7280; font-size: 0.9rem; margin-top: 0.5rem;">Xem trước hình ảnh</p>
            </div>
        `;
    },

    /**
     * Hiển thị modal với kiểm tra quyền
     */
    show() {
        console.log('🎯 ProductModal.show() called');
        console.log('Current user:', window.currentUser);
        console.log('Permission check:', window.PermissionManager?.checkPostPermission());
        
        // Kiểm tra đăng nhập
        if (!window.currentUser) {
            window.Utils?.showToast('Vui lòng đăng nhập để đăng sản phẩm!', 'warning');
            document.getElementById('loginButton')?.click();
            return;
        }

        // Kiểm tra quyền admin
        if (!window.PermissionManager?.checkPostPermission()) {
            window.Utils?.showToast('Bạn không có quyền đăng sản phẩm!\nChỉ admin mới có thể đăng sản phẩm.', 'error');
            window.PermissionManager?.debugPermissions();
            return;
        }
        
        // Khởi tạo modal nếu cần
        this.init();
        
        // Hiển thị modal
        this.modal.style.display = 'flex';
        setTimeout(() => this.modal.classList.add('show'), 10);
        document.body.style.overflow = 'hidden';
        
        // Reset form
        this.resetForm();
        
        console.log('✅ ProductModal shown successfully');
    },

    /**
     * Reset form về trạng thái ban đầu
     */
    resetForm() {
        const form = this.modal.querySelector('#addProductForm');
        form.reset();
        
        this.modal.querySelector('#imagePreview').innerHTML = '';
        this.modal.querySelector('#titleCharCount').textContent = `0/${UI_CONFIG.MAX_PRODUCT_TITLE}`;
        this.modal.querySelector('#descCharCount').textContent = `0/${UI_CONFIG.MAX_PRODUCT_DESC}`;
        
        // Reset input colors and styles
        this.modal.querySelectorAll('.form-input, .form-textarea').forEach(input => {
            input.style.color = '';
            input.style.borderColor = '';
        });
    },

    /**
     * Ẩn modal
     */
    hide() {
        if (!this.modal) return;
        
        this.modal.classList.remove('show');
        setTimeout(() => {
            this.modal.style.display = 'none';
            document.body.style.overflow = '';
        }, 300);
    },

    /**
     * Xử lý submit form
     */
    async handleSubmit(e) {
        e.preventDefault();
        
        console.log('📝 ProductModal form submitted');
        
        if (this.isSubmitting) {
            console.log('⏳ Already submitting, ignoring...');
            return;
        }
        
        const submitBtn = this.modal.querySelector('#submitProductBtn');
        const spinner = submitBtn.querySelector('.spinner');
        const btnText = submitBtn.querySelector('span');

        // Collect form data
        const formData = {
            title: this.modal.querySelector('#productTitle').value.trim(),
            description: this.modal.querySelector('#productDescription').value.trim(),
            price: this.modal.querySelector('#productPrice').value,
            image: this.modal.querySelector('#productImage').value.trim(),
            badge: this.modal.querySelector('#productBadge').value,
            sales: this.modal.querySelector('#productSales').value || '0',
            link: this.modal.querySelector('#productLink').value.trim(),
        };

        console.log('📋 Form data:', formData);

        // Validation
        const errors = this.validateFormData(formData);
        if (errors.length > 0) {
            window.Utils?.showToast(errors.join('\n'), 'error');
            return;
        }

        // Set loading state
        this.isSubmitting = true;
        submitBtn.disabled = true;
        spinner.style.display = 'inline-block';
        btnText.textContent = 'Đang đăng...';

        try {
            console.log('🚀 Creating product via ProductManager...');
            
            if (!window.ProductManager) {
                throw new Error('ProductManager không khả dụng!');
            }

            const success = await window.ProductManager.createProduct(formData);
            
            if (success) {
                console.log('✅ Product created successfully');
                this.hide();
                window.Utils?.showToast('Đăng sản phẩm thành công!', 'success');
            }
        } catch (error) {
            console.error('❌ Error creating product:', error);
            window.Utils?.showToast(error.message || 'Có lỗi xảy ra khi đăng sản phẩm!', 'error');
        } finally {
            // Reset loading state
            this.isSubmitting = false;
            submitBtn.disabled = false;
            spinner.style.display = 'none';
            btnText.textContent = 'Đăng sản phẩm';
        }
    },

    /**
     * Validate form data với kiểm tra chi tiết
     */
    validateFormData(data) {
        const errors = [];

        // Title validation
        if (!data.title || data.title.length < 5) {
            errors.push('Tên sản phẩm phải có ít nhất 5 ký tự');
        }
        if (data.title.length > UI_CONFIG.MAX_PRODUCT_TITLE) {
            errors.push(`Tên sản phẩm không được vượt quá ${UI_CONFIG.MAX_PRODUCT_TITLE} ký tự`);
        }

        // Description validation
        if (!data.description || data.description.length < 10) {
            errors.push('Mô tả phải có ít nhất 10 ký tự');
        }
        if (data.description.length > UI_CONFIG.MAX_PRODUCT_DESC) {
            errors.push(`Mô tả không được vượt quá ${UI_CONFIG.MAX_PRODUCT_DESC} ký tự`);
        }

        // Price validation
        const price = parseInt(data.price);
        if (isNaN(price) || price < UI_CONFIG.MIN_PRODUCT_PRICE || price > UI_CONFIG.MAX_PRODUCT_PRICE) {
            errors.push(`Giá phải từ ${window.Utils?.formatPrice(UI_CONFIG.MIN_PRODUCT_PRICE)} đến ${window.Utils?.formatPrice(UI_CONFIG.MAX_PRODUCT_PRICE)}`);
        }

        // Image URL validation
        if (!window.Utils?.validateURL(data.image)) {
            errors.push('URL hình ảnh không hợp lệ');
        }

        // Link validation
        if (!window.Utils?.validateURL(data.link)) {
            errors.push('Link sản phẩm không hợp lệ');
        }

        // Sales validation
        const sales = parseInt(data.sales);
        if (isNaN(sales) || sales < 0) {
            errors.push('Số lượng đã bán phải là số không âm');
        }

        return errors;
    }
};

// =================================================================
// ENHANCED PRODUCT RENDERING (FIXED)
// =================================================================

/**
 * Hiển thị danh sách sản phẩm lên lưới sản phẩm
 */
function renderApiProducts(products) {
    console.log('🎨 Rendering products:', products?.length || 0);
    
    const productsGrid = document.getElementById('productsGrid');
    if (!productsGrid) {
        console.error('❌ Products grid not found');
        return;
    }

    productsGrid.innerHTML = '';

    if (!products || products.length === 0) {
        productsGrid.innerHTML = `
            <div class="no-products-found" style="grid-column: 1 / -1; text-align: center; padding: 60px 20px;">
                <i class="fas fa-search" style="font-size: 3rem; color: #cbd5e1; margin-bottom: 1rem;"></i>
                <h3 style="color: #64748b; margin-bottom: 1rem;">Không có sản phẩm nào</h3>
                <p style="color: #9ca3af; font-size: 1rem;">Hiện tại chưa có sản phẩm nào được đăng.</p>
                ${window.PermissionManager?.checkPostPermission() ? `
                    <button class="btn btn-primary" onclick="window.ProductModal?.show()" style="margin-top: 1rem;">
                        <i class="fas fa-plus"></i> <span>Đăng sản phẩm đầu tiên</span>
                    </button>
                ` : ''}
            </div>
        `;
        hideFilterResult();
        return;
    }
    
    products.forEach((product, index) => {
        const productCard = createProductCard(product, index);
        productsGrid.appendChild(productCard);
    });
    
    attachProductEventListeners();
    console.log('✅ Products rendered successfully');
}

/**
 * Tạo thẻ sản phẩm với kiểm tra quyền chính xác
 */
function createProductCard(product, index) {
    const productCard = document.createElement('div');
    productCard.className = 'product-card fade-in';
    productCard.dataset.id = product._id;
    productCard.dataset.price = product.price;
    productCard.dataset.note = product.description || '';
    productCard.dataset.category = product.category || '';
    
    // Kiểm tra quyền xóa
    const canDelete = window.PermissionManager?.checkDeletePermission(product);
    let deleteButtonHTML = '';
    
    if (canDelete) {
        deleteButtonHTML = `
            <button class="btn-icon btn-delete" title="Xóa sản phẩm" data-id="${product._id}">
                <i class="fas fa-trash-alt"></i>
            </button>
        `;
    }

    // Hiển thị badge
    let badgeHTML = '';
    if (product.badge) {
        const badgeClass = product.badge.toLowerCase();
        badgeHTML = `<span class="product-badge ${badgeClass}">${product.badge}</span>`;
    }

    // Xây dựng HTML thẻ sản phẩm
    productCard.innerHTML = `
        <div class="product-image">
            <img src="${product.images?.[0] || product.image || 'https://via.placeholder.com/300x200?text=No+Image'}" 
                 alt="${product.title}" 
                 loading="lazy" 
                 onerror="this.src='https://via.placeholder.com/300x200?text=Image+Error'">
            ${badgeHTML}
            <div class="product-overlay">
                <button class="btn-favorite btn-icon" title="Thêm vào yêu thích" data-id="${product._id}">
                    <i class="far fa-heart"></i>
                </button>
                <a href="${product.link || '#'}" class="btn-view btn-icon" title="Xem chi tiết" 
                   target="_blank" rel="noopener noreferrer">
                    <i class="fas fa-eye"></i>
                </a>
                ${deleteButtonHTML} 
            </div>
        </div>
        <div class="product-info">
            <h3 class="product-title">${product.title}</h3>
            <p class="product-description">${product.description}</p>
            <div class="product-price">
                <span class="product-current-price">${window.Utils?.formatPrice(product.price) || product.price + 'đ'}</span>
            </div>
            <div class="product-meta">
                <span class="product-sales"><i class="fas fa-user"></i> ${product.sales || 0}</span>
                <span class="product-stock"><i class="fas fa-box"></i> ${product.stock !== undefined ? product.stock : 'N/A'}</span>
            </div>
            <p class="product-id">ID: #${product._id.slice(-6)}</p>
            <div class="product-actions">
                <a href="${product.link || '#'}" class="add-to-cart-link" target="_blank" rel="noopener noreferrer">
                    <i class="fas fa-shopping-cart"></i><span>Mua Ngay</span>
                </a>
            </div>
        </div>
    `;

    productCard.style.animationDelay = `${index * UI_CONFIG.ANIMATION_DELAY}s`;
    return productCard;
}

/**
 * Gắn các trình xử lý sự kiện cho các nút trên thẻ sản phẩm
 */
function attachProductEventListeners() {
    // Nút "Yêu thích"
    document.querySelectorAll('.btn-favorite').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault(); 
            e.stopPropagation();
            
            if (!window.currentUser) {
                window.Utils?.showToast('Vui lòng đăng nhập để sử dụng tính năng này!', 'info');
                document.getElementById('loginButton')?.click();
                return;
            }
            
            const productId = e.currentTarget.dataset.id;
            const isFavorite = btn.classList.contains('active');
            
            // Disable button to prevent double-click
            btn.disabled = true;
            
            try {
                if (isFavorite) {
                    await window.FavoriteManager?.remove(productId);
                    window.Utils?.showToast('Đã xóa khỏi yêu thích', 'info');
                } else {
                    await window.FavoriteManager?.add(productId);
                    window.Utils?.showToast('Đã thêm vào yêu thích!', 'success');
                }
            } catch (error) {
                console.error('Favorite error:', error);
                window.Utils?.showToast(error.message || 'Có lỗi xảy ra!', 'error');
            } finally {
                btn.disabled = false;
            }
        });
    });

    // Nút xóa sản phẩm
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault(); 
            e.stopPropagation();
            
            const productId = e.currentTarget.dataset.id;
            const product = window.allProducts?.find(p => p._id === productId);
            
            if (!window.PermissionManager?.checkDeletePermission(product)) {
                window.Utils?.showToast('Bạn không có quyền xóa sản phẩm này!', 'error');
                return;
            }
            
            const productTitle = product?.title || 'sản phẩm này';
            
            if (confirm(`Bạn có chắc chắn muốn xóa "${productTitle}"?\n\nHành động này không thể hoàn tác.`)) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                
                try {
                    await window.ProductManager?.deleteProduct(productId);
                } catch (error) {
                    console.error('Delete error:', error);
                    window.Utils?.showToast(error.message || 'Không thể xóa sản phẩm!', 'error');
                    // Restore button
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-trash-alt"></i>';
                }
            }
        });
    });
}

// =================================================================
// ENHANCED FILTER SYSTEM
// =================================================================

function filterProducts() {
    console.log('🔍 Filtering products...');
    
    const searchId = document.getElementById('searchId')?.value.toLowerCase().trim() || '';
    const searchPrice = document.getElementById('searchPrice')?.value || '';
    const searchNote = document.getElementById('searchNote')?.value.toLowerCase().trim() || '';
    
    let visibleCount = 0;
    
    document.querySelectorAll('.product-card').forEach(card => {
        const cardId = card.dataset.id?.toLowerCase() || '';
        const cardPrice = parseInt(card.dataset.price) || 0;
        const cardNote = card.dataset.note?.toLowerCase() || '';
        
        let isVisible = true;
        
        // Filter by ID
        if (searchId && !cardId.includes(searchId)) {
            isVisible = false;
        }
        
        // Filter by note/description
        if (searchNote && !cardNote.includes(searchNote)) {
            isVisible = false;
        }
        
        // Filter by price range
        if (searchPrice) {
            const ranges = {
                'duoi-50k': [0, 49999], 
                'tu-50k-200k': [50000, 200000], 
                'tren-200k': [200001, Infinity]
            };
            const [min, max] = ranges[searchPrice] || [0, Infinity];
            if (cardPrice < min || cardPrice > max) {
                isVisible = false;
            }
        }
        
        // Apply visibility
        card.style.display = isVisible ? 'block' : 'none';
        if (isVisible) visibleCount++;
    });
    
    showFilterResult(visibleCount);
    console.log(`🎯 Filter complete: ${visibleCount} products visible`);
}

function resetFilters() {
    console.log('🔄 Resetting filters...');
    
    const searchId = document.getElementById('searchId');
    const searchPrice = document.getElementById('searchPrice');
    const searchNote = document.getElementById('searchNote');
    
    if (searchId) searchId.value = '';
    if (searchPrice) searchPrice.value = '';
    if (searchNote) searchNote.value = '';
    
    document.querySelectorAll('.product-card').forEach(card => {
        card.style.display = 'block';
    });
    
    hideFilterResult();
    
    window.Utils?.showToast('Đã xóa bộ lọc', 'info');
}

function showFilterResult(count) {
    let resultMessage = document.getElementById('filterResult');
    if (!resultMessage) {
        resultMessage = document.createElement('div');
        resultMessage.id = 'filterResult';
        Object.assign(resultMessage.style, {
            gridColumn: '1/-1', 
            textAlign: 'center', 
            padding: '20px',
            background: 'linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%)',
            borderRadius: '12px', 
            marginBottom: '20px', 
            borderLeft: '4px solid #6366f1',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', 
            animation: 'fadeInUp 0.5s'
        });
        document.getElementById('productsGrid')?.prepend(resultMessage);
    }
    
    if (resultMessage) {
        const icon = count > 0 ? 'fa-search' : 'fa-search-minus';
        const color = count > 0 ? '#6366f1' : '#ef4444';
        
        resultMessage.innerHTML = `
            <i class="fas ${icon}" style="margin-right: 8px; color: ${color};"></i>
            <strong>Kết quả lọc:</strong> ${count > 0 ? `Tìm thấy <strong>${count}</strong> sản phẩm phù hợp` : 'Không tìm thấy sản phẩm nào'}
        `;
        resultMessage.style.display = 'block';
        resultMessage.style.borderLeftColor = color;
    }
}

function hideFilterResult() {
    const resultMessage = document.getElementById('filterResult');
    if (resultMessage) {
        resultMessage.style.display = 'none';
    }
}

// =================================================================
// ENHANCED SEARCH FUNCTIONALITY
// =================================================================

function setupSearchHandlers() {
    const searchInputs = document.querySelectorAll('#searchId, #searchNote');
    const searchPrice = document.getElementById('searchPrice');
    
    // Debounced search for text inputs
    searchInputs.forEach(input => {
        if (input) {
            input.addEventListener('input', window.Utils?.debounce(() => {
                filterProducts();
            }, UI_CONFIG.DEBOUNCE_DELAY) || filterProducts);
        }
    });
    
    // Immediate search for select
    if (searchPrice) {
        searchPrice.addEventListener('change', filterProducts);
    }
    
    // Enter key support
    searchInputs.forEach(input => {
        if (input) {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    filterProducts();
                }
            });
        }
    });
}

// =================================================================
// ACCESSIBILITY ENHANCEMENTS
// =================================================================

function setupAccessibility() {
    // Add keyboard navigation for product cards
    document.addEventListener('keydown', (e) => {
        if (e.target.classList.contains('product-card')) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                const buyLink = e.target.querySelector('.add-to-cart-link');
                if (buyLink) buyLink.click();
            }
        }
    });
    
    // Add ARIA labels
    document.querySelectorAll('.product-card').forEach(card => {
        card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'article');
        
        const title = card.querySelector('.product-title')?.textContent;
        if (title) {
            card.setAttribute('aria-label', `Sản phẩm: ${title}`);
        }
    });
}

// =================================================================
// PERFORMANCE OPTIMIZATIONS
// =================================================================

function setupPerformanceOptimizations() {
    // Lazy load images that are not visible
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    if (img.dataset.src) {
                        img.src = img.dataset.src;
                        img.removeAttribute('data-src');
                        observer.unobserve(img);
                    }
                }
            });
        });
        
        // Observe all product images
        document.querySelectorAll('.product-image img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    }
}

// =================================================================
// INITIALIZATION AND EXPORTS
// =================================================================

function initIndexPageScript() {
    console.log('🎨 Initializing Index Page Script...');
    
    // Add enhanced CSS
    addEnhancedStyles();
    
    // Setup search handlers with debouncing
    setupSearchHandlers();
    
    // Setup accessibility features
    setupAccessibility();
    
    // Setup performance optimizations
    setupPerformanceOptimizations();
    
    console.log('✅ Index Page Script initialized successfully');
}

function addEnhancedStyles() {
    if (document.getElementById('enhancedUIStyles')) return;
    
    const style = document.createElement('style');
    style.id = 'enhancedUIStyles';
    style.innerHTML = `
        .btn-delete { 
            color: #fff !important; 
            background: #ef4444 !important; 
            transition: all 0.3s ease !important;
        } 
        .btn-delete:hover { 
            background: #dc2626 !important; 
            transform: scale(1.1) !important;
        }
        .btn-delete:disabled {
            opacity: 0.6 !important;
            cursor: not-allowed !important;
            transform: none !important;
        }
        .char-count {
            font-size: 0.8rem;
            color: #6b7280;
            margin-left: auto;
            font-weight: normal;
        }
        .image-preview {
            margin-top: 0.5rem;
            transition: all 0.3s ease;
        }
        .form-input:invalid {
            border-color: #ef4444;
        }
        .form-input:valid {
            border-color: #10b981;
        }
        .product-overlay {
            opacity: 0;
            transition: all 0.3s ease;
        }
        .product-card:hover .product-overlay {
            opacity: 1;
        }
        .fade-in {
            animation: fadeInUp 0.6s ease-out forwards;
        }
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .loading-shimmer {
            background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
            background-size: 200% 100%;
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        .no-products-found {
            grid-column: 1 / -1;
            text-align: center;
            padding: 60px 20px;
            background: rgba(255, 255, 255, 0.8);
            border-radius: 12px;
            margin: 20px 0;
        }
        .add-product-modal-content {
            max-width: 600px;
            width: 95%;
            max-height: 90vh;
            overflow-y: auto;
        }
        .form-grid-2col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        @media (max-width: 768px) {
            .form-grid-2col {
                grid-template-columns: 1fr;
            }
        }
    `;
    document.head.appendChild(style);
}

// =================================================================
// ERROR HANDLING & DEBUGGING
// =================================================================

function debugScript() {
    console.log('🐛 SCRIPT DEBUG INFO:');
    console.log('- ProductModal:', !!window.ProductModal);
    console.log('- Utils:', !!window.Utils);
    console.log('- PermissionManager:', !!window.PermissionManager);
    console.log('- ProductManager:', !!window.ProductManager);
    console.log('- currentUser:', window.currentUser);
    console.log('- allProducts:', window.allProducts?.length || 0);
}

// Add error handling for uncaught errors
window.addEventListener('error', (e) => {
    console.error('🚨 Script Error:', e.error);
    if (window.Utils?.showToast) {
        window.Utils.showToast('Có lỗi xảy ra trong ứng dụng!', 'error');
    }
});

// =================================================================
// GLOBAL EXPORTS
// =================================================================

// Export functions to global scope
window.renderApiProducts = renderApiProducts;
window.filterProducts = filterProducts;
window.resetFilters = resetFilters;
window.ProductModal = ProductModal;

// Export utility functions
window.showFilterResult = showFilterResult;
window.hideFilterResult = hideFilterResult;
window.createProductCard = createProductCard;
window.attachProductEventListeners = attachProductEventListeners;
window.debugScript = debugScript;

// =================================================================
// AUTO INITIALIZATION
// =================================================================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initIndexPageScript);
} else {
    initIndexPageScript();
}

// Wait for main.js to load
let mainJsReady = setInterval(() => {
    if (window.Utils && window.PermissionManager && window.ProductManager) {
        console.log('✅ Main.js dependencies loaded, script.js ready');
        clearInterval(mainJsReady);
    }
}, 100);

console.log('📦 Script.js loaded successfully');
