const API_BASE_URL = 'https://shop3-t86z.onrender.com/api/v1';

$(document).ready(function() {

    // --- KHỞI TẠO CÁC CHỨC NĂNG CHUNG ---

    $('body').on("click", ".dropdown-profile, .user-menu-button", function(event) {
        event.stopPropagation();
        $(".dropdown-content, .user-dropdown-content").toggleClass("show");
    });

    $(document).on("click", function(e) {
        if (!$(e.target).closest('.dropdown-profile, .user-menu').length) {
            $('.dropdown-content, .user-dropdown-content').removeClass('show');
        }
    });

    /* Menu Mobile */
    $("#menuToggle").on('click', function() {
        $(this).hide();
        $("#menuProfile").show();
    });
    $("#menuHide").on('click', function() {
        $("#menuToggle").show();
        $("#menuProfile").hide();
    });

    /* Nút Back To Top */
    $('#backToTop').on('click', function(e) {
        e.preventDefault();
        $('html, body').animate({ scrollTop: 0 }, 300);
    });

    if ($("#modalThongBao").length) {
        $("#modalThongBao").modal('show');
    }

    /* Nhận Quà Miễn Phí (Event) */
    $('body').delegate('#reward', 'click', function() {
         showDevelopingAlert('.content-popup');
         $('#modalMinigame').modal('show');
    });

    // --- BẮT ĐẦU LUỒNG XÁC THỰC NGƯỜI DÙNG ---
    checkAuthOnLoad();
});


// --- CÁC HÀM GIAO DIỆN VÀ XÁC THỰC ---

/**
 * Cập nhật giao diện khi người dùng đã đăng nhập.
 * @param {object} user - Thông tin người dùng.
 */
function updateUIForLoggedInUser(user) {
    if (!user || !user.name) return;

    // Use avatarText if available, otherwise generate from name
    const avatarText = user.avatarText || user.name.charAt(0).toUpperCase();

    // Use a simpler ID generation for display purposes
    const simpleUID = (user._id) ? user._id.slice(-5).toUpperCase() : 'N/A';
    
    // Balance should be a number, default to 0
    const balance = user.balance || 0;

    const userMenuHTML = `
        <div class="user-menu">
            <button class="user-menu-button">
                <span>${user.name} | ${balance.toLocaleString('vi-VN')}đ</span>
            </button>
            <div class="user-dropdown-content">
                <div class="user-info-header">
                    <div class="user-avatar">${avatarText}</div>
                    <div class="user-details">
                        <span class="user-uid">UID: ${simpleUID}</span>
                        <span class="user-balance-dropdown">Số dư: ${balance.toLocaleString('vi-VN')} <small>đ</small></span>
                    </div>
                </div>
                <ul class="main-menu">
                   <h3 class="menu-title">-- Tài Khoản</h3>
                    <li><a href="user/history/acc.html">Thông Tin Tài Khoản</a></li>
                    <li><a href="user/history/acc.html">Đổi Mật Khẩu</a></li>
                </ul>
                <ul class="main-menu">
                     <h3 class="menu-title">-- Giao Dịch</h3>
                     <li><a href="acc.html">Nạp Thẻ Cào (Tự Động)</a></li>
                     <li><a href="acc.html">Rút Vật Phẩm</a></li>
                </ul>
                <ul class="history-menu">
                    <h3 class="menu-title">-- Lịch Sử</h3>
                    <li><a href="acc.html">Lịch Sử Mua Hàng</a></li>
                    <li><a href="acc.html">Lịch Sử Nạp Thẻ</a></li>
                </ul>
                 <div class="charge-section" style="padding: 10px 15px; border-top: 1px solid #ddd;">
                      <button class="logout-button" onclick="Logout()">Đăng Xuất</button>
                </div>
            </div>
        </div>`;

    $('.tw-menu-right').html(userMenuHTML);
}

function updateUIForLoggedOutUser() {
    const loginButtonHTML = `
        <button class="tw-bg-red-500 hover:tw-bg-red-600 tw-transition tw-duration-200 tw-text-white tw-text-sm tw-px-4 tw-rounded-full tw-font-semibold tw-h-8 md:tw-h-10 tw-relative" data-toggle="modal" data-target="#loginModal">
            <span class="tw-hidden md:tw-inline-block"><i class="tw-absolute tw-text-lg bx bxs-user" style="top: 10px;"></i></span> <span class="md:tw-ml-6">ĐĂNG NHẬP</span>
        </button>`;
    $('.tw-menu-right').html(loginButtonHTML);
}

function checkAuthOnLoad() {
    const userString = localStorage.getItem('user');
    const token = localStorage.getItem('token');
    
    if (userString && token) {
        try {
            const user = JSON.parse(userString);
            updateUIForLoggedInUser(user);

            // Verify with server
            $.ajax({
                url: `${API_BASE_URL}/users/me`,
                type: "GET",
                beforeSend: function(xhr) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + token);
                },
                xhrFields: { withCredentials: true },
                success: function(data) {
                    if (data.status === 'success' && data.data.user) {
                        localStorage.setItem('user', JSON.stringify(data.data.user));
                        updateUIForLoggedInUser(data.data.user);
                    } else {
                        Logout(false);
                    }
                },
                error: function() {
                    Logout(false);
                }
            });
        } catch (e) {
            console.error("Lỗi parse JSON:", e);
            Logout(false);
        }
    } else {
        updateUIForLoggedOutUser();
    }
}


function Login() {
    $('#msgLogin').empty();
    var data = $("#form-Login").serialize();
    $.ajax({
        url: `${API_BASE_URL}/users/login`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success' && data.data.user && data.token) {
                $('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">Đăng nhập thành công!</div>');
                // MODIFIED: Store both user object and token
                localStorage.setItem('user', JSON.stringify(data.data.user));
                localStorage.setItem('token', data.token); 
                updateUIForLoggedInUser(data.data.user);
                setTimeout(() => { window.location.reload(); }, 1000);
            } else {
                $('#msgLogin').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message || 'Đăng nhập thất bại'}</div>`);
            }
        },
        error: function(xhr) {
            let errorMsg = (xhr.responseJSON && xhr.responseJSON.message) ? xhr.responseJSON.message : 'Sai tài khoản hoặc mật khẩu!';
            $('#msgLogin').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${errorMsg}</div>`);
        }
    });
}


function Register() {
    $('#msgReg').empty();
    var data = $("#form-Register").serialize();
    $.ajax({
        url: `${API_BASE_URL}/users/signup`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success' && data.data.user && data.token) {
                $('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">Đăng ký thành công! Đang đăng nhập...</div>');
                // MODIFIED: Store both user object and token
                localStorage.setItem('user', JSON.stringify(data.data.user));
                localStorage.setItem('token', data.token);
                setTimeout(() => { window.location.reload(); }, 1500);
            } else {
                $('#msgReg').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message || 'Đăng ký thất bại'}</div>`);
            }
        },
        error: function(xhr) {
            let errorMsg = (xhr.responseJSON && xhr.responseJSON.message) ? xhr.responseJSON.message : 'Có lỗi xảy ra, vui lòng kiểm tra lại thông tin!';
            $('#msgReg').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${errorMsg}</div>`);
        }
    });
}


function Logout(redirect = true) {
    // MODIFIED: Remove both user and token
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    
    updateUIForLoggedOutUser();
    
    $.ajax({
        url: `${API_BASE_URL}/users/logout`,
        type: "GET",
        xhrFields: { withCredentials: true },
        complete: function() {
            if (redirect) {
                // Redirect to home page instead of reloading a potentially protected page
                window.location.href = 'index.html';
            }
        }
    });
}

function changePassword() {
     $('#msgPassword').empty();
     var data = $("#form-Pass").serialize();
     const token = localStorage.getItem('token');
     if (!token) {
         alert('Vui lòng đăng nhập để thực hiện chức năng này.');
         return;
     }

     $.ajax({
         url: `${API_BASE_URL}/users/updateMyPassword`,
         data: data,
         dataType: "json",
         type: "PATCH",
         beforeSend: function(xhr) {
             xhr.setRequestHeader('Authorization', 'Bearer ' + token);
         },
         xhrFields: {
             withCredentials: true
         },
         success: function(data) {
             if (data.status == 'success') {
                 $('#msgPassword').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">Đổi mật khẩu thành công!</div>`);
                 // It's better to just show success message than to reload
             } else {
                 $('#msgPassword').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message || 'Đổi mật khẩu thất bại'}</div>`);
             }
         },
         error: function(xhr) {
             const errorMsg = (xhr.responseJSON && xhr.responseJSON.message) ? xhr.responseJSON.message : 'Có lỗi xảy ra. Vui lòng thử lại!';
             $('#msgPassword').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${errorMsg}</div>`);
         }
     });
}

// --- UTILITY FUNCTIONS ---
function showDevelopingAlert(selector) {
    const message = 'Chức năng này đang được phát triển. Vui lòng quay lại sau!';
    const alertHTML = `<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-blue-100 tw-border-blue-300 tw-text-blue-500">${message}</div>`;
    
    // Check if selector is a modal content area or a message div
    if ($(selector).hasClass('content-popup')) {
        $(selector).html(message);
    } else {
        $(selector).empty().html(alertHTML);
    }
}

function Napthe() {
    showDevelopingAlert('#msgCard');
}

// Global scope for modal management
(function($) {
    "use strict";
    
    // Manual modal controls for compatibility
    $('[data-toggle="modal"]').on('click', function(e) {
        e.preventDefault();
        var target = $(this).data('target');
        $(target).addClass('show');
    });

    $('.modal .close, .modal [data-dismiss="modal"]').on('click', function() {
        $(this).closest('.modal').removeClass('show');
    });

    // Close modal on outside click
    $('.modal').on('click', function(e) {
        if ($(e.target).is('.modal')) {
            $(this).removeClass('show');
        }
    });

})(jQuery);
