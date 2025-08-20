const API_BASE_URL = 'https://shop3-t86z.onrender.com/api/v1';

$(document).ready(function() {

    // --- KHỞI TẠO CÁC CHỨC NĂNG CHUNG ---

    /* Dropdown Profile - Event này sẽ được gán lại sau khi đăng nhập */
    // Sự kiện được ủy quyền (delegated event) để hoạt động với cả các phần tử được thêm sau
    $('body').on("click", ".dropdown-profile, .user-menu-button", function(event) {
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

    /* Tự động hiển thị Modal thông báo (nếu có) */
    if ($("#modalThongBao").length) {
        $("#modalThongBao").modal('show');
    }

    /* Nhận Quà Miễn Phí (Event) */
    $('body').delegate('#reward', 'click', function() {
        $.ajax({
            url: `${API_BASE_URL}/event`, // Endpoint này chưa có trong server.js
            dataType: 'json',
            type: 'POST',
            xhrFields: {
                withCredentials: true
            },
            success: function(data) {
                if (data.status == 'LOGIN') {
                    $("#loginModal").modal('show');
                } else {
                    $('#reward').css('opacity', '0');
                    $('.content-popup').html(data.message || data.msg);
                    $('#modalMinigame').modal('show');
                }
            },
            error: function(xhr, status, error) {
                console.error('Event error:', error);
                // Xử lý khi chưa đăng nhập
                 $("#loginModal").modal('show');
            }
        });
    });

    // --- BẮT ĐẦU LUỒNG XÁC THỰC NGƯỜI DÙNG ---
    checkAuthOnLoad();
});

// --- CÁC HÀM ĐIỀU KHIỂN MODAL ---

function closeModalindex() {
    $("#modalThongBao").hide();
}

function closeModal() {
    $("#modalMinigame").removeClass("show");
}

function closeGift() {
    $('#modalGift').remove();
}

// --- CÁC HÀM GIAO DIỆN VÀ XÁC THỰC ---

/**
 * Cập nhật giao diện khi người dùng đã đăng nhập.
 * @param {object} user - Thông tin người dùng.
 */
function updateUIForLoggedInUser(user) {
    if (!user || !user.name) return;

    // Tạo mã UID đơn giản từ ID của MongoDB
    const generateSimpleUID = (mongoId) => {
        if (!mongoId) return 'N/A';
        let hash = 0;
        for (let i = 0; i < mongoId.length; i++) {
            const char = mongoId.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0; // Convert to 32bit integer
        }
        return Math.abs(hash).toString().slice(0, 5); // Lấy 5 chữ số đầu
    }
    const simpleUID = generateSimpleUID(user._id);

    const userMenuHTML = `
        <div class="user-menu">
            <button class="user-menu-button">
                <img src="https://ui-avatars.com/api/?name=${user.avatarText}&amp;background=random&amp;color=fff" alt="Avatar">
                ${user.name} | ${user.balance.toLocaleString('vi-VN')}đ
            </button>
            <div class="user-dropdown-content">
                <div class="user-info-header">
                    <div class="user-avatar">${user.avatarText}</div>
                    <div class="user-details">
                        <span class="user-uid">UID: ${simpleUID}</span>
                        <span class="user-balance-dropdown">Số dư: ${user.balance.toLocaleString('vi-VN')} <small>đ</small></span>
                    </div>
                </div>
                <ul class="main-menu">
                   <h3 class="menu-title">-- Tài Khoản</h3>
                    <li><a href="shopgrowgarden.com/user/history/acc.html">Thông Tin Tài Khoản</a></li>
                    <li><a href="/user/changepass">Đổi Mật Khẩu</a></li>
                </ul>
                <ul class="main-menu">
                     <h3 class="menu-title">-- Giao Dịch</h3>
                     <li><a href="/user/recharge">Nạp Thẻ Cào (Tự Động)</a></li>
                     <li><a href="/user/withdraw">Rút Vật Phẩm</a></li>
                </ul>
                <ul class="history-menu">
                    <h3 class="menu-title">-- Lịch Sử</h3>
                    <li><a href="/user/orders">Lịch Sử Mua Hàng</a></li>
                    <li><a href="/user/recharge/history">Lịch Sử Nạp Thẻ</a></li>
                </ul>
                 <div class="charge-section" style="padding-top: 10px; border-top: 1px solid #ddd;">
                      <button class="logout-button" onclick="Logout()">Đăng Xuất</button>
                </div>
            </div>
        </div>`;

    $('.tw-menu-right').html(userMenuHTML);
}


/**
 * Cập nhật giao diện khi người dùng chưa đăng nhập.
 */
function updateUIForLoggedOutUser() {
    const loginButtonHTML = `
        <button class="tw-bg-red-500 hover:tw-bg-red-600 tw-transition tw-duration-200 tw-text-white tw-text-sm tw-px-4 tw-rounded-full tw-font-semibold tw-h-8 md:tw-h-10 tw-relative" data-toggle="modal" data-target="#loginModal">
            <span class="tw-hidden md:tw-inline-block"><i class="tw-absolute tw-text-lg bx bxs-user" style="top: 10px;"></i></span> <span class="md:tw-ml-6">ĐĂNG NHẬP</span>
        </button>`;
    $('.tw-menu-right').html(loginButtonHTML);
}

/**
 * [QUAN TRỌNG] Kiểm tra trạng thái đăng nhập khi tải trang.
 * Luồng hoạt động:
 * 1. Kiểm tra localStorage trước để cập nhật UI ngay lập tức.
 * 2. Gửi yêu cầu ngầm đến server để xác thực lại và cập nhật dữ liệu mới nhất.
 */
function checkAuthOnLoad() {
    const userString = localStorage.getItem('user');
    if (userString) {
        try {
            const user = JSON.parse(userString);
            updateUIForLoggedInUser(user); // Cập nhật UI ngay lập tức

            // Xác thực lại với server để lấy dữ liệu mới nhất
            $.ajax({
                url: `${API_BASE_URL}/users/me`,
                type: "GET",
                xhrFields: { withCredentials: true },
                success: function(data) {
                    if (data.status === 'success' && data.data.user) {
                        localStorage.setItem('user', JSON.stringify(data.data.user));
                        updateUIForLoggedInUser(data.data.user); // Cập nhật lại với data mới nhất
                    } else {
                        Logout(false); // Token không hợp lệ hoặc lỗi, đăng xuất
                    }
                },
                error: function() {
                    Logout(false); // Lỗi API, đăng xuất
                }
            });
        } catch (e) {
            console.error("Lỗi parse JSON từ localStorage:", e);
            Logout(false); // Dữ liệu trong localStorage bị lỗi
        }
    } else {
        updateUIForLoggedOutUser();
    }
}


/**
 * Đăng nhập tài khoản.
 */
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
            if (data.status == 'success' && data.data.user) {
                $('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">Đăng nhập thành công!</div>');
                localStorage.setItem('user', JSON.stringify(data.data.user));
                updateUIForLoggedInUser(data.data.user);
                setTimeout(() => { window.location.reload(); }, 1000);
            } else {
                $('#msgLogin').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message || 'Đăng nhập thất bại'}</div>`);
            }
        },
        error: function(xhr) {
            let errorMsg = (xhr.responseJSON && xhr.responseJSON.message) ? xhr.responseJSON.message : 'Có lỗi xảy ra. Vui lòng thử lại!';
            $('#msgLogin').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${errorMsg}</div>`);
        }
    });
}

/**
 * Đăng ký tài khoản mới.
 */
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
            if (data.status == 'success' && data.data.user) {
                $('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">Đăng ký thành công! Đang chuyển hướng...</div>');
                localStorage.setItem('user', JSON.stringify(data.data.user));
                setTimeout(() => { window.location.href = "/"; }, 1500);
            } else {
                $('#msgReg').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message || 'Đăng ký thất bại'}</div>`);
            }
        },
        error: function(xhr) {
            let errorMsg = (xhr.responseJSON && xhr.responseJSON.message) ? xhr.responseJSON.message : 'Có lỗi xảy ra. Vui lòng thử lại!';
            $('#msgReg').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${errorMsg}</div>`);
        }
    });
}

/**
 * Đăng xuất tài khoản.
 * @param {boolean} redirect - Có chuyển hướng về trang chủ sau khi đăng xuất không.
 */
function Logout(redirect = true) {
    localStorage.removeItem('user');
    updateUIForLoggedOutUser(); // Cập nhật UI trước khi gọi API
    $.ajax({
        url: `${API_BASE_URL}/users/logout`,
        type: "GET",
        xhrFields: { withCredentials: true },
        complete: function() {
            if (redirect) {
                window.location.href = '/';
            }
        }
    });
}

/**
 * Đổi mật khẩu.
 */
function changePassword() {
    $('#msgPassword').empty();
    var data = $("#form-Pass").serialize();
    $.ajax({
        // SỬA LỖI: Sửa endpoint và phương thức cho đúng với chức năng đổi mật khẩu của người dùng đã đăng nhập.
        url: `${API_BASE_URL}/users/updateMyPassword`,
        data: data,
        dataType: "json",
        type: "PATCH",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgPassword').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">${data.message || 'Đổi mật khẩu thành công!'}</div>`);
                setTimeout(() => { window.location.href = "/user/changepass"; }, 2000);
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


// --- CÁC HÀM CHỨC NĂNG NGHIỆP VỤ (NẠP THẺ, MUA BÁN) ---

// SỬA LỖI: Hiển thị thông báo thân thiện cho các chức năng chưa có API thay vì gây lỗi console.
function showDevelopingAlert(selector) {
    $(selector).empty().html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-blue-100 tw-border-blue-300 tw-text-blue-500">Chức năng này đang được phát triển. Vui lòng quay lại sau!</div>');
}

/**
 * Sao chép ID người dùng.
 * @param {string} textToCopy - Nội dung cần sao chép.
 */
function copy(textToCopy) {
    navigator.clipboard.writeText(textToCopy).then(function() {
        alert('Sao chép thành công!');
    }, function(err) {
        console.error('Lỗi khi sao chép: ', err);
        alert('Sao chép thất bại!');
    });
}


function Napthe() {
    showDevelopingAlert('#msgCard');
}

function Withdrawal() {
    showDevelopingAlert('#msgDiamond');
}

function RobuxGamePass() {
    showDevelopingAlert('#msgRobuxGamePass');
}

function GamePass() {
    showDevelopingAlert('#msgGamePass');
}

function Items() {
    $("#items").prop("disabled", false).text('MUA NGAY');
    showDevelopingAlert('#msgItems');
}
