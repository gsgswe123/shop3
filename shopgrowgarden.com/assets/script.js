/****************************************************************
 * SCRIPT TỔNG HỢP CHO WEBSITE
 *
 * Phiên bản này đã được hợp nhất và tối ưu hóa để:
 * 1. Khắc phục lỗi đăng nhập liên tục.
 * 2. Cải thiện trải nghiệm người dùng bằng cách cập nhật giao diện ngay lập tức.
 * 3. Loại bỏ mã nguồn trùng lặp, giúp dễ bảo trì hơn.
 *
 ****************************************************************/

/* Backend API URL - CẬP NHẬT URL NÀY NẾU CẦN */
const API_BASE_URL = 'https://shop3-t86z.onrender.com/api/v1';

$(document).ready(function() {

    // --- KHỞI TẠO CÁC CHỨC NĂNG CHUNG ---

    /* Dropdown Profile */
    $(".dropdown-profile").on("click", function(event) {
        $(".dropdown-content").toggleClass("open");
    });

    $(document).on("click", function(e) {
        if (!$(e.target).closest('.dropdown-profile').length) {
            $('.dropdown-content').removeClass('open');
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
            url: `${API_BASE_URL}/event`,
            dataType: 'json',
            type: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
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

// --- CÁC HÀM XÁC THỰC VÀ QUẢN LÝ TÀI KHOẢN ---

/**
 * Cập nhật giao diện khi người dùng đã đăng nhập.
 * @param {object} user - Thông tin người dùng.
 */
function updateUIForLoggedInUser(user) {
    if (user && user.name) {
        $('.user-name').text(user.name);
        $('.user-email').text(user.email);
        $('.user-balance').text(user.balance || 0);
        $('.login-section').hide();
        $('.user-section').show();
    }
}

/**
 * Cập nhật giao diện khi người dùng chưa đăng nhập.
 */
function updateUIForLoggedOutUser() {
    $('.login-section').show();
    $('.user-section').hide();
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
            updateUIForLoggedInUser(user); // Cập nhật UI ngay

            // Xác thực lại với server
            $.ajax({
                url: `${API_BASE_URL}/users/me`,
                type: "GET",
                xhrFields: { withCredentials: true },
                success: function(data) {
                    if (data.status === 'success' && data.data.user) {
                        localStorage.setItem('user', JSON.stringify(data.data.user));
                        updateUIForLoggedInUser(data.data.user); // Cập nhật lại với data mới nhất
                    } else {
                        Logout(false); // Token không hợp lệ, đăng xuất
                    }
                },
                error: function() {
                    Logout(false); // Lỗi API, đăng xuất
                }
            });
        } catch (e) {
            Logout(false); // Dữ liệu trong localStorage lỗi
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
                setTimeout(() => { window.location.reload(); }, 1500);
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
                $('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">Đăng ký thành công!</div>');
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
    updateUIForLoggedOutUser();
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
        url: `${API_BASE_URL}/users/resetPassword`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgPassword').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">${data.message}</div>`);
                setTimeout(() => { window.location.href = "/user/changepass"; }, 2000);
            } else {
                $('#msgPassword').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message}</div>`);
            }
        },
        error: function() {
            $('#msgPassword').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">Có lỗi xảy ra. Vui lòng thử lại!</div>');
        }
    });
}

// --- CÁC HÀM CHỨC NĂNG NGHIỆP VỤ (NẠP THẺ, MUA BÁN) ---

/**
 * Sao chép ID người dùng.
 * @param {string} iduser - ID cần sao chép.
 */
function copy(iduser) {
    navigator.clipboard.writeText(iduser).then(function() {
        alert('Sao Chép Thành Công!');
    }, function(err) {
        console.error('Sao Chép Lỗi: ', err);
    });
}

/**
 * Nạp thẻ cào.
 */
function Napthe() {
    $('#msgCard').empty();
    var data = $("#charge").serialize();
    $.ajax({
        url: `${API_BASE_URL}/recharge`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgCard').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">${data.message}</div>`);
                setTimeout(() => { window.location.href = "/user/recharge"; }, 2000);
            } else {
                $('#msgCard').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message}</div>`);
            }
        },
        error: function() {
            $('#msgCard').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">Có lỗi xảy ra. Vui lòng thử lại!</div>');
        }
    });
}

/**
 * Rút vật phẩm.
 */
function Withdrawal() {
    $('#msgDiamond').empty();
    var data = $("#form-Diamond").serialize();
    $.ajax({
        url: `${API_BASE_URL}/withdrawal`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgDiamond').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">${data.message}</div>`);
                setTimeout(() => { window.location.href = "/user/withdraw"; }, 2000);
            } else {
                $('#msgDiamond').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message}</div>`);
            }
        },
        error: function() {
            $('#msgDiamond').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">Có lỗi xảy ra. Vui lòng thử lại!</div>');
        }
    });
}

/**
 * Mua Robux Gamepass & SeverVIP.
 */
function RobuxGamePass() {
    $('#msgRobuxGamePass').empty();
    var data = $("#form-RobuxGamePass").serialize();
    $.ajax({
        url: `${API_BASE_URL}/robux-gamepass`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgRobuxGamePass').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">${data.message}</div>`);
                setTimeout(() => { window.location.href = "/robux-gamepass-severvip"; }, 2000);
            } else {
                $('#msgRobuxGamePass').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message}</div>`);
            }
        },
        error: function() {
            $('#msgRobuxGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">Có lỗi xảy ra. Vui lòng thử lại!</div>');
        }
    });
}

/**
 * Mua GamePass Blox Fruit.
 */
function GamePass() {
    $('#msgGamePass').empty();
    var data = $("#form-GamePass").serialize();
    $.ajax({
        url: `${API_BASE_URL}/gamepass`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgGamePass').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500">${data.message}</div>`);
                setTimeout(() => { window.location.href = "/gamepass-blox-fruit"; }, 2000);
            } else {
                $('#msgGamePass').html(`<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">${data.message}</div>`);
            }
        },
        error: function() {
            $('#msgGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500">Có lỗi xảy ra. Vui lòng thử lại!</div>');
        }
    });
}

/**
 * Mua Items Anime Defenders.
 */
function Items() {
    $('#msgItems').empty();
    $("#items").prop("disabled", true).text('ĐANG MUA...');
    var data = $("#form-Items").serialize();
    $.ajax({
        url: `${API_BASE_URL}/items`,
        data: data,
        dataType: "json",
        type: "POST",
        xhrFields: { withCredentials: true },
        success: function(data) {
            if (data.status == 'success') {
                $('#msgItems').html(`<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-green-100 ws-border-green-300 ws-text-green-500">${data.message}</div>`);
                setTimeout(() => { window.location.href = "/items-anime-defenders"; }, 2000);
            } else {
                $('#msgItems').html(`<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-red-100 ws-border-red-300 ws-text-red-500">${data.message}</div>`);
            }
        },
        error: function() {
            $('#msgItems').html('<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-red-100 ws-border-red-300 ws-text-red-500">Có lỗi xảy ra. Vui lòng thử lại!</div>');
        },
        complete: function() {
             $("#items").prop("disabled", false).text('MUA NGAY');
        }
    });
}