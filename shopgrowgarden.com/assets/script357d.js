/* Dropdown Profile */
$(document).ready( function() {
$(".dropdown-profile").on("click", (event) =>{
console.log("click");
$(".dropdown-content").toggleClass("open");
});
$(document).click(function (e) {
$('.dropdown-profile').not($('.dropdown-profile').has($(e.target))).children('.dropdown-content').removeClass('open');
})
})

/* Menu */
$(document).ready(function(){
$("#menuToggle").on('click', function(){
$(this).hide();
$("#menuProfile").show();
});
$("#menuHide").on('click', function(){
$("#menuToggle").show();
$("#menuProfile").hide();
});
});

/* Back To TOP */
$('#backToTop').on('click', function(e) {
e.preventDefault();
$('html, body').animate({ scrollTop: 0 }, '300');
});

/* Alert */
$(document).ready(function(){
$("#modalThongBao").modal('show');
});

/* Index modal */
function closeModalindex(){
$("#modalThongBao").hide();
}
function closeModal(){
$("#modalMinigame").removeClass("show");
}
function closeGift() {
$('#modalGift').remove();
}

/* Backend API URL - UPDATE THIS TO YOUR ACTUAL BACKEND URL */
const API_BASE_URL = 'https://shop3-374p.onrender.com/api/v1'; // Replace with your actual backend URL

/* Đổi Mật Khẩu */
function changePassword(){
$('#msgPassword').empty();
var data = $("#form-Pass").serialize();
$.ajax({
    url: `${API_BASE_URL}/users/resetPassword`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
if (data.status == 'success') {
$('#msgPassword').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.message+'</div>');
setTimeout(function(){window.location.href = "/user/changepass"}, 2000);
}else{
$('#msgPassword').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.message+'</div>');
}
},
error: function(xhr, status, error) {
$('#msgPassword').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">Có lỗi xảy ra. Vui lòng thử lại!</div>');
}
});
}

/* Rút Vật Phẩm */
function Withdrawal(){
$('#msgDiamond').empty();
var data = $("#form-Diamond").serialize();
$.ajax({
    url: `${API_BASE_URL}/withdrawal`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
if(data.status == 'success') {
$('#msgDiamond').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.message+'</div>');
setTimeout(function(){window.location.href = "/user/withdraw"}, 2000);
}else{
$('#msgDiamond').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.message+'</div>');
}
},
error: function(xhr, status, error) {
$('#msgDiamond').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">Có lỗi xảy ra. Vui lòng thử lại!</div>');
}
});
}

/* Nhận Quà Miễn Phí */
$(document).ready(function(){
$('body').delegate('#reward', 'click', function() {
$.ajax({
    url : `${API_BASE_URL}/event`,
    dataType : 'json',
    type : 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    xhrFields: {
        withCredentials: true
    },
success : function(data){
if (data.status == 'LOGIN') {
$("#loginModal").modal('show');
}else{
$('#reward').css('opacity','0');
$('.content-popup').html(data.message || data.msg);
$('#modalMinigame').modal('show');
}
},
error: function(xhr, status, error) {
console.error('Event error:', error);
}
});
});
});

/* Nạp Thẻ Cào */
function Napthe(){
$('#msgCard').empty();
var data = $("#charge").serialize();
$.ajax({
    url: `${API_BASE_URL}/recharge`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
if (data.status == 'success') {
$('#msgCard').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.message+'</div>');
setTimeout(function(){window.location.href = "/user/recharge"}, 2000);
}else{
$('#msgCard').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.message+'</div>');
}
},
error: function(xhr, status, error) {
$('#msgCard').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">Có lỗi xảy ra. Vui lòng thử lại!</div>');
}
});
}

/* Sao Chép ID */
function copy(iduser){
navigator.clipboard.writeText(iduser).then(function() {
alert('Sao Chép Thành Công!');
}, function(err) {
console.error('Sao Chép Lỗi: ', err);
});
}

/* Đăng Nhập Tài Khoản */
function Login(){
$('#msgLogin').empty();
var data = $("#form-Login").serialize();
$.ajax({
    url: `${API_BASE_URL}/users/login`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
if (data.status == 'success') {
$('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">Đăng nhập thành công!</div>');
// Store user data if needed
if(data.data && data.data.user) {
    localStorage.setItem('user', JSON.stringify(data.data.user));
}
setTimeout(function(){window.location.href = "/"}, 2000);
}else{
$('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+(data.message || 'Đăng nhập thất bại')+'</div>');
}
},
error: function(xhr, status, error) {
console.error('Login error:', xhr.responseText);
let errorMsg = 'Có lỗi xảy ra. Vui lòng thử lại!';
if(xhr.responseJSON && xhr.responseJSON.message) {
    errorMsg = xhr.responseJSON.message;
}
$('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+errorMsg+'</div>');
}
});
}

/* Tạo Tài Khoản */
function Register(){
$('#msgReg').empty();
var data = $("#form-Register").serialize();
$.ajax({
    url: `${API_BASE_URL}/users/signup`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data){
if(data.status == 'success') {
$('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">Đăng ký thành công!</div>');
// Store user data if needed
if(data.data && data.data.user) {
    localStorage.setItem('user', JSON.stringify(data.data.user));
}
setTimeout(function(){window.location.href = "/"}, 2000);
}else{
$('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+(data.message || 'Đăng ký thất bại')+'</div>');
}
},
error: function(xhr, status, error) {
console.error('Register error:', xhr.responseText);
let errorMsg = 'Có lỗi xảy ra. Vui lòng thử lại!';
if(xhr.responseJSON && xhr.responseJSON.message) {
    errorMsg = xhr.responseJSON.message;
}
$('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+errorMsg+'</div>');
}
});
}

/* Robux Gamepass & SeverVIP */
function RobuxGamePass(){
$('#msgRobuxGamePass').empty();
var data = $("#form-RobuxGamePass").serialize();
$.ajax({
    url: `${API_BASE_URL}/robux-gamepass`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
if(data.status == 'success') {
$('#msgRobuxGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.message+'</div>');
setTimeout(function(){window.location.href = "/robux-gamepass-severvip"}, 2000);
}else{
$('#msgRobuxGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.message+'</div>');
}
},
error: function(xhr, status, error) {
$('#msgRobuxGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">Có lỗi xảy ra. Vui lòng thử lại!</div>');
}
});
}

/* GamePass Blox Fruit */
function GamePass(){
$('#msgGamePass').empty();
var data = $("#form-GamePass").serialize();
$.ajax({
    url: `${API_BASE_URL}/gamepass`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
if(data.status == 'success') {
$('#msgGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.message+'</div>');
setTimeout(function(){window.location.href = "/gamepass-blox-fruit"}, 2000);
}else{
$('#msgGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.message+'</div>');
}
},
error: function(xhr, status, error) {
$('#msgGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">Có lỗi xảy ra. Vui lòng thử lại!</div>');
}
});
}

/* Items Anime Defenders */
function Items(){
$('#msgItems').empty();
$("#items").attr("disabled", true);
$("#items").text('ĐANG MUA...');
var data = $("#form-Items").serialize();
$.ajax({
    url: `${API_BASE_URL}/items`,
    data: data,
    dataType: "json",
    type: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    xhrFields: {
        withCredentials: true
    },
success: function(data) {
$("#items").attr("disabled", false);
$("#items").text('MUA NGAY');
if(data.status == 'success') {
$('#msgItems').html('<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-green-100 ws-border-green-300 ws-text-green-500"><div class="relative">'+data.message+'</div>');
setTimeout(function(){window.location.href = "/items-anime-defenders"}, 2000);
}else{
$('#msgItems').html('<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-red-100 ws-border-red-300 ws-text-red-500"><div class="relative">'+data.message+'</div>');
}
},
error: function(xhr, status, error) {
$("#items").attr("disabled", false);
$("#items").text('MUA NGAY');
$('#msgItems').html('<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-red-100 ws-border-red-300 ws-text-red-500"><div class="relative">Có lỗi xảy ra. Vui lòng thử lại!</div>');
}
});
}

/* Logout function */
function Logout() {
    $.ajax({
        url: `${API_BASE_URL}/users/logout`,
        type: "GET",
        xhrFields: {
            withCredentials: true
        },
        success: function(data) {
            localStorage.removeItem('user');
            window.location.href = '/';
        },
        error: function(xhr, status, error) {
            console.error('Logout error:', error);
            // Force logout even if request fails
            localStorage.removeItem('user');
            window.location.href = '/';
        }
    });
}

/* Check if user is logged in */
function checkAuthStatus() {
    $.ajax({
        url: `${API_BASE_URL}/users/me`,
        type: "GET",
        xhrFields: {
            withCredentials: true
        },
        success: function(data) {
            if(data.status === 'success' && data.data.user) {
                // User is logged in
                localStorage.setItem('user', JSON.stringify(data.data.user));
                updateUIForLoggedInUser(data.data.user);
            }
        },
        error: function(xhr, status, error) {
            // User is not logged in
            localStorage.removeItem('user');
            updateUIForLoggedOutUser();
        }
    });
}

/* Update UI based on auth status */
function updateUIForLoggedInUser(user) {
    // Update user info in UI
    $('.user-name').text(user.name);
    $('.user-email').text(user.email);
    $('.user-balance').text(user.balance || 0);
    $('.login-section').hide();
    $('.user-section').show();
}

function updateUIForLoggedOutUser() {
    $('.login-section').show();
    $('.user-section').hide();
}

/* Initialize on page load */
$(document).ready(function() {
    checkAuthStatus();
});