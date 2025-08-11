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

/* Đổi Mật Khẩu */
function changePassword(){
$('#msgPassword').empty();
var data = $("#form-Pass").serialize();
$.ajax({
    url: '/Model/Password',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
if (data.status == 'success') {
$('#msgPassword').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/user/changepass"}, 2000);
}else{
$('#msgPassword').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
}
});
}

/* Rút Vật Phẩm */
function Withdrawal(){
$('#msgDiamond').empty();
var data = $("#form-Diamond").serialize();
$.ajax({
    url: '/Model/Withdrawal',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
if(data.status == 'success') {
$('#msgDiamond').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/user/withdraw"}, 2000);
}else{
$('#msgDiamond').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
}
});
}

/* Nhận Quà Miễn Phí */
$(document).ready(function(){
$('body').delegate('#reward', 'click', function() {
$.ajax({
    url : '/Model/Event',
    dataType : 'json',
    type : 'POST',
success : function(data){
if (data.status == 'LOGIN') {
$("#loginModal").modal('show');
}else{
$('#reward').css('opacity','0');
$('.content-popup').html(data.msg);
$('#modalMinigame').modal('show');
}
}
});
});
});

/* Nạp Thẻ Cào */
function Napthe(){
$('#msgCard').empty();
var data = $("#charge").serialize();
$.ajax({
    url: '/Model/Recharge',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
if (data.status == 'success') {
$('#msgCard').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/user/recharge"}, 2000);
}else{
$('#msgCard').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
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
var data = $("#form-Login").serialize();
$.ajax({
    url: '/Model/Login',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
if (data.status == 'success') {
$('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/"}, 2000);
}else{
$('#msgLogin').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
}
});
}

/* Tạo Tài Khoản */
function Register(){
var data = $("#form-Register").serialize();
$.ajax({
    url: '/Model/SignUp',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data){
if(data.status == 'success') {
$('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/"}, 2000);
}else{
$('#msgReg').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
}
});
}

/* Robux Gamepass & SeverVIP */
function RobuxGamePass(){
$('#msgRobuxGamePass').empty();
var data = $("#form-RobuxGamePass").serialize();
$.ajax({
    url: '/Model/RobuxGamePass',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
if(data.status == 'success') {
$('#msgRobuxGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/robux-gamepass-severvip"}, 2000);
}else{
$('#msgRobuxGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
}
});
}

/* GamePass Blox Fruit */
function GamePass(){
$('#msgGamePass').empty();
var data = $("#form-GamePass").serialize();
$.ajax({
    url: '/Model/GamePass',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
if(data.status == 'success') {
$('#msgGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-green-100 tw-border-green-300 tw-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/gamepass-blox-fruit"}, 2000);
}else{
$('#msgGamePass').html('<div class="tw-py-2 tw-px-3 tw-border tw-rounded tw-text-sm tw-w-full tw-block tw-font-semibold tw-bg-red-100 tw-border-red-300 tw-text-red-500"><div class="relative">'+data.msg+'</div>');
}
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
    url: '/Model/Items',
    data: data,
    dataType: "json",
    type: "POST",
success: function(data) {
$("#items").attr("disabled", false);
$("#items").text('MUA NGAY');
if(data.status == 'success') {
$('#msgItems').html('<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-green-100 ws-border-green-300 ws-text-green-500"><div class="relative">'+data.msg+'</div>');
setTimeout(function(){window.location.href = "/items-anime-defenders"}, 2000);
}else{
$('#msgItems').html('<div class="ws-py-2 ws-px-3 ws-border ws-rounded ws-text-sm ws-w-full ws-block ws-font-semibold ws-bg-red-100 ws-border-red-300 ws-text-red-500"><div class="relative">'+data.msg+'</div>');
}
}
});
}