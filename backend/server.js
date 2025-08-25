const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const nodemailer = require('nodemailer');
const validator = require('validator');
const axios = require('axios');

// Load environment variables
dotenv.config({ path: './config.env' });

const app = express();

// Middleware configuration - ĐẶC BIỆT QUAN TRỌNG CHO CALLBACK
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Quan trọng cho callback form-data
app.use(cookieParser());
app.set('trust proxy', true);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://gsgswe123.github.io',
      'https://gsgswe123.github.io/shop3/',
      'http://127.0.0.1:5500',
      'http://localhost:3000',
      'https://localhost:3000'
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Database configuration
const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

// Schemas
const sessionSchema = new mongoose.Schema({
  tokenIdentifier: { type: String, unique: true, required: true },
  deviceInfo: String,
  ipAddress: String,
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: Date.now }
}, { _id: false });

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please provide your name'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  avatarText: {
    type: String,
    default: function() {
      return this.name ? this.name.charAt(0).toUpperCase() : 'U';
    }
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords do not match!',
    },
  },
  balance: {
    type: Number,
    default: 0,
    min: [0, 'Balance cannot be negative']
  },
  favorites: [{
    type: mongoose.Schema.ObjectId,
    ref: 'Product',
  }],
  cart: [{
    product: {
      type: mongoose.Schema.ObjectId,
      ref: 'Product',
    },
    quantity: {
      type: Number,
      default: 1,
      min: [1, 'Quantity must be at least 1']
    }
  }],
  sessions: [sessionSchema],
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ 'sessions.tokenIdentifier': 1 });

// User middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  this.sessions = [];
  next();
});

// User methods
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'A product must have a title'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'A product must have a description'],
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  price: {
    type: Number,
    required: [true, 'A product must have a price'],
    min: [1000, 'Price must be at least 1,000 VND']
  },
  oldPrice: {
    type: Number,
    validate: {
      validator: function(val) {
        return !val || val > this.price;
      },
      message: 'Old price must be greater than current price'
    }
  },
  images: {
    type: [String],
    validate: {
      validator: function(images) {
        return images && images.length > 0;
      },
      message: 'Product must have at least one image'
    }
  },
  image: {
    type: String,
    default: function() {
      return this.images && this.images.length > 0 ? this.images[0] : null;
    }
  },
  category: {
    type: String,
    enum: ['plants', 'pets', 'game-accounts', 'services'],
    default: 'services'
  },
  features: [String],
  sales: {
    type: Number,
    default: 0,
    min: [0, 'Sales cannot be negative']
  },
  stock: {
    type: Number,
    default: 999,
    min: [0, 'Stock cannot be negative']
  },
  badge: {
    type: String,
    enum: ['HOT', 'NEW', 'SALE', 'BEST', null],
    default: null,
  },
  link: {
    type: String,
    required: [true, 'Product must have a purchase link'],
    validate: {
      validator: function(v) {
        return validator.isURL(v);
      },
      message: 'Please provide a valid URL'
    }
  },
  createdBy: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Product must have a creator']
  },
  active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Product indexes
productSchema.index({ createdAt: -1 });
productSchema.index({ category: 1 });
productSchema.index({ price: 1 });
productSchema.index({ createdBy: 1 });
productSchema.index({ active: 1 });

// Product virtual
productSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'product',
  localField: '_id'
});

// Product middleware
productSchema.pre('save', function(next) {
  if (this.images && this.images.length > 0 && !this.image) {
    this.image = this.images[0];
  }
  next();
});

const Product = mongoose.model('Product', productSchema);

// Review Schema
const reviewSchema = new mongoose.Schema({
  review: {
    type: String,
    required: [true, 'Review cannot be empty'],
    maxlength: [500, 'Review cannot exceed 500 characters']
  },
  rating: {
    type: Number,
    min: [1, 'Rating must be at least 1'],
    max: [5, 'Rating cannot exceed 5'],
    required: [true, 'Review must have a rating']
  },
  product: {
    type: mongoose.Schema.ObjectId,
    ref: 'Product',
    required: [true, 'Review must belong to a product'],
  },
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'Review must belong to a user'],
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Review indexes
reviewSchema.index({ product: 1, user: 1 }, { unique: true });
reviewSchema.index({ product: 1 });
reviewSchema.index({ user: 1 });

// Review middleware
reviewSchema.pre(/^find/, function(next) {
  this.populate({
    path: 'user',
    select: 'name avatarText',
  });
  next();
});

const Review = mongoose.model('Review', reviewSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    enum: ['deposit', 'purchase'],
    required: true,
  },
  method: {
    type: String,
    enum: ['card', 'system'],
    default: 'card',
  },
  amount: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    enum: ['pending', 'success', 'failed'],
    default: 'pending',
  },
  description: String,
  gatewayTransactionId: String, // Dùng để lưu request_id
  failureReason: String,
  details: {
    cardType: String,
    cardSerial: String,
    cardNumber: String,
  },
}, { timestamps: true });

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ gatewayTransactionId: 1 }); // Thêm index này cho tìm kiếm nhanh

const Transaction = mongoose.model('Transaction', transactionSchema);

// Utility functions
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// JWT functions
const signToken = (id, sessionId) => {
  return jwt.sign({ id, sessionId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '90d',
  });
};

const createSendToken = (user, sessionId, statusCode, res) => {
  const token = signToken(user._id, sessionId);
  const cookieOptions = {
    expires: new Date(
      Date.now() + (process.env.JWT_COOKIE_EXPIRES_IN || 90) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  };

  res.cookie('jwt', token, cookieOptions);
  
  const userResponse = {
    _id: user._id,
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    balance: user.balance || 0,
    avatarText: user.avatarText,
    createdAt: user.createdAt
  };

  res.status(statusCode).json({
    status: 'success',
    token,
    sessionId,
    data: { user: userResponse },
  });
};

// Error handling functions
const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}.`;
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg ? err.errmsg.match(/(["'])(\\?.)*?\1/)?.[0] : 'duplicate value';
  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new AppError(message, 400);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

const handleJWTError = () => new AppError('Invalid token. Please log in again!', 401);
const handleJWTExpiredError = () => new AppError('Your token has expired! Please log in again.', 401);

const sendErrorDev = (err, res) => {
  res.status(err.statusCode || 500).json({
    status: err.status || 'error',
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

const sendErrorProd = (err, res) => {
  if (err.isOperational) {
    res.status(err.statusCode || 500).json({
      status: err.status || 'error',
      message: err.message,
    });
  } else {
    console.error('ERROR 💥', err);
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong!',
    });
  }
};

const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;
    error.name = err.name;

    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, res);
  }
};

// -----------------------------------------------------------------------------
// --- DOITHE1S.VN PAYMENT SERVICE - CẢI TIẾN VÀ BẢO MẬT HƠN ---
// -----------------------------------------------------------------------------
const doithe1sService = {
  /**
   * Gửi yêu cầu đổi thẻ lên doithe1s.vn
   * @param {Object} cardInfo - Thông tin thẻ cào
   * @returns {Promise<Object>} Response từ API
   */
  sendCardRequest: async (cardInfo) => {
    const { telco, code, serial, amount, request_id } = cardInfo;
    
    // Kiểm tra các biến môi trường bắt buộc
    const PARTNER_ID = process.env.DOITHE1S_PARTNER_ID;
    const PARTNER_KEY = process.env.DOITHE1S_PARTNER_KEY;
    const API_URL = process.env.DOITHE1S_API_URL;

    if (!PARTNER_ID || !PARTNER_KEY || !API_URL) {
      console.error('❌ [DOITHE1S] Missing required environment variables');
      return { 
        status: -1, 
        message: 'Cấu hình thanh toán chưa đầy đủ. Vui lòng liên hệ admin.' 
      };
    }

    try {
      // -----------------------------------------------------------------
      // CẢNH BÁO BẢO MẬT: CÔNG THỨC TẠO CHỮ KÝ KHI GỬI THẺ (SIGN)
      // - Công thức dưới đây chỉ là VÍ DỤ phổ biến: md5(PARTNER_KEY + code + serial)
      // - BẠN BẮT BUỘC PHẢI MỞ TÀI LIỆU API CHÍNH THỨC CỦA DOITHE1S.VN
      // - ĐỂ XÁC NHẬN CÔNG THỨC CHÍNH XÁC CHO VIỆC GỬI THẺ
      // - Sai chữ ký sẽ khiến mọi giao dịch của bạn bị từ chối ngay lập tức
      // -----------------------------------------------------------------
      const sign = crypto
        .createHash('md5')
        .update(PARTNER_KEY + code + serial)
        .digest('hex');

      // Chuẩn bị parameters theo format form-urlencoded
      const params = new URLSearchParams();
      params.append('telco', telco);
      params.append('code', code);
      params.append('serial', serial);
      params.append('amount', amount.toString());
      params.append('request_id', request_id);
      params.append('partner_id', PARTNER_ID);
      params.append('sign', sign);
      params.append('command', 'charging');

      console.log('🔄 [DOITHE1S] Sending card request:', {
        request_id,
        telco,
        amount,
        serial: `${serial.substring(0, 4)}****${serial.substring(serial.length - 4)}` // Che serial để bảo mật log
      });

      const response = await axios.post(API_URL, params, {
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Shop-Backend/1.0'
        },
        timeout: 30000 // 30 giây timeout
      });

      console.log('✅ [DOITHE1S] API Response:', {
        request_id,
        status: response.data.status,
        message: response.data.message
      });

      return response.data;
      
    } catch (error) {
      console.error('❌ [DOITHE1S] API Call Failed:', {
        request_id,
        error: error.message,
        response: error.response?.data
      });
      
      // Trả về response thống nhất cho mọi lỗi
      return { 
        status: -1, 
        message: 'Không thể kết nối đến cổng thanh toán. Vui lòng thử lại sau.' 
      };
    }
  },

  /**
   * Validate callback signature - QUAN TRỌNG NHẤT CHO BẢO MẬT
   * @param {Object} callbackData - Dữ liệu từ callback
   * @returns {boolean} True nếu chữ ký hợp lệ
   */
  validateCallbackSignature: (callbackData) => {
    const { status, request_id, sign } = callbackData;
    const PARTNER_KEY = process.env.DOITHE1S_PARTNER_KEY;

    if (!sign || !status || !request_id || !PARTNER_KEY) {
      console.warn('⚠️  [CALLBACK-SECURITY] Missing required fields for signature validation');
      return false;
    }

    // -----------------------------------------------------------------
    // CẢNH BÁO BẢO MẬT CỰC QUAN TRỌNG: CÔNG THỨC XÁC THỰC CHỮ KÝ CALLBACK
    // - Công thức dưới đây là VÍ DỤ: md5(PARTNER_KEY + status + request_id)
    // - BẠN BẮT BUỘC PHẢI KIỂM TRA VỚI TÀI LIỆU CHÍNH THỨC CỦA DOITHE1S.VN
    // - NẾU SAI CÔNG THỨC NÀY, KẺ GIAN CÓ THỂ TỰ CỘNG TIỀN VÀO TÀI KHOẢN NGƯỜI DÙNG!
    // -----------------------------------------------------------------
    const expectedSign = crypto
      .createHash('md5')
      .update(PARTNER_KEY + status + request_id)
      .digest('hex');

    const isValid = sign === expectedSign;
    
    if (!isValid) {
      console.error('🚨 [CALLBACK-SECURITY] INVALID SIGNATURE DETECTED:', {
        request_id,
        received_sign: sign,
        expected_sign: expectedSign,
        ip: 'unknown' // Có thể thêm IP logging
      });
    }

    return isValid;
  }
};

// Controllers
const authController = {
  signup: catchAsync(async (req, res, next) => {
    const { name, email, password, passwordConfirm, role } = req.body;

    if (!name || !email || !password || !passwordConfirm) {
      return next(new AppError('Please provide all required fields', 400));
    }

    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return next(new AppError('User with this email already exists', 400));
    }

    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      passwordConfirm,
      role: role === 'admin' ? 'user' : (role || 'user'), // Chặn tự đăng ký admin
    });

    const sessionId = crypto.randomBytes(16).toString('hex');
    const newSession = {
      tokenIdentifier: sessionId,
      deviceInfo: req.headers['user-agent'] || 'Unknown Device',
      ipAddress: req.ip,
    };
    newUser.sessions.push(newSession);
    await newUser.save({ validateBeforeSave: false });

    createSendToken(newUser, sessionId, 201, res);
  }),

  login: catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new AppError('Please provide email and password', 400));
    }

    const user = await User.findOne({
      email: email.toLowerCase().trim(),
      active: { $ne: false }
    }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    const sessionId = crypto.randomBytes(16).toString('hex');
    const newSession = {
      tokenIdentifier: sessionId,
      deviceInfo: req.headers['user-agent'] || 'Unknown Device',
      ipAddress: req.ip,
      lastUsedAt: Date.now()
    };

    const MAX_SESSIONS = 10;
    if (user.sessions.length >= MAX_SESSIONS) {
      user.sessions.sort((a, b) => a.lastUsedAt - b.lastUsedAt).shift();
    }

    user.sessions.push(newSession);
    await user.save({ validateBeforeSave: false });

    createSendToken(user, sessionId, 200, res);
  }),

  logout: (req, res) => {
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });
    res.status(200).json({
      status: 'success',
      message: 'Logged out successfully. Please clear token on client-side.'
    });
  }),

  protect: catchAsync(async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt && req.cookies.jwt !== 'loggedout') {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    const currentSession = currentUser.sessions.find(session => session.tokenIdentifier === decoded.sessionId);
    if (!currentSession) {
      return next(new AppError('This session has been terminated. Please log in again.', 401));
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('User recently changed password! Please log in again.', 401));
    }
    
    // Update last used time asynchronously
    User.updateOne(
      { _id: currentUser._id, 'sessions.tokenIdentifier': decoded.sessionId },
      { $set: { 'sessions.$.lastUsedAt': Date.now() } }
    ).exec();

    req.user = currentUser;
    req.sessionId = decoded.sessionId;
    res.locals.user = currentUser;
    next();
  }),

  restrictTo: (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return next(new AppError('You are not logged in', 401));
      }
      if (!roles.includes(req.user.role)) {
        return next(new AppError('You do not have permission to perform this action', 403));
      }
      next();
    };
  },

  forgotPassword: catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email?.toLowerCase().trim() });
    if (!user) {
      return next(new AppError('There is no user with that email address.', 404));
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Password reset token sent to email!',
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
  }),

  resetPassword: catchAsync(async (req, res, next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const sessionId = crypto.randomBytes(16).toString('hex');
    const newSession = {
      tokenIdentifier: sessionId,
      deviceInfo: req.headers['user-agent'] || 'Unknown Device',
      ipAddress: req.ip,
    };
    user.sessions = [newSession];
    await user.save({ validateBeforeSave: false });

    createSendToken(user, sessionId, 200, res);
  }),

  updatePassword: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).select('+password');

    if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
      return next(new AppError('Your current password is incorrect.', 401));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    
    const currentSession = user.sessions.find(s => s.tokenIdentifier === req.sessionId);
    user.sessions = currentSession ? [currentSession] : [];
    await user.save();
    
    createSendToken(user, req.sessionId, 200, res);
  }),
};

// -----------------------------------------------------------------------------
// --- TRANSACTION AND PAYMENT CONTROLLERS - CẢI TIẾN VÀ BẢO MẬT HƠN ---
// -----------------------------------------------------------------------------
const transactionController = {
  /**
   * Nạp tiền bằng thẻ cào - với validation và security tốt hơn
   */
  depositWithCard: catchAsync(async (req, res, next) => {
    const { telco, code, serial, amount } = req.body;
    const userId = req.user.id;

    // Validation đầu vào chi tiết hơn
    if (!telco || !code || !serial || !amount) {
      return next(new AppError('Vui lòng điền đầy đủ thông tin thẻ cào (nhà mạng, mã thẻ, serial, mệnh giá).', 400));
    }

    // Validate telco
    const validTelcos = ['VIETTEL', 'VINAPHONE', 'MOBIFONE', 'VIETNAMOBILE', 'GMOBILE'];
    if (!validTelcos.includes(telco.toUpperCase())) {
      return next(new AppError('Nhà mạng không được hỗ trợ.', 400));
    }

    // Validate và parse amount
    const parsedAmount = parseInt(amount, 10);
    const validAmounts = [10000, 20000, 50000, 100000, 200000, 300000, 500000, 1000000];
    
    if (isNaN(parsedAmount) || !validAmounts.includes(parsedAmount)) {
      return next(new AppError(`Mệnh giá không hợp lệ. Chỉ chấp nhận: ${validAmounts.map(a => a.toLocaleString('vi-VN')).join(', ')}đ`, 400));
    }

    // Validate format thẻ (có thể tùy chỉnh theo từng nhà mạng)
    if (code.length < 10 || code.length > 15) {
      return next(new AppError('Mã thẻ không đúng định dạng.', 400));
    }

    if (serial.length < 10 || serial.length > 15) {
      return next(new AppError('Serial không đúng định dạng.', 400));
    }

    // Kiểm tra rate limit (không cho phép spam request)
    const recentTransactions = await Transaction.find({
      user: userId,
      type: 'deposit',
      createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) } // 5 phút gần đây
    });

    if (recentTransactions.length >= 3) {
      return next(new AppError('Bạn đã nạp quá nhiều lần trong 5 phút. Vui lòng chờ một chút.', 429));
    }

    // Tạo request_id duy nhất
    const requestId = `NAP_${userId.toString().slice(-6)}_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`;
    
    // Tạo transaction pending trước
    const pendingTransaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      method: 'card',
      amount: parsedAmount,
      status: 'pending',
      gatewayTransactionId: requestId,
      description: `Đang xử lý nạp thẻ ${telco} mệnh giá ${parsedAmount.toLocaleString('vi-VN')}đ`,
      details: { 
        cardType: telco.toUpperCase(), 
        cardNumber: code.slice(-4), // Chỉ lưu 4 số cuối để bảo mật
        cardSerial: serial.slice(-4) // Chỉ lưu 4 số cuối để bảo mật
      }
    });

    console.log('💳 [DEPOSIT] New card request:', {
      user: req.user.name,
      userId,
      requestId,
      telco,
      amount: parsedAmount
    });

    // Gọi API doithe1s
    const apiResponse = await doithe1sService.sendCardRequest({
      telco: telco.toUpperCase(),
      code,
      serial,
      amount: parsedAmount,
      request_id: requestId,
    });

    // Xử lý response từ API
    if (apiResponse.status !== 99 && apiResponse.status !== '99') { // Một số API trả về string
      pendingTransaction.status = 'failed';
      pendingTransaction.description = `Thất bại: ${apiResponse.message || 'Thẻ không hợp lệ hoặc đã được sử dụng.'}`;
      pendingTransaction.failureReason = apiResponse.status?.toString();
      await pendingTransaction.save();
      
      console.log('❌ [DEPOSIT] Failed request:', {
        requestId,
        status: apiResponse.status,
        message: apiResponse.message
      });
      
      return next(new AppError(pendingTransaction.description, 400));
    }

    console.log('✅ [DEPOSIT] Request accepted:', {
      requestId,
      status: apiResponse.status,
      message: apiResponse.message
    });

    res.status(200).json({
      status: 'success',
      message: 'Yêu cầu nạp thẻ đã được gửi thành công và đang được xử lý. Kết quả sẽ được cập nhật trong vài phút.',
      data: { 
        transaction: {
          _id: pendingTransaction._id,
          requestId,
          amount: parsedAmount,
          status: 'pending',
          createdAt: pendingTransaction.createdAt
        }
      },
    });
  }),

  /**
   * Lấy lịch sử giao dịch của user
   */
  getMyTransactions: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const transactions = await Transaction.find({ user: req.user.id })
      .sort('-createdAt')
      .skip(skip)
      .limit(limit)
      .select('-details.cardNumber -details.cardSerial'); // Ẩn thông tin nhạy cảm

    const total = await Transaction.countDocuments({ user: req.user.id });

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      data: { transactions }
    });
  }),

  /**
   * Lấy thống kê giao dịch (cho admin)
   */
  getTransactionStats: catchAsync(async (req, res, next) => {
    const stats = await Transaction.aggregate([
      {
        $group: {
          _id: {
            status: '$status',
            type: '$type'
          },
          count: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      },
      {
        $group: {
          _id: '$_id.type',
          stats: {
            $push: {
              status: '$_id.status',
              count: '$count',
              totalAmount: '$totalAmount'
            }
          }
        }
      }
    ]);

    res.status(200).json({
      status: 'success',
      data: { stats }
    });
  })
};

/**
 * Controller xử lý callback từ doithe1s.vn - CỰC KỲ QUAN TRỌNG CHO BẢO MẬT
 */
const paymentCallbackController = {
  /**
   * Xử lý callback từ doithe1s - PHẢI CỰC KỲ BẢO MẬT
   */
  handleDoithe1sCallback: catchAsync(async (req, res, next) => {
    // Merge cả body và query để đảm bảo nhận đủ data
    const callbackData = { ...req.body, ...req.query };
    const { status, request_id, value, amount, message, sign } = callbackData;
    
    console.log('📞 [CALLBACK] Received data:', {
      request_id,
      status,
      amount: amount || value,
      message,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // BƯỚC 1: VALIDATION CƠ BẢN
    if (!status || !request_id) {
      console.warn('⚠️  [CALLBACK-WARN] Missing required fields:', callbackData);
      return res.status(400).send('Error: Missing required fields.');
    }

    // BƯỚC 2: XÁC THỰC CHỮ KÝ - QUAN TRỌNG NHẤT!
    if (!doithe1sService.validateCallbackSignature(callbackData)) {
      // Log chi tiết để debug nhưng không expose ra response
      console.error('🚨 [CALLBACK-SECURITY] SIGNATURE VALIDATION FAILED:', {
        request_id,
        received_data: { status, request_id, sign },
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
      return res.status(403).send('Error: Unauthorized.');
    }

    // BƯỚC 3: TÌM TRANSACTION
    const transaction = await Transaction.findOne({ 
      gatewayTransactionId: request_id 
    });

    if (!transaction) {
      console.warn(`⚠️  [CALLBACK-WARN] Transaction not found: ${request_id}`);
      return res.status(404).send('Error: Transaction not found.');
    }
    
    // BƯỚC 4: KIỂM TRA TRẠNG THÁI ĐÃ XỬ LÝ CHƯA
    if (transaction.status !== 'pending') {
      console.log(`ℹ️  [CALLBACK-INFO] Transaction already processed: ${request_id}, Status: ${transaction.status}`);
      return res.status(200).send('OK'); // Vẫn trả về OK để tránh retry
    }

    // BƯỚC 5: XỬ LÝ CÁC TRẠNG THÁI KHÁC NHAU
    const realAmount = Number(amount || value || 0);
    const STATUS_SUCCESS = '1';
    const STATUS_WRONG_AMOUNT = '2';
    const STATUS_USED_CARD = '3';
    const STATUS_WRONG_CARD = '4';

    let balanceUpdate = 0;

    switch (status) {
      case STATUS_SUCCESS:
        transaction.status = 'success';
        transaction.description = `✅ Nạp thẻ thành công! Đã cộng ${realAmount.toLocaleString('vi-VN')}đ vào tài khoản.`;
        balanceUpdate = realAmount;
        break;
        
      case STATUS_WRONG_AMOUNT:
        transaction.status = 'success'; // Vẫn thành công nhưng số tiền khác
        transaction.description = `✅ Thẻ hợp lệ nhưng sai mệnh giá. Thực nhận: ${realAmount.toLocaleString('vi-VN')}đ`;
        balanceUpdate = realAmount;
        break;
        
      case STATUS_USED_CARD:
        transaction.status = 'failed';
        transaction.description = `❌ Thẻ đã được sử dụng trước đó.`;
        transaction.failureReason = 'USED_CARD';
        break;
        
      case STATUS_WRONG_CARD:
        transaction.status = 'failed';
        transaction.description = `❌ Thông tin thẻ không chính xác.`;
        transaction.failureReason = 'WRONG_CARD';
        break;
        
      default:
        transaction.status = 'failed';
        transaction.description = `❌ Giao dịch thất bại: ${message || `Mã lỗi: ${status}`}`;
        transaction.failureReason = status.toString();
    }
    
    // BƯỚC 6: CẬP NHẬT DATABASE - TRANSACTION ĐỂ ĐẢM BẢO TÍNH NHẤT QUÁN
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Cập nhật transaction
      await transaction.save({ session });
      
      // Cộng tiền vào tài khoản nếu thành công
      if (balanceUpdate > 0) {
        await User.findByIdAndUpdate(
          transaction.user, 
          { $inc: { balance: balanceUpdate } },
          { session }
        );
        
        console.log('💰 [CALLBACK-SUCCESS] Balance updated:', {
          request_id,
          userId: transaction.user,
          amount: balanceUpdate,
          newStatus: transaction.status
        });
      }
      
      await session.commitTransaction();
      
      console.log('✅ [CALLBACK-SUCCESS] Transaction processed:', {
        request_id,
        status: transaction.status,
        amount: balanceUpdate,
        description: transaction.description
      });
      
    } catch (error) {
      await session.abortTransaction();
      console.error('❌ [CALLBACK-ERROR] Database update failed:', {
        request_id,
        error: error.message
      });
      
      // Vẫn trả về OK để tránh retry nhưng log lỗi
      return res.status(200).send('OK');
      
    } finally {
      session.endSession();
    }

    // BƯỚC 7: TRẢ VỀ RESPONSE CHO DOITHE1S
    // Quan trọng: Phải trả về chính xác format mà doithe1s yêu cầu
    res.status(200).send('OK');
  }),

  /**
   * Endpoint để test callback (chỉ dùng trong development)
   */
  testCallback: catchAsync(async (req, res, next) => {
    if (process.env.NODE_ENV !== 'development') {
      return next(new AppError('This endpoint is only available in development mode', 403));
    }

    const { request_id, status = '1', amount = '50000' } = req.body;
    
    if (!request_id) {
      return next(new AppError('request_id is required', 400));
    }

    // Tạo fake callback data với chữ ký hợp lệ
    const PARTNER_KEY = process.env.DOITHE1S_PARTNER_KEY;
    const sign = crypto
      .createHash('md5')
      .update(PARTNER_KEY + status + request_id)
      .digest('hex');

    const fakeCallbackData = {
      status,
      request_id,
      amount,
      message: 'Test callback',
      sign
    };

    // Gọi lại chính callback handler
    req.body = fakeCallbackData;
    req.query = {};
    
    return paymentCallbackController.handleDoithe1sCallback(req, res, next);
  })
};

// -----------------------------------------------------------------------------
// --- CÁC CONTROLLER CÒN LẠI GIỮ NGUYÊN NHƯNG CẢI TIẾN MỘT CHÚT ---
// -----------------------------------------------------------------------------
const userController = {
  getMe: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    const userResponse = {
      _id: user._id,
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      balance: user.balance || 0,
      avatarText: user.avatarText,
      createdAt: user.createdAt,
      // Thêm thống kê nhanh
      totalTransactions: await Transaction.countDocuments({ user: user._id }),
      cartItemsCount: user.cart.length,
      favoritesCount: user.favorites.length
    };

    res.status(200).json({
      status: 'success',
      data: { user: userResponse },
    });
  }),

  getSessions: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    const sessions = user.sessions.sort((a, b) => {
      if (a.tokenIdentifier === req.sessionId) return -1;
      if (b.tokenIdentifier === req.sessionId) return 1;
      return new Date(b.lastUsedAt) - new Date(a.lastUsedAt);
    });

    res.status(200).json({
      status: 'success',
      data: {
        sessions: sessions.map(s => ({
          id: s.tokenIdentifier,
          deviceInfo: s.deviceInfo,
          ipAddress: s.ipAddress,
          createdAt: s.createdAt,
          lastUsedAt: s.lastUsedAt,
          isCurrent: s.tokenIdentifier === req.sessionId
        }))
      }
    });
  }),

  logoutSession: catchAsync(async (req, res, next) => {
    const { sessionId } = req.params;
    
    if (sessionId === req.sessionId) {
      return next(new AppError('You cannot log out your current session via this endpoint.', 400));
    }
    
    await User.findByIdAndUpdate(req.user.id, {
      $pull: { sessions: { tokenIdentifier: sessionId } }
    });

    res.status(204).json({
      status: 'success',
      data: null
    });
  }),

  logoutAllOtherSessions: catchAsync(async (req, res, next) => {
    const user = req.user;
    
    user.sessions = user.sessions.filter(s => s.tokenIdentifier === req.sessionId);
    
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'All other sessions have been logged out.'
    });
  }),

  updateMe: catchAsync(async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) {
      return next(new AppError('This route is not for password updates. Please use /updateMyPassword.', 400));
    }

    const { name } = req.body;
    if (!name || name.trim().length === 0) {
      return next(new AppError('Please provide a valid name', 400));
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      {
        name: name.trim(),
        avatarText: name.trim().charAt(0).toUpperCase()
      },
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      status: 'success',
      data: {
        user: {
          _id: updatedUser._id,
          name: updatedUser.name,
          email: updatedUser.email,
          role: updatedUser.role,
          balance: updatedUser.balance,
          avatarText: updatedUser.avatarText
        },
      },
    });
  }),

  deleteMe: catchAsync(async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, { active: false });

    res.status(204).json({
      status: 'success',
      data: null,
    });
  }),

  getAllUsers: catchAsync(async (req, res, next) => {
    const users = await User.find({ active: { $ne: false } }).select('-password');

    res.status(200).json({
      status: 'success',
      results: users.length,
      data: { users },
    });
  }),

  getUser: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id).select('-password');

    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: { user },
    });
  }),

  updateUser: catchAsync(async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) {
      return next(new AppError('This route is not for password updates.', 400));
    }

    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    }).select('-password');

    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: { user },
    });
  }),

  deleteUser: catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    res.status(204).json({
      status: 'success',
      data: null,
    });
  }),

  makeUserAdmin: catchAsync(async (req, res, next) => {
    const { email } = req.body;

    if (!email) {
      return next(new AppError('Please provide email address', 400));
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    user.role = 'admin';
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: `${email} is now an admin`,
      data: {
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      }
    });
  }),
};

const productController = {
  getAllProducts: catchAsync(async (req, res, next) => {
    const queryObj = { ...req.query };
    const excludedFields = ['page', 'sort', 'limit', 'fields'];
    excludedFields.forEach(el => delete queryObj[el]);

    queryObj.active = { $ne: false };

    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, match => `${match}`);

    let query = Product.find(JSON.parse(queryStr));

    if (req.query.sort) {
      const sortBy = req.query.sort.split(',').join(' ');
      query = query.sort(sortBy);
    } else {
      query = query.sort('-createdAt');
    }

    if (req.query.fields) {
      const fields = req.query.fields.split(',').join(' ');
      query = query.select(fields);
    } else {
      query = query.select('-__v');
    }

    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 100;
    const skip = (page - 1) * limit;

    query = query.skip(skip).limit(limit);

    const products = await query.populate({
      path: 'createdBy',
      select: 'name email'
    });

    res.status(200).json({
      status: 'success',
      results: products.length,
      data: { products },
    });
  }),

  getProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findOne({
      _id: req.params.id,
      active: { $ne: false }
    }).populate({
      path: 'createdBy',
      select: 'name email'
    }).populate('reviews');

    if (!product) {
      return next(new AppError('No product found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: { product },
    });
  }),

  createProduct: catchAsync(async (req, res, next) => {
    const { title, description, price, images, link } = req.body;

    if (!title || !description || !price || !link) {
      return next(new AppError('Please provide all required fields: title, description, price, and link', 400));
    }

    let productImages = images;
    if (typeof images === 'string') {
      productImages = [images];
    } else if (!Array.isArray(images) || images.length === 0) {
      return next(new AppError('Please provide at least one product image', 400));
    }

    const productData = {
      title: title.trim(),
      description: description.trim(),
      price: parseInt(price, 10),
      images: productImages,
      link: link.trim(),
      category: req.body.category || 'services',
      badge: req.body.badge || null,
      sales: parseInt(req.body.sales, 10) || 0,
      stock: parseInt(req.body.stock, 10) || 999,
      features: req.body.features || [],
      oldPrice: req.body.oldPrice ? parseInt(req.body.oldPrice, 10) : undefined,
      createdBy: req.user._id,
    };

    const newProduct = await Product.create(productData);
    await newProduct.populate({
      path: 'createdBy',
      select: 'name email'
    });

    res.status(201).json({
      status: 'success',
      data: { product: newProduct },
    });
  }),

  updateProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);

    if (!product) {
      return next(new AppError('No product found with that ID', 404));
    }

    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return next(new AppError('You do not have permission to update this product', 403));
    }

    if (req.body.images) {
      if (typeof req.body.images === 'string') {
        req.body.images = [req.body.images];
      }
    }

    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true,
      }
    ).populate({
      path: 'createdBy',
      select: 'name email'
    });

    res.status(200).json({
      status: 'success',
      data: { product: updatedProduct },
    });
  }),

  deleteProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);

    if (!product) {
      return next(new AppError('No product found with that ID', 404));
    }

    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return next(new AppError('You do not have permission to delete this product', 403));
    }

    await Product.findByIdAndDelete(req.params.id);

    res.status(204).json({
      status: 'success',
      data: null,
    });
  }),

  getProductStats: catchAsync(async (req, res, next) => {
    const stats = await Product.aggregate([
      {
        $match: { active: { $ne: false } }
      },
      {
        $group: {
          _id: '$category',
          numProducts: { $sum: 1 },
          avgPrice: { $avg: '$price' },
          minPrice: { $min: '$price' },
          maxPrice: { $max: '$price' },
          totalSales: { $sum: '$sales' }
        }
      },
      {
        $sort: { numProducts: -1 }
      }
    ]);

    res.status(200).json({
      status: 'success',
      data: { stats },
    });
  }),
};

const cartFavoriteController = {
  addToCart: catchAsync(async (req, res, next) => {
    const { productId, quantity = 1 } = req.body;

    if (!productId) {
      return next(new AppError('Please provide a product ID', 400));
    }

    const product = await Product.findOne({
      _id: productId,
      active: { $ne: false
