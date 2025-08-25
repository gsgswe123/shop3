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

// 1. TẢI BIẾN MÔI TRƯỜNG ĐẦU TIÊN
dotenv.config({ path: './config.env' });

// 2. KHỞI TẠO ỨNG DỤNG EXPRESS
const app = express();

// 3. CẤU HÌNH MIDDLEWARE
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Quan trọng cho callback form-data
app.use(cookieParser());
app.set('trust proxy', true);

// Cấu hình CORS
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

// Logging trong môi trường development
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// 4. CÁC HÀM TIỆN ÍCH (UTILITIES)
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

// Các hàm liên quan đến JWT
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


// 5. ĐỊNH NGHĨA DATABASE SCHEMAS & MODELS

// Session Schema
const sessionSchema = new mongoose.Schema({
  tokenIdentifier: { type: String, unique: true, required: true },
  deviceInfo: String,
  ipAddress: String,
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: Date.now }
}, { _id: false });

// User Schema
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

// User indexes and middleware
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ 'sessions.tokenIdentifier': 1 });

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
  },
  views: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Product indexes, virtuals, middleware
productSchema.index({ createdAt: -1 });
productSchema.index({ category: 1 });
productSchema.index({ price: 1 });
productSchema.index({ createdBy: 1 });
productSchema.index({ active: 1 });

productSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'product',
  localField: '_id'
});

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

// Review indexes and middleware
reviewSchema.index({ product: 1, user: 1 }, { unique: true });
reviewSchema.index({ product: 1 });
reviewSchema.index({ user: 1 });

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
    enum: ['deposit', 'purchase', 'withdrawal', 'refund'],
    required: true,
  },
  method: {
    type: String,
    enum: ['card', 'banking', 'momo', 'zalopay', 'system'],
    default: 'card',
  },
  amount: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    enum: ['pending', 'success', 'failed', 'processing'],
    default: 'pending',
  },
  description: String,
  gatewayTransactionId: String,
  failureReason: String,
  details: {
    cardType: String,
    cardSerial: String,
    cardNumber: String,
    bankCode: String,
    transactionCode: String,
  },
  metadata: {
    ipAddress: String,
    userAgent: String,
    processedAt: Date,
    callbackData: Object,
  }
}, { timestamps: true });

// Transaction indexes
transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ gatewayTransactionId: 1 });
transactionSchema.index({ status: 1, createdAt: -1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// 6. SERVICES (E.G., PAYMENT GATEWAY)
const paymentGatewayService = {
  doithe1s: {
    sendCardRequest: async (cardInfo) => {
      const { telco, code, serial, amount, request_id } = cardInfo;
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
        const sign = crypto
          .createHash('md5')
          .update(PARTNER_KEY + code + serial)
          .digest('hex');

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
          serial: `${serial.substring(0, 4)}****${serial.substring(serial.length - 4)}`
        });

        const response = await axios.post(API_URL, params, {
          headers: { 
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Shop-Backend/1.0'
          },
          timeout: 30000
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
        
        return { 
          status: -1, 
          message: 'Không thể kết nối đến cổng thanh toán. Vui lòng thử lại sau.' 
        };
      }
    },
    validateCallbackSignature: (callbackData) => {
      const { status, request_id, sign } = callbackData;
      const PARTNER_KEY = process.env.DOITHE1S_PARTNER_KEY;

      if (!sign || !status || !request_id || !PARTNER_KEY) {
        console.warn('⚠️  [CALLBACK-SECURITY] Missing required fields for signature validation');
        return false;
      }
      
      const expectedSign = crypto
        .createHash('md5')
        .update(PARTNER_KEY + status + request_id)
        .digest('hex');

      const isValid = sign === expectedSign;
      
      if (!isValid) {
        console.error('🚨 [CALLBACK-SECURITY] INVALID SIGNATURE DETECTED:', {
          request_id,
          received_sign: sign,
          expected_sign: expectedSign
        });
      }

      return isValid;
    }
  },
  common: {
    generateRequestId: (userId, type = 'NAP') => {
      return `${type}_${userId.toString().slice(-6)}_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`;
    },
    validateCardData: (telco, code, serial, amount) => {
      const validTelcos = ['VIETTEL', 'VINAPHONE', 'MOBIFONE', 'VIETNAMOBILE', 'GMOBILE'];
      if (!validTelcos.includes(telco.toUpperCase())) {
        return { valid: false, error: 'Nhà mạng không được hỗ trợ.' };
      }

      const parsedAmount = parseInt(amount, 10);
      const validAmounts = [10000, 20000, 50000, 100000, 200000, 300000, 500000, 1000000];
      
      if (isNaN(parsedAmount) || !validAmounts.includes(parsedAmount)) {
        return { 
          valid: false, 
          error: `Mệnh giá không hợp lệ. Chỉ chấp nhận: ${validAmounts.map(a => a.toLocaleString('vi-VN')).join(', ')}đ` 
        };
      }

      if (code.length < 10 || code.length > 15) {
        return { valid: false, error: 'Mã thẻ không đúng định dạng.' };
      }

      if (serial.length < 10 || serial.length > 15) {
        return { valid: false, error: 'Serial không đúng định dạng.' };
      }

      return { valid: true, amount: parsedAmount };
    },
    checkRateLimit: async (userId, timeWindow = 5, maxRequests = 3) => {
      const recentTransactions = await Transaction.find({
        user: userId,
        type: 'deposit',
        createdAt: { $gte: new Date(Date.now() - timeWindow * 60 * 1000) }
      });
      return recentTransactions.length >= maxRequests;
    }
  }
};

// 7. CONTROLLERS
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
      role: role === 'admin' ? 'user' : (role || 'user'),
    });
    const sessionId = crypto.randomBytes(16).toString('hex');
    newUser.sessions.push({
      tokenIdentifier: sessionId,
      deviceInfo: req.headers['user-agent'] || 'Unknown Device',
      ipAddress: req.ip,
    });
    await newUser.save({ validateBeforeSave: false });
    createSendToken(newUser, sessionId, 201, res);
  }),
  login: catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return next(new AppError('Please provide email and password', 400));
    }
    const user = await User.findOne({ email: email.toLowerCase().trim(), active: { $ne: false } }).select('+password');
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
    if (user.sessions.length >= 10) {
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
    res.status(200).json({ status: 'success', message: 'Logged out successfully. Please clear token on client-side.' });
  },
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
    User.updateOne({ _id: currentUser._id, 'sessions.tokenIdentifier': decoded.sessionId }, { $set: { 'sessions.$.lastUsedAt': Date.now() } }).exec();
    req.user = currentUser;
    req.sessionId = decoded.sessionId;
    res.locals.user = currentUser;
    next();
  }),
  restrictTo: (...roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  },
  forgotPassword: catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email?.toLowerCase().trim() });
    if (!user) {
      return next(new AppError('There is no user with that email address.', 404));
    }
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    res.status(200).json({ status: 'success', message: 'Password reset token sent to email!', resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined });
  }),
  resetPassword: catchAsync(async (req, res, next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } });
    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    const sessionId = crypto.randomBytes(16).toString('hex');
    user.sessions = [{
      tokenIdentifier: sessionId,
      deviceInfo: req.headers['user-agent'] || 'Unknown Device',
      ipAddress: req.ip,
    }];
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

const userController = {
  getMe: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) return next(new AppError('User not found', 404));
    const [totalTransactions, pendingTransactions, successfulTransactions] = await Promise.all([
      Transaction.countDocuments({ user: user._id }),
      Transaction.countDocuments({ user: user._id, status: 'pending' }),
      Transaction.countDocuments({ user: user._id, status: 'success' })
    ]);
    const userResponse = {
      _id: user._id,
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      balance: user.balance || 0,
      avatarText: user.avatarText,
      createdAt: user.createdAt,
      stats: { totalTransactions, pendingTransactions, successfulTransactions, cartItemsCount: user.cart.length, favoritesCount: user.favorites.length }
    };
    res.status(200).json({ status: 'success', data: { user: userResponse } });
  }),
  getSessions: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    const sessions = user.sessions.sort((a, b) => {
      if (a.tokenIdentifier === req.sessionId) return -1;
      if (b.tokenIdentifier === req.sessionId) return 1;
      return new Date(b.lastUsedAt) - new Date(a.lastUsedAt);
    });
    res.status(200).json({ status: 'success', data: { sessions: sessions.map(s => ({ id: s.tokenIdentifier, deviceInfo: s.deviceInfo, ipAddress: s.ipAddress, createdAt: s.createdAt, lastUsedAt: s.lastUsedAt, isCurrent: s.tokenIdentifier === req.sessionId })) } });
  }),
  logoutSession: catchAsync(async (req, res, next) => {
    const { sessionId } = req.params;
    if (sessionId === req.sessionId) return next(new AppError('You cannot log out your current session via this endpoint.', 400));
    await User.findByIdAndUpdate(req.user.id, { $pull: { sessions: { tokenIdentifier: sessionId } } });
    res.status(204).json({ status: 'success', data: null });
  }),
  logoutAllOtherSessions: catchAsync(async (req, res, next) => {
    req.user.sessions = req.user.sessions.filter(s => s.tokenIdentifier === req.sessionId);
    await req.user.save({ validateBeforeSave: false });
    res.status(200).json({ status: 'success', message: 'All other sessions have been logged out.' });
  }),
  updateMe: catchAsync(async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) {
      return next(new AppError('This route is not for password updates. Please use /updateMyPassword.', 400));
    }
    const { name } = req.body;
    if (!name || name.trim().length === 0) {
      return next(new AppError('Please provide a valid name', 400));
    }
    const updatedUser = await User.findByIdAndUpdate(req.user.id, { name: name.trim(), avatarText: name.trim().charAt(0).toUpperCase() }, { new: true, runValidators: true });
    res.status(200).json({ status: 'success', data: { user: { _id: updatedUser._id, name: updatedUser.name, email: updatedUser.email, role: updatedUser.role, balance: updatedUser.balance, avatarText: updatedUser.avatarText } } });
  }),
  deleteMe: catchAsync(async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, { active: false });
    res.status(204).json({ status: 'success', data: null });
  }),
  getAllUsers: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;
    const filter = { active: { $ne: false } };
    if (req.query.role) filter.role = req.query.role;
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      filter.$or = [{ name: searchRegex }, { email: searchRegex }];
    }
    const users = await User.find(filter).select('-password').sort('-createdAt').skip(skip).limit(limit);
    const total = await User.countDocuments(filter);
    res.status(200).json({ status: 'success', results: users.length, total, currentPage: page, totalPages: Math.ceil(total / limit), data: { users } });
  }),
  getUser: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return next(new AppError('No user found with that ID', 404));
    const [totalTransactions, totalSpent, successfulTransactions] = await Promise.all([
      Transaction.countDocuments({ user: user._id }),
      Transaction.aggregate([
        { $match: { user: new mongoose.Types.ObjectId(user._id), status: 'success', type: 'purchase' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Transaction.countDocuments({ user: user._id, status: 'success' })
    ]);
    const userWithStats = { ...user.toObject(), stats: { totalTransactions, totalSpent: totalSpent[0]?.total || 0, successfulTransactions } };
    res.status(200).json({ status: 'success', data: { user: userWithStats } });
  }),
  updateUser: catchAsync(async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) return next(new AppError('This route is not for password updates.', 400));
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true }).select('-password');
    if (!user) return next(new AppError('No user found with that ID', 404));
    res.status(200).json({ status: 'success', data: { user } });
  }),
  deleteUser: catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return next(new AppError('No user found with that ID', 404));
    res.status(204).json({ status: 'success', data: null });
  }),
  makeUserAdmin: catchAsync(async (req, res, next) => {
    const { email } = req.body;
    if (!email) return next(new AppError('Please provide email address', 400));
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return next(new AppError('User not found', 404));
    user.role = 'admin';
    await user.save({ validateBeforeSave: false });
    res.status(200).json({ status: 'success', message: `${email} is now an admin`, data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role } } });
  }),
  updateUserBalance: catchAsync(async (req, res, next) => {
    const { userId } = req.params;
    const { amount, action, reason } = req.body;
    if (!amount || !action || !['add', 'subtract', 'set'].includes(action)) {
      return next(new AppError('Please provide valid amount and action (add/subtract/set)', 400));
    }
    const user = await User.findById(userId);
    if (!user) return next(new AppError('User not found', 404));
    const oldBalance = user.balance;
    let newBalance;
    switch (action) {
      case 'add': newBalance = oldBalance + Math.abs(amount); break;
      case 'subtract': newBalance = Math.max(0, oldBalance - Math.abs(amount)); break;
      case 'set': newBalance = Math.max(0, amount); break;
    }
    user.balance = newBalance;
    await user.save({ validateBeforeSave: false });
    await Transaction.create({
      user: userId,
      type: action === 'subtract' ? 'withdrawal' : 'deposit',
      method: 'system',
      amount: Math.abs(amount),
      status: 'success',
      description: reason || `Admin ${action} balance: ${Math.abs(amount).toLocaleString('vi-VN')}đ`,
      gatewayTransactionId: `ADMIN_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      metadata: { adminAction: true, adminId: req.user._id, oldBalance, newBalance, processedAt: new Date() }
    });
    res.status(200).json({ status: 'success', message: `User balance updated from ${oldBalance.toLocaleString('vi-VN')}đ to ${newBalance.toLocaleString('vi-VN')}đ`, data: { user: { _id: user._id, name: user.name, email: user.email, balance: newBalance } } });
  })
};

const productController = {
  getAllProducts: catchAsync(async (req, res, next) => {
    const queryObj = { ...req.query };
    const excludedFields = ['page', 'sort', 'limit', 'fields', 'search'];
    excludedFields.forEach(el => delete queryObj[el]);
    queryObj.active = { $ne: false };
    let queryStr = JSON.stringify(queryObj).replace(/\b(gte|gt|lte|lt)\b/g, match => `${match}`);
    let query = Product.find(JSON.parse(queryStr));
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      query = query.find({ $or: [{ title: searchRegex }, { description: searchRegex }, { features: { $in: [searchRegex] } }] });
    }
    if (req.query.sort) query = query.sort(req.query.sort.split(',').join(' '));
    else query = query.sort('-createdAt');
    if (req.query.fields) query = query.select(req.query.fields.split(',').join(' '));
    else query = query.select('-__v');
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 100;
    const skip = (page - 1) * limit;
    query = query.skip(skip).limit(limit);
    const products = await query.populate({ path: 'createdBy', select: 'name email' });
    const total = await Product.countDocuments({ ...JSON.parse(queryStr), ...(req.query.search && { $or: [{ title: new RegExp(req.query.search, 'i') }, { description: new RegExp(req.query.search, 'i') }, { features: { $in: [new RegExp(req.query.search, 'i')] } }] }) });
    res.status(200).json({ status: 'success', results: products.length, total, currentPage: page, totalPages: Math.ceil(total / limit), data: { products } });
  }),
  getProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findOne({ _id: req.params.id, active: { $ne: false } }).populate({ path: 'createdBy', select: 'name email' }).populate('reviews');
    if (!product) return next(new AppError('No product found with that ID', 404));
    Product.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }).exec();
    res.status(200).json({ status: 'success', data: { product } });
  }),
  createProduct: catchAsync(async (req, res, next) => {
    const { title, description, price, images, link } = req.body;
    if (!title || !description || !price || !link) {
      return next(new AppError('Please provide all required fields: title, description, price, and link', 400));
    }
    let productImages = Array.isArray(images) ? images : (typeof images === 'string' ? [images] : []);
    if (productImages.length === 0) return next(new AppError('Please provide at least one product image', 400));
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
    await newProduct.populate({ path: 'createdBy', select: 'name email' });
    res.status(201).json({ status: 'success', data: { product: newProduct } });
  }),
  updateProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);
    if (!product) return next(new AppError('No product found with that ID', 404));
    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return next(new AppError('You do not have permission to update this product', 403));
    }
    if (req.body.images && typeof req.body.images === 'string') req.body.images = [req.body.images];
    const updatedProduct = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true }).populate({ path: 'createdBy', select: 'name email' });
    res.status(200).json({ status: 'success', data: { product: updatedProduct } });
  }),
  deleteProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);
    if (!product) return next(new AppError('No product found with that ID', 404));
    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return next(new AppError('You do not have permission to delete this product', 403));
    }
    await Product.findByIdAndDelete(req.params.id);
    res.status(204).json({ status: 'success', data: null });
  }),
  getProductStats: catchAsync(async (req, res, next) => {
    const stats = await Product.aggregate([{ $match: { active: { $ne: false } } }, { $group: { _id: '$category', numProducts: { $sum: 1 }, avgPrice: { $avg: '$price' }, minPrice: { $min: '$price' }, maxPrice: { $max: '$price' }, totalSales: { $sum: '$sales' } } }, { $sort: { numProducts: -1 } }]);
    const totalProducts = await Product.countDocuments({ active: { $ne: false } });
    const totalSales = await Product.aggregate([{ $match: { active: { $ne: false } } }, { $group: { _id: null, total: { $sum: '$sales' } } }]);
    res.status(200).json({ status: 'success', data: { stats, totalProducts, totalSales: totalSales[0]?.total || 0 } });
  }),
  getMyProducts: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;
    const filter = { createdBy: req.user._id };
    if (req.query.category) filter.category = req.query.category;
    if (req.query.status === 'active') filter.active = true;
    else if (req.query.status === 'inactive') filter.active = false;
    const products = await Product.find(filter).sort('-createdAt').skip(skip).limit(limit);
    const total = await Product.countDocuments(filter);
    res.status(200).json({ status: 'success', results: products.length, total, currentPage: page, totalPages: Math.ceil(total / limit), data: { products } });
  })
};

const cartFavoriteController = {
  addToCart: catchAsync(async (req, res, next) => {
    const { productId, quantity = 1 } = req.body;
    if (!productId) return next(new AppError('Please provide a product ID', 400));
    if (quantity < 1 || quantity > 99) return next(new AppError('Quantity must be between 1 and 99', 400));
    const product = await Product.findOne({ _id: productId, active: { $ne: false } });
    if (!product) return next(new AppError('Product not found or no longer available', 404));
    if (product.stock < quantity) return next(new AppError(`Only ${product.stock} items available in stock`, 400));
    const user = await User.findById(req.user.id);
    const existingItemIndex = user.cart.findIndex(item => item.product.toString() === productId);
    if (existingItemIndex !== -1) {
      const newQuantity = user.cart[existingItemIndex].quantity + parseInt(quantity, 10);
      if (newQuantity > product.stock) return next(new AppError(`Cannot add more items. Maximum available: ${product.stock}`, 400));
      user.cart[existingItemIndex].quantity = Math.min(newQuantity, 99);
    } else {
      user.cart.push({ product: productId, quantity: parseInt(quantity, 10) });
    }
    await user.save({ validateBeforeSave: false });
    await user.populate({ path: 'cart.product', select: 'title price images link category badge stock' });
    res.status(200).json({ status: 'success', message: 'Product added to cart', data: { cart: user.cart } });
  }),
  getCart: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).populate({ path: 'cart.product', select: 'title price images link category badge stock active' });
    user.cart = user.cart.filter(item => item.product && item.product.active !== false);
    const cartTotal = user.cart.reduce((total, item) => total + (item.product.price * item.quantity), 0);
    const cartItemsCount = user.cart.reduce((count, item) => count + item.quantity, 0);
    res.status(200).json({ status: 'success', data: { cart: user.cart, summary: { itemsCount: cartItemsCount, totalAmount: cartTotal } } });
  }),
  updateCartItem: catchAsync(async (req, res, next) => {
    const { productId } = req.params;
    const { quantity } = req.body;
    if (!quantity || quantity < 1 || quantity > 99) return next(new AppError('Quantity must be between 1 and 99', 400));
    const product = await Product.findOne({ _id: productId, active: { $ne: false } });
    if (!product) return next(new AppError('Product not found', 404));
    if (quantity > product.stock) return next(new AppError(`Only ${product.stock} items available`, 400));
    const user = await User.findById(req.user.id);
    const cartItemIndex = user.cart.findIndex(item => item.product.toString() === productId);
    if (cartItemIndex === -1) return next(new AppError('Product not found in cart', 404));
    user.cart[cartItemIndex].quantity = parseInt(quantity, 10);
    await user.save({ validateBeforeSave: false });
    res.status(200).json({ status: 'success', message: 'Cart updated successfully', data: { cart: user.cart } });
  }),
  removeFromCart: catchAsync(async (req, res, next) => {
    const { productId } = req.params;
    const user = await User.findById(req.user.id);
    const initialCartLength = user.cart.length;
    user.cart = user.cart.filter(item => item.product.toString() !== productId);
    if (user.cart.length === initialCartLength) return next(new AppError('Product not found in cart', 404));
    await user.save({ validateBeforeSave: false });
    res.status(200).json({ status: 'success', message: 'Product removed from cart', data: { cart: user.cart } });
  }),
  clearCart: catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndUpdate(req.user.id, { cart: [] }, { new: true });
    res.status(200).json({ status: 'success', message: 'Cart cleared successfully', data: { cart: user.cart } });
  }),
  addToFavorites: catchAsync(async (req, res, next) => {
    const { productId } = req.body;
    if (!productId) return next(new AppError('Please provide a product ID', 400));
    const product = await Product.findOne({ _id: productId, active: { $ne: false } });
    if (!product) return next(new AppError('Product not found', 404));
    const user = await User.findById(req.user.id);
    if (!user.favorites.includes(productId)) {
      user.favorites.push(productId);
      await user.save({ validateBeforeSave: false });
    }
    res.status(200).json({ status: 'success', message: 'Product added to favorites', data: { favorites: user.favorites } });
  }),
  getFavorites: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;
    const user = await User.findById(req.user.id).populate({ path: 'favorites', select: 'title price images link category badge sales stock', match: { active: { $ne: false } } });
    const totalFavorites = user.favorites.length;
    const paginatedFavorites = user.favorites.slice(skip, skip + limit);
    res.status(200).json({ status: 'success', results: paginatedFavorites.length, total: totalFavorites, currentPage: page, totalPages: Math.ceil(totalFavorites / limit), data: { favorites: paginatedFavorites } });
  }),
  removeFromFavorites: catchAsync(async (req, res, next) => {
    const { productId } = req.params;
    const user = await User.findById(req.user.id);
    user.favorites = user.favorites.filter(id => id.toString() !== productId);
    await user.save({ validateBeforeSave: false });
    res.status(200).json({ status: 'success', message: 'Product removed from favorites', data: { favorites: user.favorites } });
  }),
  checkFavorite: catchAsync(async (req, res, next) => {
    const { productId } = req.params;
    const user = await User.findById(req.user.id);
    const isFavorite = user.favorites.some(id => id.toString() === productId);
    res.status(200).json({ status: 'success', data: { isFavorite } });
  }),
};

const reviewController = {
  getAllReviews: catchAsync(async (req, res, next) => {
    let filter = req.params.productId ? { product: req.params.productId } : {};
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;
    const reviews = await Review.find(filter).sort('-createdAt').skip(skip).limit(limit);
    const total = await Review.countDocuments(filter);
    let averageRating = null;
    if (req.params.productId) {
      const ratingStats = await Review.aggregate([{ $match: filter }, { $group: { _id: null, averageRating: { $avg: '$rating' } } }]);
      averageRating = ratingStats[0]?.averageRating || 0;
    }
    res.status(200).json({ status: 'success', results: reviews.length, total, currentPage: page, totalPages: Math.ceil(total / limit), averageRating, data: { reviews } });
  }),
  createReview: catchAsync(async (req, res, next) => {
    req.body.product = req.body.product || req.params.productId;
    req.body.user = req.user.id;
    const { product, rating, review } = req.body;
    if (!product || !rating || !review) return next(new AppError('Please provide product, rating, and review content', 400));
    const productExists = await Product.findOne({ _id: product, active: { $ne: false } });
    if (!productExists) return next(new AppError('Product not found', 404));
    const existingReview = await Review.findOne({ product, user: req.user.id });
    if (existingReview) return next(new AppError('You have already reviewed this product', 400));
    const newReview = await Review.create({ product, user: req.user.id, rating: parseInt(rating, 10), review: review.trim() });
    await newReview.populate({ path: 'user', select: 'name avatarText' });
    res.status(201).json({ status: 'success', data: { review: newReview } });
  }),
  getReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);
    if (!review) return next(new AppError('No review found with that ID', 404));
    res.status(200).json({ status: 'success', data: { review } });
  }),
  updateReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);
    if (!review) return next(new AppError('No review found with that ID', 404));
    if (review.user._id.toString() !== req.user._id.toString()) return next(new AppError('You do not have permission to update this review', 403));
    const updatedReview = await Review.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    res.status(200).json({ status: 'success', data: { review: updatedReview } });
  }),
  deleteReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);
    if (!review) return next(new AppError('No review found with that ID', 404));
    if (review.user._id.toString() !== req.user._id.toString() && req.user.role !== 'admin') return next(new AppError('You do not have permission to delete this review', 403));
    await Review.findByIdAndDelete(req.params.id);
    res.status(204).json({ status: 'success', data: null });
  }),
  getMyReviews: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;
    const reviews = await Review.find({ user: req.user.id }).populate({ path: 'product', select: 'title images category' }).sort('-createdAt').skip(skip).limit(limit);
    const total = await Review.countDocuments({ user: req.user.id });
    res.status(200).json({ status: 'success', results: reviews.length, total, currentPage: page, totalPages: Math.ceil(total / limit), data: { reviews } });
  })
};

const transactionController = {
  depositWithCard: catchAsync(async (req, res, next) => {
    const { telco, code, serial, amount } = req.body;
    const userId = req.user.id;
    if (!telco || !code || !serial || !amount) return next(new AppError('Vui lòng điền đầy đủ thông tin thẻ cào.', 400));
    const validation = paymentGatewayService.common.validateCardData(telco, code, serial, amount);
    if (!validation.valid) return next(new AppError(validation.error, 400));
    if (await paymentGatewayService.common.checkRateLimit(userId)) return next(new AppError('Bạn đã nạp quá nhiều lần trong 5 phút.', 429));
    const requestId = paymentGatewayService.common.generateRequestId(userId, 'NAP');
    const pendingTransaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      method: 'card',
      amount: validation.amount,
      status: 'pending',
      gatewayTransactionId: requestId,
      description: `Đang xử lý nạp thẻ ${telco.toUpperCase()} mệnh giá ${validation.amount.toLocaleString('vi-VN')}đ`,
      details: { cardType: telco.toUpperCase(), cardNumber: code.slice(-4), cardSerial: serial.slice(-4) },
      metadata: { ipAddress: req.ip, userAgent: req.headers['user-agent'] }
    });
    const apiResponse = await paymentGatewayService.doithe1s.sendCardRequest({ telco: telco.toUpperCase(), code, serial, amount: validation.amount, request_id: requestId });
    if (apiResponse.status !== 99 && apiResponse.status !== '99') {
      pendingTransaction.status = 'failed';
      pendingTransaction.description = `Thất bại: ${apiResponse.message || 'Thẻ không hợp lệ hoặc đã được sử dụng.'}`;
      pendingTransaction.failureReason = apiResponse.status?.toString();
      await pendingTransaction.save();
      return next(new AppError(pendingTransaction.description, 400));
    }
    res.status(200).json({ status: 'success', message: 'Yêu cầu nạp thẻ đã được gửi thành công và đang được xử lý.', data: { transaction: { _id: pendingTransaction._id, requestId, amount: validation.amount, status: 'pending', createdAt: pendingTransaction.createdAt } } });
  }),
  getMyTransactions: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;
    const filter = { user: req.user.id };
    if (req.query.type) filter.type = req.query.type;
    if (req.query.status) filter.status = req.query.status;
    if (req.query.method) filter.method = req.query.method;
    if (req.query.from || req.query.to) {
      filter.createdAt = {};
      if (req.query.from) filter.createdAt.$gte = new Date(req.query.from);
      if (req.query.to) filter.createdAt.$lte = new Date(req.query.to);
    }
    const transactions = await Transaction.find(filter).sort('-createdAt').skip(skip).limit(limit).select('-details.cardNumber -details.cardSerial -metadata.callbackData');
    const total = await Transaction.countDocuments(filter);
    res.status(200).json({ status: 'success', results: transactions.length, total, currentPage: page, totalPages: Math.ceil(total / limit), data: { transactions } });
  }),
  getTransaction: catchAsync(async (req, res, next) => {
    const transaction = await Transaction.findOne({ _id: req.params.id, user: req.user.id }).select('-details.cardNumber -details.cardSerial -metadata.callbackData');
    if (!transaction) return next(new AppError('Không tìm thấy giao dịch', 404));
    res.status(200).json({ status: 'success', data: { transaction } });
  }),
  getMyTransactionStats: catchAsync(async (req, res, next) => {
    const stats = await Transaction.aggregate([{ $match: { user: new mongoose.Types.ObjectId(req.user.id) } }, { $group: { _id: { status: '$status', type: '$type', method: '$method' }, count: { $sum: 1 }, totalAmount: { $sum: '$amount' } } }, { $group: { _id: '$_id.type', methods: { $push: { method: '$_id.method', status: '$_id.status', count: '$count', totalAmount: '$totalAmount' } }, totalCount: { $sum: '$count' }, totalAmount: { $sum: '$totalAmount' } } }]);
    const recentTransactions = await Transaction.find({ user: req.user.id }).sort('-createdAt').limit(5).select('type amount status description createdAt');
    res.status(200).json({ status: 'success', data: { stats, recentTransactions, balance: req.user.balance || 0 } });
  }),
  getTransactionStats: catchAsync(async (req, res, next) => {
    const stats = await Transaction.aggregate([{ $group: { _id: { status: '$status', type: '$type', method: '$method' }, count: { $sum: 1 }, totalAmount: { $sum: '$amount' } } }, { $group: { _id: '$_id.type', stats: { $push: { method: '$_id.method', status: '$_id.status', count: '$count', totalAmount: '$totalAmount' } } } }]);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const dailyStats = await Transaction.aggregate([{ $match: { createdAt: { $gte: thirtyDaysAgo } } }, { $group: { _id: { date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, type: '$type', status: '$status' }, count: { $sum: 1 }, totalAmount: { $sum: '$amount' } } }, { $sort: { '_id.date': 1 } }]);
    res.status(200).json({ status: 'success', data: { stats, dailyStats } });
  })
};

const paymentCallbackController = {
  handleDoithe1sCallback: catchAsync(async (req, res, next) => {
    const callbackData = { ...req.body, ...req.query };
    console.log('📞 [CALLBACK] Received data:', { ...callbackData, ip: req.ip });

    if (!callbackData.status || !callbackData.request_id) return res.status(400).send('Error: Missing required fields.');
    if (!paymentGatewayService.doithe1s.validateCallbackSignature(callbackData)) return res.status(403).send('Error: Unauthorized.');
    
    const transaction = await Transaction.findOne({ gatewayTransactionId: callbackData.request_id });
    if (!transaction) return res.status(404).send('Error: Transaction not found.');
    if (transaction.status !== 'pending') return res.status(200).send('OK');

    const { status, value, amount, message } = callbackData;
    const realAmount = Number(amount || value || 0);
    let balanceUpdate = 0;

    switch (status.toString()) {
      case '1':
      case '2': // Thẻ đúng, sai mệnh giá (vẫn cộng tiền)
        transaction.status = 'success';
        transaction.description = status === '1'
          ? `✅ Nạp thẻ thành công! Đã cộng ${realAmount.toLocaleString('vi-VN')}đ.`
          : `✅ Thẻ hợp lệ nhưng sai mệnh giá. Thực nhận: ${realAmount.toLocaleString('vi-VN')}đ`;
        balanceUpdate = realAmount;
        break;
      case '3': // Thẻ đã dùng
        transaction.status = 'failed';
        transaction.description = `❌ Thẻ đã được sử dụng trước đó.`;
        transaction.failureReason = 'USED_CARD';
        break;
      default:
        transaction.status = 'failed';
        transaction.description = `❌ Giao dịch thất bại: ${message || `Mã lỗi: ${status}`}`;
        transaction.failureReason = status.toString();
    }

    transaction.metadata.processedAt = new Date();
    transaction.metadata.callbackData = callbackData;

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        await transaction.save({ session });
        if (balanceUpdate > 0) {
          await User.findByIdAndUpdate(transaction.user, { $inc: { balance: balanceUpdate } }, { session });
        }
      });
      console.log(`✅ [CALLBACK-SUCCESS] Processed: ${callbackData.request_id}, Status: ${transaction.status}`);
    } catch (error) {
      console.error(`❌ [CALLBACK-ERROR] DB update failed: ${callbackData.request_id}`, error);
    } finally {
      session.endSession();
    }
    res.status(200).send('OK');
  }),
  testCallback: catchAsync(async (req, res, next) => {
    if (process.env.NODE_ENV !== 'development') return next(new AppError('Endpoint only for development', 403));
    const { request_id, status = '1', amount = '50000' } = req.body;
    if (!request_id) return next(new AppError('request_id is required', 400));
    const sign = crypto.createHash('md5').update(process.env.DOITHE1S_PARTNER_KEY + status + request_id).digest('hex');
    req.body = { status, request_id, amount, message: 'Test callback', sign };
    req.query = {};
    return paymentCallbackController.handleDoithe1sCallback(req, res, next);
  })
};


// 8. ĐỊNH NGHĨA ROUTES
// Health check
app.get('/api/v1/health', (req, res) => res.status(200).json({ status: 'success', message: 'Server is running' }));

// Callback routes (public, no auth)
app.all('/api/v1/payment/callback/doithe1s', paymentCallbackController.handleDoithe1sCallback);
if (process.env.NODE_ENV === 'development') {
  app.post('/api/v1/payment/test-callback', paymentCallbackController.testCallback);
}

// Public routes
app.post('/api/v1/users/signup', authController.signup);
app.post('/api/v1/users/login', authController.login);
app.get('/api/v1/users/logout', authController.logout);
app.post('/api/v1/users/forgotPassword', authController.forgotPassword);
app.patch('/api/v1/users/resetPassword/:token', authController.resetPassword);

app.get('/api/v1/products', productController.getAllProducts);
app.get('/api/v1/products/stats', productController.getProductStats);
app.get('/api/v1/products/:id', productController.getProduct);

app.get('/api/v1/reviews', reviewController.getAllReviews);
app.get('/api/v1/products/:productId/reviews', reviewController.getAllReviews);

// Protected routes (authentication required)
app.use(authController.protect);

app.get('/api/v1/users/me', userController.getMe);
app.patch('/api/v1/users/updateMe', userController.updateMe);
app.patch('/api/v1/users/updateMyPassword', authController.updatePassword);
app.delete('/api/v1/users/deleteMe', userController.deleteMe);

app.get('/api/v1/users/sessions', userController.getSessions);
app.delete('/api/v1/users/sessions/all-but-current', userController.logoutAllOtherSessions);
app.delete('/api/v1/users/sessions/:sessionId', userController.logoutSession);

app.post('/api/v1/users/deposit/card', transactionController.depositWithCard);
app.get('/api/v1/users/transactions', transactionController.getMyTransactions);
app.get('/api/v1/users/transactions/stats', transactionController.getMyTransactionStats);
app.get('/api/v1/users/transactions/:id', transactionController.getTransaction);

app.route('/api/v1/cart').get(cartFavoriteController.getCart).post(cartFavoriteController.addToCart).delete(cartFavoriteController.clearCart);
app.route('/api/v1/cart/:productId').patch(cartFavoriteController.updateCartItem).delete(cartFavoriteController.removeFromCart);
app.route('/api/v1/favorites').get(cartFavoriteController.getFavorites).post(cartFavoriteController.addToFavorites);
app.route('/api/v1/favorites/:productId').delete(cartFavoriteController.removeFromFavorites);
app.get('/api/v1/favorites/check/:productId', cartFavoriteController.checkFavorite);

app.route('/api/v1/reviews').post(reviewController.createReview);
app.post('/api/v1/products/:productId/reviews', reviewController.createReview);
app.get('/api/v1/users/reviews', reviewController.getMyReviews);
app.route('/api/v1/reviews/:id').get(reviewController.getReview).patch(reviewController.updateReview).delete(reviewController.deleteReview);

app.get('/api/v1/my-products', productController.getMyProducts);
app.post('/api/v1/my-products', productController.createProduct);
app.patch('/api/v1/my-products/:id', productController.updateProduct);
app.delete('/api/v1/my-products/:id', productController.deleteProduct);

// Admin routes
app.use('/api/v1/admin', authController.restrictTo('admin'));
app.route('/api/v1/admin/users').get(userController.getAllUsers);
app.route('/api/v1/admin/users/:id').get(userController.getUser).patch(userController.updateUser).delete(userController.deleteUser);
app.post('/api/v1/admin/users/make-admin', userController.makeUserAdmin);
app.patch('/api/v1/admin/users/:userId/balance', userController.updateUserBalance);
app.route('/api/v1/admin/products').post(productController.createProduct);
app.route('/api/v1/admin/products/:id').patch(productController.updateProduct).delete(productController.deleteProduct);
app.get('/api/v1/admin/transactions/stats', transactionController.getTransactionStats);
app.delete('/api/v1/admin/reviews/:id', reviewController.deleteReview);

// 9. BỘ XỬ LÝ LỖI (ERROR HANDLING)
// Các hàm xử lý lỗi chi tiết
const handleCastErrorDB = err => new AppError(`Invalid ${err.path}: ${err.value}.`, 400);
const handleDuplicateFieldsDB = err => {
  const value = err.errmsg?.match(/(["'])(\\?.)*?\1/)?.[0] || 'duplicate value';
  return new AppError(`Duplicate field value: ${value}. Please use another value!`, 400);
};
const handleValidationErrorDB = err => {
  const errors = Object.values(err.errors).map(el => el.message);
  return new AppError(`Invalid input data. ${errors.join('. ')}`, 400);
};
const handleJWTError = () => new AppError('Invalid token. Please log in again!', 401);
const handleJWTExpiredError = () => new AppError('Your token has expired! Please log in again.', 401);

// Hàm gửi lỗi tùy theo môi trường
const sendErrorDev = (err, res) => res.status(err.statusCode).json({ status: err.status, error: err, message: err.message, stack: err.stack });
const sendErrorProd = (err, res) => {
  if (err.isOperational) {
    res.status(err.statusCode).json({ status: err.status, message: err.message });
  } else {
    console.error('ERROR 💥', err);
    res.status(500).json({ status: 'error', message: 'Something went very wrong!' });
  }
};

// Global error handling middleware
const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err, message: err.message, name: err.name, code: err.code };
    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();
    sendErrorProd(error, res);
  }
};

// Middleware cho các route không tồn tại (404)
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Gắn global error handler vào cuối cùng
app.use(globalErrorHandler);

// 10. KẾT NỐI DATABASE VÀ KHỞI ĐỘNG SERVER
// Cấu hình chuỗi kết nối
const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

// Hàm tạo admin mặc định
const createDefaultAdmin = async () => {
  try {
    const adminEmails = ['chinhan20917976549a@gmail.com', 'ryantran149@gmail.com'];
    for (const email of adminEmails) {
      let user = await User.findOne({ email: email.toLowerCase() });
      if (user) {
        if (user.role !== 'admin') {
          user.role = 'admin';
          await user.save({ validateBeforeSave: false });
          console.log(`✅ Updated ${email} to admin role`);
        }
      } else {
        await User.create({
          name: email.startsWith('chinhan') ? 'Co-owner (Chí Nghĩa)' : 'Ryan Tran Admin',
          email: email.toLowerCase(),
          password: 'admin123456',
          passwordConfirm: 'admin123456',
          role: 'admin'
        });
        console.log(`✅ Created admin user: ${email}`);
      }
    }
  } catch (error) {
    console.error('❌ Error creating/updating default admin:', error);
  }
};

// Hàm kết nối DB
const connectDB = async () => {
  try {
    await mongoose.connect(DB, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ DB connection successful!');
    await createDefaultAdmin();
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
};

// Khởi động kết nối DB
connectDB();

// Khởi động server
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`🚀 Server running on port ${port} in ${process.env.NODE_ENV || 'development'} mode`);
});

// Xử lý các lỗi toàn cục (unhandled rejections, exceptions)
process.on('unhandledRejection', (err) => {
  console.log('💥 UNHANDLED REJECTION! Shutting down...');
  console.log(err.name, err.message);
  server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
  console.log('💥 UNCAUGHT EXCEPTION! Shutting down...');
  console.log(err.name, err.message);
  server.close(() => process.exit(1));
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => console.log('💥 Process terminated!'));
});

// 11. EXPORT APP (CHO MỤC ĐÍCH KIỂM THỬ - TESTING)
module.exports = app;
