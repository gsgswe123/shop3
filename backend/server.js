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

// Middleware configuration
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.set('trust proxy', true);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://gsgswe123.github.io',
      'https://gsgswe123.github.io/shop3/',
      'http://127.0.0.1:5500'
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

// Error handling
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
// --- DOITHE1S.VN PAYMENT SERVICE ---
// -----------------------------------------------------------------------------
const doithe1sService = {
  sendCardRequest: async (cardInfo) => {
    const { telco, code, serial, amount, request_id } = cardInfo;
    const PARTNER_ID = process.env.DOITHE1S_PARTNER_ID;
    const PARTNER_KEY = process.env.DOITHE1S_PARTNER_KEY;
    const API_URL = process.env.DOITHE1S_API_URL;

    // -----------------------------------------------------------------
    // CẢNH BÁO BẢO MẬT: CÔNG THỨC TẠO CHỮ KÝ KHI GỬI THẺ (SIGN)
    // - Công thức `md5(PARTNER_KEY + code + serial)` là một ví dụ phổ biến.
    // - BẠN BẮT BUỘC PHẢI MỞ TÀI LIỆU API CỦA DOITHE1S.VN ĐỂ XÁC NHẬN CÔNG THỨC CHÍNH XÁC.
    // - Sai chữ ký sẽ khiến mọi giao dịch của bạn bị từ chối.
    // -----------------------------------------------------------------
    const sign = crypto.createHash('md5').update(PARTNER_KEY + code + serial).digest('hex');

    const params = new URLSearchParams();
    params.append('telco', telco);
    params.append('code', code);
    params.append('serial', serial);
    params.append('amount', amount);
    params.append('request_id', request_id);
    params.append('partner_id', PARTNER_ID);
    params.append('sign', sign);
    params.append('command', 'charging');

    try {
      const response = await axios.post(API_URL, params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      return response.data;
    } catch (error) {
      console.error('Error calling Doithe1s API:', error.message);
      return { status: -1, message: 'Không thể kết nối đến cổng thanh toán.' };
    }
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
      role: role === 'admin' ? 'user' : (role || 'user'),
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
// --- TRANSACTION AND PAYMENT CONTROLLERS ---
// -----------------------------------------------------------------------------
const transactionController = {
  depositWithCard: catchAsync(async (req, res, next) => {
    const { telco, code, serial, amount } = req.body;
    const userId = req.user.id;

    if (!telco || !code || !serial || !amount) {
      return next(new AppError('Vui lòng điền đầy đủ thông tin thẻ cào.', 400));
    }

    const parsedAmount = parseInt(amount, 10);
    if (isNaN(parsedAmount) || parsedAmount < 10000) {
      return next(new AppError('Mệnh giá thẻ không hợp lệ (tối thiểu 10,000đ).', 400));
    }

    const requestId = `NAP_${userId.toString().slice(-6)}_${Date.now()}`;
    
    const pendingTransaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      method: 'card',
      amount: parsedAmount,
      status: 'pending',
      gatewayTransactionId: requestId,
      description: `Chờ xử lý nạp thẻ ${telco} ${parsedAmount.toLocaleString('vi-VN')}đ`,
      details: { cardType: telco, cardNumber: code, cardSerial: serial }
    });

    const apiResponse = await doithe1sService.sendCardRequest({
      telco,
      code,
      serial,
      amount: parsedAmount,
      request_id: requestId,
    });

    if (apiResponse.status !== 99) {
      pendingTransaction.status = 'failed';
      pendingTransaction.description = `Thất bại: ${apiResponse.message || 'Lỗi từ cổng thanh toán.'}`;
      await pendingTransaction.save();
      return next(new AppError(pendingTransaction.description, 400));
    }

    res.status(200).json({
      status: 'success',
      message: 'Yêu cầu nạp thẻ đã được gửi đi và đang chờ xử lý.',
      data: { transaction: pendingTransaction },
    });
  }),

  getMyTransactions: catchAsync(async (req, res, next) => {
    const transactions = await Transaction.find({ user: req.user.id })
      .sort('-createdAt')
      .limit(50);

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: { transactions }
    });
  })
};


const paymentCallbackController = {
  handleDoithe1sCallback: catchAsync(async (req, res, next) => {
    const callbackData = { ...req.body, ...req.query };
    const { status, request_id, value, amount, message, sign } = callbackData;
    const PARTNER_KEY = process.env.DOITHE1S_PARTNER_KEY;
    
    console.log('Received callback:', callbackData);

    // -----------------------------------------------------------------
    // BƯỚC 1: XÁC THỰC CHỮ KÝ - BƯỚC BẢO MẬT QUAN TRỌNG NHẤT
    // - Luôn xác thực chữ ký đầu tiên để chống lại các cuộc gọi callback giả mạo.
    // - Cảnh báo: Công thức `md5(PARTNER_KEY + status + request_id)` LÀ MỘT VÍ DỤ.
    // - BẠN PHẢI KIỂM TRA LẠI VỚI TÀI LIỆU CỦA DOITHE1S.VN ĐỂ CÓ CÔNG THỨC CHÍNH XÁC.
    // - Nếu sai công thức này, kẻ gian có thể tự cộng tiền vào tài khoản người dùng.
    // -----------------------------------------------------------------
    const expectedSign = crypto.createHash('md5').update(PARTNER_KEY + status + request_id).digest('hex');

    if (!sign || sign !== expectedSign) {
      console.warn(`[CALLBACK-SECURITY] Invalid signature for request_id: ${request_id}. Received: ${sign}`);
      return res.status(400).send('Error: Invalid signature.');
    }

    const transaction = await Transaction.findOne({ gatewayTransactionId: request_id });
    if (!transaction) {
      console.warn(`[CALLBACK-WARN] Transaction not found for request_id: ${request_id}`);
      return res.status(404).send('Error: Transaction not found.');
    }
    
    if (transaction.status !== 'pending') {
      console.log(`[CALLBACK-INFO] Transaction ${request_id} already processed. Status: ${transaction.status}`);
      return res.status(200).send('OK: Already processed.');
    }

    const realAmount = Number(amount);
    const STATUS_SUCCESS = '1';
    const STATUS_WRONG_AMOUNT = '2';

    if (status === STATUS_SUCCESS) {
        transaction.status = 'success';
        transaction.description = `Nạp thẻ thành công. Đã cộng ${realAmount.toLocaleString('vi-VN')}đ.`;
        await User.findByIdAndUpdate(transaction.user, { $inc: { balance: realAmount } });
    } else if (status === STATUS_WRONG_AMOUNT) {
        transaction.status = 'success';
        transaction.description = `Thẻ đúng nhưng sai mệnh giá. Thực nhận ${realAmount.toLocaleString('vi-VN')}đ.`;
        await User.findByIdAndUpdate(transaction.user, { $inc: { balance: realAmount } });
    } else {
        transaction.status = 'failed';
        transaction.description = `Nạp thẻ thất bại: ${message || `Mã lỗi hệ thống: ${status}`}`;
        transaction.failureReason = status.toString();
    }
    
    await transaction.save();

    console.log(`[CALLBACK-SUCCESS] Processed request_id: ${request_id}, New Status: ${transaction.status}`);
    res.status(200).send('OK');
  }),
};

// -----------------------------------------------------------------------------
// --- CÁC CONTROLLER CÒN LẠI GIỮ NGUYÊN ---
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
      createdAt: user.createdAt
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
      active: { $ne: false }
    });

    if (!product) {
      return next(new AppError('Product not found', 404));
    }

    const user = await User.findById(req.user.id);
    const existingItemIndex = user.cart.findIndex(item =>
      item.product.toString() === productId
    );

    if (existingItemIndex !== -1) {
      user.cart[existingItemIndex].quantity += parseInt(quantity, 10);
    } else {
      user.cart.push({
        product: productId,
        quantity: parseInt(quantity, 10)
      });
    }

    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Product added to cart',
      data: { cart: user.cart }
    });
  }),

  getCart: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).populate({
      path: 'cart.product',
      select: 'title price images link category badge'
    });

    res.status(200).json({
      status: 'success',
      data: { cart: user.cart }
    });
  }),

  updateCartItem: catchAsync(async (req, res, next) => {
    const { productId } = req.params;
    const { quantity } = req.body;

    if (!quantity || quantity < 1) {
      return next(new AppError('Quantity must be at least 1', 400));
    }

    const user = await User.findById(req.user.id);
    const cartItemIndex = user.cart.findIndex(item =>
      item.product.toString() === productId
    );

    if (cartItemIndex === -1) {
      return next(new AppError('Product not found in cart', 404));
    }

    user.cart[cartItemIndex].quantity = parseInt(quantity, 10);
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Cart updated successfully',
      data: { cart: user.cart }
    });
  }),

  removeFromCart: catchAsync(async (req, res, next) => {
    const { productId } = req.params;

    const user = await User.findById(req.user.id);
    const initialCartLength = user.cart.length;

    user.cart = user.cart.filter(item =>
      item.product.toString() !== productId
    );

    if (user.cart.length === initialCartLength) {
      return next(new AppError('Product not found in cart', 404));
    }

    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Product removed from cart',
      data: { cart: user.cart }
    });
  }),

  clearCart: catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { cart: [] },
      { new: true }
    );

    res.status(200).json({
      status: 'success',
      message: 'Cart cleared successfully',
      data: { cart: user.cart }
    });
  }),

  addToFavorites: catchAsync(async (req, res, next) => {
    const { productId } = req.body;

    if (!productId) {
      return next(new AppError('Please provide a product ID', 400));
    }

    const product = await Product.findOne({
      _id: productId,
      active: { $ne: false }
    });

    if (!product) {
      return next(new AppError('Product not found', 404));
    }

    const user = await User.findById(req.user.id);

    if (!user.favorites.includes(productId)) {
      user.favorites.push(productId);
      await user.save({ validateBeforeSave: false });
    }

    res.status(200).json({
      status: 'success',
      message: 'Product added to favorites',
      data: { favorites: user.favorites }
    });
  }),

  getFavorites: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).populate({
      path: 'favorites',
      select: 'title price images link category badge sales',
      match: { active: { $ne: false } }
    });

    res.status(200).json({
      status: 'success',
      data: { favorites: user.favorites }
    });
  }),

  removeFromFavorites: catchAsync(async (req, res, next) => {
    const { productId } = req.params;

    const user = await User.findById(req.user.id);
    const initialFavoritesLength = user.favorites.length;

    user.favorites = user.favorites.filter(id =>
      id.toString() !== productId
    );

    if (user.favorites.length === initialFavoritesLength) {
      return next(new AppError('Product not found in favorites', 404));
    }

    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Product removed from favorites',
      data: { favorites: user.favorites }
    });
  }),

  checkFavorite: catchAsync(async (req, res, next) => {
    const { productId } = req.params;

    const user = await User.findById(req.user.id);
    const isFavorite = user.favorites.some(id =>
      id.toString() === productId
    );

    res.status(200).json({
      status: 'success',
      data: { isFavorite }
    });
  }),
};

const reviewController = {
  getAllReviews: catchAsync(async (req, res, next) => {
    let filter = {};
    if (req.params.productId) filter = { product: req.params.productId };

    const reviews = await Review.find(filter);

    res.status(200).json({
      status: 'success',
      results: reviews.length,
      data: { reviews },
    });
  }),

  createReview: catchAsync(async (req, res, next) => {
    if (!req.body.product) req.body.product = req.params.productId;
    if (!req.body.user) req.body.user = req.user.id;

    const product = await Product.findOne({
      _id: req.body.product,
      active: { $ne: false }
    });

    if (!product) {
      return next(new AppError('Product not found', 404));
    }

    const newReview = await Review.create(req.body);

    res.status(201).json({
      status: 'success',
      data: { review: newReview },
    });
  }),

  getReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new AppError('No review found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: { review },
    });
  }),

  updateReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new AppError('No review found with that ID', 404));
    }

    if (review.user._id.toString() !== req.user._id.toString()) {
      return next(new AppError('You do not have permission to update this review', 403));
    }

    const updatedReview = await Review.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      status: 'success',
      data: { review: updatedReview },
    });
  }),

  deleteReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new AppError('No review found with that ID', 404));
    }

    if (review.user._id.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return next(new AppError('You do not have permission to delete this review', 403));
    }

    await Review.findByIdAndDelete(req.params.id);

    res.status(204).json({
      status: 'success',
      data: null,
    });
  })
};

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(DB, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('DB connection successful!');
    await createDefaultAdmin();
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1);
  }
};

const createDefaultAdmin = async () => {
  try {
    const adminEmails = [
      'chinhan20917976549a@gmail.com',
      'ryantran149@gmail.com'
    ];

    for (const email of adminEmails) {
      let user = await User.findOne({ email: email.toLowerCase() });

      if (user) {
        if (user.role !== 'admin') {
          user.role = 'admin';
          await user.save({ validateBeforeSave: false });
          console.log(`Updated ${email} to admin role`);
        }
      } else {
        const adminData = {
          name: email === 'chinhan20917976549a@gmail.com' ? 'Co-owner (Chí Nghĩa)' : 'Ryan Tran Admin',
          email: email.toLowerCase(),
          password: 'admin123456',
          passwordConfirm: 'admin123456',
          role: 'admin'
        };

        user = await User.create(adminData);
        console.log(`Created admin user: ${email}`);
      }
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
};

connectDB();

// -----------------------------------------------------------------------------
// --- ROUTES CONFIGURATION ---
// -----------------------------------------------------------------------------
app.get('/api/v1/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// --- PUBLIC ROUTES ---
app.post('/api/v1/users/signup', authController.signup);
app.post('/api/v1/users/login', authController.login);
app.get('/api/v1/users/logout', authController.logout);
app.post('/api/v1/users/forgotPassword', authController.forgotPassword);
app.patch('/api/v1/users/resetPassword/:token', authController.resetPassword);

app.all('/api/v1/payment/callback/doithe1s', paymentCallbackController.handleDoithe1sCallback);

app.get('/api/v1/products', productController.getAllProducts);
app.get('/api/v1/products/stats', productController.getProductStats);
app.get('/api/v1/products/:id', productController.getProduct);

app.get('/api/v1/reviews', reviewController.getAllReviews);
app.get('/api/v1/products/:productId/reviews', reviewController.getAllReviews);


// --- PROTECTED ROUTES ---
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

app.route('/api/v1/cart')
  .get(cartFavoriteController.getCart)
  .post(cartFavoriteController.addToCart)
  .delete(cartFavoriteController.clearCart);

app.route('/api/v1/cart/:productId')
  .patch(cartFavoriteController.updateCartItem)
  .delete(cartFavoriteController.removeFromCart);

app.route('/api/v1/favorites')
  .get(cartFavoriteController.getFavorites)
  .post(cartFavoriteController.addToFavorites);

app.route('/api/v1/favorites/:productId')
  .delete(cartFavoriteController.removeFromFavorites);

app.get('/api/v1/favorites/check/:productId', cartFavoriteController.checkFavorite);

app.post('/api/v1/reviews', reviewController.createReview);
app.post('/api/v1/products/:productId/reviews', reviewController.createReview);

app.route('/api/v1/reviews/:id')
  .get(reviewController.getReview)
  .patch(reviewController.updateReview)
  .delete(reviewController.deleteReview);

app.post('/api/v1/my-products', productController.createProduct);
app.patch('/api/v1/my-products/:id', productController.updateProduct);
app.delete('/api/v1/my-products/:id', productController.deleteProduct);

// --- ADMIN ROUTES ---
app.use('/api/v1/admin', authController.restrictTo('admin'));

app.route('/api/v1/admin/users')
  .get(userController.getAllUsers);

app.route('/api/v1/admin/users/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

app.post('/api/v1/admin/users/make-admin', userController.makeUserAdmin);

app.route('/api/v1/admin/products')
  .post(productController.createProduct);

app.route('/api/v1/admin/products/:id')
  .patch(productController.updateProduct)
  .delete(productController.deleteProduct);

// 404 handler for unmatched routes
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handler
app.use(globalErrorHandler);

// Server startup
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Unhandled error handlers
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
  });
});

module.exports = app;
