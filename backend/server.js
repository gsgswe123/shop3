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

// Load environment variables
dotenv.config({ path: './config.env' });

const app = express();

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// CORS configuration
const allowedOrigins = [
  'https://gsgswe123.github.io',
  'https://gsgswe123.github.io/shop3/',
  'http://127.0.0.1:5500'
];

const corsOptions = {
  origin: function (origin, callback) {
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
const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

// Mongoose Schemas
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
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// User schema indexes
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });

// User schema middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// User schema methods
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
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
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

// Product schema indexes
productSchema.index({ createdAt: -1 });
productSchema.index({ category: 1 });
productSchema.index({ price: 1 });
productSchema.index({ createdBy: 1 });
productSchema.index({ active: 1 });

// Product virtual fields
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

// **START: NEW CODE FOR DEPOSIT**
// Transaction Schema for logging deposits and purchases
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
  description: String, // e.g., 'Nạp thẻ Viettel 100,000đ' or 'Mã thẻ đã qua sử dụng'
  details: { // To store card info
    cardType: String,
    cardSerial: String,
    cardNumber: String,
  },
}, { timestamps: true });

transactionSchema.index({ user: 1, createdAt: -1 });

const Transaction = mongoose.model('Transaction', transactionSchema);
// **END: NEW CODE FOR DEPOSIT**

// Utility functions
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

const AppError = class extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
};

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '90d',
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + (process.env.JWT_COOKIE_EXPIRES_IN || 90) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  };

  res.cookie('jwt', token, cookieOptions);
  user.password = undefined;
  
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
    data: {
      user: userResponse,
    },
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

// Authentication Controller
const authController = {
  signup: catchAsync(async (req, res, next) => {
    const { name, email, password, passwordConfirm, role } = req.body;

    // Validation
    if (!name || !email || !password || !passwordConfirm) {
      return next(new AppError('Please provide all required fields', 400));
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return next(new AppError('User with this email already exists', 400));
    }

    // Create new user
    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      passwordConfirm,
      role: role === 'admin' ? 'user' : (role || 'user'), // Prevent admin signup
    });

    createSendToken(newUser, 201, res);
  }),

  login: catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    // Check if email and password exist
    if (!email || !password) {
      return next(new AppError('Please provide email and password', 400));
    }

    // Check if user exists and password is correct
    const user = await User.findOne({ 
      email: email.toLowerCase().trim(),
      active: { $ne: false }
    }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    // Send token to client
    createSendToken(user, 200, res);
  }),

  logout: (req, res) => {
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });
    res.status(200).json({ 
      status: 'success',
      message: 'Logged out successfully'
    });
  },

  protect: catchAsync(async (req, res, next) => {
    // Get token and check if it exists
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt && req.cookies.jwt !== 'loggedout') {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    // Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    // Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('User recently changed password! Please log in again.', 401));
    }

    // Grant access to protected route
    req.user = currentUser;
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
    // Get user based on POSTed email
    const user = await User.findOne({ email: req.body.email?.toLowerCase().trim() });
    if (!user) {
      return next(new AppError('There is no user with that email address.', 404));
    }

    // Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Password reset token sent to email!',
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
  }),

  resetPassword: catchAsync(async (req, res, next) => {
    // Get user based on the token
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    // If token has not expired, and there is a user, set the new password
    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Log the user in, send JWT
    createSendToken(user, 200, res);
  }),

  updatePassword: catchAsync(async (req, res, next) => {
    // Get user from collection
    const user = await User.findById(req.user.id).select('+password');

    // Check if POSTed current password is correct
    if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
      return next(new AppError('Your current password is incorrect.', 401));
    }

    // If so, update password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();

    // Log user in, send JWT
    createSendToken(user, 200, res);
  }),
};

// **START: NEW CONTROLLER FOR DEPOSITS AND TRANSACTIONS**
const transactionController = {
  // SIMULATE card processing with a fake payment gateway
  simulateCardGateway: (cardInfo) => {
    return new Promise(resolve => {
      // Simulate network delay
      setTimeout(() => {
        // Random outcome for demonstration purposes
        const random = Math.random();

        if (random < 0.75) { // 75% success rate
          resolve({
            success: true,
            message: `Giao dịch thành công. Cộng ${Number(cardInfo.amount).toLocaleString('vi-VN')}đ.`,
            transactionId: crypto.randomBytes(8).toString('hex')
          });
        } else if (random < 0.9) { // 15% incorrect card rate
          resolve({
            success: false,
            message: 'Mã thẻ hoặc số serial không đúng. Vui lòng kiểm tra lại.',
            errorCode: 'INVALID_CARD'
          });
        } else { // 10% used card rate
          resolve({
            success: false,
            message: 'Thẻ đã được sử dụng hoặc đã hết hạn.',
            errorCode: 'CARD_ALREADY_USED'
          });
        }
      }, 1500); // 1.5 second delay
    });
  },

  depositWithCard: catchAsync(async (req, res, next) => {
    const { cardType, cardNumber, cardSerial, amount } = req.body;
    const userId = req.user.id;

    if (!cardType || !cardNumber || !cardSerial || !amount) {
      return next(new AppError('Vui lòng điền đầy đủ thông tin thẻ cào.', 400));
    }

    const parsedAmount = parseInt(amount, 10);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return next(new AppError('Mệnh giá thẻ không hợp lệ.', 400));
    }

    // Create an initial pending transaction log
    const transaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      method: 'card',
      amount: parsedAmount,
      status: 'pending',
      description: `Nạp thẻ ${cardType} ${parsedAmount.toLocaleString('vi-VN')}đ`,
      details: { cardType, cardNumber, cardSerial }
    });
    
    // Simulate calling the external payment gateway
    const gatewayResponse = await transactionController.simulateCardGateway(req.body);

    if (gatewayResponse.success) {
      // If gateway confirms success, update user's balance and transaction status
      
      // Update balance atomically to prevent race conditions
      const updatedUser = await User.findByIdAndUpdate(userId, 
        { $inc: { balance: parsedAmount } }, 
        { new: true, runValidators: true }
      );
      
      // Update transaction log
      transaction.status = 'success';
      transaction.description = gatewayResponse.message;
      await transaction.save();

      res.status(200).json({
        status: 'success',
        message: 'Nạp thẻ thành công!',
        data: {
          newBalance: updatedUser.balance,
          amount: parsedAmount,
        },
      });

    } else {
      // If gateway reports failure, update transaction status and return error
      transaction.status = 'failed';
      transaction.description = gatewayResponse.message;
      await transaction.save();

      return next(new AppError(gatewayResponse.message, 400));
    }
  }),

  getMyTransactions: catchAsync(async (req, res, next) => {
    const transactions = await Transaction.find({ user: req.user.id }).sort('-createdAt');

    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  })
};
// **END: NEW CONTROLLER**

// User Controller
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
      data: {
        user: userResponse,
      },
    });
  }),

  updateMe: catchAsync(async (req, res, next) => {
    // Create error if user POSTs password data
    if (req.body.password || req.body.passwordConfirm) {
      return next(new AppError('This route is not for password updates. Please use /updateMyPassword.', 400));
    }

    const { name } = req.body;
    if (!name || name.trim().length === 0) {
      return next(new AppError('Please provide a valid name', 400));
    }

    // Update user document
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
      data: {
        users,
      },
    });
  }),

  getUser: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: {
        user,
      },
    });
  }),

  updateUser: catchAsync(async (req, res, next) => {
    // Don't allow password updates through this route
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
      data: {
        user,
      },
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

// Product Controller
const productController = {
  getAllProducts: catchAsync(async (req, res, next) => {
    // Build query
    const queryObj = { ...req.query };
    const excludedFields = ['page', 'sort', 'limit', 'fields'];
    excludedFields.forEach(el => delete queryObj[el]);

    // Add active filter
    queryObj.active = { $ne: false };

    // Advanced filtering
    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, match => `$${match}`);

    let query = Product.find(JSON.parse(queryStr));

    // Sorting
    if (req.query.sort) {
      const sortBy = req.query.sort.split(',').join(' ');
      query = query.sort(sortBy);
    } else {
      query = query.sort('-createdAt');
    }

    // Field limiting
    if (req.query.fields) {
      const fields = req.query.fields.split(',').join(' ');
      query = query.select(fields);
    } else {
      query = query.select('-__v');
    }

    // Pagination
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 100;
    const skip = (page - 1) * limit;

    query = query.skip(skip).limit(limit);

    // Execute query
    const products = await query.populate({
      path: 'createdBy',
      select: 'name email'
    });

    res.status(200).json({
      status: 'success',
      results: products.length,
      data: {
        products,
      },
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
      data: {
        product,
      },
    });
  }),

  createProduct: catchAsync(async (req, res, next) => {
    const { title, description, price, images, link } = req.body;

    // Validation
    if (!title || !description || !price || !link) {
      return next(new AppError('Please provide all required fields: title, description, price, and link', 400));
    }

    // Process images
    let productImages = images;
    if (typeof images === 'string') {
      productImages = [images];
    } else if (!Array.isArray(images) || images.length === 0) {
      return next(new AppError('Please provide at least one product image', 400));
    }

    // Create product data
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
      data: {
        product: newProduct,
      },
    });
  }),

  updateProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);

    if (!product) {
      return next(new AppError('No product found with that ID', 404));
    }

    // Check ownership
    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return next(new AppError('You do not have permission to update this product', 403));
    }

    // Process images if provided
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
      data: {
        product: updatedProduct,
      },
    });
  }),

  deleteProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);

    if (!product) {
      return next(new AppError('No product found with that ID', 404));
    }

    // Check ownership
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
      data: {
        stats,
      },
    });
  }),
};

// Cart and Favorites Controller
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
      data: {
        cart: user.cart
      }
    });
  }),

  getCart: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).populate({
      path: 'cart.product',
      select: 'title price images link category badge'
    });

    res.status(200).json({
      status: 'success',
      data: {
        cart: user.cart
      }
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
      data: {
        cart: user.cart
      }
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
      data: {
        cart: user.cart
      }
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
      data: {
        cart: user.cart
      }
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
      data: {
        favorites: user.favorites
      }
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
      data: {
        favorites: user.favorites
      }
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
      data: {
        favorites: user.favorites
      }
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
      data: {
        isFavorite
      }
    });
  }),
};

// Review Controller
const reviewController = {
  getAllReviews: catchAsync(async (req, res, next) => {
    let filter = {};
    if (req.params.productId) filter = { product: req.params.productId };

    const reviews = await Review.find(filter);

    res.status(200).json({
      status: 'success',
      results: reviews.length,
      data: {
        reviews,
      },
    });
  }),

  createReview: catchAsync(async (req, res, next) => {
    // Allow nested routes
    if (!req.body.product) req.body.product = req.params.productId;
    if (!req.body.user) req.body.user = req.user.id;

    // Check if product exists
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
      data: {
        review: newReview,
      },
    });
  }),

  getReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new AppError('No review found with that ID', 404));
    }

    res.status(200).json({
      status: 'success',
      data: {
        review,
      },
    });
  }),

  updateReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new AppError('No review found with that ID', 404));
    }

    // Check ownership
    if (review.user._id.toString() !== req.user._id.toString()) {
      return next(new AppError('You do not have permission to update this review', 403));
    }

    const updatedReview = await Review.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      status: 'success',
      data: {
        review: updatedReview,
      },
    });
  }),

  deleteReview: catchAsync(async (req, res, next) => {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return next(new AppError('No review found with that ID', 404));
    }

    // Check ownership or admin role
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
        // Update existing user to admin if not already
        if (user.role !== 'admin') {
          user.role = 'admin';
          await user.save({ validateBeforeSave: false });
          console.log(`Updated ${email} to admin role`);
        }
      } else {
        // Create new admin user
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

// Initialize database connection
connectDB();

// Routes

// Health check route
app.get('/api/v1/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Authentication routes
app.post('/api/v1/users/signup', authController.signup);
app.post('/api/v1/users/login', authController.login);
app.get('/api/v1/users/logout', authController.logout);
app.post('/api/v1/users/forgotPassword', authController.forgotPassword);
app.patch('/api/v1/users/resetPassword/:token', authController.resetPassword);

// Public product routes
app.get('/api/v1/products', productController.getAllProducts);
app.get('/api/v1/products/stats', productController.getProductStats);
app.get('/api/v1/products/:id', productController.getProduct);

// Public review routes
app.get('/api/v1/reviews', reviewController.getAllReviews);
app.get('/api/v1/products/:productId/reviews', reviewController.getAllReviews);

// Protected user routes
app.use(authController.protect); // All routes below this are protected

app.get('/api/v1/users/me', userController.getMe);
app.patch('/api/v1/users/updateMe', userController.updateMe);
app.patch('/api/v1/users/updateMyPassword', authController.updatePassword);
app.delete('/api/v1/users/deleteMe', userController.deleteMe);

// **START: NEW DEPOSIT & TRANSACTION ROUTES**
app.post('/api/v1/users/deposit/card', transactionController.depositWithCard);
app.get('/api/v1/users/transactions', transactionController.getMyTransactions);
// **END: NEW ROUTES**

// Cart routes
app.route('/api/v1/cart')
  .get(cartFavoriteController.getCart)
  .post(cartFavoriteController.addToCart)
  .delete(cartFavoriteController.clearCart);

app.route('/api/v1/cart/:productId')
  .patch(cartFavoriteController.updateCartItem)
  .delete(cartFavoriteController.removeFromCart);

// Favorites routes
app.route('/api/v1/favorites')
  .get(cartFavoriteController.getFavorites)
  .post(cartFavoriteController.addToFavorites);

app.route('/api/v1/favorites/:productId')
  .delete(cartFavoriteController.removeFromFavorites);

app.get('/api/v1/favorites/check/:productId', cartFavoriteController.checkFavorite);

// Protected review routes
app.post('/api/v1/reviews', reviewController.createReview);
app.post('/api/v1/products/:productId/reviews', reviewController.createReview);

app.route('/api/v1/reviews/:id')
  .get(reviewController.getReview)
  .patch(reviewController.updateReview)
  .delete(reviewController.deleteReview);

// User product management routes (for users to manage their own products)
app.post('/api/v1/my-products', productController.createProduct);
app.patch('/api/v1/my-products/:id', productController.updateProduct);
app.delete('/api/v1/my-products/:id', productController.deleteProduct);

// Admin only routes
app.use('/api/v1/admin', authController.restrictTo('admin'));

// Admin user management
app.route('/api/v1/admin/users')
  .get(userController.getAllUsers);

app.route('/api/v1/admin/users/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

app.post('/api/v1/admin/users/make-admin', userController.makeUserAdmin);

// Admin product management
app.route('/api/v1/admin/products')
  .post(productController.createProduct);

app.route('/api/v1/admin/products/:id')
  .patch(productController.updateProduct)
  .delete(productController.deleteProduct);

// 404 handler for undefined routes
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handling middleware
app.use(globalErrorHandler);

// Start server
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown handlers
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
