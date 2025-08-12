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

dotenv.config({ path: './config.env' });

const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

const allowedOrigins = [
  'https://greensvn.github.io',
  'https://gsgswe123.github.io',
  'https://greensvn.github.io/Shop2/',
  'https://gsgswe123.github.io/shop3/',
  'http://localhost:5500',
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

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

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

userSchema.index({ email: 1 });
userSchema.index({ role: 1 });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

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

productSchema.index({ createdAt: -1 });
productSchema.index({ category: 1 });
productSchema.index({ price: 1 });
productSchema.index({ createdBy: 1 });

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

reviewSchema.index({ product: 1, user: 1 }, { unique: true });

reviewSchema.pre(/^find/, function(next) {
  this.populate({
    path: 'user',
    select: 'name avatarText',
  });
  next();
});

const Review = mongoose.model('Review', reviewSchema);

// Utility functions
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
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
    sameSite: 'lax'
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
  return new Error(message);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new Error(message);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new Error(message);
};

const handleJWTError = () => new Error('Invalid token. Please log in again!');
const handleJWTExpiredError = () => new Error('Your token has expired! Please log in again.');

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
    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();
    sendErrorProd(error, res);
  }
};

// Controllers
const authController = {
  signup: catchAsync(async (req, res, next) => {
    const { name, email, password, passwordConfirm, role } = req.body;
    if (!name || !email || !password || !passwordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields',
      });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'User with this email already exists',
      });
    }
    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      passwordConfirm,
      role: role || 'user',
    });
    createSendToken(newUser, 201, res);
  }),

  login: catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password',
      });
    }
    const user = await User.findOne({ 
      email: email.toLowerCase().trim(),
      active: { $ne: false }
    }).select('+password');
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password',
      });
    }
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
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.',
      });
    }
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.',
      });
    }
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'fail',
        message: 'User recently changed password! Please log in again.',
      });
    }
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  }),

  restrictTo: (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          status: 'fail',
          message: 'You are not logged in',
        });
      }
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({
          status: 'fail',
          message: 'You do not have permission to perform this action',
        });
      }
      next();
    };
  },

  forgotPassword: catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'There is no user with that email address.',
      });
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
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired',
      });
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    createSendToken(user, 200, res);
  }),
};

const userController = {
  getMe: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
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
    const { name } = req.body;
    if (!name || name.trim().length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a valid name'
      });
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
      data: {
        users,
      },
    });
  }),

  getUser: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    res.status(200).json({
      status: 'success',
      data: {
        user,
      },
    });
  }),

  updateUser: catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    }).select('-password');
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
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
      return res.status(404).json({
        status: 'fail',
        message: 'No user found with that ID'
      });
    }
    res.status(204).json({
      status: 'success',
      data: null,
    });
  }),

  makeUserAdmin: catchAsync(async (req, res, next) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email address'
      });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
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
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, match => `$${match}`);
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
    const page = req.query.page * 1 || 1;
    const limit = req.query.limit * 1 || 100;
    const skip = (page - 1) * limit;
    query = query.skip(skip).limit(limit);
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
    const product = await Product.findById(req.params.id).populate({
      path: 'createdBy',
      select: 'name email'
    });
    if (!product) {
      return res.status(404).json({
        status: 'fail',
        message: 'No product found with that ID',
      });
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
    if (!title || !description || !price || !link) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide all required fields: title, description, price, and link',
      });
    }
    let productImages = images;
    if (typeof images === 'string') {
      productImages = [images];
    } else if (!Array.isArray(images) || images.length === 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide at least one product image',
      });
    }
    const productData = {
      title: title.trim(),
      description: description.trim(),
      price: parseInt(price),
      images: productImages,
      link: link.trim(),
      category: req.body.category || 'services',
      badge: req.body.badge || null,
      sales: parseInt(req.body.sales) || 0,
      stock: parseInt(req.body.stock) || 999,
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
      return res.status(404).json({
        status: 'fail',
        message: 'No product found with that ID',
      });
    }
    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to update this product',
      });
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
      data: {
        product: updatedProduct,
      },
    });
  }),

  deleteProduct: catchAsync(async (req, res, next) => {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({
        status: 'fail',
        message: 'No product found with that ID',
      });
    }
    if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to delete this product',
      });
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

const cartFavoriteController = {
  addToCart: catchAsync(async (req, res, next) => {
    const { productId, quantity = 1 } = req.body;
    if (!productId) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a product ID',
      });
    }
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({
        status: 'fail',
        message: 'Product not found',
      });
    }
    const user = await User.findById(req.user.id);
    const existingItemIndex = user.cart.findIndex(item => 
      item.product.toString() === productId
    );
    if (existingItemIndex !== -1) {
      user.cart[existingItemIndex].quantity += parseInt(quantity);
    } else {
      user.cart.push({ 
        product: productId, 
        quantity: parseInt(quantity) 
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
      return res.status(400).json({
        status: 'fail',
        message: 'Quantity must be at least 1',
      });
    }
    const user = await User.findById(req.user.id);
    const cartItemIndex = user.cart.findIndex(item => 
      item.product.toString() === productId
    );
    if (cartItemIndex === -1) {
      return res.status(404).json({
        status: 'fail',
        message: 'Product not found in cart',
      });
    }
    user.cart[cartItemIndex].quantity = parseInt(quantity);
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
    user.cart = user.cart.filter(item => 
      item.product.toString() !== productId
    );
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
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a product ID',
      });
    }
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({
        status: 'fail',
        message: 'Product not found',
      });
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
      select: 'title price images link category badge sales'
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
    user.favorites = user.favorites.filter(id => 
      id.toString() !== productId
    );
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
    if (!req.body.product) req.body.product = req.params.productId;
    if (!req.body.user) req.body.user = req.user.id;
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
      return res.status(404).json({
        status: 'fail',
        message: 'No review found with that ID',
      });
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
      return res.status(404).json({
        status: 'fail',
        message: 'No review found with that ID',
      });
    }
    if (review.user._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to update this review',
      });
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
      return res.status(404).json({
        status: 'fail',
        message: 'No review found with that ID',
      });
    }
    if (review.user._id.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to delete this review',
      });
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
      }
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
};

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

// Protected routes
app.use('/api/v1/users/me', authController.protect);
app.get('/api/v1/users/me', userController.getMe);
app.patch('/api/v1/users/updateMe', authController.protect, userController.updateMe);
app.delete('/api/v1/users/deleteMe', authController.protect, userController.deleteMe);

// Cart routes
app.use('/api/v1/cart', authController.protect);
app.route('/api/v1/cart')
  .get(cartFavoriteController.getCart)
  .post(cartFavoriteController.addToCart)
  .delete(cartFavoriteController.clearCart);

app.route('/api/v1/cart/:productId')
  .patch(cartFavoriteController.updateCartItem)
  .delete(cartFavoriteController.removeFromCart);

// Favorites routes
app.use('/api/v1/favorites', authController.protect);
app.route('/api/v1/favorites')
  .get(cartFavoriteController.getFavorites)
  .post(cartFavoriteController.addToFavorites);

app.route('/api/v1/favorites/:productId')
  .delete(cartFavoriteController.removeFromFavorites);

app.get('/api/v1/favorites/check/:productId', authController.protect, cartFavoriteController.checkFavorite);

// Review routes (protected)
app.use('/api/v1/reviews', authController.protect);
app.post('/api/v1/reviews', reviewController.createReview);
app.post('/api/v1/products/:productId/reviews', reviewController.createReview);

app.route('/api/v1/reviews/:id')
  .get(reviewController.getReview)
  .patch(reviewController.updateReview)
  .delete(reviewController.deleteReview);

// Admin only routes
app.use('/api/v1/admin', authController.protect, authController.restrictTo('admin'));

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

// User product management (own products)
app.use('/api/v1/my-products', authController.protect);
app.post('/api/v1/my-products', productController.createProduct);
app.patch('/api/v1/my-products/:id', productController.updateProduct);
app.delete('/api/v1/my-products/:id', productController.deleteProduct);

// 404 handler
app.all('*', (req, res, next) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`,
  });
});

// Global error handler
app.use(globalErrorHandler);

// Start server
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

// Handle SIGTERM
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
  });
});

module.exports = app;
