app.get('/api/v1/users/reviews', reviewController.getMyReviews);

app.route('/api/v1/reviews/:id')
  .get(reviewController.getReview)
  .patch(reviewController.updateReview)
  .delete(reviewController.deleteReview);

// User's own product management
app.get('/api/v1/my-products', productController.getMyProducts);
app.post('/api/v1/my-products', productController.createProduct);
app.patch('/api/v1/my-products/:id', productController.updateProduct);
app.delete('/api/v1/my-products/:id', productController.deleteProduct);

// --- ADMIN ROUTES (ADMIN AUTH REQUIRED) ---
// Apply admin restriction to all routes below
app.use('/api/v1/admin', authController.restrictTo('admin'));

// Admin user management
app.route('/api/v1/admin/users')
  .get(userController.getAllUsers);

app.route('/api/v1/admin/users/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

app.post('/api/v1/admin/users/make-admin', userController.makeUserAdmin);
app.patch('/api/v1/admin/users/:userId/balance', userController.updateUserBalance);

// Admin product management
app.route('/api/v1/admin/products')
  .post(productController.createProduct);

app.route('/api/v1/admin/products/:id')
  .patch(productController.updateProduct)
  .delete(productController.deleteProduct);

// Admin transaction management
app.get('/api/v1/admin/transactions/stats', transactionController.getTransactionStats);

// Admin review management
app.delete('/api/v1/admin/reviews/:id', reviewController.deleteReview);

// --- ERROR HANDLING ---
// 404 handler for unmatched routes
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handling middleware
app.use(globalErrorHandler);

// -----------------------------------------------------------------------------
// --- SERVER STARTUP AND GRACEFUL SHUTDOWN ---
// -----------------------------------------------------------------------------
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${port}/api/v1/health`);
  
  if (process.env.NODE_ENV === 'development') {
    console.log(`🧪 Test callback: http://localhost:${port}/api/v1/payment/test-callback`);
    console.log(`📋 Available endpoints:`);
    console.log(`   Public: /api/v1/products, /api/v1/users/signup, /api/v1/users/login`);
    console.log(`   Auth: /api/v1/users/me, /api/v1/cart, /api/v1/favorites`);
    console.log(`   Payment: /api/v1/users/deposit/card, /api/v1/users/transactions`);
    console.log(`   Admin: /api/v1/admin/users, /api/v1/admin/products`);
  }
});

// Graceful shutdown handlers
process.on('unhandledRejection', (err) => {
  console.log('💥 UNHANDLED REJECTION! Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err) => {
  console.log('💥 UNCAUGHT EXCEPTION! Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
  });
});

// Gracefully close database connection
process.on('SIGINT', async () => {
  console.log('\n👋 SIGINT RECEIVED. Shutting down gracefully');
  try {
    await mongoose.connection.close();
    console.log('📊 Database connection closed');
  } catch (error) {
    console.error('❌ Error closing database:', error);
  }
  process.exit(0);
});

module.exports = app;
const connectDB = async () => {
  try {
    const connectionOptions = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      bufferMaxEntries: 0 // Disable mongoose buffering
    };

    await mongoose.connect(DB, connectionOptions);
    console.log('✅ DB connection successful!');
    await createDefaultAdmin();
  } catch (error) {
    console.error('❌ Database connection failed:', error);
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
          console.log(`✅ Updated ${email} to admin role`);
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
        console.log(`✅ Created admin user: ${email}`);
      }
    }
  } catch (error) {
    console.error('❌ Error creating default admin:', error);
  }
};

// Start database connection
connectDB();

// -----------------------------------------------------------------------------
// --- ROUTES CONFIGURATION - CẢI TIẾN VÀ TỔ CHỨC LẠI ---
// -----------------------------------------------------------------------------

// Health check endpoint
app.get('/api/v1/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '1.0.0'
  });
});

// --- SPECIAL CALLBACK ROUTES (MUST BE BEFORE OTHER MIDDLEWARE) ---
// Callback từ doithe1s.vn - CỰC KỲ QUAN TRỌNG, KHÔNG ĐƯỢC BẢO VỆ BỞI AUTH
app.all('/api/v1/payment/callback/doithe1s', paymentCallbackController.handleDoithe1sCallback);

// Test callback endpoint (chỉ trong development)
if (process.env.NODE_ENV === 'development') {
  app.post('/api/v1/payment/test-callback', paymentCallbackController.testCallback);
}

// --- PUBLIC ROUTES (NO AUTH REQUIRED) ---
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

// --- PROTECTED ROUTES (AUTH REQUIRED) ---
// Apply authentication middleware to all routes below
app.use(authController.protect);

// User profile routes
app.get('/api/v1/users/me', userController.getMe);
app.patch('/api/v1/users/updateMe', userController.updateMe);
app.patch('/api/v1/users/updateMyPassword', authController.updatePassword);
app.delete('/api/v1/users/deleteMe', userController.deleteMe);

// Session management routes
app.get('/api/v1/users/sessions', userController.getSessions);
app.delete('/api/v1/users/sessions/all-but-current', userController.logoutAllOtherSessions);
app.delete('/api/v1/users/sessions/:sessionId', userController.logoutSession);

// Payment and transaction routes
app.post('/api/v1/users/deposit/card', transactionController.depositWithCard);
app.get('/api/v1/users/transactions', transactionController.getMyTransactions);
app.get('/api/v1/users/transactions/stats', transactionController.getMyTransactionStats);
app.get('/api/v1/users/transactions/:id', transactionController.getTransaction);

// Cart management routes
app.route('/api/v1/cart')
  .get(cartFavoriteController.getCart)
  .post(cartFavoriteController.addToCart)
  .delete(cartFavoriteController.clearCart);

app.route('/api/v1/cart/:productId')
  .patch(cartFavoriteController.updateCartItem)
  .delete(cartFavoriteController.removeFromCart);

// Favorites management routes
app.route('/api/v1/favorites')
  .get(cartFavoriteController.getFavorites)
  .post(cartFavoriteController.addToFavorites);

app.route('/api/v1/favorites/:productId')
  .delete(cartFavoriteController.removeFromFavorites);

app.get('/api/v1/favorites/check/:productId', cartFavoriteController.checkFavorite);

// Review routes (authenticated)
app.post('/api/v1/reviews', reviewController.createReview);
app.post('/api/v1/products/:productId/reviews', reviewController.createReview);const express = require('express');
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

// -----------------------------------------------------------------------------
// --- UTILITY FUNCTIONS ---
// -----------------------------------------------------------------------------
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

// -----------------------------------------------------------------------------
// --- ENHANCED PRODUCT CONTROLLER ---
// -----------------------------------------------------------------------------
const productController = {
  getAllProducts: catchAsync(async (req, res, next) => {
    const queryObj = { ...req.query };
    const excludedFields = ['page', 'sort', 'limit', 'fields', 'search'];
    excludedFields.forEach(el => delete queryObj[el]);

    queryObj.active = { $ne: false };

    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, match => `${match}`);

    let query = Product.find(JSON.parse(queryStr));

    // Search functionality
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      query = query.find({
        $or: [
          { title: searchRegex },
          { description: searchRegex },
          { features: { $in: [searchRegex] } }
        ]
      });
    }

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

    const products = await query.populate({
      path: 'createdBy',
      select: 'name email'
    });

    const total = await Product.countDocuments({
      ...JSON.parse(queryStr),
      ...(req.query.search && {
        $or: [
          { title: new RegExp(req.query.search, 'i') },
          { description: new RegExp(req.query.search, 'i') },
          { features: { $in: [new RegExp(req.query.search, 'i')] } }
        ]
      })
    });

    res.status(200).json({
      status: 'success',
      results: products.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
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

    // Increment views (không cần await vì không quan trọng lắm)
    Product.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }).exec();

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

    const totalProducts = await Product.countDocuments({ active: { $ne: false } });
    const totalSales = await Product.aggregate([
      { $match: { active: { $ne: false } } },
      { $group: { _id: null, total: { $sum: '$sales' } } }
    ]);

    res.status(200).json({
      status: 'success',
      data: { 
        stats,
        totalProducts,
        totalSales: totalSales[0]?.total || 0
      },
    });
  }),

  getMyProducts: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const filter = { createdBy: req.user._id };
    
    if (req.query.category) {
      filter.category = req.query.category;
    }

    if (req.query.status === 'active') {
      filter.active = true;
    } else if (req.query.status === 'inactive') {
      filter.active = false;
    }

    const products = await Product.find(filter)
      .sort('-createdAt')
      .skip(skip)
      .limit(limit);

    const total = await Product.countDocuments(filter);

    res.status(200).json({
      status: 'success',
      results: products.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      data: { products }
    });
  })
};

// -----------------------------------------------------------------------------
// --- ENHANCED CART & FAVORITES CONTROLLER ---
// -----------------------------------------------------------------------------
const cartFavoriteController = {
  addToCart: catchAsync(async (req, res, next) => {
    const { productId, quantity = 1 } = req.body;

    if (!productId) {
      return next(new AppError('Please provide a product ID', 400));
    }

    if (quantity < 1 || quantity > 99) {
      return next(new AppError('Quantity must be between 1 and 99', 400));
    }

    const product = await Product.findOne({
      _id: productId,
      active: { $ne: false }
    });

    if (!product) {
      return next(new AppError('Product not found or no longer available', 404));
    }

    if (product.stock < quantity) {
      return next(new AppError(`Only ${product.stock} items available in stock`, 400));
    }

    const user = await User.findById(req.user.id);
    const existingItemIndex = user.cart.findIndex(item =>
      item.product.toString() === productId
    );

    if (existingItemIndex !== -1) {
      const newQuantity = user.cart[existingItemIndex].quantity + parseInt(quantity, 10);
      if (newQuantity > product.stock) {
        return next(new AppError(`Cannot add more items. Maximum available: ${product.stock}`, 400));
      }
      user.cart[existingItemIndex].quantity = Math.min(newQuantity, 99);
    } else {
      user.cart.push({
        product: productId,
        quantity: parseInt(quantity, 10)
      });
    }

    await user.save({ validateBeforeSave: false });

    // Populate cart for response
    await user.populate({
      path: 'cart.product',
      select: 'title price images link category badge stock'
    });

    res.status(200).json({
      status: 'success',
      message: 'Product added to cart',
      data: { cart: user.cart }
    });
  }),

  getCart: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).populate({
      path: 'cart.product',
      select: 'title price images link category badge stock active'
    });

    // Filter out inactive products
    user.cart = user.cart.filter(item => item.product && item.product.active !== false);
    
    // Calculate cart totals
    const cartTotal = user.cart.reduce((total, item) => {
      return total + (item.product.price * item.quantity);
    }, 0);

    const cartItemsCount = user.cart.reduce((count, item) => count + item.quantity, 0);

    res.status(200).json({
      status: 'success',
      data: { 
        cart: user.cart,
        summary: {
          itemsCount: cartItemsCount,
          totalAmount: cartTotal
        }
      }
    });
  }),

  updateCartItem: catchAsync(async (req, res, next) => {
    const { productId } = req.params;
    const { quantity } = req.body;

    if (!quantity || quantity < 1 || quantity > 99) {
      return next(new AppError('Quantity must be between 1 and 99', 400));
    }

    const product = await Product.findOne({
      _id: productId,
      active: { $ne: false }
    });

    if (!product) {
      return next(new AppError('Product not found', 404));
    }

    if (quantity > product.stock) {
      return next(new AppError(`Only ${product.stock} items available`, 400));
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
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const user = await User.findById(req.user.id).populate({
      path: 'favorites',
      select: 'title price images link category badge sales stock',
      match: { active: { $ne: false } }
    });

    // Manual pagination for populated array
    const totalFavorites = user.favorites.length;
    const paginatedFavorites = user.favorites.slice(skip, skip + limit);

    res.status(200).json({
      status: 'success',
      results: paginatedFavorites.length,
      total: totalFavorites,
      currentPage: page,
      totalPages: Math.ceil(totalFavorites / limit),
      data: { favorites: paginatedFavorites }
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

// -----------------------------------------------------------------------------
// --- ENHANCED REVIEW CONTROLLER ---
// -----------------------------------------------------------------------------
const reviewController = {
  getAllReviews: catchAsync(async (req, res, next) => {
    let filter = {};
    if (req.params.productId) filter = { product: req.params.productId };

    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const reviews = await Review.find(filter)
      .sort('-createdAt')
      .skip(skip)
      .limit(limit);

    const total = await Review.countDocuments(filter);

    // Calculate average rating if filtering by product
    let averageRating = null;
    if (req.params.productId) {
      const ratingStats = await Review.aggregate([
        { $match: filter },
        {
          $group: {
            _id: null,
            averageRating: { $avg: '$rating' },
            totalReviews: { $sum: 1 }
          }
        }
      ]);
      averageRating = ratingStats[0]?.averageRating || 0;
    }

    res.status(200).json({
      status: 'success',
      results: reviews.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      averageRating,
      data: { reviews },
    });
  }),

  createReview: catchAsync(async (req, res, next) => {
    if (!req.body.product) req.body.product = req.params.productId;
    if (!req.body.user) req.body.user = req.user.id;

    const { product, rating, review } = req.body;

    if (!product || !rating || !review) {
      return next(new AppError('Please provide product, rating, and review content', 400));
    }

    const productExists = await Product.findOne({
      _id: product,
      active: { $ne: false }
    });

    if (!productExists) {
      return next(new AppError('Product not found', 404));
    }

    // Check if user already reviewed this product
    const existingReview = await Review.findOne({
      product,
      user: req.user.id
    });

    if (existingReview) {
      return next(new AppError('You have already reviewed this product', 400));
    }

    const newReview = await Review.create({
      product,
      user: req.user.id,
      rating: parseInt(rating, 10),
      review: review.trim()
    });

    await newReview.populate({
      path: 'user',
      select: 'name avatarText'
    });

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
  }),

  getMyReviews: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const reviews = await Review.find({ user: req.user.id })
      .populate({
        path: 'product',
        select: 'title images category'
      })
      .sort('-createdAt')
      .skip(skip)
      .limit(limit);

    const total = await Review.countDocuments({ user: req.user.id });

    res.status(200).json({
      status: 'success',
      results: reviews.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      data: { reviews }
    });
  })
};

// -----------------------------------------------------------------------------
// --- ENHANCED TRANSACTION AND PAYMENT CONTROLLERS ---
// -----------------------------------------------------------------------------
const transactionController = {
  /**
   * Nạp tiền bằng thẻ cào - Enhanced với validation và security tốt hơn
   */
  depositWithCard: catchAsync(async (req, res, next) => {
    const { telco, code, serial, amount } = req.body;
    const userId = req.user.id;

    // Validation đầu vào chi tiết hơn
    if (!telco || !code || !serial || !amount) {
      return next(new AppError('Vui lòng điền đầy đủ thông tin thẻ cào (nhà mạng, mã thẻ, serial, mệnh giá).', 400));
    }

    // Validate card data using common service
    const validation = paymentGatewayService.common.validateCardData(telco, code, serial, amount);
    if (!validation.valid) {
      return next(new AppError(validation.error, 400));
    }

    // Kiểm tra rate limit
    const isRateLimited = await paymentGatewayService.common.checkRateLimit(userId);
    if (isRateLimited) {
      return next(new AppError('Bạn đã nạp quá nhiều lần trong 5 phút. Vui lòng chờ một chút.', 429));
    }

    // Tạo request_id duy nhất
    const requestId = paymentGatewayService.common.generateRequestId(userId, 'NAP');
    
    // Tạo transaction pending trước
    const pendingTransaction = await Transaction.create({
      user: userId,
      type: 'deposit',
      method: 'card',
      amount: validation.amount,
      status: 'pending',
      gatewayTransactionId: requestId,
      description: `Đang xử lý nạp thẻ ${telco.toUpperCase()} mệnh giá ${validation.amount.toLocaleString('vi-VN')}đ`,
      details: { 
        cardType: telco.toUpperCase(), 
        cardNumber: code.slice(-4), // Chỉ lưu 4 số cuối để bảo mật
        cardSerial: serial.slice(-4) // Chỉ lưu 4 số cuối để bảo mật
      },
      metadata: {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    console.log('💳 [DEPOSIT] New card request:', {
      user: req.user.name,
      userId,
      requestId,
      telco: telco.toUpperCase(),
      amount: validation.amount
    });

    // Gọi API doithe1s
    const apiResponse = await paymentGatewayService.doithe1s.sendCardRequest({
      telco: telco.toUpperCase(),
      code,
      serial,
      amount: validation.amount,
      request_id: requestId,
    });

    // Xử lý response từ API
    if (apiResponse.status !== 99 && apiResponse.status !== '99') {
      pendingTransaction.status = 'failed';
      pendingTransaction.description = `Thất bại: ${apiResponse.message || 'Thẻ không hợp lệ hoặc đã được sử dụng.'}`;
      pendingTransaction.failureReason = apiResponse.status?.toString();
      pendingTransaction.metadata.processedAt = new Date();
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
          amount: validation.amount,
          status: 'pending',
          createdAt: pendingTransaction.createdAt
        }
      },
    });
  }),

  /**
   * Lấy lịch sử giao dịch của user với filtering và sorting
   */
  getMyTransactions: catchAsync(async (req, res, next) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    // Build filter object
    const filter = { user: req.user.id };
    
    if (req.query.type) {
      filter.type = req.query.type;
    }
    
    if (req.query.status) {
      filter.status = req.query.status;
    }

    if (req.query.method) {
      filter.method = req.query.method;
    }

    // Date range filter
    if (req.query.from || req.query.to) {
      filter.createdAt = {};
      if (req.query.from) {
        filter.createdAt.$gte = new Date(req.query.from);
      }
      if (req.query.to) {
        filter.createdAt.$lte = new Date(req.query.to);
      }
    }

    const transactions = await Transaction.find(filter)
      .sort('-createdAt')
      .skip(skip)
      .limit(limit)
      .select('-details.cardNumber -details.cardSerial -metadata.callbackData'); // Ẩn thông tin nhạy cảm

    const total = await Transaction.countDocuments(filter);

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
   * Lấy chi tiết một giao dịch cụ thể
   */
  getTransaction: catchAsync(async (req, res, next) => {
    const transaction = await Transaction.findOne({
      _id: req.params.id,
      user: req.user.id
    }).select('-details.cardNumber -details.cardSerial -metadata.callbackData');

    if (!transaction) {
      return next(new AppError('Không tìm thấy giao dịch', 404));
    }

    res.status(200).json({
      status: 'success',
      data: { transaction }
    });
  }),

  /**
   * Thống kê giao dịch của user
   */
  getMyTransactionStats: catchAsync(async (req, res, next) => {
    const userId = req.user.id;

    const stats = await Transaction.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: {
            status: '$status',
            type: '$type',
            method: '$method'
          },
          count: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      },
      {
        $group: {
          _id: '$_id.type',
          methods: {
            $push: {
              method: '$_id.method',
              status: '$_id.status',
              count: '$count',
              totalAmount: '$totalAmount'
            }
          },
          totalCount: { $sum: '$count' },
          totalAmount: { $sum: '$totalAmount' }
        }
      }
    ]);

    // Get recent transactions summary
    const recentTransactions = await Transaction.find({ user: userId })
      .sort('-createdAt')
      .limit(5)
      .select('type amount status description createdAt');

    res.status(200).json({
      status: 'success',
      data: { 
        stats,
        recentTransactions,
        balance: req.user.balance || 0
      }
    });
  }),

  /**
   * Lấy thống kê giao dịch tổng thể (cho admin)
   */
  getTransactionStats: catchAsync(async (req, res, next) => {
    const stats = await Transaction.aggregate([
      {
        $group: {
          _id: {
            status: '$status',
            type: '$type',
            method: '$method'
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
              method: '$_id.method',
              status: '$_id.status',
              count: '$count',
              totalAmount: '$totalAmount'
            }
          }
        }
      }
    ]);

    // Get daily stats for last 30 days
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const dailyStats = await Transaction.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            date: {
              $dateToString: {
                format: '%Y-%m-%d',
                date: '$createdAt'
              }
            },
            type: '$type',
            status: '$status'
          },
          count: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      },
      { $sort: { '_id.date': 1 } }
    ]);

    res.status(200).json({
      status: 'success',
      data: { 
        stats,
        dailyStats
      }
    });
  })
};

/**
 * Enhanced Payment Callback Controller với logging và security tốt hơn
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
      userAgent: req.headers['user-agent'],
      timestamp: new Date().toISOString()
    });

    // BƯỚC 1: VALIDATION CƠ BẢN
    if (!status || !request_id) {
      console.warn('⚠️  [CALLBACK-WARN] Missing required fields:', callbackData);
      return res.status(400).send('Error: Missing required fields.');
    }

    // BƯỚC 2: XÁC THỰC CHỮ KÝ - QUAN TRỌNG NHẤT!
    if (!paymentGatewayService.doithe1s.validateCallbackSignature(callbackData)) {
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
    
    // Update metadata
    transaction.metadata = {
      ...transaction.metadata,
      processedAt: new Date(),
      callbackData: {
        status,
        request_id,
        amount: realAmount,
        message,
        ip: req.ip
      }
    };

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
// --- DATABASE SCHEMAS ---
// -----------------------------------------------------------------------------

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

// User indexes
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

// Transaction Schema - Enhanced with more payment methods
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
  gatewayTransactionId: String, // Dùng để lưu request_id
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

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ gatewayTransactionId: 1 }); // Thêm index này cho tìm kiếm nhanh
transactionSchema.index({ status: 1, createdAt: -1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// -----------------------------------------------------------------------------
// --- ENHANCED PAYMENT SERVICE WITH MULTIPLE GATEWAYS ---
// -----------------------------------------------------------------------------
const paymentGatewayService = {
  /**
   * DOITHE1S.VN Service - Enhanced và bảo mật hơn
   */
  doithe1s: {
    /**
     * Gửi yêu cầu đổi thẻ lên doithe1s.vn
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
  },

  /**
   * Common functions for all gateways
   */
  common: {
    generateRequestId: (userId, type = 'NAP') => {
      return `${type}_${userId.toString().slice(-6)}_${Date.now()}_${crypto.randomBytes(2).toString('hex')}`;
    },

    validateCardData: (telco, code, serial, amount) => {
      // Validate telco
      const validTelcos = ['VIETTEL', 'VINAPHONE', 'MOBIFONE', 'VIETNAMOBILE', 'GMOBILE'];
      if (!validTelcos.includes(telco.toUpperCase())) {
        return { valid: false, error: 'Nhà mạng không được hỗ trợ.' };
      }

      // Validate và parse amount
      const parsedAmount = parseInt(amount, 10);
      const validAmounts = [10000, 20000, 50000, 100000, 200000, 300000, 500000, 1000000];
      
      if (isNaN(parsedAmount) || !validAmounts.includes(parsedAmount)) {
        return { 
          valid: false, 
          error: `Mệnh giá không hợp lệ. Chỉ chấp nhận: ${validAmounts.map(a => a.toLocaleString('vi-VN')).join(', ')}đ` 
        };
      }

      // Validate format thẻ (có thể tùy chỉnh theo từng nhà mạng)
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

// -----------------------------------------------------------------------------
// --- ERROR HANDLING FUNCTIONS ---
// -----------------------------------------------------------------------------
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
// --- AUTHENTICATION CONTROLLER ---
// -----------------------------------------------------------------------------
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
// --- USER CONTROLLER - Enhanced với thống kê tốt hơn ---
// -----------------------------------------------------------------------------
const userController = {
  getMe: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    // Tính toán thống kê nhanh
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
      // Thêm thống kê nhanh
      stats: {
        totalTransactions,
        pendingTransactions,
        successfulTransactions,
        cartItemsCount: user.cart.length,
        favoritesCount: user.favorites.length
      }
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
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const filter = { active: { $ne: false } };
    
    if (req.query.role) {
      filter.role = req.query.role;
    }

    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      filter.$or = [
        { name: searchRegex },
        { email: searchRegex }
      ];
    }

    const users = await User.find(filter)
      .select('-password')
      .sort('-createdAt')
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments(filter);

    res.status(200).json({
      status: 'success',
      results: users.length,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      data: { users },
    });
  }),

  getUser: catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id).select('-password');

    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    // Get user stats for admin view
    const [totalTransactions, totalSpent, successfulTransactions] = await Promise.all([
      Transaction.countDocuments({ user: user._id }),
      Transaction.aggregate([
        { $match: { user: new mongoose.Types.ObjectId(user._id), status: 'success', type: 'purchase' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Transaction.countDocuments({ user: user._id, status: 'success' })
    ]);

    const userWithStats = {
      ...user.toObject(),
      stats: {
        totalTransactions,
        totalSpent: totalSpent[0]?.total || 0,
        successfulTransactions
      }
    };

    res.status(200).json({
      status: 'success',
      data: { user: userWithStats },
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

  // New endpoint for user balance management (admin only)
  updateUserBalance: catchAsync(async (req, res, next) => {
    const { userId } = req.params;
    const { amount, action, reason } = req.body;

    if (!amount || !action || !['add', 'subtract', 'set'].includes(action)) {
      return next(new AppError('Please provide valid amount and action (add/subtract/set)', 400));
    }

    const user = await User.findById(userId);
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    const oldBalance = user.balance;
    let newBalance;

    switch (action) {
      case 'add':
        newBalance = oldBalance + Math.abs(amount);
        break;
      case 'subtract':
        newBalance = Math.max(0, oldBalance - Math.abs(amount));
        break;
      case 'set':
        newBalance = Math.max(0, amount);
        break;
    }

    user.balance = newBalance;
    await user.save({ validateBeforeSave: false });

    // Log the balance change
    await Transaction.create({
      user: userId,
      type: action === 'subtract' ? 'withdrawal' : 'deposit',
      method: 'system',
      amount: Math.abs(amount),
      status: 'success',
      description: reason || `Admin ${action} balance: ${Math.abs(amount).toLocaleString('vi-VN')}đ`,
      gatewayTransactionId: `ADMIN_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      metadata: {
        adminAction: true,
        adminId: req.user._id,
        oldBalance,
        newBalance,
        processedAt: new Date()
      }
    });

    res.status(200).json({
      status: 'success',
      message: `User balance updated from ${oldBalance.toLocaleString('vi-VN')}đ to ${newBalance.toLocaleString('vi-VN')}đ`,
      data: {
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          balance: newBalance
        }
      }
    });
  })
};
