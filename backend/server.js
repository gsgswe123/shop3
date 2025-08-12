require('dotenv').config({ path: './config.env' })
const express = require('express')
const mongoose = require('mongoose')
const morgan = require('morgan')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
const nodemailer = require('nodemailer')
const validator = require('validator')

const app = express()
app.use(cors())
app.use(morgan('dev'))
app.use(express.json({ limit: '10mb' }))
app.use(cookieParser())

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, validate: [validator.isEmail] },
  password: { type: String, required: true, minlength: 6, select: false },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  passwordResetToken: String,
  passwordResetExpires: Date,
  wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }]
})
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next()
  this.password = await bcrypt.hash(this.password, 12)
  next()
})
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password)
}
const User = mongoose.model('User', userSchema)

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  image: String,
  stock: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  ratings: [{ user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, star: Number, comment: String }]
})
const Product = mongoose.model('Product', productSchema)

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  products: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
      quantity: { type: Number, default: 1 }
    }
  ],
  totalPrice: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
})
const Order = mongoose.model('Order', orderSchema)

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
      quantity: { type: Number, default: 1 }
    }
  ]
})
const Cart = mongoose.model('Cart', cartSchema)

const protect = async (req, res, next) => {
  let token = req.cookies.jwt || (req.headers.authorization && req.headers.authorization.split(' ')[1])
  if (!token) return res.status(401).json({ message: 'Not authenticated' })
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = await User.findById(decoded.id)
    if (!user) return res.status(401).json({ message: 'User no longer exists' })
    req.user = user
    next()
  } catch {
    res.status(401).json({ message: 'Token invalid or expired' })
  }
}
const restrictTo = role => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).json({ message: 'Forbidden' })
  next()
}
const sendEmail = async options => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
  })
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: options.email,
    subject: options.subject,
    text: options.message
  })
}

app.post('/api/users/register', async (req, res) => {
  const { name, email, password } = req.body
  const exists = await User.findOne({ email })
  if (exists) return res.status(400).json({ message: 'Email already registered' })
  const user = await User.create({ name, email, password })
  res.status(201).json({ user: { name: user.name, email: user.email, role: user.role } })
})

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email }).select('+password')
  if (!user || !(await user.comparePassword(password))) return res.status(401).json({ message: 'Invalid credentials' })
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN })
  res.cookie('jwt', token, { httpOnly: true, maxAge: process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000 })
  res.json({ user: { name: user.name, email: user.email, role: user.role }, token })
})

app.get('/api/users/me', protect, async (req, res) => {
  const user = await User.findById(req.user.id)
  res.json({ user: { name: user.name, email: user.email, role: user.role } })
})

app.post('/api/users/forgot-password', async (req, res) => {
  const user = await User.findOne({ email: req.body.email })
  if (!user) return res.status(404).json({ message: 'User not found' })
  const resetToken = crypto.randomBytes(32).toString('hex')
  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000
  await user.save({ validateBeforeSave: false })
  const resetURL = `${req.protocol}://${req.get('host')}/api/users/reset-password/${resetToken}`
  await sendEmail({ email: user.email, subject: 'Shop Password Reset', message: `Reset your password here: ${resetURL}` })
  res.json({ message: 'Token sent to email' })
})

app.post('/api/users/reset-password/:token', async (req, res) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex')
  const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } })
  if (!user) return res.status(400).json({ message: 'Token invalid or expired' })
  user.password = req.body.password
  user.passwordResetToken = undefined
  user.passwordResetExpires = undefined
  await user.save()
  res.json({ message: 'Password reset successful' })
})

app.get('/api/users', protect, restrictTo('admin'), async (req, res) => {
  const users = await User.find().select('-password')
  res.json(users)
})

app.delete('/api/users/:id', protect, restrictTo('admin'), async (req, res) => {
  await User.findByIdAndDelete(req.params.id)
  res.json({ message: 'User deleted' })
})

app.put('/api/users/:id', protect, restrictTo('admin'), async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true })
  res.json(user)
})

app.get('/api/products', async (req, res) => {
  let { page = 1, limit = 20, search, min, max } = req.query
  page = Number(page)
  limit = Number(limit)
  const filter = {}
  if (search) filter.name = { $regex: search, $options: 'i' }
  if (min) filter.price = { ...filter.price, $gte: Number(min) }
  if (max) filter.price = { ...filter.price, $lte: Number(max) }
  const products = await Product.find(filter).skip((page - 1) * limit).limit(limit)
  res.json(products)
})

app.get('/api/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id)
  res.json(product)
})

app.post('/api/products', protect, restrictTo('admin'), async (req, res) => {
  const product = await Product.create(req.body)
  res.status(201).json(product)
})

app.put('/api/products/:id', protect, restrictTo('admin'), async (req, res) => {
  const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true })
  res.json(product)
})

app.delete('/api/products/:id', protect, restrictTo('admin'), async (req, res) => {
  await Product.findByIdAndDelete(req.params.id)
  res.status(204).end()
})

app.post('/api/products/:id/upload', protect, restrictTo('admin'), async (req, res) => {
  const { imageBase64 } = req.body
  const product = await Product.findByIdAndUpdate(req.params.id, { image: imageBase64 }, { new: true })
  res.json(product)
})

app.post('/api/products/:id/rate', protect, async (req, res) => {
  const { star, comment } = req.body
  const product = await Product.findById(req.params.id)
  const existing = product.ratings.find(r => r.user.toString() === req.user.id)
  if (existing) return res.status(400).json({ message: 'Already rated' })
  product.ratings.push({ user: req.user.id, star, comment })
  await product.save()
  res.json(product)
})

app.get('/api/products/:id/ratings', async (req, res) => {
  const product = await Product.findById(req.params.id).populate('ratings.user', 'name email')
  res.json(product.ratings)
})

app.post('/api/wishlist/:productId', protect, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user.wishlist.includes(req.params.productId)) {
    user.wishlist.push(req.params.productId)
    await user.save()
  }
  res.json(user.wishlist)
})

app.get('/api/wishlist', protect, async (req, res) => {
  const user = await User.findById(req.user.id).populate('wishlist')
  res.json(user.wishlist)
})

app.delete('/api/wishlist/:productId', protect, async (req, res) => {
  const user = await User.findById(req.user.id)
  user.wishlist = user.wishlist.filter(id => id.toString() !== req.params.productId)
  await user.save()
  res.json(user.wishlist)
})

app.post('/api/cart', protect, async (req, res) => {
  let cart = await Cart.findOne({ user: req.user.id })
  if (!cart) cart = await Cart.create({ user: req.user.id, items: [] })
  const { productId, quantity } = req.body
  const idx = cart.items.findIndex(i => i.product.toString() === productId)
  if (idx >= 0) cart.items[idx].quantity += quantity
  else cart.items.push({ product: productId, quantity })
  await cart.save()
  res.json(cart)
})

app.get('/api/cart', protect, async (req, res) => {
  const cart = await Cart.findOne({ user: req.user.id }).populate('items.product')
  res.json(cart)
})

app.delete('/api/cart/:productId', protect, async (req, res) => {
  const cart = await Cart.findOne({ user: req.user.id })
  cart.items = cart.items.filter(i => i.product.toString() !== req.params.productId)
  await cart.save()
  res.json(cart)
})

app.post('/api/orders', protect, async (req, res) => {
  const { products, totalPrice } = req.body
  const order = await Order.create({ user: req.user.id, products, totalPrice })
  res.status(201).json(order)
})

app.get('/api/orders', protect, async (req, res) => {
  const filter = req.user.role === 'admin' ? {} : { user: req.user.id }
  const orders = await Order.find(filter).populate('products.product user')
  res.json(orders)
})

app.get('/api/orders/:id', protect, async (req, res) => {
  const order = await Order.findById(req.params.id).populate('products.product user')
  if (req.user.role !== 'admin' && order.user._id.toString() !== req.user.id) return res.status(403).json({ message: 'Forbidden' })
  res.json(order)
})

app.put('/api/orders/:id', protect, restrictTo('admin'), async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true })
  res.json(order)
})

app.delete('/api/orders/:id', protect, restrictTo('admin'), async (req, res) => {
  await Order.findByIdAndDelete(req.params.id)
  res.json({ message: 'Order deleted' })
})

app.get('/api/stats/orders', protect, restrictTo('admin'), async (req, res) => {
  const stats = await Order.aggregate([
    { $group: { _id: '$status', count: { $sum: 1 }, total: { $sum: '$totalPrice' } } }
  ])
  res.json(stats)
})

app.get('/api/stats/products', protect, restrictTo('admin'), async (req, res) => {
  const stats = await Product.aggregate([
    { $group: { _id: null, totalStock: { $sum: '$stock' }, totalProducts: { $sum: 1 } } }
  ])
  res.json(stats.length ? stats[0] : { totalStock: 0, totalProducts: 0 })
})

app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ message: err.message })
})

mongoose.connect(process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD), {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  app.listen(process.env.PORT || 5000)
})
