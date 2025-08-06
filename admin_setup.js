// admin_setup.js - Script để thiết lập admin users và test permissions
// Chạy file này để tạo admin user hoặc test hệ thống

const API_BASE_URL = 'https://shop-4mlk.onrender.com/api/v1';

// =================================================================
// HELPER FUNCTIONS
// =================================================================

async function apiCall(endpoint, method = 'GET', body = null, token = null) {
  const headers = { 'Content-Type': 'application/json' };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  console.log(`🌐 ${method} ${API_BASE_URL}${endpoint}`);
  
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.message || `HTTP ${response.status}`);
    }
    
    return data;
  } catch (error) {
    console.error(`❌ API Error:`, error.message);
    throw error;
  }
}

// =================================================================
// MAIN FUNCTIONS
// =================================================================

/**
 * Tạo admin user mới
 */
async function createAdminUser(name, email, password) {
  try {
    console.log(`\n🔧 Creating admin user: ${email}`);
    
    const userData = {
      name,
      email,
      password,
      passwordConfirm: password,
      role: 'admin' // 🎯 QUAN TRỌNG: Set role là admin
    };
    
    const result = await apiCall('/users/signup', 'POST', userData);
    
    console.log('✅ Admin user created successfully!');
    console.log('User data:', {
      id: result.data.user._id,
      name: result.data.user.name,
      email: result.data.user.email,
      role: result.data.user.role
    });
    console.log('Token:', result.token);
    
    return result;
  } catch (error) {
    if (error.message.includes('email already exists')) {
      console.log('⚠️ User already exists, trying to login...');
      return await loginUser(email, password);
    }
    throw error;
  }
}

/**
 * Đăng nhập user
 */
async function loginUser(email, password) {
  try {
    console.log(`\n🔐 Logging in: ${email}`);
    
    const result = await apiCall('/users/login', 'POST', { email, password });
    
    console.log('✅ Login successful!');
    console.log('User data:', {
      id: result.data.user._id,
      name: result.data.user.name,
      email: result.data.user.email,
      role: result.data.user.role
    });
    
    return result;
  } catch (error) {
    console.error('❌ Login failed:', error.message);
    throw error;
  }
}

/**
 * Test tạo sản phẩm với admin token
 */
async function testCreateProduct(token) {
  try {
    console.log('\n🧪 Testing product creation...');
    
    const productData = {
      title: `Test Product ${Date.now()}`,
      description: 'This is a test product created by admin script',
      price: 50000,
      category: 'services',
      images: ['https://via.placeholder.com/300x200?text=Test+Product'],
      badge: 'NEW',
      sales: 0,
      link: 'https://example.com/product'
    };
    
    const result = await apiCall('/products', 'POST', productData, token);
    
    console.log('✅ Product created successfully!');
    console.log('Product ID:', result.data.product._id);
    console.log('Product title:', result.data.product.title);
    
    return result.data.product;
  } catch (error) {
    console.error('❌ Product creation failed:', error.message);
    throw error;
  }
}

/**
 * Test quyền admin bằng cách lấy danh sách users
 */
async function testAdminPermissions(token) {
  try {
    console.log('\n🔒 Testing admin permissions...');
    
    const result = await apiCall('/users', 'GET', null, token);
    
    console.log('✅ Admin permissions confirmed!');
    console.log(`Found ${result.results} users in database`);
    
    return result;
  } catch (error) {
    console.error('❌ Admin permission test failed:', error.message);
    throw error;
  }
}

/**
 * Kiểm tra thông tin user hiện tại
 */
async function checkCurrentUser(token) {
  try {
    console.log('\n👤 Checking current user info...');
    
    const result = await apiCall('/users/me', 'GET', null, token);
    
    console.log('✅ Current user info:');
    console.log('- ID:', result.data.user._id);
    console.log('- Name:', result.data.user.name);
    console.log('- Email:', result.data.user.email);
    console.log('- Role:', result.data.user.role);
    console.log('- Balance:', result.data.user.balance);
    
    return result.data.user;
  } catch (error) {
    console.error('❌ Failed to get user info:', error.message);
    throw error;
  }
}

// =================================================================
// MAIN EXECUTION
// =================================================================

async function main() {
  console.log('🚀 Starting Admin Setup & Test Script...\n');
  
  // 🎯 THÔNG TIN ADMIN MẶC ĐỊNH
  const ADMIN_USERS = [
    {
      name: 'co-owner (chí nghĩa)',
      email: 'chinhan20917976549a@gmail.com',
      password: 'admin123456'
    },
    {
      name: 'Ryan Tran Admin', 
      email: 'ryantran149@gmail.com',
      password: 'admin123456'
    }
  ];
  
  try {
    // Bước 1: Tạo hoặc đăng nhập admin user đầu tiên
    const adminUser = ADMIN_USERS[0];
    let authResult;
    
    try {
      authResult = await createAdminUser(adminUser.name, adminUser.email, adminUser.password);
    } catch (error) {
      console.log('⚠️ Failed to create admin, trying to login existing user...');
      authResult = await loginUser(adminUser.email, adminUser.password);
    }
    
    const token = authResult.token;
    
    // Bước 2: Kiểm tra thông tin user
    const currentUser = await checkCurrentUser(token);
    
    // Bước 3: Kiểm tra quyền admin
    if (currentUser.role === 'admin') {
      console.log('\n🎉 User has admin role! Testing permissions...');
      
      await testAdminPermissions(token);
      await testCreateProduct(token);
      
      console.log('\n✅ ALL TESTS PASSED! Admin system is working correctly.');
      console.log('\n📋 SUMMARY:');
      console.log(`- Admin Email: ${currentUser.email}`);
      console.log(`- Admin Role: ${currentUser.role}`);
      console.log(`- Can create products: ✅`);
      console.log(`- Can access admin routes: ✅`);
      console.log('\n🎯 You can now use this account to post products on the website!');
      
    } else {
      console.log('\n❌ ERROR: User does not have admin role!');
      console.log('Current role:', currentUser.role);
      console.log('Expected role: admin');
      
      console.log('\n🔧 TROUBLESHOOTING:');
      console.log('1. Check if the backend is running the latest code');
      console.log('2. Verify that the user role is being set correctly in signup');
      console.log('3. Check database directly to confirm user role');
    }
    
  } catch (error) {
    console.error('\n💥 SCRIPT FAILED:', error.message);
    console.log('\n🔧 TROUBLESHOOTING STEPS:');
    console.log('1. Make sure backend server is running');
    console.log('2. Check API_BASE_URL is correct');
    console.log('3. Verify database connection');
    console.log('4. Check server logs for detailed errors');
  }
}

// =================================================================
// BROWSER COMPATIBILITY
// =================================================================

if (typeof window !== 'undefined') {
  // Running in browser - add to window object
  window.AdminSetup = {
    createAdminUser,
    loginUser,
    testCreateProduct,
    testAdminPermissions,
    checkCurrentUser,
    main
  };
  
  console.log('🌐 Admin Setup loaded in browser. Use window.AdminSetup.main() to run.');
} else {
  // Running in Node.js
  main().then(() => {
    console.log('\n🏁 Script completed.');
    process.exit(0);
  }).catch((error) => {
    console.error('\n💥 Script failed:', error);
    process.exit(1);
  });
}

// =================================================================
// MANUAL TESTING FUNCTIONS (for browser console)
// =================================================================

/**
 * Quick test function for browser console
 */
async function quickAdminTest(email = 'chinhan20917976549a@gmail.com', password = 'admin123456') {
  console.log('🚀 Quick Admin Test Starting...');
  
  try {
    // Login
    const authResult = await fetch(`${API_BASE_URL}/users/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    }).then(r => r.json());
    
    if (authResult.status !== 'success') {
      throw new Error(authResult.message);
    }
    
    console.log('✅ Login successful');
    console.log('Role:', authResult.data.user.role);
    
    // Test product creation
    const productResult = await fetch(`${API_BASE_URL}/products`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authResult.token}`
      },
      body: JSON.stringify({
        title: `Quick Test ${Date.now()}`,
        description: 'Quick test product',
        price: 10000,
        category: 'services',
        images: ['https://via.placeholder.com/300'],
        link: 'https://example.com'
      })
    }).then(r => r.json());
    
    if (productResult.status === 'success') {
      console.log('✅ Product creation successful');
      return { success: true, token: authResult.token, user: authResult.data.user };
    } else {
      console.log('❌ Product creation failed:', productResult.message);
      return { success: false, error: productResult.message };
    }
    
  } catch (error) {
    console.error('❌ Quick test failed:', error);
    return { success: false, error: error.message };
  }
}

if (typeof window !== 'undefined') {
  window.quickAdminTest = quickAdminTest;
}
