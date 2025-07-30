/**
 * Manual zkLogin Testing Script
 * 
 * This script helps you test your zkLogin functionality manually.
 * Run this with: node test-zklogin.js
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

async function testZkLoginFlow() {
  console.log('🧪 Testing zkLogin Authentication Flow\n');

  try {
    // Test 1: Initiate login for GitHub
    console.log('1️⃣ Testing login initiation for GitHub...');
    const githubLoginResponse = await axios.get(`${BASE_URL}/auth/login/github`);

    if (githubLoginResponse.data.success) {
      console.log('✅ GitHub login initiation successful');
      console.log('📋 Session ID:', githubLoginResponse.data.data.sessionId);
      console.log('🔗 Auth URL:', githubLoginResponse.data.data.authUrl);
      console.log('');
    } else {
      console.log('❌ GitHub login initiation failed');
      return;
    }

    // Test 2: Test invalid provider
    console.log('2️⃣ Testing invalid provider...');
    try {
      await axios.get(`${BASE_URL}/auth/login/invalid-provider`);
      console.log('❌ Should have failed for invalid provider');
    } catch (error) {
      if (error.response && error.response.status === 400) {
        console.log('✅ Correctly rejected invalid provider');
        console.log('');
      } else {
        console.log('❌ Unexpected error for invalid provider:', error.message);
      }
    }

    // Test 3: Test token verification with invalid token
    console.log('3️⃣ Testing token verification with invalid token...');
    try {
      await axios.get(`${BASE_URL}/auth/verify`, {
        headers: {
          'Authorization': 'Bearer invalid-token'
        }
      });
      console.log('❌ Should have failed for invalid token');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        console.log('✅ Correctly rejected invalid token');
        console.log('');
      } else {
        console.log('❌ Unexpected error for invalid token:', error.message);
      }
    }

    // Test 4: Test callback with invalid session
    console.log('4️⃣ Testing callback with invalid session...');
    try {
      await axios.post(`${BASE_URL}/auth/callback`, {
        sessionId: 'invalid-session-id',
        code: 'test-code'
      });
      console.log('❌ Should have failed for invalid session');
    } catch (error) {
      if (error.response && error.response.status === 500) {
        console.log('✅ Correctly rejected invalid session');
        console.log('');
      } else {
        console.log('❌ Unexpected error for invalid session:', error.message);
      }
    }

    console.log('🎉 Basic zkLogin API tests completed!');
    console.log('\n📝 Manual Testing Instructions:');
    console.log('1. Copy one of the auth URLs from above');
    console.log('2. Open it in your browser');
    console.log('3. Complete the OAuth flow');
    console.log('4. Copy the authorization code from the callback URL');
    console.log('5. Use the callback endpoint to complete authentication');
    console.log('\nExample callback request:');
    console.log(`curl -X POST ${BASE_URL}/auth/callback \\`);
    console.log('  -H "Content-Type: application/json" \\');
    console.log('  -d \'{"sessionId": "YOUR_SESSION_ID", "code": "YOUR_AUTH_CODE"}\'');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
  }
}

async function testServerHealth() {
  console.log('🏥 Testing server health...');
  try {
    const response = await axios.get(`${BASE_URL}/`);
    console.log('✅ Server is running');
    console.log('Response:', response.data);
    console.log('');
    return true;
  } catch (error) {
    console.log('❌ Server is not running or not accessible');
    console.log('Please make sure your NestJS server is running on port 3000');
    console.log('Run: yarn start:dev');
    return false;
  }
}

async function main() {
  console.log('🚀 zkLogin Testing Suite\n');
  
  const serverHealthy = await testServerHealth();
  if (!serverHealthy) {
    process.exit(1);
  }

  await testZkLoginFlow();
}

// Install axios if not already installed
try {
  require('axios');
} catch (error) {
  console.log('❌ axios is required for this test script');
  console.log('Install it with: npm install axios');
  process.exit(1);
}

main().catch(console.error);
