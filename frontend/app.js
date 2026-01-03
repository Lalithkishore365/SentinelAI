const API_URL = 'http://127.0.0.1:8000';

// Load from localStorage on page load
window.addEventListener('load', () => {
    const token = localStorage.getItem('accessToken');
    const sessionId = localStorage.getItem('sessionId');
    const username = localStorage.getItem('username');
    const userId = localStorage.getItem('userId');
    const expiresIn = localStorage.getItem('expiresIn');

    if (token && username) {
        showTokenInfo(username, userId, expiresIn);
        document.getElementById('sessionIdInput').value = sessionId || '';
        document.getElementById('trackSessionId').value = sessionId || '';
    }
});

// API Call helper
async function apiCall(endpoint, method = 'GET', body = null, useAuth = false) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        }
    };

    const token = localStorage.getItem('accessToken');
    if (useAuth && token) {
        options.headers['Authorization'] = `Bearer ${token}`;
    }

    if (body) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_URL}${endpoint}`, options);
        const data = await response.json();
        return { status: response.status, data, ok: response.ok };
    } catch (error) {
        return { status: 0, error: error.message, ok: false };
    }
}

// Display response
function displayResponse(elementId, response, isSuccess) {
    const element = document.getElementById(elementId);
    const json = JSON.stringify(response, null, 2);
    element.textContent = json;
    element.className = `response-box ${isSuccess ? 'success' : 'error'}`;
}

// Show token info
function showTokenInfo(username, userId, expiresIn) {
    document.getElementById('tokenInfo').style.display = 'block';
    document.getElementById('username').textContent = username;
    document.getElementById('userId').textContent = userId;
    document.getElementById('expiresIn').textContent = expiresIn;
}

// Clear storage
function clearStorage() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('sessionId');
    localStorage.removeItem('username');
    localStorage.removeItem('userId');
    localStorage.removeItem('expiresIn');
    document.getElementById('tokenInfo').style.display = 'none';
    document.getElementById('sessionIdInput').value = '';
    document.getElementById('trackSessionId').value = '';
    alert('✅ Tokens cleared!');
}

// Register
async function register() {
    const username = document.getElementById('regUsername').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;

    if (!username || !email || !password) {
        displayResponse('registerResponse', { error: 'All fields required' }, false);
        return;
    }

    const response = await apiCall('/register', 'POST', { username, email, password });
    displayResponse('registerResponse', response.data, response.ok);
}

// Login
async function login() {
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;

    if (!username || !password) {
        displayResponse('loginResponse', { error: 'Username and password required' }, false);
        return;
    }

    const response = await apiCall('/login', 'POST', { username, password });

    if (response.ok) {
        localStorage.setItem('accessToken', response.data.access_token);
        localStorage.setItem('refreshToken', response.data.refresh_token);
        localStorage.setItem('sessionId', response.data.session_id || '');
        localStorage.setItem('username', username);
        localStorage.setItem('userId', response.data.user_id);
        localStorage.setItem('expiresIn', response.data.expires_in);

        document.getElementById('sessionIdInput').value = response.data.session_id || '';
        document.getElementById('trackSessionId').value = response.data.session_id || '';

        showTokenInfo(username, response.data.user_id, response.data.expires_in);
    }

    displayResponse('loginResponse', response.data, response.ok);
}

// Get current user
async function getCurrentUser() {
    const response = await apiCall('/me', 'GET', null, true);
    displayResponse('userResponse', response.data, response.ok);
}

// Get session info
async function getSessionInfo() {
    const sessionId = document.getElementById('sessionIdInput').value;

    if (!sessionId) {
        displayResponse('sessionResponse', { error: 'Session ID required' }, false);
        return;
    }

    const response = await apiCall(`/sessions/${sessionId}`, 'GET', null, true);
    displayResponse('sessionResponse', response.data, response.ok);
}

// Track activity
async function trackActivity() {
    const sessionId = document.getElementById('trackSessionId').value;

    if (!sessionId) {
        displayResponse('trackResponse', { error: 'Session ID required' }, false);
        return;
    }

    const response = await apiCall(`/track?session_id=${sessionId}`, 'GET', null, true);
    displayResponse('trackResponse', response.data, response.ok);
}

// Track activity multiple times
async function trackActivityMultiple(times = 5) {
    const sessionId = document.getElementById('trackSessionId').value;

    if (!sessionId) {
        displayResponse('trackMultipleResponse', { error: 'Session ID required' }, false);
        return;
    }

    const results = [];
    for (let i = 1; i <= times; i++) {
        const response = await apiCall(`/track?session_id=${sessionId}`, 'GET', null, true);
        results.push({
            call: i,
            status: response.status,
            success_count: response.data?.features?.success_login_count || 0,
            unique_ips: response.data?.features?.unique_ip_count || 0
        });
    }

    const summary = {
        message: `Logged activity ${times} times`,
        calls: results,
        final_features: results[results.length - 1]
    };

    displayResponse('trackMultipleResponse', summary, true);
}

// Refresh access token
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refreshToken');

    if (!refreshToken) {
        displayResponse('refreshResponse', { error: 'No refresh token stored. Login first.' }, false);
        return;
    }

    const response = await apiCall(`/refresh?refresh_token=${refreshToken}`, 'POST');

    if (response.ok) {
        localStorage.setItem('accessToken', response.data.access_token);
        alert('✅ Token refreshed!');
    }

    displayResponse('refreshResponse', response.data, response.ok);
}

// Logout
async function logout() {
    const sessionId = localStorage.getItem('sessionId');

    if (!sessionId) {
        displayResponse('logoutResponse', { error: 'No session found' }, false);
        return;
    }

    const response = await apiCall(`/logout?session_id=${sessionId}`, 'POST', null, true);

    if (response.ok) {
        clearStorage();
        alert('✅ Logged out successfully!');
    }

    displayResponse('logoutResponse', response.data, response.ok);
}

// Health check
async function healthCheck() {
    const response = await apiCall('/health', 'GET');
    displayResponse('healthResponse', response.data, response.ok);
}

// Run all tests
async function runAllTests() {
    const testResults = document.getElementById('testResults');
    testResults.innerHTML = '<p style="color: #999;">Running tests...</p>';

    const results = [];

    // Test 1: Health Check
    let response = await apiCall('/health', 'GET');
    results.push({
        name: 'Health Check',
        passed: response.ok,
        status: response.status
    });

    // Test 2: Register
    const testUsername = `testuser_${Date.now()}`;
    response = await apiCall('/register', 'POST', {
        username: testUsername,
        email: `test_${Date.now()}@example.com`,
        password: 'password123'
    });
    results.push({
        name: 'Register User',
        passed: response.ok,
        status: response.status
    });

    // Test 3: Login
    response = await apiCall('/login', 'POST', {
        username: testUsername,
        password: 'password123'
    });
    const loginPassed = response.ok;
    results.push({
        name: 'Login',
        passed: loginPassed,
        status: response.status
    });

    let sessionId = null;
    let accessToken = null;

    if (loginPassed) {
        sessionId = response.data.session_id;
        accessToken = response.data.access_token;
    }

    // Test 4: Get Current User
    if (accessToken) {
        const tempToken = localStorage.getItem('accessToken');
        localStorage.setItem('accessToken', accessToken);
        response = await apiCall('/me', 'GET', null, true);
        results.push({
            name: 'Get Current User',
            passed: response.ok,
            status: response.status
        });
        if (tempToken) localStorage.setItem('accessToken', tempToken);
    }

    // Test 5: Track Activity
    if (sessionId && accessToken) {
        localStorage.setItem('accessToken', accessToken);
        response = await apiCall(`/track?session_id=${sessionId}`, 'GET', null, true);
        results.push({
            name: 'Track Activity',
            passed: response.ok,
            status: response.status
        });
    }

    // Test 6: Get Session Info
    if (sessionId && accessToken) {
        response = await apiCall(`/sessions/${sessionId}`, 'GET', null, true);
        results.push({
            name: 'Get Session Info',
            passed: response.ok,
            status: response.status
        });
    }

    // Test 7: Logout
    if (sessionId && accessToken) {
        response = await apiCall(`/logout?session_id=${sessionId}`, 'POST', null, true);
        results.push({
            name: 'Logout',
            passed: response.ok,
            status: response.status
        });
    }

    // Test 8: Session should be invalid after logout
    if (sessionId && accessToken) {
        response = await apiCall(`/track?session_id=${sessionId}`, 'GET', null, true);
        results.push({
            name: 'Track After Logout (should fail)',
            passed: !response.ok,
            status: response.status
        });
    }

    // Display results
    let html = '';
    let passedCount = 0;

    results.forEach((result, index) => {
        const passed = result.passed;
        if (passed) passedCount++;

        html += `
            <div class="test-item ${passed ? 'passed' : 'failed'}">
                <div>
                    <strong>${index + 1}. ${result.name}</strong>
                    <br/>
                    <span style="font-size: 0.85em; color: #999;">Status: ${result.status}</span>
                </div>
                <span class="badge ${passed ? 'passed' : 'failed'}">
                    ${passed ? '✅ PASS' : '❌ FAIL'}
                </span>
            </div>
        `;
    });

    html += `<hr style="margin-top: 15px;"/>`;
    html += `<p><strong>Result: ${passedCount}/${results.length} tests passed</strong></p>`;

    testResults.innerHTML = html;
}
