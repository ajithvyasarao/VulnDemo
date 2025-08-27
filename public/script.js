// OWASP Broken Authentication Demo - Interactive JavaScript

// Global state
let currentUser = null;
let attackResults = [];
let vulnerabilities = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadVulnerabilities();
    setupEventListeners();
});

function initializeApp() {
    // Set up tab navigation
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            switchTab(tabName);
        });
    });

    // Set up modal functionality
    setupModal();
    
    // Initialize security monitoring
    initializeSecurityMonitoring();
}

function switchTab(tabName) {
    // Update navigation
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update content
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    
    // Clear previous states when switching tabs
    if (tabName === 'vulnerable' || tabName === 'secure') {
        clearAuthState();
    }
}

function setupEventListeners() {
    // Vulnerable login form
    const vulnForm = document.getElementById('vulnerableLoginForm');
    if (vulnForm) {
        vulnForm.addEventListener('submit', handleVulnerableLogin);
    }
    
    // Secure login form
    const secureForm = document.getElementById('secureLoginForm');
    if (secureForm) {
        secureForm.addEventListener('submit', handleSecureLogin);
    }
}

function setupModal() {
    const modal = document.getElementById('dashboardModal');
    const closeBtn = modal.querySelector('.close');
    
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });
    
    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

// Vulnerability Management
function loadVulnerabilities() {
    vulnerabilities = [
        {
            id: 1,
            title: 'Plain Text Password Storage',
            description: 'Passwords are stored in plain text instead of being hashed',
            severity: 'Critical',
            example: 'password: "admin123"'
        },
        {
            id: 2,
            title: 'Weak Session Management',
            description: 'Session cookies are not secure and can be hijacked',
            severity: 'High',
            example: 'httpOnly: false, secure: false'
        },
        {
            id: 3,
            title: 'No Rate Limiting',
            description: 'No protection against brute force attacks',
            severity: 'High',
            example: 'Unlimited login attempts allowed'
        },
        {
            id: 4,
            title: 'Information Disclosure',
            description: 'Error messages reveal whether username exists',
            severity: 'Medium',
            example: '"Username not found" vs "Invalid password"'
        },
        {
                id: 5,
                title: 'No Account Lockout',
                description: 'Accounts are never locked after failed attempts',
                severity: 'High',
                example: 'No protection against credential stuffing'
            },
            {
                id: 6,
                title: 'Broken Access Control',
                description: 'No role-based access control validation',
                severity: 'Critical',
                example: 'Normal users can access admin/root functions'
            },
            {
                id: 7,
                title: 'Privilege Escalation',
                description: 'Users can access higher privilege dashboards',
                severity: 'Critical',
                example: 'user role accessing root dashboard'
            },
            {
                id: 8,
                title: 'Sensitive Data Exposure',
                description: 'Critical system data exposed without authorization',
                severity: 'Critical',
                example: 'Database passwords, API keys, SSNs exposed'
            }
    ];
    
    updateVulnerabilityDisplay();
}

function updateVulnerabilityDisplay() {
    const container = document.getElementById('vulnerabilityList');
    if (!container) return;
    
    container.innerHTML = vulnerabilities.map(vuln => `
        <div class="vulnerability-item">
            <h4><i class="fas fa-exclamation-triangle"></i> ${vuln.title}</h4>
            <p><strong>Severity:</strong> <span class="text-danger">${vuln.severity}</span></p>
            <p>${vuln.description}</p>
            <code>${vuln.example}</code>
        </div>
    `).join('');
}

// Authentication Handlers
async function handleVulnerableLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('vulnUsername').value;
    const password = document.getElementById('vulnPassword').value;
    
    try {
        const response = await fetch('/api/login/vulnerable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            showLoginSuccess('vulnerable', data);
            addAttackResult('success', 'Login successful', `User ${username} logged in successfully. Session ID: ${data.session}`);
            
            // Demonstrate vulnerabilities
            demonstrateVulnerabilities(data);
        } else {
            addAttackResult('danger', 'Login failed', data.error);
        }
    } catch (error) {
        addAttackResult('danger', 'Network error', error.message);
    }
}

async function handleSecureLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('secureUsername').value;
    const password = document.getElementById('securePassword').value;
    
    try {
        const response = await fetch('/api/login/secure', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            showLoginSuccess('secure', data);
            addSecurityEvent('success', 'Secure login', `User ${username} logged in securely with proper validation`);
        } else {
            addSecurityEvent('warning', 'Login attempt blocked', data.error);
            addAttackPrevention('Rate limiting active', 'Login attempt was blocked due to security policies');
        }
    } catch (error) {
        addSecurityEvent('danger', 'Network error', error.message);
    }
}

function showLoginSuccess(type, data) {
    const isVulnerable = type === 'vulnerable';
    const content = `
        <div class="card">
            <div class="card-header">
                <h3>${isVulnerable ? 'Vulnerable' : 'Secure'} Dashboard Access</h3>
                <span class="badge ${isVulnerable ? 'badge-danger' : 'badge-success'}">
                    ${isVulnerable ? 'INSECURE' : 'SECURE'}
                </span>
            </div>
            <div class="card-body">
                <h4>Welcome, ${data.user.username}!</h4>
                <p><strong>Role:</strong> ${data.user.role}</p>
                <p><strong>Email:</strong> ${data.user.email || 'Not provided'}</p>
                ${isVulnerable ? `
                    <div class="vulnerability-item">
                        <h4>⚠️ Security Issues Detected</h4>
                        <ul>
                            <li>Session ID exposed: ${data.session}</li>
                            <li>User data fully exposed in response</li>
                            <li>No session regeneration</li>
                        </ul>
                    </div>
                ` : `
                    <div class="feature">
                        <i class="fas fa-check-circle text-success"></i>
                        <span>Secure session established</span>
                    </div>
                `}
                <div style="margin-top: 1rem;">
                    <button class="btn ${isVulnerable ? 'btn-danger' : 'btn-success'}" 
                            onclick="accessDashboard('${type}')">
                        Access ${data.user.role.toUpperCase()} Dashboard
                    </button>
                    ${isVulnerable ? `
                        <button class="btn btn-warning" onclick="accessUserDashboard('${type}')">
                            User Dashboard
                        </button>
                        <button class="btn btn-warning" onclick="accessAdminDashboard('${type}')">
                            Admin Dashboard
                        </button>
                        <button class="btn btn-danger" onclick="accessRootDashboard('${type}')">
                            Root Dashboard
                        </button>
                    ` : `
                        <button class="btn btn-info" onclick="testRoleAccess('${type}', '${data.user.role}')">
                            Test Role Access
                        </button>
                    `}
                    <button class="btn btn-secondary" onclick="logout('${type}')">
                        Logout
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.getElementById('dashboardContent').innerHTML = content;
    document.getElementById('dashboardModal').style.display = 'block';
}

// Attack Demonstrations
async function bruteForceAttack() {
    addAttackResult('info', 'Starting brute force attack...', 'Attempting common passwords');
    
    const commonPasswords = ['password', '123456', 'admin', 'qwerty', 'letmein'];
    const username = 'admin';
    
    for (let i = 0; i < commonPasswords.length; i++) {
        const password = commonPasswords[i];
        
        try {
            const response = await fetch('/api/login/vulnerable', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                addAttackResult('danger', `Brute force successful!`, 
                    `Password cracked: ${password}. This took ${i + 1} attempts.`);
                return;
            } else {
                addAttackResult('warning', `Attempt ${i + 1}/5`, 
                    `Password "${password}" failed: ${data.error}`);
            }
        } catch (error) {
            addAttackResult('danger', 'Attack error', error.message);
        }
        
        // Small delay to show progress
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    addAttackResult('info', 'Brute force completed', 'No vulnerabilities found with common passwords');
}

function sessionHijack() {
    addAttackResult('info', 'Demonstrating session hijacking...', 'Inspecting session cookies');
    
    // Get all cookies
    const cookies = document.cookie.split(';');
    const sessionCookie = cookies.find(cookie => cookie.includes('connect.sid'));
    
    if (sessionCookie) {
        addAttackResult('danger', 'Session hijacking possible!', 
            `Session cookie found: ${sessionCookie.trim()}. This cookie could be stolen via XSS or network sniffing.`);
        
        addAttackResult('warning', 'Vulnerability details', 
            'The session cookie is not marked as httpOnly or secure, making it vulnerable to client-side attacks.');
    } else {
        addAttackResult('info', 'No session found', 'Login first to see session vulnerabilities');
    }
}

async function passwordReset() {
    addAttackResult('info', 'Testing password reset...', 'Attempting to reset admin password');
    
    try {
        const response = await fetch('/api/reset-password/vulnerable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                username: 'admin', 
                newPassword: 'hacked123' 
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            addAttackResult('danger', 'Password reset successful!', 
                'Admin password was reset without any authentication. This is a critical vulnerability.');
        } else {
            addAttackResult('warning', 'Password reset failed', data.error);
        }
    } catch (error) {
        addAttackResult('danger', 'Reset error', error.message);
    }
}

// Privilege Escalation Attacks
async function privilegeEscalation() {
    addAttackResult('info', 'Testing privilege escalation...', 'Attempting to access higher privilege functions');
    
    if (!currentUser) {
        addAttackResult('warning', 'No active session', 'Login first to test privilege escalation');
        return;
    }
    
    addAttackResult('danger', 'Privilege escalation possible!', 
        `User '${currentUser.username}' with role '${currentUser.role}' can access admin and root functions due to missing access control checks.`);
}

async function accessAdminAsUser() {
    if (!currentUser) {
        addAttackResult('warning', 'No active session', 'Login as a normal user first');
        return;
    }
    
    try {
        const response = await fetch('/api/dashboard/admin/vulnerable', {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            addAttackResult('danger', 'CRITICAL: Admin access granted to normal user!', 
                `User '${currentUser.username}' accessed admin dashboard and retrieved sensitive data including: ${JSON.stringify(data.adminData.systemConfig, null, 2)}`);
        } else {
            addAttackResult('info', 'Admin access denied', data.error);
        }
    } catch (error) {
        addAttackResult('danger', 'Admin access error', error.message);
    }
}

async function accessRootAsUser() {
    if (!currentUser) {
        addAttackResult('warning', 'No active session', 'Login as a normal user first');
        return;
    }
    
    try {
        const response = await fetch('/api/dashboard/root/vulnerable', {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            addAttackResult('danger', 'CATASTROPHIC: ROOT ACCESS COMPROMISED!', 
                `User '${currentUser.username}' gained root access! Exposed data includes:
                - All user passwords: ${data.rootData.allUsersWithPasswords.map(u => u.username + ':' + u.password).join(', ')}
                - Database credentials: ${data.rootData.systemSecrets.databaseUrl}
                - AWS keys: ${data.rootData.systemSecrets.awsCredentials.accessKey}
                - Employee SSNs: ${data.rootData.employeeRecords.map(u => u.ssn).join(', ')}`);
        } else {
            addAttackResult('info', 'Root access denied', data.error);
        }
    } catch (error) {
        addAttackResult('danger', 'Root access error', error.message);
    }
}

// Dashboard Access Functions
async function accessUserDashboard(type) {
    const endpoint = `/api/dashboard/user/${type}`;
    await accessSpecificDashboard(endpoint, 'User', type);
}

async function accessAdminDashboard(type) {
    const endpoint = `/api/dashboard/admin/${type}`;
    await accessSpecificDashboard(endpoint, 'Admin', type);
}

async function accessRootDashboard(type) {
    const endpoint = `/api/dashboard/root/${type}`;
    await accessSpecificDashboard(endpoint, 'Root', type);
}

async function accessSpecificDashboard(endpoint, dashboardType, type) {
    try {
        const response = await fetch(endpoint, {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (type === 'vulnerable') {
                let message = `${dashboardType} dashboard accessed successfully!`;
                let details = JSON.stringify(data, null, 2);
                
                if (dashboardType === 'Root' && data.rootData) {
                    message = 'SYSTEM COMPROMISED - ROOT ACCESS GAINED!';
                    details = `Critical data exposed:
                    - Passwords: ${data.rootData.allUsersWithPasswords?.map(u => u.password).join(', ')}
                    - Database URL: ${data.rootData.systemSecrets?.databaseUrl}
                    - AWS Credentials: ${JSON.stringify(data.rootData.systemSecrets?.awsCredentials)}`;
                }
                
                addAttackResult(dashboardType === 'Root' ? 'danger' : 'warning', message, details);
            } else {
                addSecurityEvent('success', `${dashboardType} dashboard accessed`, 
                    `Proper role validation successful for ${dashboardType.toLowerCase()} access`);
            }
        } else {
            if (type === 'vulnerable') {
                addAttackResult('info', `${dashboardType} dashboard access denied`, data.error);
            } else {
                addSecurityEvent('success', 'Access control working', 
                    `${dashboardType} dashboard properly protected: ${data.error}`);
            }
        }
    } catch (error) {
        const resultFunc = type === 'vulnerable' ? addAttackResult : addSecurityEvent;
        resultFunc('danger', `${dashboardType} dashboard error`, error.message);
    }
}

async function testRoleAccess(type, userRole) {
    addSecurityEvent('info', 'Testing role-based access control', 
        `Testing access permissions for ${userRole} role`);
    
    // Test user dashboard
    await accessUserDashboard(type);
    
    // Test admin dashboard
    await accessAdminDashboard(type);
    
    // Test root dashboard  
    await accessRootDashboard(type);
}

// Dashboard Access
async function accessDashboard(type) {
    const endpoint = `/api/dashboard/${type}`;
    
    try {
        const response = await fetch(endpoint, {
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (type === 'vulnerable') {
                addAttackResult('info', 'Dashboard accessed', 
                    `Full user data exposed: ${JSON.stringify(data.user, null, 2)}`);
            } else {
                addSecurityEvent('success', 'Dashboard accessed', 
                    'User authenticated successfully with proper session validation');
            }
        } else {
            if (type === 'vulnerable') {
                addAttackResult('warning', 'Dashboard access denied', data.error);
            } else {
                addSecurityEvent('warning', 'Dashboard access denied', data.error);
            }
        }
    } catch (error) {
        const resultFunc = type === 'vulnerable' ? addAttackResult : addSecurityEvent;
        resultFunc('danger', 'Dashboard error', error.message);
    }
}

// Logout
async function logout(type) {
    const endpoint = `/api/logout/${type}`;
    
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = null;
            document.getElementById('dashboardModal').style.display = 'none';
            
            if (type === 'vulnerable') {
                addAttackResult('warning', 'Incomplete logout', 
                    'Session was not properly destroyed. User ID set to null but session remains.');
            } else {
                addSecurityEvent('success', 'Secure logout', 
                    'Session properly destroyed and cookies cleared');
            }
        }
    } catch (error) {
        const resultFunc = type === 'vulnerable' ? addAttackResult : addSecurityEvent;
        resultFunc('danger', 'Logout error', error.message);
    }
}

// Helper Functions
function addAttackResult(type, title, description) {
    const container = document.getElementById('attackResults');
    if (!container) return;
    
    const result = {
        type,
        title,
        description,
        timestamp: new Date().toISOString()
    };
    
    attackResults.unshift(result);
    updateAttackResults();
}

function updateAttackResults() {
    const container = document.getElementById('attackResults');
    if (!container) return;
    
    if (attackResults.length === 0) {
        container.innerHTML = '<p class="text-muted">Run an attack to see results...</p>';
        return;
    }
    
    container.innerHTML = attackResults.slice(0, 10).map(result => `
        <div class="attack-result ${result.type}">
            <h4>${result.title}</h4>
            <p>${result.description}</p>
            <small class="text-muted">${new Date(result.timestamp).toLocaleString()}</small>
        </div>
    `).join('');
}

function initializeSecurityMonitoring() {
    const container = document.getElementById('securityMonitoring');
    if (!container) return;
    
    container.innerHTML = `
        <div class="security-event info">
            <h4>Security Monitoring Active</h4>
            <p>All authentication attempts are being monitored and logged.</p>
            <small class="text-muted">${new Date().toLocaleString()}</small>
        </div>
    `;
}

function addSecurityEvent(type, title, description) {
    const container = document.getElementById('securityMonitoring');
    if (!container) return;
    
    const event = `
        <div class="security-event ${type}">
            <h4>${title}</h4>
            <p>${description}</p>
            <small class="text-muted">${new Date().toLocaleString()}</small>
        </div>
    `;
    
    container.insertAdjacentHTML('afterbegin', event);
    
    // Keep only last 5 events
    const events = container.querySelectorAll('.security-event');
    if (events.length > 5) {
        events[events.length - 1].remove();
    }
}

function addAttackPrevention(title, description) {
    const container = document.getElementById('attackPrevention');
    if (!container) return;
    
    const prevention = `
        <div class="attack-result success">
            <h4><i class="fas fa-shield-alt"></i> ${title}</h4>
            <p>${description}</p>
            <small class="text-muted">${new Date().toLocaleString()}</small>
        </div>
    `;
    
    container.insertAdjacentHTML('afterbegin', prevention);
}

function demonstrateVulnerabilities(loginData) {
    // Demonstrate session vulnerabilities
    setTimeout(() => {
        addAttackResult('warning', 'Session vulnerability detected', 
            'Session ID is predictable and exposed in the response');
    }, 1000);
    
    // Demonstrate data exposure
    setTimeout(() => {
        addAttackResult('danger', 'Data exposure vulnerability', 
            'Complete user object including sensitive data returned in response');
    }, 2000);
}

function clearAuthState() {
    currentUser = null;
    attackResults = [];
    
    // Clear attack results
    const attackContainer = document.getElementById('attackResults');
    if (attackContainer) {
        attackContainer.innerHTML = '<p class="text-muted">Run an attack to see results...</p>';
    }
    
    // Reset security monitoring
    initializeSecurityMonitoring();
    
    // Clear attack prevention
    const preventionContainer = document.getElementById('attackPrevention');
    if (preventionContainer) {
        preventionContainer.innerHTML = '<p class="text-muted">Security measures will appear here when attacks are prevented...</p>';
    }
}

// Make functions globally available
window.switchTab = switchTab;
window.bruteForceAttack = bruteForceAttack;
window.sessionHijack = sessionHijack;
window.passwordReset = passwordReset;
window.privilegeEscalation = privilegeEscalation;
window.accessAdminAsUser = accessAdminAsUser;
window.accessRootAsUser = accessRootAsUser;
window.accessDashboard = accessDashboard;
window.accessUserDashboard = accessUserDashboard;
window.accessAdminDashboard = accessAdminDashboard;
window.accessRootDashboard = accessRootDashboard;
window.testRoleAccess = testRoleAccess;
window.logout = logout;
