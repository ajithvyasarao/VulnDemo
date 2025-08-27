// BusBook JavaScript - Main application functionality

document.addEventListener('DOMContentLoaded', function() {
    loadRoutes();
    setupNavigation();
    setupSearchForm();
});

// Load popular routes
async function loadRoutes() {
    const routesGrid = document.getElementById('routesGrid');
    if (!routesGrid) return;

    try {
        const response = await fetch('/api/routes');
        const routes = await response.json();
        
        routesGrid.innerHTML = routes.map(route => `
            <div class="route-card">
                <div class="route-header">
                    <div class="route-cities">${route.fromCity} → ${route.toCity}</div>
                    <div class="route-price">$${route.price}</div>
                </div>
                <div class="route-details">
                    <div class="route-detail">
                        <i class="fas fa-clock"></i>
                        <span>${route.duration}</span>
                    </div>
                    <div class="route-detail">
                        <i class="fas fa-calendar"></i>
                        <span>Daily departures</span>
                    </div>
                    <div class="route-detail">
                        <i class="fas fa-users"></i>
                        <span>${route.availableSeats} seats</span>
                    </div>
                    <div class="route-detail">
                        <i class="fas fa-star"></i>
                        <span>${route.rating}/5</span>
                    </div>
                </div>
                <button class="btn btn-primary" onclick="bookRoute('${route.fromCity}', '${route.toCity}')">
                    <i class="fas fa-ticket-alt"></i>
                    Book Now
                </button>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load routes:', error);
        routesGrid.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; color: #64748b;">
                <p>Unable to load routes at this time. Please try again later.</p>
            </div>
        `;
    }
}

// Setup navigation functionality
function setupNavigation() {
    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Active navigation highlighting
    window.addEventListener('scroll', () => {
        const sections = document.querySelectorAll('section[id]');
        const navLinks = document.querySelectorAll('.nav-link');
        
        let currentSection = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionHeight = section.clientHeight;
            if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {
                currentSection = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${currentSection}`) {
                link.classList.add('active');
            }
        });
    });
}

// Setup search form
function setupSearchForm() {
    const searchForm = document.getElementById('searchForm');
    if (!searchForm) return;

    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const fromCity = document.getElementById('fromCity').value;
        const toCity = document.getElementById('toCity').value;
        const departureDate = document.getElementById('departureDate').value;
        const passengers = document.getElementById('passengers').value;
        
        if (!fromCity || !toCity || !departureDate) {
            showAlert('Please fill in all required fields.', 'warning');
            return;
        }
        
        if (fromCity === toCity) {
            showAlert('Please select different departure and destination cities.', 'warning');
            return;
        }
        
        // Redirect to registration/login for booking
        sessionStorage.setItem('searchParams', JSON.stringify({
            fromCity,
            toCity,
            departureDate,
            passengers
        }));
        
        showAlert('Please login or register to continue with your booking.', 'warning');
        setTimeout(() => {
            window.location.href = '/register';
        }, 2000);
    });
    
    // Set minimum date to tomorrow
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const departureInput = document.getElementById('departureDate');
    if (departureInput) {
        departureInput.min = tomorrow.toISOString().split('T')[0];
    }
}

// Book route function
function bookRoute(fromCity, toCity) {
    // Store route info for booking
    sessionStorage.setItem('selectedRoute', JSON.stringify({
        fromCity,
        toCity,
        departureDate: new Date().toISOString().split('T')[0],
        passengers: 1
    }));
    
    showAlert('Please login or register to book this route.', 'warning');
    setTimeout(() => {
        window.location.href = '/register';
    }, 2000);
}

// Alert system
function showAlert(message, type = 'info') {
    // Remove existing alerts
    const existingAlert = document.querySelector('.alert-banner');
    if (existingAlert) {
        existingAlert.remove();
    }
    
    const alert = document.createElement('div');
    alert.className = `alert-banner alert-${type}`;
    alert.style.cssText = `
        position: fixed;
        top: 80px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 9999;
        padding: 1rem 2rem;
        border-radius: 0.5rem;
        box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
        max-width: 500px;
        width: 90%;
        text-align: center;
        animation: slideDown 0.3s ease-out;
    `;
    
    // Set colors based on type
    const colors = {
        success: { bg: '#dcfce7', color: '#166534', border: '#bbf7d0' },
        error: { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
        warning: { bg: '#fef3c7', color: '#92400e', border: '#fed7aa' },
        info: { bg: '#dbeafe', color: '#1d4ed8', border: '#bfdbfe' }
    };
    
    const colorSet = colors[type] || colors.info;
    alert.style.backgroundColor = colorSet.bg;
    alert.style.color = colorSet.color;
    alert.style.border = `1px solid ${colorSet.border}`;
    
    alert.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <span>${message}</span>
            <button onclick="this.parentNode.parentNode.remove()" style="background: none; border: none; color: inherit; cursor: pointer; padding: 0.25rem;">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Add animation styles
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateX(-50%) translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(-50%) translateY(0);
            }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.style.animation = 'slideDown 0.3s ease-out reverse';
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, 300);
        }
    }, 5000);
}

// Contact form (if needed)
function handleContactForm(event) {
    event.preventDefault();
    showAlert('Thank you for your message! We will get back to you soon.', 'success');
    event.target.reset();
}

// Newsletter signup
function handleNewsletterSignup(email) {
    if (!email || !email.includes('@')) {
        showAlert('Please enter a valid email address.', 'error');
        return;
    }
    
    showAlert('Thank you for subscribing to our newsletter!', 'success');
}

// Utility functions
function formatPrice(price) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(price);
}

function formatDate(date) {
    return new Intl.DateTimeFormat('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    }).format(new Date(date));
}

// Mobile menu toggle (if needed)
function toggleMobileMenu() {
    const navMenu = document.querySelector('.nav-menu');
    if (navMenu) {
        navMenu.classList.toggle('mobile-open');
    }
}

// Check authentication status
async function checkAuthStatus() {
    try {
        const response = await fetch('/api/session');
        if (response.ok) {
            const user = await response.json();
            updateNavForLoggedInUser(user);
        }
    } catch (error) {
        // User not logged in, keep default nav
    }
}

function updateNavForLoggedInUser(user) {
    const navAuth = document.querySelector('.nav-auth');
    if (navAuth) {
        navAuth.innerHTML = `
            <span style="margin-right: 1rem; color: #64748b;">Welcome, ${user.fullName}</span>
            <a href="/dashboard" class="btn btn-outline">Dashboard</a>
            <button onclick="logout()" class="btn btn-primary">Logout</button>
        `;
    }
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.reload();
    } catch (error) {
        console.error('Logout failed:', error);
    }
}

// Initialize auth check on page load
document.addEventListener('DOMContentLoaded', checkAuthStatus);
