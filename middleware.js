// Middleware to ensure user is a logged-in Admin (master) or Super Admin
const requireMaster = (req, res, next) => {
    if (!req.session.user || !['admin', 'superadmin'].includes(req.session.user.role)) {
        return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>');
    }
    next();
};

// Middleware to allow staff roles (admin/master, operator, superadmin)
const requireStaff = (req, res, next) => {
    if (!req.session.user || !['admin', 'operator', 'superadmin'].includes(req.session.user.role)) {
        return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>');
    }
    next();
};

// Middleware to ensure user is a logged-in Customer
const requireCustomer = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'customer') {
        return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>');
    }
    next();
};

// Middleware to ensure user is Super Admin only
const requireSuperAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'superadmin') {
        return res.status(403).send('<h1>403 Forbidden</h1><p>Super Admin access required.</p>');
    }
    next();
};

// Alias for write-protected routes (master only)
const requireWrite = requireMaster;

// Backward compatibility: requireAdmin maps to master-only
const requireAdmin = requireMaster;

// Export ALL functions so other files can use them
module.exports = { requireAdmin, requireCustomer, requireStaff, requireMaster, requireWrite, requireSuperAdmin };