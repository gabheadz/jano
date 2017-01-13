const debug = require('debug')('jano');

/**
 * Function that process a request and determines if is traveling using a secure
 * protocol
 * 
 */
var filter = function(req, res, next) {
    debug('request protocol', req.protocol);
    debug('is request secure', req.secure);
    if (req.secure) {
        next();
    } else {
        res.status(409).json({ error: 'Protocol not supported' });
    }
}

module.exports = {
    filter: filter
};