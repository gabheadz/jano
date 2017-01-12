
var filter = function(req, res, next) {
    //console.log('protocol', req.protocol);
    //console.log('secure', req.secure);
    if (req.secure) {
        next();
    } else {
        res.status(409).json({ error: 'Protocol not supported' });
    }
}

module.exports = {
    filter: filter
};