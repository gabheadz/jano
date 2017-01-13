var _ = require("lodash");
var fs = require("fs");
var token = require("./token");
const debug = require('debug')('jano');

/**
 * Function that process a request and determines if requestor is authenticated. That is 
 * if requestor provided a JWT in the 'Authorization' http header, and the JWT is valid
 * and has not expired.
 * 
 */
var filter = function(req, res, next) {
    
    if (!req.janoConf) {
        res.status(500).json({ error: 'Jano not configured' });
        return;    
    }
    
    if (isWhiteListed(req)) {
        //no credencials are set on request, only a flag to indicate the requestor is whitelisted
        req.whitelisted = true;
        next();
        return;
    }
    
    if (isAnonAllowed(req)) {
        req.anon = true;
        next();
        return;
    }

    //search for authorization header in the http request
    var autzHeader;
    if (!req.get('Authorization')) {
        res.status(401).json({ error: 'No authorization header present' });
        return;
    }
    
    if (!req.janoConf.publicKey || req.janoConf.publicKey === undefined) {
        res.status(500).json({ error: 'Pub/Priv keys not configured' });
        return;
    }
    
    //read public key file, to validate jwt
    var cert = fs.readFileSync(req.janoConf.publicKey);  // get public key
    try {
        //verifies jwt token and, if valid, returns the payload. Then
        //sets te payload in request for other middleware to use
        req.credentials = token.verify(req.get('Authorization').substring(7), cert);
    } catch(err){
        debug(err);
        //TODO: depending on error return status 500 or 401
        res.status(401).json({ error: err.message });
        return;
    }
    
    if (req.janoConf.validateIp && req.janoConf.validateIp == true) {
        if (!reqIpMatchCredentialsIp(req)) {
            res.status(403).json({ error: 'Client\'s IP mismatch token signed IP' });
            return;            
        }
    }
    
    if (req.janoConf.checkUser !== undefined) {
        if (!req.janoConf.checkUser()) {
            res.status(403).json({ error: 'User validation against user repository failed' });
            return;            
        }
    }
    
    next();

}

//----- support methods ------

/**
 * Determines if requestor is in white listed ip's
 * 
 */
var isWhiteListed = function(req) {
    if (!req.janoConf.whitelisted || req.janoConf.whitelisted === undefined)
        return false;
    
    var index = _.findIndex(req.janoConf.whitelisted, function(o) { 
        return o == req.ip;
    });
    
    if (index >= 0) {
        return true;
    }
    else {
        return false;
    }
}

/**
 * Determines if a rule has property anon=true
 * 
 */
var isAnonAllowed = function(req) {
    
    if (!req.janoConf.rules || req.janoConf.rules === undefined)
        return true;
        
    var url = req.originalUrl;
    var method = req.method;

    var _rule = _.find(req.janoConf.rules, function(o) {
        var urlMatch = url.match(o.url);
        var methodMatch = _.find(o.method, function(m) {
            return method.match(o.method);
        });
        return (urlMatch != null) && (methodMatch != null);
    });
    
    if (_rule && _rule.anon == true) {
        return true;
    }

    return false;
}

/**
 * Determines if requestor Ip address matches Ip address signed in JWT
 * 
 */
var reqIpMatchCredentialsIp = function(req) {
    if (req.credentials) {
        if (req.credentials.ipaddr === req.ip)
            return true;
        else
            return false;
    }
    return false;
}

module.exports = {
    filter: filter
}