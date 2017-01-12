var _ = require("lodash");
var fs = require("fs");
var token = require("./token");

var filter = function(req, res, next) {
    
    if (req.whitelisted) {
        next();
        return;
    }
    
    var _ruleSelected = appliesToRequest(req);
    if(_ruleSelected) {
        var roleMatched = _.find(req.credentials.roles, function(r) {
            if (r.match(_ruleSelected.role)) {
                return true;
            } else {
                return false;
            }
        });
        if (roleMatched) {
            next();
        } else {
            res.status(403).json({ error: 'Insufficient privileges to invoke api method'});
            return;
        }
    }
    else {
        next();
    }
    
}

var appliesToRequest = function(req) {
    
    if (!req.janoConf.rules || req.janoConf.rules === undefined)
        return null;
        
    var url = req.originalUrl;
    var method = req.method;

    var _rule = _.find(req.janoConf.rules, function(o) {
        var urlMatch = url.match(o.url);
        var methodMatch = _.find(o.method, function(m) {
            return method.match(o.method);
        });
        return (urlMatch != null) && (methodMatch != null);
    });
    
    if (_rule) {
        if (_rule.anon)
            return null;
        else
            return _rule;
    }
    
    return null;
}

module.exports = {
    filter: filter
}