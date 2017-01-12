var token = require("./token");
var fs = require("fs");


const USR_PWD_STRATEGY = 'USR_PWD';
const TOKEN_STRATEGY = 'JWT_TOKEN';

var signIn = function(req, res, next) {
    
    var strategy = determineAuthenticationStrategy(req);
    if (strategy === USR_PWD_STRATEGY) {
        autenticateWithUsrAndPwd(req).then(function(data) {
            req.jwt = data;
            next();
        }, function(err) {
            req.error = err;
            next();
        });
    }    
    else if (strategy === TOKEN_STRATEGY) {
        authenticateWithJwt(req).then(function(data) {
            req.jwt = data;
            next();
        }, function(err){
            req.error = err;
            next();
        });
    } else {
        req.error =  new Error("Unable to determine authentication strategy.");
        next();
    }

    //TODO: check & control number of sessions opened.

}

var determineAuthenticationStrategy = function(req) {
    if (req.body.username || req.body.password) {
        return USR_PWD_STRATEGY;
    }
    else if (req.params.token || req.query.token) {
        return TOKEN_STRATEGY;
    }
    else {
        return 'UNKNOWN';
    }
}

var autenticateWithUsrAndPwd = function(req) {
    
    return new Promise(function(resolve, reject){
            
        console.log("Authenticating with username and password");
        
        var username = req.body.username;
        var password = req.body.password;
        
        if (!username || !password) {
            reject(new Error("username and/or password credentials not provided in request body."));
            return;
        }
        
        if (req.janoConf.authenticateFn) {
            req.janoConf.authenticateFn(username, password).then( function(data) {
                
                if (!data.subject || !data.roles) {
                    reject(new Error("'authenticateFn' did not resolve required data for JWT: subject and/or roles."));
                    return;
                }
                
                var payload = {
                    sub: data.subject,
                    iss: req.janoConf.appName,
                    ipaddr: req.ip,
                    roles: data.roles
                }
                var cert = fs.readFileSync(req.janoConf.privateKey);  // get private key
                console.log('authentication successful');
    
                resolve(token.sign(payload, cert));
                
            }, function(err) {
                console.log(err);
                reject(err);
            });
        }
        else {
            console.log("No 'authenticateFn' provided.");
            reject(new Error("No 'authenticateFn' provided."));
        }
    });
}

var authenticateWithJwt = function(req) {
    
    return new Promise(function(resolve, reject){
                
        console.log("Authenticating with token");
    
        var token = req.params.token || req.query.token;
    
        if (!token) {
            reject(new Error("Token credential not provided as param or query property"));
            return;        
        }
        
        reject(new Error("Not Implemented yet"));
    });
}

module.exports = {
    signIn: signIn
}